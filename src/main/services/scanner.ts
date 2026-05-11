import { BrowserWindow } from 'electron'
import { spawn, ChildProcess } from 'child_process'
import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import { getBinaryPath } from '../utils/binary'
import { updateScanStatus, insertHost, insertVulnerability, insertWebUrl, insertWebFingerprint } from './database'

// ---------------------------------------------------------------------------
// State tracking
// ---------------------------------------------------------------------------
const activeProcesses = new Map<string, ChildProcess>()
const cancelledScans = new Set<string>()
const scanPhases = new Map<string, string>()

function safeSend(win: BrowserWindow, channel: string, ...args: any[]): void {
  if (!win.isDestroyed()) win.webContents.send(channel, ...args)
}

// ---------------------------------------------------------------------------
// Temp file helpers
// ---------------------------------------------------------------------------
function tempFile(prefix: string, ext: string): string {
  const id = `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`
  return path.join(os.tmpdir(), `${id}.${ext}`)
}

// ---------------------------------------------------------------------------
// parseNaabuJSON → extract IP:port pairs
// ---------------------------------------------------------------------------
function parseNaabuJSON(raw: string): { host: string; port: number }[] {
  const results: { host: string; port: number }[] = []
  const lines = raw.split(/\r?\n/).filter(Boolean)
  for (const line of lines) {
    try {
      const obj = JSON.parse(line)
      const host = obj.host || obj.ip || ''
      if (host && obj.port) {
        results.push({ host, port: Number(obj.port) })
      }
    } catch { /* skip */ }
  }
  return results
}

// ---------------------------------------------------------------------------
// parseNmapXML → extract host/service/version data
// ---------------------------------------------------------------------------
interface NmapHost {
  ip: string
  ports: { port: number; protocol: string; service: string; product: string; version: string; extrainfo: string }[]
  os: string
}
function parseNmapXML(xml: string): NmapHost[] {
  const hosts: NmapHost[] = []
  // Simple regex-based XML parsing (avoids XML parser dependency)
  const hostRegex = /<host[^>]*>([\s\S]*?)<\/host>/gi
  let hostMatch: RegExpExecArray | null
  while ((hostMatch = hostRegex.exec(xml)) !== null) {
    const hostBlock = hostMatch[1]
    const addrMatch = hostBlock.match(/<address[^>]*addr="([^"]+)"[^>]*addrtype="ipv4"/i)
    if (!addrMatch) continue
    const ip = addrMatch[1]

    const ports: NmapHost['ports'] = []
    const portRegex = /<port\s+protocol="([^"]+)"\s+portid="(\d+)"[^>]*>([\s\S]*?)<\/port>/gi
    let portMatch: RegExpExecArray | null
    while ((portMatch = portRegex.exec(hostBlock)) !== null) {
      const protocol = portMatch[1]
      const portNum = Number(portMatch[2])
      const portBlock = portMatch[3]

      const svcMatch = portBlock.match(/<service[^>]*name="([^"]*)"(?:[^>]*product="([^"]*)")?(?:[^>]*version="([^"]*)")?(?:[^>]*extrainfo="([^"]*)")?/i)
      ports.push({
        port: portNum,
        protocol,
        service: svcMatch?.[1] || '',
        product: svcMatch?.[2] || '',
        version: svcMatch?.[3] || '',
        extrainfo: svcMatch?.[4] || ''
      })
    }

    // Parse NSE script output for vulnerabilities and brute force findings
    const scriptRegexAll = /<script\s+id="([^"]+)"\s+output="([^"]*)"/gi
    let scriptMatch: RegExpExecArray | null
    while ((scriptMatch = scriptRegexAll.exec(hostBlock)) !== null) {
      const scriptId = scriptMatch[1]
      const output = scriptMatch[2].replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')
      if (output.includes('VULNERABLE') || output.includes('State: VULNERABLE') ||
          output.includes('Login Successful') || output.includes('valid credentials') ||
          output.includes('CVE-') || output.includes('MS17-010')) {
        // This is a critical finding — add to the first port as a vulnerability marker
        if (ports.length > 0) {
          ports[0].extrainfo = (ports[0].extrainfo ? ports[0].extrainfo + ' | ' : '') + `[${scriptId}] ${output.slice(0, 200)}`
        }
      }
    }

    const osMatch = hostBlock.match(/<osmatch[^>]*name="([^"]+)"[^>]*accuracy="(\d+)"/i)
    hosts.push({ ip, ports, os: osMatch?.[1] || '' })
  }
  return hosts
}

// ---------------------------------------------------------------------------
// parseHttpxJSON → extract URL, title, tech, status
// ---------------------------------------------------------------------------
interface HttpxResult {
  url: string; title: string; statusCode: number; tech: string[]
  webserver: string; contentType: string; contentLength: number
}
function parseHttpxJSON(raw: string): HttpxResult[] {
  const results: HttpxResult[] = []
  const lines = raw.split(/\r?\n/).filter(Boolean)
  for (const line of lines) {
    try {
      const obj = JSON.parse(line)
      results.push({
        url: obj.url || obj.input || '',
        title: obj.title || '',
        statusCode: obj.status_code || 0,
        tech: obj.tech || obj.technologies || [],
        webserver: obj.webserver || '',
        contentType: obj.content_type || '',
        contentLength: obj.content_length || 0
      })
    } catch { /* skip */ }
  }
  return results
}

// ---------------------------------------------------------------------------
// Spawn helper
// ---------------------------------------------------------------------------
function spawnTool(
  win: BrowserWindow, scanId: string, toolName: string,
  binPath: string, args: string[], phaseName: string
): ChildProcess | null {
  if (cancelledScans.has(scanId)) return null

  safeSend(win, 'scan:stdout', { scanId, line: `[*] ${toolName} 启动: ${args.slice(0, 6).join(' ')}...` })

  const child = spawn(binPath, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true })

  child.on('error', (err) => {
    safeSend(win, 'scan:stderr', { scanId, line: `[!] ${toolName} 启动失败: ${err.message}` })
  })

  child.stderr!.on('data', (chunk: Buffer) => {
    const lines = chunk.toString().split(/\r?\n/).filter(Boolean)
    for (const line of lines) {
      safeSend(win, 'scan:stderr', { scanId, line })
    }
  })

  return child
}

// ---------------------------------------------------------------------------
// handleNmapResult → insert hosts and collect web URLs
// ---------------------------------------------------------------------------
function handleNmapResults(
  win: BrowserWindow, scanId: string, hosts: NmapHost[],
  sentIps: Set<string>
): { webUrls: string[]; hostCount: number } {
  const webUrls: string[] = []
  let hostCount = 0

  for (const h of hosts) {
    for (const p of h.ports) {
      const dedupKey = `${h.ip}:${p.port}`
      if (sentIps.has(dedupKey)) continue
      sentIps.add(dedupKey)

      const service = p.product || p.service
      const fingerprint = [p.product, p.version, p.extrainfo].filter(Boolean).join(' ') || p.service
      const isWeb = p.service === 'http' || p.service === 'https' || p.port === 80 || p.port === 443 || p.port === 8080 || p.port === 8443

      // Build URL for web services
      let url = ''
      if (isWeb) {
        const scheme = p.service === 'https' || p.port === 443 || p.port === 8443 ? 'https' : 'http'
        url = `${scheme}://${h.ip}:${p.port}`
        if (!webUrls.includes(url)) webUrls.push(url)
      }

      insertHost({
        scan_id: scanId, ip: h.ip, port: String(p.port),
        service: service || p.service, url, fingerprint, os: h.os
      })

      safeSend(win, 'scan:stdout', {
        scanId,
        line: `[+] ${h.ip}:${p.port} ${service || ''} ${fingerprint}`
      })

      safeSend(win, 'scan:result', {
        scanId, result: { IP: h.ip, Port: String(p.port), Service: service, FingerPrint: fingerprint, URL: url }, tool: 'nmap'
      })

      hostCount++
    }

    // Insert NSE findings as vulnerabilities
    for (const p of h.ports) {
      if (!p.extrainfo) continue
      const findings = p.extrainfo.split(' | ')
      for (const finding of findings) {
        const m = finding.match(/\[([^\]]+)\]\s*(.+)/)
        if (!m) continue
        const scriptId = m[1], detail = m[2]
        let sev = 'medium'
        if (scriptId.includes('vuln') || detail.includes('VULNERABLE') || detail.includes('CVE-')) sev = 'critical'
        else if (scriptId.includes('brute') || detail.includes('Valid credentials')) sev = 'high'

        insertVulnerability({
          scan_id: scanId, template_id: scriptId,
          name: scriptId, severity: sev, host: h.ip,
          matched_at: `${h.ip}:${p.port}`,
          description: detail, solution: '', raw_data: finding
        })
        safeSend(win, 'scan:stdout', { scanId, line: `[!] ${scriptId} [${sev}] — ${h.ip}:${p.port}` })
      }
    }
  }

  return { webUrls, hostCount }
}

// ---------------------------------------------------------------------------
// handleHttpxResults → insert web URLs and fingerprint data
// ---------------------------------------------------------------------------
function handleHttpxResults(
  win: BrowserWindow, scanId: string, results: HttpxResult[]
): { allTechs: string[]; urlCount: number } {
  const allTechs = new Set<string>()
  let urlCount = 0

  for (const r of results) {
    insertWebUrl({
      scan_id: scanId, url: r.url, title: r.title || r.webserver,
      tech_stack: r.tech.join(', '), status_code: r.statusCode
    })

    for (const tech of r.tech) {
      insertWebFingerprint({
        scan_id: scanId, url: r.url, tech_name: tech,
        category: '', version: '', confidence: 80
      })
      allTechs.add(tech.toLowerCase())
    }

    safeSend(win, 'scan:stdout', {
      scanId,
      line: `[+] ${r.url} — ${r.title || r.webserver || '无标题'}${r.tech.length ? ' [' + r.tech.slice(0, 5).join(', ') + ']' : ''}`
    })

    urlCount++
  }

  return { allTechs: Array.from(allTechs), urlCount }
}

// ---------------------------------------------------------------------------
// handleNucleiResult → insert vulnerabilities
// ---------------------------------------------------------------------------
function handleNucleiResult(win: BrowserWindow, scanId: string, line: string): boolean {
  try {
    const parsed = JSON.parse(line)
    if (!(parsed['templateID'] || parsed['template-id'] || parsed.type)) return false

    const templateId = parsed['templateID'] || parsed['template-id'] || ''
    const info = parsed.info || {}
    const name = info.name || templateId
    const severity = (info.severity || 'info').toLowerCase()
    const host = parsed.host || ''
    const matchedAt = parsed['matched-at'] || host
    const description = info.description || ''
    const refs = info.reference || []
    const solution = Array.isArray(refs) ? refs.join('\n') : String(refs || '')

    insertVulnerability({
      scan_id: scanId, template_id: templateId, name, severity,
      host, matched_at: matchedAt, description, solution,
      raw_data: JSON.stringify(parsed)
    })

    safeSend(win, 'scan:result', { scanId, result: parsed, tool: 'nuclei' })
    safeSend(win, 'scan:stdout', {
      scanId,
      line: `[!] ${name} [${severity}] — ${matchedAt}`
    })
    return true
  } catch {
    return false
  }
}

// ---------------------------------------------------------------------------
// Phase 1: Host discovery — naabu ping sweep (Go-based, handles CIDR natively)
// ---------------------------------------------------------------------------
function runHostDiscovery(
  win: BrowserWindow, scanId: string, target: string
): Promise<string[]> {
  return new Promise((resolve) => {
    const binPath = getBinaryPath('nmap')
    const args = ['-sn', '-n', target.trim(), '-T5']

    safeSend(win, 'scan:stdout', { scanId, line: `[*] 主机发现: nmap -sn ${target.trim()}` })

    const child = spawn(binPath, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true })
    activeProcesses.set(scanId, child)
    const aliveHosts: string[] = []
    const seen = new Set<string>()

    child.stdout!.on('data', (chunk: Buffer) => {
      const text = chunk.toString()
      const lines = text.split(/\r?\n/).filter(Boolean)
      for (const line of lines) {
        // Filter out garbled encoding lines (nmap 7.80 Windows locale bug)
        if (line.includes('?') && line.length > 80) continue
        safeSend(win, 'scan:stdout', { scanId, line })
        // Parse: "Nmap scan report for 192.168.1.1"
        const ipMatch = line.match(/Nmap scan report for (\d+\.\d+\.\d+\.\d+)/)
        if (ipMatch && !seen.has(ipMatch[1])) {
          seen.add(ipMatch[1])
          aliveHosts.push(ipMatch[1])
          safeSend(win, 'scan:stdout', { scanId, line: `[+] 存活: ${ipMatch[1]}` })
        }
      }
    })

    child.stderr!.on('data', (chunk: Buffer) => {
      chunk.toString().split(/\r?\n/).filter(Boolean).forEach(l =>
        safeSend(win, 'scan:stderr', { scanId, line: l }))
    })

    child.on('close', () => {
      activeProcesses.delete(scanId)
      resolve(aliveHosts)
    })
    child.on('error', () => resolve(aliveHosts))
  })
}

// ---------------------------------------------------------------------------
// Phase 1: naabu — fast port discovery
// ---------------------------------------------------------------------------
function runNaabuPhase(win: BrowserWindow, scanId: string, target: string, portRange?: string | null): Promise<{ host: string; port: number }[]> {
  return new Promise((resolve) => {
    const binPath = getBinaryPath('naabu')
    const outputPath = tempFile('naabu', 'json')
    const args = ['-host', target, '-json', '-o', outputPath]
    if (portRange) args.push('-p', portRange)

    const child = spawnTool(win, scanId, 'Naabu', binPath, args, 'naabu')
    if (!child) { resolve([]); return }

    scanPhases.set(scanId, 'naabu')
    activeProcesses.set(scanId, child)

    let stdoutBuffer = ''
    let naabuLineCount = 0
    const naabuStart = Date.now()
    const naabuHeartbeat = setInterval(() => {
      const elapsed = Math.floor((Date.now() - naabuStart) / 1000)
      safeSend(win, 'scan:progress', { scanId, progress: Math.min(15, 5 + elapsed * 0.5), phase: 'naabu' })
      if (naabuLineCount === 0 && elapsed > 5) {
        safeSend(win, 'scan:stdout', { scanId, line: `[*] Naabu 扫描中... (${elapsed}s)` })
      }
    }, 3000)

    child.stdout!.on('data', (chunk: Buffer) => {
      const text = chunk.toString()
      stdoutBuffer += text
      const lines = text.split(/\r?\n/).filter(Boolean)
      naabuLineCount += lines.length
      for (const line of lines) {
        safeSend(win, 'scan:stdout', { scanId, line: `[naabu] ${line}` })
        // Parse JSON lines for real-time host display
        try {
          const obj = JSON.parse(line)
          const host = obj.host || obj.ip
          if (host && obj.port) {
            safeSend(win, 'scan:result', {
              scanId,
              result: { IP: host, Port: String(obj.port), Service: '', FingerPrint: '', URL: '' },
              tool: 'nmap'
            })
          }
        } catch { /* not JSON */ }
      }
    })

    child.on('close', () => {
      clearInterval(naabuHeartbeat)
      activeProcesses.delete(scanId)

      let results: { host: string; port: number }[] = []
      try {
        if (fs.existsSync(outputPath)) {
          results = parseNaabuJSON(fs.readFileSync(outputPath, 'utf-8'))
          try { fs.unlinkSync(outputPath) } catch { /* */ }
        } else if (stdoutBuffer.trim()) {
          results = parseNaabuJSON(stdoutBuffer)
        }
      } catch { /* */ }

      safeSend(win, 'scan:stdout', {
        scanId,
        line: `[*] Naabu 完成: 发现 ${results.length} 个开放端口`
      })
      resolve(results)
    })
    child.on('error', () => resolve([]))
  })
}

// ---------------------------------------------------------------------------
// Phase 2: nmap — service/version detection
// ---------------------------------------------------------------------------
function runNmapPhase(
  win: BrowserWindow, scanId: string,
  naabuResults: { host: string; port: number }[]
): Promise<{ hosts: NmapHost[]; hostCount: number }> {
  return new Promise((resolve) => {
    if (cancelledScans.has(scanId)) { resolve({ hosts: [], hostCount: 0 }); return }
    if (naabuResults.length === 0) { resolve({ hosts: [], hostCount: 0 }); return }

    // Collect unique host IPs and all unique ports
    const hostSet = new Set<string>()
    const portSet = new Set<number>()
    for (const r of naabuResults) {
      hostSet.add(r.host)
      portSet.add(r.port)
    }

    // Write only IPs to target file (nmap -iL does NOT support host:port format)
    const targetPath = tempFile('nmap_targets', 'txt')
    fs.writeFileSync(targetPath, Array.from(hostSet).join('\n'), 'utf-8')

    const binPath = getBinaryPath('nmap')
    const outputPath = tempFile('nmap', 'xml')
    const allPorts = Array.from(portSet).sort((a, b) => a - b).join(',')
    const args = [
      '-iL', targetPath, '-p', allPorts,
      '-n', '-sV', '-sC',
      '--script', 'http-vuln-*,smb-vuln-*,ssl-*,vuln',
      '-oX', outputPath, '--open', '-T4', '--host-timeout', '3m'
    ]

    safeSend(win, 'scan:stdout', {
      scanId,
      line: `[*] Nmap 正在检测 ${hostSet.size} 个主机的 ${portSet.size} 个端口...`
    })

    const child = spawnTool(win, scanId, 'Nmap', binPath, args, 'nmap')
    if (!child) { resolve({ hosts: [], hostCount: 0 }); return }

    scanPhases.set(scanId, 'nmap')
    activeProcesses.set(scanId, child)

    let currentNmapIp = ''
    child.stdout!.on('data', (chunk: Buffer) => {
      const text = chunk.toString()
      const lines = text.split(/\r?\n/).filter(Boolean)
      for (const line of lines) {
        // Filter garbled encoding lines (nmap 7.80 locale bug)
        if (line.includes('?') && line.length > 60) continue
        if (line.trim()) safeSend(win, 'scan:stdout', { scanId, line })
        // Real-time parse: track current IP
        const ipMatch = line.match(/Nmap scan report for (\d+\.\d+\.\d+\.\d+)/)
        if (ipMatch) currentNmapIp = ipMatch[1]
        // Real-time parse: open port with service info
        const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)/)
        if (portMatch && currentNmapIp) {
          const port = portMatch[1]
          const svc = portMatch[3]
          const extra = portMatch[4] || ''
          safeSend(win, 'scan:result', {
            scanId,
            result: { IP: currentNmapIp, Port: port, Service: svc, FingerPrint: extra, URL: '' },
            tool: 'nmap'
          })
        }
      }
    })

    const nmapStart = Date.now()
    const nmapHeartbeat = setInterval(() => {
      const elapsed = Math.floor((Date.now() - nmapStart) / 1000)
      safeSend(win, 'scan:progress', { scanId, progress: Math.min(65, 20 + elapsed * 0.3), phase: 'nmap' })
      safeSend(win, 'scan:stdout', { scanId, line: `[*] Nmap 运行中... (${elapsed}s)` })
    }, 15000)

    child.on('close', () => {
      clearInterval(nmapHeartbeat)
      activeProcesses.delete(scanId)

      let hosts: NmapHost[] = []
      try {
        if (fs.existsSync(outputPath)) {
          const xml = fs.readFileSync(outputPath, 'utf-8')
          hosts = parseNmapXML(xml)
          try { fs.unlinkSync(outputPath) } catch { /* */ }
        }
      } catch (err) {
        safeSend(win, 'scan:stderr', { scanId, line: `[!] Nmap XML 解析失败: ${err}` })
      }

      try { fs.unlinkSync(targetPath) } catch { /* */ }

      safeSend(win, 'scan:stdout', {
        scanId,
        line: `[*] Nmap 完成: 识别到 ${hosts.length} 个主机`
      })
      resolve({ hosts, hostCount: hosts.length })
    })
    child.on('error', () => resolve({ hosts: [], hostCount: 0 }))
  })
}

// ---------------------------------------------------------------------------
// Phase 3: httpx — web probing + technology fingerprint
// ---------------------------------------------------------------------------
function runHttpxPhase(
  win: BrowserWindow, scanId: string, webUrls: string[]
): Promise<{ results: HttpxResult[]; allTechs: string[] }> {
  return new Promise((resolve) => {
    if (cancelledScans.has(scanId) || webUrls.length === 0) {
      resolve({ results: [], allTechs: [] })
      return
    }

    const urlPath = tempFile('httpx_urls', 'txt')
    fs.writeFileSync(urlPath, webUrls.join('\n'), 'utf-8')

    const binPath = getBinaryPath('httpx')
    const outputPath = tempFile('httpx', 'json')
    const args = ['-l', urlPath, '-tech-detect', '-title', '-status-code', '-json', '-silent', '-no-color', '-o', outputPath]

    safeSend(win, 'scan:stdout', {
      scanId,
      line: `[*] httpx 正在探测 ${webUrls.length} 个 Web URL...`
    })

    const child = spawnTool(win, scanId, 'httpx', binPath, args, 'httpx')
    if (!child) { resolve({ results: [], allTechs: [] }); return }

    scanPhases.set(scanId, 'httpx')
    activeProcesses.set(scanId, child)

    child.stdout!.on('data', (chunk: Buffer) => {
      const text = chunk.toString()
      const lines = text.split(/\r?\n/).filter(Boolean)
      for (const line of lines) {
        if (line.trim()) safeSend(win, 'scan:stdout', { scanId, line })
        // Real-time parse: httpx JSON output
        try {
          const obj = JSON.parse(line)
          if (obj.url || obj.input) {
            const url = obj.url || obj.input || ''
            const techs = obj.tech || obj.technologies || []
            safeSend(win, 'scan:result', {
              scanId,
              result: { URL: url, IP: '', Port: '', Service: obj.webserver || '', FingerPrint: techs.join(', '), Keyword: obj.title || '' },
              tool: 'nmap'
            })
            // Also send web fingerprint results immediately
            for (const tech of techs) {
              insertWebFingerprint({
                scan_id: scanId, url, tech_name: tech,
                category: '', version: '', confidence: 80
              })
            }
          }
        } catch { /* not JSON */ }
      }
    })

    const httpxStart = Date.now()
    const httpxHeartbeat = setInterval(() => {
      const elapsed = Math.floor((Date.now() - httpxStart) / 1000)
      safeSend(win, 'scan:progress', { scanId, progress: Math.min(92, 70 + elapsed * 0.5), phase: 'httpx' })
    }, 3000)

    child.on('close', () => {
      clearInterval(httpxHeartbeat)
      activeProcesses.delete(scanId)

      let results: HttpxResult[] = []
      try {
        if (fs.existsSync(outputPath)) {
          results = parseHttpxJSON(fs.readFileSync(outputPath, 'utf-8'))
          try { fs.unlinkSync(outputPath) } catch { /* */ }
        }
      } catch (err) {
        safeSend(win, 'scan:stderr', { scanId, line: `[!] httpx JSON 解析失败: ${err}` })
      }

      try { fs.unlinkSync(urlPath) } catch { /* */ }

      safeSend(win, 'scan:stdout', {
        scanId,
        line: `[*] httpx 完成: 探测了 ${results.length} 个 URL`
      })
      resolve({ results, allTechs: [] })
    })
    child.on('error', () => resolve({ results: [], allTechs: [] }))
  })
}

// ---------------------------------------------------------------------------
// Phase 4: nuclei — vulnerability scanning
// ---------------------------------------------------------------------------
function runNucleiPhase(
  win: BrowserWindow, scanId: string,
  webUrls: string[], techNames: string[] = []
): Promise<void> {
  return new Promise((resolve) => {
    if (cancelledScans.has(scanId) || webUrls.length === 0) { resolve(); return }

    const urlPath = tempFile('nuclei_urls', 'txt')
    fs.writeFileSync(urlPath, webUrls.join('\n'), 'utf-8')

    const binPath = getBinaryPath('nuclei')
    const args = ['-l', urlPath, '-jsonl', '-no-color', '-timeout', '3', '-stats-interval', '30']

    if (techNames.length > 0) {
      args.push('-tech', techNames.join(','))
      safeSend(win, 'scan:stdout', {
        scanId,
        line: `[*] Nuclei 技术过滤: ${techNames.length} 项`
      })
    }

    safeSend(win, 'scan:stdout', {
      scanId,
      line: techNames.length > 0
        ? `[*] Nuclei 正在扫描 ${webUrls.length} 个目标 (已过滤模板)`
        : `[*] Nuclei 正在扫描 ${webUrls.length} 个目标 (全部模板)`
    })

    const child = spawnTool(win, scanId, 'Nuclei', binPath, args, 'nuclei')
    if (!child) { resolve(); return }

    scanPhases.set(scanId, 'nuclei')
    activeProcesses.set(scanId, child)

    let vulnCount = 0
    let anyOutput = false
    const startTime = Date.now()
    const heartbeat = setInterval(() => {
      const elapsed = Math.floor((Date.now() - startTime) / 1000)
      if (!anyOutput) {
        safeSend(win, 'scan:stdout', { scanId, line: `[*] Nuclei 运行中... (${elapsed}s)` })
      }
    }, 30000)

    child.stdout!.on('data', (chunk: Buffer) => {
      anyOutput = true
      const text = chunk.toString()
      const lines = text.split(/\r?\n/).filter(Boolean)
      for (const line of lines) {
        safeSend(win, 'scan:stdout', { scanId, line })
        if (handleNucleiResult(win, scanId, line)) vulnCount++

        const elapsed = Math.floor((Date.now() - startTime) / 1000)
        const progress = Math.min(99.9, 96 + Math.log2(1 + elapsed) * 0.8)
        safeSend(win, 'scan:progress', { scanId, progress, phase: 'nuclei' })
      }
    })

    child.on('close', (code) => {
      clearInterval(heartbeat)
      activeProcesses.delete(scanId)
      scanPhases.delete(scanId)

      try { fs.unlinkSync(urlPath) } catch { /* */ }

      safeSend(win, 'scan:stdout', {
        scanId,
        line: code === 0 ? `[*] Nuclei 完成: 发现 ${vulnCount} 个漏洞` : `[!] Nuclei 结束，退出码: ${code ?? -1}`
      })

      const status = cancelledScans.has(scanId) ? 'cancelled'
        : code === 0 ? 'completed' : 'failed'
      updateScanStatus(scanId, status, new Date().toISOString())

      safeSend(win, 'scan:progress', { scanId, progress: 100, phase: 'nuclei' })
      safeSend(win, 'scan:complete', { scanId, code: code ?? -1 })
      resolve()
    })
    child.on('error', () => resolve())
  })
}

// ---------------------------------------------------------------------------
// Main entry point: 4-phase pipeline
// ---------------------------------------------------------------------------
export function startScan(
  win: BrowserWindow, scanId: string, _tool: string, args: string[]
): number {
  const target = args[args.indexOf('-t') + 1] || args[1] || 'unknown'
  const portRange = args.includes('-p') ? args[args.indexOf('-p') + 1] : null

  // Track real-time results across phases
  const sentIps = new Set<string>()

  // Start the pipeline asynchronously
  scanPhases.set(scanId, 'pipeline')  // Mark as running across all phases

  ;(async () => {
    try {
    // Phase 1: Host discovery — nmap ping sweep
    scanPhases.set(scanId, 'naabu')
    safeSend(win, 'scan:progress', { scanId, progress: 3, phase: 'naabu' })
    safeSend(win, 'scan:stdout', { scanId, line: `[*] 阶段1: 主机发现 (Ping Sweep) — ${target}` })

    const aliveHosts = await runHostDiscovery(win, scanId, target)
    if (cancelledScans.has(scanId)) { finalizeCancelled(win, scanId); return }

    if (aliveHosts.length === 0) {
      safeSend(win, 'scan:stdout', { scanId, line: `[*] 未发现存活主机，扫描结束。` })
      scanPhases.delete(scanId); updateScanStatus(scanId, 'completed', new Date().toISOString())
      safeSend(win, 'scan:progress', { scanId, progress: 100, phase: 'naabu' })
      safeSend(win, 'scan:complete', { scanId, code: 0 }); return
    }
    safeSend(win, 'scan:stdout', { scanId, line: `[*] 发现 ${aliveHosts.length} 台存活主机，开始端口扫描...` })

    // Phase 2: naabu — port scan only alive hosts
    safeSend(win, 'scan:progress', { scanId, progress: 5, phase: 'naabu' })
    const naabuResults = await runNaabuPhase(win, scanId, aliveHosts.join(','), portRange)
    if (cancelledScans.has(scanId)) { finalizeCancelled(win, scanId); return }

    if (naabuResults.length === 0) {
      safeSend(win, 'scan:stdout', { scanId, line: `[*] 存活主机未发现开放端口。` })
      scanPhases.delete(scanId); updateScanStatus(scanId, 'completed', new Date().toISOString())
      safeSend(win, 'scan:progress', { scanId, progress: 100, phase: 'naabu' })
      safeSend(win, 'scan:complete', { scanId, code: 0 }); return
    }

    // Phase 3: nmap — service/version detection
    safeSend(win, 'scan:progress', { scanId, progress: 20, phase: 'nmap' })
    safeSend(win, 'scan:stdout', { scanId, line: `[*] 阶段3: Nmap 服务版本检测 (${naabuResults.length} 个端口)` })

    const { hosts } = await runNmapPhase(win, scanId, naabuResults)
    if (cancelledScans.has(scanId)) { finalizeCancelled(win, scanId); return }

    const { webUrls, hostCount } = handleNmapResults(win, scanId, hosts, sentIps)

    safeSend(win, 'scan:stdout', {
      scanId, line: `[*] 阶段3 完成: ${hosts.length} 个主机, ${hostCount} 个服务, ${webUrls.length} 个 Web URL`
    })
    safeSend(win, 'scan:progress', { scanId, progress: 70, phase: 'nmap' })

    // Phase 4: httpx — web probing + fingerprint
    let allTechs: string[] = []
    if (webUrls.length > 0) {
      safeSend(win, 'scan:progress', { scanId, progress: 75, phase: 'httpx' })
      safeSend(win, 'scan:stdout', { scanId, line: `[*] 阶段4: httpx Web 指纹识别` })

      const httpxResults = await runHttpxPhase(win, scanId, webUrls)
      if (cancelledScans.has(scanId)) { finalizeCancelled(win, scanId); return }

      const handled = handleHttpxResults(win, scanId, httpxResults.results)
      allTechs = handled.allTechs

      safeSend(win, 'scan:stdout', {
        scanId,
        line: allTechs.length > 0
          ? `[*] 阶段3 完成: 识别到 ${allTechs.slice(0, 15).join(', ')}${allTechs.length > 15 ? ' ...' : ''}`
          : `[*] 阶段3 完成: 未识别到明确技术栈`
      })
    }

    // Phase 4: nuclei — vulnerability scanning
    if (webUrls.length > 0) {
      safeSend(win, 'scan:progress', { scanId, progress: 96, phase: 'nuclei' })
      safeSend(win, 'scan:stdout', {
        scanId,
        line: `[*] 阶段5: Nuclei 漏洞扫描 (${allTechs.length > 0 ? '已过滤模板' : '全部模板'})`
      })

      await runNucleiPhase(win, scanId, webUrls, allTechs)
    } else {
      // No web URLs — finalize now
      scanPhases.delete(scanId)
      updateScanStatus(scanId, 'completed', new Date().toISOString())
      safeSend(win, 'scan:progress', { scanId, progress: 100, phase: 'nmap' })
      safeSend(win, 'scan:complete', { scanId, code: 0 })
    }
    } catch (err) {
      scanPhases.delete(scanId)
      cancelledScans.delete(scanId)
      updateScanStatus(scanId, 'failed', new Date().toISOString())
      safeSend(win, 'scan:stderr', { scanId, line: `[!] 扫描管道异常: ${err}` })
      safeSend(win, 'scan:progress', { scanId, progress: 100, phase: 'nuclei' })
      safeSend(win, 'scan:complete', { scanId, code: -1 })
    }
  })()

  // Return a fake PID since we're async now
  return 0
}

function finalizeCancelled(win: BrowserWindow, scanId: string): void {
  scanPhases.delete(scanId)
  cancelledScans.delete(scanId)
  updateScanStatus(scanId, 'cancelled', new Date().toISOString())
  safeSend(win, 'scan:stdout', { scanId, line: `[*] 扫描已被取消。` })
  safeSend(win, 'scan:progress', { scanId, progress: 100, phase: 'cancelled' })
  safeSend(win, 'scan:complete', { scanId, code: -1 })
}

// ---------------------------------------------------------------------------
// Cancel scan
// ---------------------------------------------------------------------------
export function cancelScan(scanId: string): boolean {
  cancelledScans.add(scanId)
  const child = activeProcesses.get(scanId)
  if (child) {
    try {
      if (process.platform === 'win32') {
        spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'])
      } else {
        child.kill('SIGTERM')
      }
    } catch { /* */ }
    activeProcesses.delete(scanId)
    scanPhases.delete(scanId)
    return true
  }
  return cancelledScans.has(scanId)
}

export function isScanRunning(scanId: string): boolean {
  return activeProcesses.has(scanId) || scanPhases.has(scanId)
}

export function isScanCancelled(scanId: string): boolean {
  return cancelledScans.has(scanId)
}
