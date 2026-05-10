import React, { useState, useEffect, useRef, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { StopCircle, Server, Shield, Clock, Activity, Globe, FileText } from 'lucide-react'
import { useScanStore, type ScanPhase, type TerminalLine } from '../stores/scanStore'
import { translateVulnName } from '../utils/translateVuln'

function getTerminalLineColor(line: string): string {
  if (line.startsWith('[+]') || line.includes('[+]')) return 'text-[#00ff88]'
  if (line.startsWith('[-]') || line.includes('[-]')) return 'text-[#ff4444]'
  if (line.startsWith('[*]') || line.includes('[*]')) return 'text-[#ffd000]'
  if (line.startsWith('[!]') || line.includes('[!]')) return 'text-[#bf00ff]'
  if (line.includes('http://') || line.includes('https://')) return 'text-[#00f0ff]'
  if (line.includes('CrackSuccess')) return 'text-[#ff0066]'
  if (line.includes('hydra') || line.includes('Hydra')) return 'text-[#ff6600]'
  return 'text-[#94a3b8]'
}

const PHASE_LABELS: Record<ScanPhase, string> = {
  naabu: '阶段1: 端口发现',
  nmap: '阶段2: 服务识别',
  httpx: '阶段3: Web 指纹',
  nuclei: '阶段4: 漏洞扫描',
  pipeline: '初始化中',
  cancelled: '已取消'
}

const ScanResult: React.FC = () => {
  const { id } = useParams<{ id: string }>()
  const scanId = id ?? ''
  const navigate = useNavigate()

  const {
    getOrCreateSession, updateSession, addTerminalLine,
    addHost, addVuln, addWebUrl, completeSession, sessions
  } = useScanStore()

  const session = sessions.get(scanId)
  const [isLive, setIsLive] = useState(false)
  const terminalRef = useRef<HTMLDivElement>(null)
  const elapsedRef = useRef<ReturnType<typeof setInterval>>()

  // Initialize or restore session
  useEffect(() => {
    let cancelled = false

    const init = async () => {
      if (cancelled) return

      const existing = sessions.get(scanId)
      let running = false
      try {
        running = await window.electronAPI.isScanRunning(scanId)
      } catch { /* ignore */ }

      if (cancelled) return

      // If running, create session immediately and subscribe
      if (running) {
        if (!existing) {
          // Try to get target from DB, fallback to scanId
          let target = scanId
          try {
            const scan = await window.electronAPI.getScanById(scanId)
            if (scan) target = scan.target || scanId
          } catch { /* */ }
          getOrCreateSession(scanId, target)
        }
        setIsLive(true)
        return
      }

      if (existing) {
        if (existing.completedCode === null) {
          // Scan finished while user was away — finalize orphaned session
          completeSession(scanId, -1)
        }
        return
      }

      // No session and not running — load from DB
      try {
        const scan = await window.electronAPI.getScanById(scanId)
        if (!scan) {
          getOrCreateSession(scanId, scanId)
          updateSession(scanId, { isScanning: false, completedCode: -1, progress: 100 })
          addTerminalLine(scanId, '[!] 未找到此扫描记录。', 'error')
          return
        }

        const target = scan.target || scanId
        getOrCreateSession(scanId, target)

        if (scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled') {
          // Load historical data from DB
          const [hosts, vulns, webUrls] = await Promise.all([
            window.electronAPI.getHostsByScanId(scanId),
            window.electronAPI.getVulnsByScanId(scanId),
            window.electronAPI.getWebUrlsByScanId(scanId)
          ])

          if (cancelled) return

          const termLines: TerminalLine[] = []
          let lineId = 0
          const addLine = (text: string, type: TerminalLine['type']) => {
            lineId++
            termLines.push({ id: lineId, text, type })
          }

          addLine(`[*] 扫描任务: ${scan.name || target}`, 'info')
          addLine(`[*] 状态: ${scan.status}`, 'info')
          addLine('', 'info')

          const uniqueIps = new Set<string>()
          for (const h of (hosts || [])) {
            const ip = h.ip || ''
            if (ip) uniqueIps.add(ip)
            addLine(`[+] ${ip}:${h.port || ''} ${h.service || ''} ${h.fingerprint || ''}`, 'stdout')
            addHost(scanId, {
              ip,
              port: String(h.port || ''),
              service: h.service || '',
              fingerprint: h.fingerprint || ''
            })
          }

          for (const w of (webUrls || [])) {
            addLine(`[+] Web: ${w.url} ${w.techStack || ''}`, 'stdout')
            addWebUrl(scanId, {
              url: w.url,
              ip: '', port: '',
              keyword: w.title || '',
              fingerprint: w.techStack || ''
            })
          }

          for (const v of (vulns || [])) {
            const sev = (v.severity || 'info').toLowerCase()
            addLine(`[!] ${v.name} [${sev}] — ${v.matchedAt || v.host || ''}`, 'error')
            addVuln(scanId, {
              name: v.name || '未知',
              url: v.matchedAt || v.host || '',
              severity: sev as any,
              templateId: v.templateId
            })
          }

          addLine('', 'info')
          addLine(`[*] 扫描已完成。发现 ${uniqueIps.size} 台主机, ${(vulns || []).length} 个漏洞`, 'info')

          const completedCode = scan.status === 'completed' ? 0 : -1
          updateSession(scanId, {
            terminalLines: termLines,
            nextLineId: lineId,
            isScanning: false,
            progress: 100,
            completedCode,
            phase: 'naabu'
          })
          completeSession(scanId, completedCode)
        } else if (running) {
          // Still running but no local state — reconnect
          getOrCreateSession(scanId, target)
          setIsLive(true)
        }
      } catch (err) {
        console.error('加载扫描数据失败:', err)
      }
    }

    init()
    return () => { cancelled = true }
  }, [scanId])

  // Subscribe to live events when scan is running
  useEffect(() => {
    if (!isLive) return

    const unsubStdout = window.electronAPI.onScanStdout((data) => {
      if (data.scanId !== scanId) return
      addTerminalLine(scanId, data.line, 'stdout')
      if (data.line.includes('阶段4') || data.line.includes('Nuclei')) {
        updateSession(scanId, { phase: 'nuclei' })
      } else if (data.line.includes('阶段3') || data.line.includes('httpx') || data.line.includes('指纹')) {
        updateSession(scanId, { phase: 'httpx' })
      } else if (data.line.includes('阶段2') || data.line.includes('Nmap')) {
        updateSession(scanId, { phase: 'nmap' })
      }
    })

    const unsubStderr = window.electronAPI.onScanStderr((data) => {
      if (data.scanId !== scanId) return
      addTerminalLine(scanId, data.line, 'stderr')
    })

    const unsubResult = window.electronAPI.onScanResult((data) => {
      if (data.scanId !== scanId) return
      const r = data.result as Record<string, any>
      const tool = data.tool as 'nmap' | 'nuclei' | undefined

      if (tool === 'nuclei') {
        const info = r.info || {}
        const name = info.name || r['templateID'] || r['template-id'] || '未知漏洞'
        const severity = (info.severity || 'info').toLowerCase() as any
        const url = r['matched-at'] || r.host || ''
        const templateId = r['templateID'] || r['template-id'] || ''
        addVuln(scanId, { name, url, severity, templateId })
        addTerminalLine(scanId, `[+] 发现漏洞: ${name} [${severity}] — ${url}`, 'error')
      } else {
        const url = r.URL ?? ''
        const ip = r.IP ?? ''
        const port = r.Port ?? ''
        const keyword = r.Keyword ?? ''
        const fingerprint = r.FingerPrint ?? r.fingerprint ?? ''
        const service = r.Service ?? ''

        if (url.startsWith('http://') || url.startsWith('https://')) {
          addWebUrl(scanId, { url, ip, port, keyword, fingerprint })
          addTerminalLine(scanId, `[+] 发现 Web 服务: ${url} (${fingerprint || service})`, 'info')
          if (keyword && (keyword.includes('CrackSuccess') || keyword.toLowerCase().includes('vuln'))) {
            addVuln(scanId, { name: keyword, url, severity: keyword.includes('CrackSuccess') ? 'high' : 'medium' })
          }
        } else if (ip) {
          addHost(scanId, { ip, port, service, fingerprint })
          addTerminalLine(scanId, `[+] 发现主机: ${ip}:${port} ${service} ${fingerprint}`, 'info')
        }
      }
    })

    const unsubComplete = window.electronAPI.onScanComplete((data) => {
      if (data.scanId !== scanId) return
      completeSession(scanId, data.code)
      setIsLive(false)
      if (data.code === 0) {
        addTerminalLine(scanId, '[*] 扫描完成。', 'info')
      } else {
        addTerminalLine(scanId, `[!] 扫描结束，退出码: ${data.code}`, 'error')
      }
    })

    const unsubProgress = window.electronAPI.onUpdateProgress((data: any) => {
      if (data.scanId !== scanId) return
      updateSession(scanId, { progress: data.progress })
      if (data.phase) {
        updateSession(scanId, { phase: data.phase as ScanPhase })
      }
    })

    return () => {
      unsubStdout()
      unsubStderr()
      unsubResult()
      unsubComplete()
      unsubProgress()
    }
  }, [scanId, isLive])

  // Elapsed timer
  useEffect(() => {
    if (!session?.isScanning) return
    elapsedRef.current = setInterval(() => {
      const currentSession = useScanStore.getState().sessions.get(scanId)
      updateSession(scanId, { elapsed: (currentSession?.elapsed || 0) + 1 })
    }, 1000)
    return () => {
      if (elapsedRef.current) clearInterval(elapsedRef.current)
    }
  }, [scanId, session?.isScanning])

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight
    }
  }, [session?.terminalLines?.length])

  const handleStop = async () => {
    try {
      await window.electronAPI.cancelScan(scanId)
      addTerminalLine(scanId, '[!] 扫描已被用户停止', 'error')
      completeSession(scanId, -1)
      setIsLive(false)
    } catch {
      addTerminalLine(scanId, '[!] 停止扫描失败', 'error')
    }
  }

  if (!session) {
    return (
      <div className="flex items-center justify-center h-full text-[#94a3b8]">
        <div className="text-center">
          <Activity size={24} className="animate-spin mb-3 mx-auto" />
          <p className="text-sm">加载扫描数据...</p>
        </div>
      </div>
    )
  }

  const progress = session.progress || 0
  const currentPhase = session.phase || 'pipeline'
  const isScanning = session.isScanning
  const completedCode = session.completedCode
  const elapsed = session.elapsed || 0
  const hosts = session.hosts || []
  const vulns = session.vulns || []
  const webUrls = session.webUrls || []
  const terminalLines = session.terminalLines || []

  // Unique IP count
  const uniqueIpCount = new Set(hosts.map(h => h.ip).filter(Boolean)).size

  const formatTime = (seconds: number) => {
    const m = Math.floor(seconds / 60).toString().padStart(2, '0')
    const s = (seconds % 60).toString().padStart(2, '0')
    return `${m}:${s}`
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-[#ff0044]'
      case 'high': return 'text-[#ff6600]'
      case 'medium': return 'text-[#ffd000]'
      case 'low': return 'text-[#00ff88]'
      default: return 'text-[#94a3b8]'
    }
  }

  return (
    <div className="space-y-4 h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold neon-text">扫描结果</h1>
          <p className="text-xs text-[#94a3b8] mt-1">
            会话: {scanId.slice(0, 8)}... | 目标: {session.target}
          </p>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-sm text-[#94a3b8]">
            <Clock size={14} />
            <span className="font-mono">{formatTime(elapsed)}</span>
          </div>
          {isScanning && (
            <button
              onClick={handleStop}
              className="flex items-center gap-2 px-4 py-2 rounded border border-[#ff0044] text-[#ff0044] hover:bg-[#ff0044]/10 transition-colors"
            >
              <StopCircle size={16} />
              <span className="text-sm">停止</span>
            </button>
          )}
          {!isScanning && completedCode === 0 && (
            <button
              onClick={() => navigate('/reports')}
              className="flex items-center gap-2 px-4 py-2 bg-[#00f0ff]/10 text-[#00f0ff] border border-[#00f0ff]/30 rounded text-sm hover:bg-[#00f0ff]/20 transition-colors"
            >
              <FileText size={16} />
              导出报告
            </button>
          )}
          {!isScanning && completedCode !== null && (
            <span className="text-sm text-[#00ff88] font-bold">
              {completedCode === 0 ? '已完成' : `已结束 (退出码: ${completedCode})`}
            </span>
          )}
        </div>
      </div>

      {/* Stats Bar */}
      <div className="grid grid-cols-3 gap-4">
        <div className="cyber-card p-3 flex items-center gap-3">
          <Server size={18} className="text-[#bf00ff]" />
          <div>
            <div className="text-xs text-[#94a3b8]">发现主机</div>
            <div className="text-lg font-bold text-[#00f0ff]">{uniqueIpCount}</div>
          </div>
        </div>
        <div className="cyber-card p-3 flex items-center gap-3">
          <Globe size={18} className="text-[#00ff88]" />
          <div>
            <div className="text-xs text-[#94a3b8]">Web 服务</div>
            <div className="text-lg font-bold text-[#00ff88]">{webUrls.length}</div>
          </div>
        </div>
        <div className="cyber-card p-3 flex items-center gap-3">
          <Shield size={18} className="text-[#ff0066]" />
          <div>
            <div className="text-xs text-[#94a3b8]">发现漏洞</div>
            <div className="text-lg font-bold text-[#ff0066]">{vulns.length}</div>
          </div>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="cyber-card p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-[#94a3b8] uppercase tracking-wider">
            {isScanning ? PHASE_LABELS[currentPhase] : '扫描完成'}
          </span>
          <span className="text-sm text-[#00f0ff] font-bold">
            {Math.min(progress, 100).toFixed(1)}%
          </span>
        </div>
        <div className="h-2 bg-[#1e293b] rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-300 relative"
            style={{
              width: `${Math.min(progress, 100)}%`,
              background: currentPhase === 'nuclei'
                ? 'linear-gradient(90deg, #bf00ff, #ff0066)'
                : currentPhase === 'httpx'
                ? 'linear-gradient(90deg, #00ff88, #00f0ff)'
                : currentPhase === 'nmap'
                ? 'linear-gradient(90deg, #ffd000, #ff6600)'
                : 'linear-gradient(90deg, #00f0ff, #bf00ff)',
            }}
          >
            {isScanning && (
              <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent animate-pulse" />
            )}
          </div>
        </div>
      </div>

      {/* Content Grid */}
      <div className="grid grid-cols-3 gap-4 flex-1 min-h-0">
        {/* Terminal Output */}
        <div className="col-span-2 cyber-card flex flex-col min-h-0">
          <div className="px-4 py-2 border-b border-[#1e293b] flex items-center gap-2">
            <Activity size={14} className="text-[#00f0ff]" />
            <span className="text-xs uppercase tracking-wider text-[#94a3b8]">
              实时终端
            </span>
            {isScanning && (
              <span className="ml-auto w-2 h-2 rounded-full bg-[#00ff88] cyber-pulse" />
            )}
          </div>
          <div ref={terminalRef} className="terminal flex-1 min-h-0">
            {terminalLines.map((line) => (
              <div key={line.id} className={`terminal-line ${getTerminalLineColor(line.text)}`}>
                {line.text}
              </div>
            ))}
          </div>
        </div>

        {/* Discovered Hosts & Vulns */}
        <div className="space-y-4 flex flex-col min-h-0">
          {/* Hosts */}
          <div className="cyber-card flex-1 flex flex-col min-h-0">
            <div className="px-4 py-2 border-b border-[#1e293b] flex items-center gap-2">
              <Server size={14} className="text-[#bf00ff]" />
              <span className="text-xs uppercase tracking-wider text-[#94a3b8]">
                发现主机 ({uniqueIpCount})
              </span>
            </div>
            <div className="flex-1 overflow-y-auto p-2 space-y-2">
              {hosts.length === 0 ? (
                <div className="text-center py-4 text-xs text-[#4a5568]">
                  {isScanning ? '等待发现...' : '未发现主机'}
                </div>
              ) : (
                // Group hosts by IP
                Array.from(
                  hosts.reduce((map, host) => {
                    if (!map.has(host.ip)) map.set(host.ip, [])
                    map.get(host.ip)!.push(host)
                    return map
                  }, new Map<string, typeof hosts>())
                ).map(([ip, ipHosts]) => (
                  <div key={ip} className="bg-[#050510] rounded overflow-hidden">
                    <div className="px-3 py-1.5 border-b border-[#1e293b]/50 text-xs font-mono text-[#00f0ff] font-bold">
                      {ip}
                      {ipHosts.length > 1 && (
                        <span className="text-[#4a5568] font-normal ml-1">({ipHosts.length} 个端口)</span>
                      )}
                    </div>
                    {ipHosts.map((host, j) => (
                      <div key={j} className="px-3 py-1.5 flex items-center justify-between text-xs">
                        <span className="text-[#00f0ff] font-mono">:{host.port || '--'}</span>
                        <span className="text-[#94a3b8]">
                          {host.service || '--'} {host.fingerprint && `— ${host.fingerprint.slice(0, 30)}`}
                        </span>
                      </div>
                    ))}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Vulnerabilities */}
          <div className="cyber-card flex-1 flex flex-col min-h-0">
            <div className="px-4 py-2 border-b border-[#1e293b] flex items-center gap-2">
              <Shield size={14} className="text-[#ff0066]" />
              <span className="text-xs uppercase tracking-wider text-[#94a3b8]">
                发现漏洞 ({vulns.length})
              </span>
            </div>
            <div className="flex-1 overflow-y-auto p-2 space-y-1">
              {vulns.length === 0 ? (
                <div className="text-center py-4 text-xs text-[#4a5568]">
                  {isScanning ? '正在分析...' : '未发现漏洞'}
                </div>
              ) : (
                vulns.map((vuln, i) => (
                  <div key={i} className="px-3 py-2 bg-[#050510] rounded text-xs">
                    <div className="flex items-center gap-2">
                      <span className={`font-bold uppercase text-[10px] ${getSeverityColor(vuln.severity)}`}>
                        {vuln.severity}
                      </span>
                      <span className="text-[#e2e8f0] truncate">{translateVulnName(vuln.name)}</span>
                    </div>
                    <div className="text-[#4a5568] mt-1 truncate">{vuln.url}</div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ScanResult
