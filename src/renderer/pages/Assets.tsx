import React, { useState, useEffect, useMemo } from 'react'
import { Server, Search, RefreshCw, ChevronDown, ChevronRight, Globe, Fingerprint, Download, Monitor, Shield, Terminal, Database, HardDrive, Folder } from 'lucide-react'

interface Host {
  id: number
  ip: string
  port: number | string
  service: string
  fingerprint: string
  url: string
  discoveredAt: string
  scanId: string
  vulnCount?: number
  [key: string]: any
}

interface WebFingerprint {
  id: number
  url: string
  techName: string
  category: string
  version: string
  confidence: number
  scanId: string
}

interface IpGroup {
  ip: string
  hosts: Host[]
  portCount: number
  services: string[]
  fingerprints: string[]
  hasWeb: boolean
  maxVulnCount: number
}

interface ParsedFp {
  label: string
  version: string
  extra: string
}

function getServiceIcon(service: string): React.ReactNode {
  const s = (service || '').toLowerCase()
  if (s.includes('ssh')) return <Terminal size={14} className="text-[#00ff88]" />
  if (s.includes('mysql') || s.includes('mariadb') || s.includes('sql') || s.includes('redis') || s.includes('postgres') || s.includes('mongo'))
    return <Database size={14} className="text-[#ffd000]" />
  if (s.includes('http') || s.includes('https')) return <Globe size={14} className="text-[#00f0ff]" />
  if (s.includes('smb') || s.includes('netbios')) return <Folder size={14} className="text-[#bf00ff]" />
  if (s.includes('rdp')) return <Monitor size={14} className="text-[#ff6600]" />
  if (s.includes('ftp')) return <HardDrive size={14} className="text-[#94a3b8]" />
  return <Server size={14} className="text-[#94a3b8]" />
}

function parseFingerprint(fp: string, service: string): ParsedFp {
  if (!fp) return { label: service || '--', version: '', extra: '' }
  const s = (service || '').toLowerCase()
  const raw = fp.trim()

  // SSH
  if (s === 'ssh' || raw.includes('SSH') || raw.includes('OpenSSH')) {
    const m = raw.match(/OpenSSH[_\s](\d\S+)/i)
    return { label: 'OpenSSH', version: m?.[1] || '', extra: raw }
  }
  // MySQL / Database
  if (s.includes('mysql') || s.includes('mariadb')) {
    const m = raw.match(/(MySQL|MariaDB)[\s-]*(\S+)/i) || raw.match(/(\d+\.\d+\.\d+)/)
    return { label: m?.[1] || 'MySQL', version: m?.[2] || m?.[1] || '', extra: raw }
  }
  // MS SQL
  if (s.includes('mssql') || raw.includes('Microsoft SQL')) {
    const m = raw.match(/Microsoft SQL Server[\s-]*(\S+)/i) || raw.match(/(\d{4})/)
    return { label: 'MS SQL Server', version: m?.[1] || '', extra: raw }
  }
  // Redis
  if (s === 'redis' || raw.includes('Redis')) {
    const m = raw.match(/Redis[\s-]*(\S+)/i) || raw.match(/(\d+\.\d+\.\d+)/)
    return { label: 'Redis', version: m?.[1] || '', extra: raw }
  }
  // PostgreSQL
  if (s.includes('postgres') || raw.includes('PostgreSQL')) {
    const m = raw.match(/PostgreSQL[\s-]*(\S+)/i) || raw.match(/(\d+\.\d+)/)
    return { label: 'PostgreSQL', version: m?.[1] || '', extra: raw }
  }
  // HTTP server
  if (s === 'http' || s === 'https') {
    const m = raw.match(/(nginx|Apache|IIS|Tomcat|Jetty|Caddy|Lighttpd)[\s\/]*(\S*)/i)
    return m ? { label: m[1], version: m[2] || '', extra: raw } : { label: s, version: '', extra: raw }
  }
  // SMB
  if (s === 'smb' || raw.includes('SMB')) {
    const host = raw.match(/SMB@(\S+)/i)
    return { label: 'SMB', version: host?.[1] || '', extra: raw }
  }
  // RDP
  if (s.includes('rdp') || raw.includes('RDP')) {
    return { label: 'Remote Desktop', version: '', extra: raw }
  }
  // FTP
  if (s === 'ftp') {
    const m = raw.match(/(vsftpd|ProFTPD|FileZilla|Pure-FTPd)[\s-]*(\S+)/i)
    return m ? { label: m[1], version: m[2] || '', extra: raw } : { label: 'FTP', version: '', extra: raw }
  }
  // Generic fallback: try to extract version
  const vm = raw.match(/(\d+\.\d+\.\d+)/) || raw.match(/(\d+\.\d+)/)
  return { label: s || 'unknown', version: vm?.[1] || '', extra: raw }
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

function getTechCategoryColor(category: string): { bg: string; text: string } {
  const c = category.toLowerCase()
  if (c.includes('web server') || c.includes('webserver')) return { bg: '#00f0ff15', text: '#00f0ff' }
  if (c.includes('cms') || c.includes('blog')) return { bg: '#bf00ff15', text: '#bf00ff' }
  if (c.includes('javascript') || c.includes('js')) return { bg: '#ffd00015', text: '#ffd000' }
  if (c.includes('cdn') || c.includes('cache')) return { bg: '#00ff8815', text: '#00ff88' }
  if (c.includes('database') || c.includes('db')) return { bg: '#ff660015', text: '#ff6600' }
  if (c.includes('analytics') || c.includes('tracking')) return { bg: '#ff006615', text: '#ff0066' }
  if (c.includes('security') || c.includes('ssl')) return { bg: '#00ff8815', text: '#00ff88' }
  return { bg: '#1e293b', text: '#94a3b8' }
}

const Assets: React.FC = () => {
  const [hosts, setHosts] = useState<Host[]>([])
  const [webFingerprints, setWebFingerprints] = useState<WebFingerprint[]>([])
  const [scans, setScans] = useState<any[]>([])
  const [selectedScanId, setSelectedScanId] = useState<string>('')
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [expandedIps, setExpandedIps] = useState<Set<string>>(new Set())

  const fetchData = async () => {
    setLoading(true)
    try {
      const [hostsData, fpData, scansData] = await Promise.all([
        window.electronAPI.getAllHosts(),
        window.electronAPI.getAllWebFingerprints(),
        window.electronAPI.getScans()
      ])
      setHosts(hostsData || [])
      setWebFingerprints(fpData || [])
      setScans(scansData || [])
    } catch (err) {
      console.error('获取资产数据失败:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  // Build URL → fingerprints map
  const fpByUrl = useMemo(() => {
    const map = new Map<string, WebFingerprint[]>()
    webFingerprints.forEach(fp => {
      if (!map.has(fp.url)) map.set(fp.url, [])
      map.get(fp.url)!.push(fp)
    })
    return map
  }, [webFingerprints])

  const toggleIp = (ip: string) => {
    setExpandedIps(prev => {
      const next = new Set(prev)
      if (next.has(ip)) next.delete(ip)
      else next.add(ip)
      return next
    })
  }

  const expandAll = () => setExpandedIps(new Set(ipGroups.map(g => g.ip)))
  const collapseAll = () => setExpandedIps(new Set())

  const ipGroups: IpGroup[] = useMemo(() => {
    const map = new Map<string, IpGroup>()
    const q = search.toLowerCase()

    hosts.forEach(h => {
      if (!h.ip) return
      if (selectedScanId && h.scanId !== selectedScanId) return
      if (q) {
        const match =
          (h.ip && h.ip.toLowerCase().includes(q)) ||
          (h.url && h.url.toLowerCase().includes(q)) ||
          (h.fingerprint && h.fingerprint.toLowerCase().includes(q)) ||
          (h.service && h.service.toLowerCase().includes(q)) ||
          (h.port && String(h.port).includes(q))
        if (!match) return
      }

      if (!map.has(h.ip)) {
        map.set(h.ip, { ip: h.ip, hosts: [], portCount: 0, services: [], fingerprints: [], hasWeb: false, maxVulnCount: 0 })
      }
      const g = map.get(h.ip)!
      g.hosts.push(h)
      g.portCount++
      if (h.service && !g.services.includes(h.service)) g.services.push(h.service)
      if (h.fingerprint && !g.fingerprints.includes(h.fingerprint)) g.fingerprints.push(h.fingerprint)
      if (h.url && (h.url.startsWith('http://') || h.url.startsWith('https://'))) g.hasWeb = true
      if ((h.vulnCount || 0) > g.maxVulnCount) g.maxVulnCount = h.vulnCount || 0
    })

    return Array.from(map.values()).sort((a, b) => {
      const pa = a.ip.split('.').map(Number)
      const pb = b.ip.split('.').map(Number)
      for (let i = 0; i < 4; i++) {
        if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0)
      }
      return 0
    })
  }, [hosts, search, selectedScanId])

  const totalIps = ipGroups.length
  const totalPorts = ipGroups.reduce((s, g) => s + g.portCount, 0)

  const getIpSeverity = (group: IpGroup) => {
    const v = group.maxVulnCount
    if (v >= 5) return { border: 'border-l-[#ff0066]', dot: '#ff0066' }
    if (v >= 2) return { border: 'border-l-[#ffd000]', dot: '#ffd000' }
    if (v >= 1) return { border: 'border-l-[#00f0ff]', dot: '#00f0ff' }
    return { border: 'border-l-transparent', dot: '#00ff88' }
  }

  const formatTime = (timeStr: string) => {
    if (!timeStr) return '--'
    try {
      return new Date(timeStr).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
    } catch { return timeStr }
  }

  const escCSV = (s: string) => '"' + s.replace(/"/g, '""').replace(/\r?\n/g, ' ') + '"'

  const handleExportCSV = () => {
    const header = 'IP,端口,服务,指纹,URL,发现时间\n'
    const rows = ipGroups.flatMap(g =>
      g.hosts.map(h =>
        [h.ip, h.port, h.service || '', h.fingerprint || '', h.url || '', formatTime(h.discoveredAt || h.createdAt || '')]
          .map(escCSV).join(',')
      )
    ).join('\n')
    downloadFile(header + rows, 'assets_export.csv', 'text/csv;charset=utf-8')
  }

  const handleExportJSON = () => {
    const data = ipGroups.map(g => ({
      ip: g.ip,
      ports: g.hosts.map(h => ({
        port: h.port, service: h.service, fingerprint: h.fingerprint, url: h.url,
        discoveredAt: h.discoveredAt || h.createdAt
      }))
    }))
    downloadFile(JSON.stringify(data, null, 2), 'assets_export.json', 'application/json')
  }

  const downloadFile = (content: string, filename: string, mime: string) => {
    const blob = new Blob(['﻿' + content], { type: mime })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = filename; a.click()
    URL.revokeObjectURL(url)
  }

  const getTopService = (services: string[]): string => {
    for (const s of services) {
      const l = s.toLowerCase()
      if (l.includes('http') || l.includes('ssh') || l.includes('mysql') || l.includes('smb') || l.includes('rdp') || l.includes('redis') || l.includes('ftp'))
        return l
    }
    return services[0] || ''
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold neon-text">资产管理</h1>
          <span className="px-3 py-1 bg-[#00f0ff]/10 text-[#00f0ff] border border-[#00f0ff]/30 rounded-full text-xs">
            {totalIps} 台主机 · {totalPorts} 个端口 · {webFingerprints.length} 个技术栈
          </span>
        </div>
        <div className="flex items-center gap-3">
          <select
            value={selectedScanId}
            onChange={(e) => setSelectedScanId(e.target.value)}
            className="bg-[#0a0a0f] border border-[#1e293b] rounded px-3 py-2 text-sm text-[#e2e8f0] focus:border-[#00f0ff] outline-none"
          >
            <option value="">全部扫描</option>
            {scans.slice(0, 50).map((s: any) => (
              <option key={s.id} value={s.id}>
                {s.name || s.target || s.id?.slice(0, 8)} ({s.status === 'completed' ? '已完成' : s.status})
              </option>
            ))}
          </select>
          <div className="relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#94a3b8]" />
            <input type="text" placeholder="搜索 IP / 端口 / 服务..." value={search} onChange={(e) => setSearch(e.target.value)}
              className="bg-[#0a0a0f] border border-[#1e293b] rounded pl-9 pr-3 py-2 text-sm text-[#e2e8f0] focus:border-[#00f0ff] outline-none w-64 transition-colors" />
          </div>
          <button onClick={expandAll} className="text-xs px-3 py-2 border border-[#1e293b] text-[#94a3b8] rounded hover:border-[#00f0ff] hover:text-[#00f0ff] transition-colors">全部展开</button>
          <button onClick={collapseAll} className="text-xs px-3 py-2 border border-[#1e293b] text-[#94a3b8] rounded hover:border-[#00f0ff] hover:text-[#00f0ff] transition-colors">全部折叠</button>
          <button onClick={fetchData} className="px-4 py-2 bg-[#00f0ff]/10 text-[#00f0ff] border border-[#00f0ff]/30 rounded hover:bg-[#00f0ff]/20 transition-colors flex items-center gap-2 text-sm">
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />刷新
          </button>
        </div>
      </div>

      {/* Export Bar */}
      {ipGroups.length > 0 && (
        <div className="flex items-center gap-3">
          <span className="text-xs text-[#94a3b8]">导出:</span>
          <button onClick={handleExportCSV} className="flex items-center gap-1.5 text-xs px-3 py-1.5 border border-[#1e293b] text-[#94a3b8] rounded hover:border-[#00ff88] hover:text-[#00ff88] transition-colors"><Download size={12} /> CSV</button>
          <button onClick={handleExportJSON} className="flex items-center gap-1.5 text-xs px-3 py-1.5 border border-[#1e293b] text-[#94a3b8] rounded hover:border-[#00ff88] hover:text-[#00ff88] transition-colors"><Download size={12} /> JSON</button>
        </div>
      )}

      {/* Asset Tree */}
      <div className="bg-[#111827] border border-[#1e293b] rounded overflow-hidden">
        {loading ? (
          <div className="text-center py-12 text-[#94a3b8] text-sm">加载中...</div>
        ) : ipGroups.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-[#94a3b8]">
            <Server size={36} className="mb-3 text-[#4a5568]" />
            <p className="text-sm">暂无资产数据</p>
            <p className="text-xs text-[#4a5568] mt-1">扫描完成后，发现的主机和服务将在此处展示。</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <div className="flex items-center border-b border-[#1e293b] bg-[#0a0a0f]/50 text-xs uppercase tracking-wider text-[#94a3b8]">
              <div className="w-8 py-3 px-2"></div>
              <div className="w-8 py-3 px-1"></div>
              <div className="flex-1 py-3 px-3 min-w-[140px]">IP 地址</div>
              <div className="w-20 py-3 px-3 text-center">端口</div>
              <div className="w-36 py-3 px-3">服务识别</div>
              <div className="w-20 py-3 px-3 text-center">Web</div>
              <div className="w-16 py-3 px-3 text-center">漏洞</div>
            </div>

            {ipGroups.map((group) => {
              const isExpanded = expandedIps.has(group.ip)
              const severity = getIpSeverity(group)
              const topService = getTopService(group.services)

              return (
                <React.Fragment key={group.ip}>
                  {/* IP Group Row */}
                  <div
                    className={`flex items-center border-b border-[#1e293b]/30 hover:bg-[#1e293b]/20 transition-colors cursor-pointer border-l-2 ${severity.border}`}
                    onClick={() => toggleIp(group.ip)}
                  >
                    <div className="w-8 py-3 px-2 text-[#94a3b8]">
                      {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    </div>
                    <div className="w-8 py-3 px-1">
                      {getServiceIcon(topService)}
                    </div>
                    <div className="flex-1 py-3 px-3 text-[#00f0ff] font-mono text-sm font-bold">
                      {group.ip}
                    </div>
                    <div className="w-20 py-3 px-3 text-center">
                      <span className="text-[#e2e8f0] font-mono text-sm">{group.portCount}</span>
                      <span className="text-[#4a5568] text-xs ml-1">个</span>
                    </div>
                    <div className="w-36 py-3 px-3">
                      {group.services.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {group.services.slice(0, 3).map(s => (
                            <span key={s} className="text-[10px] px-1.5 py-0.5 rounded bg-[#1e293b] text-[#94a3b8]">{s}</span>
                          ))}
                          {group.services.length > 3 && (
                            <span className="text-[10px] text-[#4a5568]">+{group.services.length - 3}</span>
                          )}
                        </div>
                      ) : <span className="text-[#4a5568] text-xs">--</span>}
                    </div>
                    <div className="w-20 py-3 px-3 text-center">
                      {group.hasWeb ? <Globe size={14} className="inline text-[#00f0ff]" /> : <span className="text-[#4a5568] text-xs">--</span>}
                    </div>
                    <div className="w-16 py-3 px-3 text-center">
                      {group.maxVulnCount > 0
                        ? <span className="text-xs text-[#ff0066] font-bold">{group.maxVulnCount}</span>
                        : <span className="text-xs text-[#00ff88]">0</span>}
                    </div>
                  </div>

                  {/* Expanded Port Rows */}
                  {isExpanded && group.hosts.map((host) => {
                    const parsed = parseFingerprint(host.fingerprint, host.service)
                    const techs = host.url ? (fpByUrl.get(host.url) || []) : []

                    return (
                      <div key={host.id} className="border-b border-[#1e293b]/20 bg-[#0a0a0f]/40">
                        {/* Port row */}
                        <div className="flex items-center hover:bg-[#0a0a0f]/60 transition-colors">
                          <div className="w-16"></div>
                          <div className="w-8 py-2 px-1 text-[#4a5568]">
                            {getServiceIcon(host.service)}
                          </div>
                          <div className="flex-1 py-2 px-3 min-w-0">
                            {/* URL + fingerprint info */}
                            {host.url ? (
                              <div>
                                <span
                                  className="text-[#00f0ff] text-xs cursor-pointer hover:underline break-all"
                                  onClick={(e) => { e.stopPropagation(); window.electronAPI.openExternal(host.url) }}
                                >
                                  {host.url}
                                </span>
                                {parsed.version && (
                                  <span className="text-[#4a5568] text-[10px] ml-2">{parsed.label} {parsed.version}</span>
                                )}
                                {/* Tech badges */}
                                {techs.length > 0 && (
                                  <div className="flex flex-wrap gap-1 mt-1.5">
                                    {techs.map((t, i) => {
                                      const cc = getTechCategoryColor(t.category)
                                      return (
                                        <span key={i}
                                          className="text-[10px] px-1.5 py-0.5 rounded"
                                          style={{ background: cc.bg, color: cc.text }}
                                        >
                                          {t.techName}{t.version ? ` ${t.version}` : ''}
                                        </span>
                                      )
                                    })}
                                  </div>
                                )}
                              </div>
                            ) : (
                              <div>
                                <span className="text-[#e2e8f0] text-xs">
                                  {parsed.label}{parsed.version ? ` ${parsed.version}` : ''}
                                </span>
                                {parsed.extra && parsed.extra !== host.fingerprint && (
                                  <span className="text-[#4a5568] text-[10px] ml-2 truncate">{parsed.extra.slice(0, 60)}</span>
                                )}
                              </div>
                            )}
                          </div>
                          <div className="w-20 py-2 px-3 text-center text-[#00f0ff] font-mono text-xs">
                            :{host.port || '--'}
                          </div>
                          <div className="w-36 py-2 px-3 text-[#94a3b8] text-xs truncate">
                            {host.service || '--'}
                          </div>
                          <div className="w-20 py-2 px-3 text-center text-xs text-[#4a5568]">
                            {host.url ? <Globe size={10} className="inline text-[#00f0ff]" /> : ''}
                          </div>
                          <div className="w-16 py-2 px-3 text-center text-xs text-[#4a5568]">
                            {(host.vulnCount || 0) > 0 ? <span className="text-[#ff0066]">{host.vulnCount}</span> : ''}
                          </div>
                        </div>
                        {/* Raw fingerprint tooltip row (only if different from parsed) */}
                        {host.fingerprint && host.fingerprint !== parsed.extra && (
                          <div className="flex items-center pl-24 pb-2">
                            <span className="text-[#4a5568] text-[10px] truncate max-w-[400px]">
                              <Fingerprint size={8} className="inline mr-1" />
                              {host.fingerprint.slice(0, 100)}
                            </span>
                          </div>
                        )}
                      </div>
                    )
                  })}
                </React.Fragment>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

export default Assets
