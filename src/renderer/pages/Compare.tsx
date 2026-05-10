import React, { useState, useEffect } from 'react'
import { GitCompare, Server, Shield, AlertTriangle, ArrowLeftRight, RefreshCw, Search, CheckCircle2, XCircle, MinusCircle } from 'lucide-react'

interface Scan {
  id: string
  target: string
  tool: string
  status: string
  startedAt: string
  createdAt: string
  [key: string]: any
}

interface Host {
  ip: string
  port: string
  service: string
  fingerprint: string
  [key: string]: any
}

interface Vuln {
  id: number
  name: string
  severity: string
  host: string
  matchedAt: string
  [key: string]: any
}

interface ScanDetail {
  scan: Scan
  hosts: Host[]
  vulns: Vuln[]
}

interface ComparisonResult {
  newHosts: Host[]
  removedHosts: Host[]
  unchangedHosts: Host[]
  newVulns: Vuln[]
  fixedVulns: Vuln[]
  unchangedVulns: Vuln[]
  statsA: {
    totalHosts: number
    totalVulns: number
    criticalCount: number
  }
  statsB: {
    totalHosts: number
    totalVulns: number
    criticalCount: number
  }
}

type CompareTab = 'hosts' | 'vulns'

const Compare: React.FC = () => {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [scanAId, setScanAId] = useState<string>('')
  const [scanBId, setScanBId] = useState<string>('')
  const [comparing, setComparing] = useState(false)
  const [result, setResult] = useState<ComparisonResult | null>(null)
  const [activeTab, setActiveTab] = useState<CompareTab>('hosts')
  const [hostFilter, setHostFilter] = useState<'all' | 'new' | 'removed' | 'unchanged'>('all')
  const [vulnFilter, setVulnFilter] = useState<'all' | 'new' | 'fixed' | 'unchanged'>('all')

  useEffect(() => {
    fetchScans()
  }, [])

  const fetchScans = async () => {
    setLoading(true)
    try {
      const data = await window.electronAPI.getScans()
      setScans((data || []).filter((s: Scan) => s.status === 'completed'))
    } catch (err) {
      console.error('获取扫描列表失败:', err)
    } finally {
      setLoading(false)
    }
  }

  const formatTime = (timeStr: string) => {
    if (!timeStr) return '--'
    try {
      return new Date(timeStr).toLocaleString('zh-CN')
    } catch {
      return timeStr
    }
  }

  const makeHostKey = (h: Host) => `${h.ip}:${h.port}`

  const makeVulnKey = (v: Vuln) => `${v.name}||${v.host || v.matchedAt}`

  const handleCompare = async () => {
    if (!scanAId || !scanBId) return
    if (scanAId === scanBId) return
    setComparing(true)
    setResult(null)
    try {
      const [detailA, detailB] = await Promise.all([
        fetchScanDetail(scanAId),
        fetchScanDetail(scanBId),
      ])
      if (!detailA || !detailB) {
        setComparing(false)
        return
      }

      const hostKeysA = new Set(detailA.hosts.map(makeHostKey))
      const hostKeysB = new Set(detailB.hosts.map(makeHostKey))

      const newHosts = detailB.hosts.filter((h) => !hostKeysA.has(makeHostKey(h)))
      const removedHosts = detailA.hosts.filter((h) => !hostKeysB.has(makeHostKey(h)))
      const unchangedHosts = detailA.hosts.filter((h) => hostKeysB.has(makeHostKey(h)))

      const vulnKeysA = new Set(detailA.vulns.map(makeVulnKey))
      const vulnKeysB = new Set(detailB.vulns.map(makeVulnKey))

      const newVulns = detailB.vulns.filter((v) => !vulnKeysA.has(makeVulnKey(v)))
      const fixedVulns = detailA.vulns.filter((v) => !vulnKeysB.has(makeVulnKey(v)))
      const unchangedVulns = detailA.vulns.filter((v) => vulnKeysB.has(makeVulnKey(v)))

      const countCritical = (vulns: Vuln[]) =>
        vulns.filter((v) => (v.severity || '').toLowerCase() === 'critical').length

      setResult({
        newHosts,
        removedHosts,
        unchangedHosts,
        newVulns,
        fixedVulns,
        unchangedVulns,
        statsA: {
          totalHosts: detailA.hosts.length,
          totalVulns: detailA.vulns.length,
          criticalCount: countCritical(detailA.vulns),
        },
        statsB: {
          totalHosts: detailB.hosts.length,
          totalVulns: detailB.vulns.length,
          criticalCount: countCritical(detailB.vulns),
        },
      })
    } catch (err) {
      console.error('对比失败:', err)
    } finally {
      setComparing(false)
    }
  }

  const fetchScanDetail = async (scanId: string): Promise<ScanDetail | null> => {
    try {
      const [scan, hosts, vulns] = await Promise.all([
        window.electronAPI.getScanById(scanId),
        window.electronAPI.getHostsByScanId(scanId),
        window.electronAPI.getVulnsByScanId(scanId),
      ])
      return {
        scan,
        hosts: hosts || [],
        vulns: vulns || [],
      }
    } catch (err) {
      console.error('获取扫描详情失败:', err)
      return null
    }
  }

  const scanLabel = (scan: Scan) => {
    const target = scan.target || scan.args || scan.id
    const time = formatTime(scan.startedAt || scan.createdAt)
    return `${target} | ${scan.tool} | ${time}`
  }

  const scanA = scans.find((s) => s.id === scanAId)
  const scanB = scans.find((s) => s.id === scanBId)

  const filteredHosts = result
    ? (() => {
        switch (hostFilter) {
          case 'new': return result.newHosts
          case 'removed': return result.removedHosts
          case 'unchanged': return result.unchangedHosts
          default: return [
            ...result.newHosts.map((h) => ({ ...h, _status: 'new' as const })),
            ...result.removedHosts.map((h) => ({ ...h, _status: 'removed' as const })),
            ...result.unchangedHosts.map((h) => ({ ...h, _status: 'unchanged' as const })),
          ]
        }
      })()
    : []

  const filteredVulns = result
    ? (() => {
        switch (vulnFilter) {
          case 'new': return result.newVulns
          case 'fixed': return result.fixedVulns
          case 'unchanged': return result.unchangedVulns
          default: return [
            ...result.newVulns.map((v) => ({ ...v, _status: 'new' as const })),
            ...result.fixedVulns.map((v) => ({ ...v, _status: 'fixed' as const })),
            ...result.unchangedVulns.map((v) => ({ ...v, _status: 'unchanged' as const })),
          ]
        }
      })()
    : []

  const hostStatusIcon = (status: 'new' | 'removed' | 'unchanged') => {
    switch (status) {
      case 'new': return <CheckCircle2 size={14} className="text-[#00ff88]" />
      case 'removed': return <XCircle size={14} className="text-[#ff0066]" />
      case 'unchanged': return <MinusCircle size={14} className="text-[#94a3b8]" />
    }
  }

  const hostStatusBg = (status: 'new' | 'removed' | 'unchanged') => {
    switch (status) {
      case 'new': return 'bg-[#00ff88]/5 border-l-2 border-l-[#00ff88]'
      case 'removed': return 'bg-[#ff0066]/5 border-l-2 border-l-[#ff0066]'
      case 'unchanged': return 'bg-[#94a3b8]/5 border-l-2 border-l-[#94a3b8]'
    }
  }

  const hostStatusLabel = (status: 'new' | 'removed' | 'unchanged') => {
    switch (status) {
      case 'new': return <span className="text-[#00ff88] text-xs">新增</span>
      case 'removed': return <span className="text-[#ff0066] text-xs">消失</span>
      case 'unchanged': return <span className="text-[#94a3b8] text-xs">未变化</span>
    }
  }

  const vulnStatusIcon = (status: 'new' | 'fixed' | 'unchanged') => {
    switch (status) {
      case 'new': return <AlertTriangle size={14} className="text-[#ffd000]" />
      case 'fixed': return <CheckCircle2 size={14} className="text-[#00ff88]" />
      case 'unchanged': return <MinusCircle size={14} className="text-[#94a3b8]" />
    }
  }

  const vulnStatusBg = (status: 'new' | 'fixed' | 'unchanged') => {
    switch (status) {
      case 'new': return 'bg-[#ffd000]/5 border-l-2 border-l-[#ffd000]'
      case 'fixed': return 'bg-[#00ff88]/5 border-l-2 border-l-[#00ff88]'
      case 'unchanged': return 'bg-[#94a3b8]/5 border-l-2 border-l-[#94a3b8]'
    }
  }

  const vulnStatusLabel = (status: 'new' | 'fixed' | 'unchanged') => {
    switch (status) {
      case 'new': return <span className="text-[#ffd000] text-xs">新增漏洞</span>
      case 'fixed': return <span className="text-[#00ff88] text-xs">已修复</span>
      case 'unchanged': return <span className="text-[#94a3b8] text-xs">未变化</span>
    }
  }

  const severityBadge = (severity: string) => {
    const s = (severity || 'info').toLowerCase()
    const map: Record<string, { label: string; color: string }> = {
      critical: { label: '严重', color: '#ff0044' },
      high: { label: '高危', color: '#ff6600' },
      medium: { label: '中危', color: '#ffd000' },
      low: { label: '低危', color: '#00ff88' },
      info: { label: '信息', color: '#00f0ff' },
    }
    const cfg = map[s] || map.info
    return (
      <span
        className="inline-block px-2 py-0.5 text-xs rounded border"
        style={{
          color: cfg.color,
          borderColor: cfg.color + '66',
          background: cfg.color + '15',
        }}
      >
        {cfg.label}
      </span>
    )
  }

  return (
    <div className="space-y-6">
      {/* 页面标题 */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <GitCompare size={24} className="text-[#bf00ff]" />
          <h1 className="text-2xl font-bold neon-text">结果对比</h1>
        </div>
        <button
          onClick={fetchScans}
          className="px-4 py-2 bg-[#bf00ff]/10 text-[#bf00ff] border border-[#bf00ff]/30 rounded hover:bg-[#bf00ff]/20 transition-colors flex items-center gap-2 text-sm"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          刷新
        </button>
      </div>

      {/* 扫描选择器 */}
      <div className="cyber-card p-5">
        <h2 className="text-sm uppercase tracking-wider text-[#94a3b8] mb-4">选择扫描任务</h2>
        {loading ? (
          <div className="text-[#94a3b8] text-sm py-4 text-center">加载中...</div>
        ) : scans.length < 2 ? (
          <div className="text-center py-8 text-[#94a3b8] text-sm">
            至少需要 2 个已完成的扫描任务才能进行对比，请先执行更多扫描。
          </div>
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-6">
              {/* 扫描 A */}
              <div>
                <label className="text-xs text-[#94a3b8] uppercase tracking-wider mb-2 block">
                  扫描 A（基准）
                </label>
                <select
                  value={scanAId}
                  onChange={(e) => setScanAId(e.target.value)}
                  className="w-full bg-[#0a0a0f] border border-[#1e293b] rounded px-4 py-2.5 text-sm text-[#e2e8f0] focus:border-[#00f0ff] outline-none cursor-pointer"
                >
                  <option value="">-- 选择扫描 A --</option>
                  {scans
                    .filter((s) => s.id !== scanBId)
                    .map((scan) => (
                      <option key={scan.id} value={scan.id}>
                        {scanLabel(scan)}
                      </option>
                    ))}
                </select>
                {scanA && (
                  <div className="mt-2 p-3 bg-[#0a0a0f] rounded border border-[#1e293b] text-xs text-[#94a3b8] space-y-1">
                    <div>目标: <span className="text-[#00f0ff] font-mono">{scanA.target || scanA.args || '--'}</span></div>
                    <div>工具: <span className="text-[#e2e8f0]">{scanA.tool}</span></div>
                    <div>时间: <span className="text-[#e2e8f0]">{formatTime(scanA.startedAt || scanA.createdAt)}</span></div>
                  </div>
                )}
              </div>

              {/* 扫描 B */}
              <div>
                <label className="text-xs text-[#94a3b8] uppercase tracking-wider mb-2 block">
                  扫描 B（对比）
                </label>
                <select
                  value={scanBId}
                  onChange={(e) => setScanBId(e.target.value)}
                  className="w-full bg-[#0a0a0f] border border-[#1e293b] rounded px-4 py-2.5 text-sm text-[#e2e8f0] focus:border-[#bf00ff] outline-none cursor-pointer"
                >
                  <option value="">-- 选择扫描 B --</option>
                  {scans
                    .filter((s) => s.id !== scanAId)
                    .map((scan) => (
                      <option key={scan.id} value={scan.id}>
                        {scanLabel(scan)}
                      </option>
                    ))}
                </select>
                {scanB && (
                  <div className="mt-2 p-3 bg-[#0a0a0f] rounded border border-[#1e293b] text-xs text-[#94a3b8] space-y-1">
                    <div>目标: <span className="text-[#bf00ff] font-mono">{scanB.target || scanB.args || '--'}</span></div>
                    <div>工具: <span className="text-[#e2e8f0]">{scanB.tool}</span></div>
                    <div>时间: <span className="text-[#e2e8f0]">{formatTime(scanB.startedAt || scanB.createdAt)}</span></div>
                  </div>
                )}
              </div>
            </div>

            {/* 对比按钮 */}
            <div className="flex justify-center pt-2">
              <button
                onClick={handleCompare}
                disabled={!scanAId || !scanBId || scanAId === scanBId || comparing}
                className="flex items-center gap-2 px-8 py-3 rounded text-sm font-bold border border-[#bf00ff]/50 bg-[#bf00ff]/15 text-[#bf00ff] hover:bg-[#bf00ff]/25 transition-colors disabled:opacity-40 disabled:cursor-not-allowed neon-glow-purple"
              >
                <ArrowLeftRight size={18} />
                {comparing ? '正在对比...' : '开始对比'}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* 对比结果 */}
      {result && (
        <>
          {/* 统计概览 */}
          <div className="grid grid-cols-2 gap-6">
            {/* 扫描 A 统计 */}
            <div className="cyber-card p-5 neon-glow">
              <div className="flex items-center gap-2 mb-4">
                <Server size={16} className="text-[#00f0ff]" />
                <span className="text-xs uppercase tracking-wider text-[#94a3b8]">扫描 A — 基准</span>
              </div>
              <div className="grid grid-cols-3 gap-4">
                <div className="text-center p-3 bg-[#0a0a0f] rounded border border-[#1e293b]">
                  <div className="text-2xl font-bold text-[#00f0ff]">{result.statsA.totalHosts}</div>
                  <div className="text-xs text-[#94a3b8] mt-1">主机总数</div>
                </div>
                <div className="text-center p-3 bg-[#0a0a0f] rounded border border-[#1e293b]">
                  <div className="text-2xl font-bold text-[#ffd000]">{result.statsA.totalVulns}</div>
                  <div className="text-xs text-[#94a3b8] mt-1">漏洞总数</div>
                </div>
                <div className="text-center p-3 bg-[#0a0a0f] rounded border border-[#1e293b]">
                  <div className="text-2xl font-bold text-[#ff0044]">{result.statsA.criticalCount}</div>
                  <div className="text-xs text-[#94a3b8] mt-1">严重漏洞</div>
                </div>
              </div>
            </div>

            {/* 扫描 B 统计 */}
            <div className="cyber-card p-5 neon-glow-purple">
              <div className="flex items-center gap-2 mb-4">
                <Server size={16} className="text-[#bf00ff]" />
                <span className="text-xs uppercase tracking-wider text-[#94a3b8]">扫描 B — 对比</span>
              </div>
              <div className="grid grid-cols-3 gap-4">
                <div className="text-center p-3 bg-[#0a0a0f] rounded border border-[#1e293b]">
                  <div className="text-2xl font-bold text-[#00f0ff]">{result.statsB.totalHosts}</div>
                  <div className="text-xs text-[#94a3b8] mt-1">主机总数</div>
                </div>
                <div className="text-center p-3 bg-[#0a0a0f] rounded border border-[#1e293b]">
                  <div className="text-2xl font-bold text-[#ffd000]">{result.statsB.totalVulns}</div>
                  <div className="text-xs text-[#94a3b8] mt-1">漏洞总数</div>
                </div>
                <div className="text-center p-3 bg-[#0a0a0f] rounded border border-[#1e293b]">
                  <div className="text-2xl font-bold text-[#ff0044]">{result.statsB.criticalCount}</div>
                  <div className="text-xs text-[#94a3b8] mt-1">严重漏洞</div>
                </div>
              </div>
            </div>
          </div>

          {/* 变化摘要 */}
          <div className="grid grid-cols-6 gap-3">
            <div className="cyber-card p-4 text-center">
              <div className="text-xl font-bold text-[#00ff88]">{result.newHosts.length}</div>
              <div className="text-xs text-[#94a3b8] mt-1">新增主机</div>
            </div>
            <div className="cyber-card p-4 text-center">
              <div className="text-xl font-bold text-[#ff0066]">{result.removedHosts.length}</div>
              <div className="text-xs text-[#94a3b8] mt-1">消失主机</div>
            </div>
            <div className="cyber-card p-4 text-center">
              <div className="text-xl font-bold text-[#94a3b8]">{result.unchangedHosts.length}</div>
              <div className="text-xs text-[#94a3b8] mt-1">未变化主机</div>
            </div>
            <div className="cyber-card p-4 text-center">
              <div className="text-xl font-bold text-[#ffd000]">{result.newVulns.length}</div>
              <div className="text-xs text-[#94a3b8] mt-1">新增漏洞</div>
            </div>
            <div className="cyber-card p-4 text-center">
              <div className="text-xl font-bold text-[#00ff88]">{result.fixedVulns.length}</div>
              <div className="text-xs text-[#94a3b8] mt-1">已修复漏洞</div>
            </div>
            <div className="cyber-card p-4 text-center">
              <div className="text-xl font-bold text-[#94a3b8]">{result.unchangedVulns.length}</div>
              <div className="text-xs text-[#94a3b8] mt-1">未变化漏洞</div>
            </div>
          </div>

          {/* 选项卡切换 */}
          <div className="flex items-center gap-1 bg-[#0d0d14] p-1 rounded-lg border border-[#1e293b] w-fit">
            <button
              onClick={() => setActiveTab('hosts')}
              className={`flex items-center gap-2 px-5 py-2.5 rounded text-sm transition-all ${
                activeTab === 'hosts'
                  ? 'bg-[#00f0ff]/15 text-[#00f0ff] border border-[#00f0ff]/30'
                  : 'text-[#94a3b8] hover:text-[#e2e8f0]'
              }`}
            >
              <Server size={16} />
              主机对比
            </button>
            <button
              onClick={() => setActiveTab('vulns')}
              className={`flex items-center gap-2 px-5 py-2.5 rounded text-sm transition-all ${
                activeTab === 'vulns'
                  ? 'bg-[#ff0066]/15 text-[#ff0066] border border-[#ff0066]/30'
                  : 'text-[#94a3b8] hover:text-[#e2e8f0]'
              }`}
            >
              <Shield size={16} />
              漏洞对比
            </button>
          </div>

          {/* 主机对比详情 */}
          {activeTab === 'hosts' && (
            <div className="cyber-card p-5">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm uppercase tracking-wider text-[#94a3b8]">主机变化详情</h2>
                <div className="flex items-center gap-2">
                  {[
                    { key: 'all' as const, label: '全部', count: result.newHosts.length + result.removedHosts.length + result.unchangedHosts.length },
                    { key: 'new' as const, label: '新增', count: result.newHosts.length },
                    { key: 'removed' as const, label: '消失', count: result.removedHosts.length },
                    { key: 'unchanged' as const, label: '未变化', count: result.unchangedHosts.length },
                  ].map((f) => (
                    <button
                      key={f.key}
                      onClick={() => setHostFilter(f.key)}
                      className={`px-3 py-1.5 rounded text-xs border transition-colors ${
                        hostFilter === f.key
                          ? f.key === 'new'
                            ? 'bg-[#00ff88]/10 text-[#00ff88] border-[#00ff88]/40'
                            : f.key === 'removed'
                              ? 'bg-[#ff0066]/10 text-[#ff0066] border-[#ff0066]/40'
                              : f.key === 'unchanged'
                                ? 'bg-[#94a3b8]/10 text-[#94a3b8] border-[#94a3b8]/40'
                                : 'bg-[#00f0ff]/10 text-[#00f0ff] border-[#00f0ff]/40'
                          : 'text-[#4a5568] border-[#1e293b] hover:border-[#4a5568]'
                      }`}
                    >
                      {f.label} ({f.count})
                    </button>
                  ))}
                </div>
              </div>

              {filteredHosts.length === 0 ? (
                <div className="text-center py-8 text-[#94a3b8] text-sm">
                  {hostFilter === 'all' ? '未发现主机变化' : '该筛选条件下无数据'}
                </div>
              ) : hostFilter !== 'all' ? (
                <div className="space-y-2">
                  {(filteredHosts as Host[]).map((host, i) => {
                    const status = hostFilter === 'new' ? 'new' : hostFilter === 'removed' ? 'removed' : 'unchanged'
                    return (
                      <div
                        key={i}
                        className={`flex items-center gap-4 px-4 py-3 rounded ${hostStatusBg(status)}`}
                      >
                        {hostStatusIcon(status)}
                        <span className="text-[#e2e8f0] font-mono text-sm">{host.ip}</span>
                        <span className="text-[#00f0ff] font-mono text-sm">:{host.port}</span>
                        <span className="text-[#94a3b8] text-xs flex-1">
                          {host.service} {host.fingerprint && `— ${host.fingerprint}`}
                        </span>
                        {hostStatusLabel(status)}
                      </div>
                    )
                  })}
                </div>
              ) : (
                <div className="space-y-2">
                  {(filteredHosts as (Host & { _status: 'new' | 'removed' | 'unchanged' })[]).map((host, i) => (
                    <div
                      key={i}
                      className={`flex items-center gap-4 px-4 py-3 rounded ${hostStatusBg(host._status)}`}
                    >
                      {hostStatusIcon(host._status)}
                      <span className="text-[#e2e8f0] font-mono text-sm">{host.ip}</span>
                      <span className="text-[#00f0ff] font-mono text-sm">:{host.port}</span>
                      <span className="text-[#94a3b8] text-xs flex-1">
                        {host.service} {host.fingerprint && `— ${host.fingerprint}`}
                      </span>
                      {hostStatusLabel(host._status)}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* 漏洞对比详情 */}
          {activeTab === 'vulns' && (
            <div className="cyber-card p-5">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm uppercase tracking-wider text-[#94a3b8]">漏洞变化详情</h2>
                <div className="flex items-center gap-2">
                  {[
                    { key: 'all' as const, label: '全部', count: result.newVulns.length + result.fixedVulns.length + result.unchangedVulns.length },
                    { key: 'new' as const, label: '新增漏洞', count: result.newVulns.length },
                    { key: 'fixed' as const, label: '已修复', count: result.fixedVulns.length },
                    { key: 'unchanged' as const, label: '未变化', count: result.unchangedVulns.length },
                  ].map((f) => (
                    <button
                      key={f.key}
                      onClick={() => setVulnFilter(f.key)}
                      className={`px-3 py-1.5 rounded text-xs border transition-colors ${
                        vulnFilter === f.key
                          ? f.key === 'new'
                            ? 'bg-[#ffd000]/10 text-[#ffd000] border-[#ffd000]/40'
                            : f.key === 'fixed'
                              ? 'bg-[#00ff88]/10 text-[#00ff88] border-[#00ff88]/40'
                              : f.key === 'unchanged'
                                ? 'bg-[#94a3b8]/10 text-[#94a3b8] border-[#94a3b8]/40'
                                : 'bg-[#ff0066]/10 text-[#ff0066] border-[#ff0066]/40'
                          : 'text-[#4a5568] border-[#1e293b] hover:border-[#4a5568]'
                      }`}
                    >
                      {f.label} ({f.count})
                    </button>
                  ))}
                </div>
              </div>

              {filteredVulns.length === 0 ? (
                <div className="text-center py-8 text-[#94a3b8] text-sm">
                  {vulnFilter === 'all' ? '未发现漏洞变化' : '该筛选条件下无数据'}
                </div>
              ) : vulnFilter !== 'all' ? (
                <div className="space-y-2">
                  {(filteredVulns as Vuln[]).map((vuln, i) => {
                    const status = vulnFilter === 'new' ? 'new' : vulnFilter === 'fixed' ? 'fixed' : 'unchanged'
                    return (
                      <div
                        key={i}
                        className={`flex items-center gap-4 px-4 py-3 rounded ${vulnStatusBg(status)}`}
                      >
                        {vulnStatusIcon(status)}
                        <div className="flex-1 min-w-0">
                          <div className="text-[#e2e8f0] text-sm truncate">{vuln.name || vuln.templateId || '未知漏洞'}</div>
                          <div className="text-[#4a5568] text-xs truncate mt-0.5">{vuln.host || vuln.matchedAt || '--'}</div>
                        </div>
                        {severityBadge(vuln.severity)}
                        {vulnStatusLabel(status)}
                      </div>
                    )
                  })}
                </div>
              ) : (
                <div className="space-y-2">
                  {(filteredVulns as (Vuln & { _status: 'new' | 'fixed' | 'unchanged' })[]).map((vuln, i) => (
                    <div
                      key={i}
                      className={`flex items-center gap-4 px-4 py-3 rounded ${vulnStatusBg(vuln._status)}`}
                    >
                      {vulnStatusIcon(vuln._status)}
                      <div className="flex-1 min-w-0">
                        <div className="text-[#e2e8f0] text-sm truncate">{vuln.name || vuln.templateId || '未知漏洞'}</div>
                        <div className="text-[#4a5568] text-xs truncate mt-0.5">{vuln.host || vuln.matchedAt || '--'}</div>
                      </div>
                      {severityBadge(vuln.severity)}
                      {vulnStatusLabel(vuln._status)}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  )
}

export default Compare
