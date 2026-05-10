import React, { useState, useEffect } from 'react'
import { FileText, Download, Eye, RefreshCw, ChevronDown } from 'lucide-react'
import { translateVulnName, translateSeverity } from '../utils/translateVuln'

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
  description: string
  templateId: string
  type: string
  status: string
  [key: string]: any
}

interface WebUrl {
  url: string
  ip: string
  port: string
  keyword: string
  fingerprint: string
  [key: string]: any
}

type ReportType = 'summary' | 'technical' | 'full'
type ExportFormat = 'html' | 'csv' | 'json'

const reportTypes: { key: ReportType; label: string; desc: string }[] = [
  { key: 'summary', label: '执行摘要', desc: '高层次的扫描结果概览' },
  { key: 'technical', label: '技术报告', desc: '详细的技术漏洞分析' },
  { key: 'full', label: '完整报告', desc: '包含所有扫描数据和分析' },
]

const severityOptions: { key: string; label: string; color: string }[] = [
  { key: 'critical', label: '严重', color: '#ff0044' },
  { key: 'high', label: '高危', color: '#ff6600' },
  { key: 'medium', label: '中危', color: '#ffd000' },
  { key: 'low', label: '低危', color: '#00ff88' },
  { key: 'info', label: '信息', color: '#00f0ff' },
]

const severityBadgeCSS = (severity: string): string => {
  const s = (severity || 'info').toLowerCase()
  const map: Record<string, string> = {
    critical: 'background:rgba(255,0,68,0.15);color:#ff0044;border:1px solid rgba(255,0,68,0.4);',
    high: 'background:rgba(255,102,0,0.15);color:#ff6600;border:1px solid rgba(255,102,0,0.4);',
    medium: 'background:rgba(255,208,0,0.15);color:#ffd000;border:1px solid rgba(255,208,0,0.4);',
    low: 'background:rgba(0,255,136,0.15);color:#00ff88;border:1px solid rgba(0,255,136,0.4);',
    info: 'background:rgba(0,240,255,0.15);color:#00f0ff;border:1px solid rgba(0,240,255,0.4);',
  }
  return map[s] || map.info
}

const Reports: React.FC = () => {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedScanId, setSelectedScanId] = useState<string>('')
  const [reportType, setReportType] = useState<ReportType>('summary')
  const [severityFilters, setSeverityFilters] = useState<Record<string, boolean>>({
    critical: true,
    high: true,
    medium: true,
    low: true,
    info: true,
  })
  const [previewContent, setPreviewContent] = useState<string>('')
  const [previewFormat, setPreviewFormat] = useState<'html' | 'raw'>('html')
  const [exporting, setExporting] = useState(false)

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

  const toggleSeverity = (key: string) => {
    setSeverityFilters((prev) => ({ ...prev, [key]: !prev[key] }))
  }

  const formatTime = (timeStr: string) => {
    if (!timeStr) return '--'
    try {
      return new Date(timeStr).toLocaleString('zh-CN')
    } catch {
      return timeStr
    }
  }

  const getReportData = async () => {
    if (!selectedScanId) return null
    const scan = await window.electronAPI.getScanById(selectedScanId)
    const hosts = await window.electronAPI.getHostsByScanId(selectedScanId)
    const vulns = await window.electronAPI.getVulnsByScanId(selectedScanId)
    const webUrls = await window.electronAPI.getWebUrlsByScanId(selectedScanId)
    const filteredVulns = (vulns || []).filter((v: Vuln) => {
      const sev = (v.severity || 'info').toLowerCase()
      return severityFilters[sev] !== false
    })
    return { scan, hosts: hosts || [], vulns: filteredVulns, webUrls: webUrls || [] }
  }

  const generateHTML = (data: NonNullable<Awaited<ReturnType<typeof getReportData>>>) => {
    const { scan, hosts, vulns, webUrls } = data
    const now = new Date().toLocaleString('zh-CN')
    const vulnCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    vulns.forEach((v: Vuln) => {
      const s = (v.severity || 'info').toLowerCase()
      if (vulnCounts[s] !== undefined) vulnCounts[s]++
    })

    const esc = (s: string | undefined | null) => (s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")

    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>CyberScan ${reportTypes.find((t) => t.key === reportType)?.label || '报告'}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: #0a0a0f; color: #e2e8f0; font-family: 'JetBrains Mono','Microsoft YaHei',monospace; padding: 40px; }
  .header { border-bottom: 2px solid #00f0ff; padding-bottom: 20px; margin-bottom: 30px; }
  .header h1 { font-size: 24px; color: #00f0ff; text-shadow: 0 0 10px rgba(0,240,255,0.5); }
  .header .meta { color: #94a3b8; font-size: 13px; margin-top: 8px; }
  .section { margin-bottom: 30px; }
  .section h2 { font-size: 16px; color: #bf00ff; border-left: 3px solid #bf00ff; padding-left: 12px; margin-bottom: 15px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { background: #111827; color: #94a3b8; text-align: left; padding: 10px 12px; border: 1px solid #1e293b; }
  td { padding: 8px 12px; border: 1px solid #1e293b; }
  tr:hover td { background: rgba(0,240,255,0.03); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; }
  .badge-critical { background: rgba(255,0,68,0.15); color: #ff0044; border: 1px solid rgba(255,0,68,0.4); }
  .badge-high { background: rgba(255,102,0,0.15); color: #ff6600; border: 1px solid rgba(255,102,0,0.4); }
  .badge-medium { background: rgba(255,208,0,0.15); color: #ffd000; border: 1px solid rgba(255,208,0,0.4); }
  .badge-low { background: rgba(0,255,136,0.15); color: #00ff88; border: 1px solid rgba(0,255,136,0.4); }
  .badge-info { background: rgba(0,240,255,0.15); color: #00f0ff; border: 1px solid rgba(0,240,255,0.4); }
  .stat-grid { display: grid; grid-template-columns: repeat(5,1fr); gap: 12px; margin-bottom: 20px; }
  .stat-card { background: #111827; border: 1px solid #1e293b; border-radius: 4px; padding: 15px; text-align: center; }
  .stat-card .num { font-size: 28px; font-weight: bold; }
  .stat-card .label { color: #94a3b8; font-size: 12px; margin-top: 4px; }
  .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #1e293b; color: #4a5568; font-size: 11px; text-align: center; }
</style>
</head>
<body>
<div class="header">
  <h1>CyberScan ${reportTypes.find((t) => t.key === reportType)?.label || '报告'}</h1>
  <div class="meta">
    目标: ${esc(scan?.target || scan?.args)} | 工具: ${scan?.tool || '--'} | 生成时间: ${now}
  </div>
</div>

<div class="stat-grid">
  <div class="stat-card"><div class="num" style="color:#00f0ff">${hosts.length}</div><div class="label">发现主机</div></div>
  <div class="stat-card"><div class="num" style="color:#ff0044">${vulnCounts.critical}</div><div class="label">严重</div></div>
  <div class="stat-card"><div class="num" style="color:#ff6600">${vulnCounts.high}</div><div class="label">高危</div></div>
  <div class="stat-card"><div class="num" style="color:#ffd000">${vulnCounts.medium}</div><div class="label">中危</div></div>
  <div class="stat-card"><div class="num" style="color:#00ff88">${vulnCounts.low + vulnCounts.info}</div><div class="label">低危/信息</div></div>
</div>

${reportType !== 'summary' ? `
<div class="section">
  <h2>主机列表</h2>
  <table>
    <thead><tr><th>IP 地址</th><th>端口</th><th>服务</th><th>指纹</th></tr></thead>
    <tbody>${hosts.map((h: Host) => `<tr><td style="color:#00f0ff">${esc(h.ip)}</td><td>${esc(h.port)}</td><td>${esc(h.service)}</td><td>${esc(h.fingerprint)}</td></tr>`).join('\n')}</tbody>
  </table>
</div>
` : ''}

<div class="section">
  <h2>漏洞详情</h2>
  ${vulns.length === 0 ? '<p style="color:#94a3b8">未发现符合筛选条件的漏洞。</p>' : `
  <table>
    <thead><tr><th>严重性</th><th>漏洞名称</th><th>目标</th>${reportType === 'full' ? '<th>描述</th><th>模板 ID</th>' : ''}</tr></thead>
    <tbody>${vulns.map((v: Vuln) => {
      const sev = (v.severity || 'info').toLowerCase()
      return `<tr>
        <td><span class="badge badge-${sev}">${translateSeverity(sev)}</span></td>
        <td style="color:#e2e8f0">${esc(translateVulnName(v.name || v.templateId))}</td>
        <td style="color:#00f0ff;font-size:12px">${esc(v.host || v.matchedAt)}</td>
        ${reportType === 'full' ? `<td style="color:#94a3b8;font-size:12px">${esc(v.description)}</td><td style="font-size:12px">${esc(v.templateId)}</td>` : ''}
      </tr>`
    }).join('\n')}</tbody>
  </table>`}
</div>

${reportType === 'full' && webUrls.length > 0 ? `
<div class="section">
  <h2>Web 服务</h2>
  <table>
    <thead><tr><th>URL</th><th>IP</th><th>指纹</th></tr></thead>
    <tbody>${webUrls.map((w: WebUrl) => `<tr><td style="color:#00f0ff;font-size:12px">${esc(w.url)}</td><td>${esc(w.ip)}</td><td>${esc(w.fingerprint)}</td></tr>`).join('\n')}</tbody>
  </table>
</div>
` : ''}

<div class="footer">CyberScan 赛博安全扫描平台 | 报告生成于 ${now}</div>
</body>
</html>`
  }

  const generateCSV = (data: NonNullable<Awaited<ReturnType<typeof getReportData>>>) => {
    const { vulns } = data
    const header = '严重性,漏洞名称,目标,匹配地址,类型,模板ID,状态,发现时间'
    const rows = vulns.map((v: Vuln) => {
      const sev = (v.severity || 'info').toLowerCase()
      const label = translateSeverity(sev)
      return `"${label}","${(translateVulnName(v.name || v.templateId)).replace(/"/g, '""')}","${(v.host || '').replace(/"/g, '""')}","${(v.matchedAt || '').replace(/"/g, '""')}","${v.type || ''}","${v.templateId || ''}","${v.status || ''}","${v.discoveredAt || ''}"`
    })
    return [header, ...rows].join('\n')
  }

  const generateJSON = (data: NonNullable<Awaited<ReturnType<typeof getReportData>>>) => {
    return JSON.stringify({
      reportType: reportTypes.find((t) => t.key === reportType)?.label,
      generatedAt: new Date().toISOString(),
      scan: data.scan,
      hosts: data.hosts,
      vulnerabilities: data.vulns,
      webUrls: data.webUrls,
    }, null, 2)
  }

  const downloadFile = (content: string, filename: string, mimeType: string) => {
    const blob = new Blob([content], { type: mimeType })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleExport = async (format: ExportFormat) => {
    if (!selectedScanId) return
    setExporting(true)
    try {
      const data = await getReportData()
      if (!data) return

      const scan = await window.electronAPI.getScanById(selectedScanId)
      const targetSlug = (scan?.target || scan?.args || 'report').replace(/[^a-zA-Z0-9]/g, '_').slice(0, 30)
      const timestamp = new Date().toISOString().slice(0, 10)

      let content = ''
      if (format === 'html') {
        content = generateHTML(data)
        setPreviewContent(content)
        setPreviewFormat('html')
        downloadFile(content, `XingEye_${targetSlug}_${timestamp}.html`, 'text/html')
      } else if (format === 'csv') {
        content = generateCSV(data)
        setPreviewContent(content)
        setPreviewFormat('raw')
        downloadFile(content, `XingEye_${targetSlug}_${timestamp}.csv`, 'text/csv')
      } else {
        content = generateJSON(data)
        setPreviewContent(content)
        setPreviewFormat('raw')
        downloadFile(content, `XingEye_${targetSlug}_${timestamp}.json`, 'application/json')
      }
    } catch (err) {
      console.error('导出报告失败:', err)
    } finally {
      setExporting(false)
    }
  }

  const handlePreview = async () => {
    if (!selectedScanId) return
    try {
      const data = await getReportData()
      if (!data) return
      const html = generateHTML(data)
      setPreviewContent(html)
      setPreviewFormat('html')
    } catch (err) {
      console.error('预览失败:', err)
    }
  }

  const selectedScan = scans.find((s) => s.id === selectedScanId)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold neon-text">报告中心</h1>
        <button
          onClick={fetchScans}
          className="px-4 py-2 bg-[#00f0ff]/10 text-[#00f0ff] border border-[#00f0ff]/30 rounded hover:bg-[#00f0ff]/20 transition-colors flex items-center gap-2 text-sm"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          刷新
        </button>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Left: Report Configuration */}
        <div className="space-y-4">
          {/* Scan Selector */}
          <div className="cyber-card p-5">
            <h2 className="text-sm uppercase tracking-wider text-[#94a3b8] mb-4">选择扫描任务</h2>
            {loading ? (
              <div className="text-[#94a3b8] text-sm py-4 text-center">加载中...</div>
            ) : scans.length === 0 ? (
              <div className="text-[#94a3b8] text-sm py-4 text-center">暂无已完成的扫描任务</div>
            ) : (
              <>
                <select
                  value={selectedScanId}
                  onChange={(e) => setSelectedScanId(e.target.value)}
                  className="w-full bg-[#0a0a0f] border border-[#1e293b] rounded px-4 py-2.5 text-sm text-[#e2e8f0] focus:border-[#00f0ff] outline-none cursor-pointer"
                >
                  <option value="">-- 选择扫描任务 --</option>
                  {scans.map((scan) => (
                    <option key={scan.id} value={scan.id}>
                      {scan.target || scan.args || scan.id} | {scan.tool} | {formatTime(scan.startedAt || scan.createdAt)}
                    </option>
                  ))}
                </select>
                {selectedScan && (
                  <div className="mt-3 p-3 bg-[#0a0a0f] rounded border border-[#1e293b] text-xs text-[#94a3b8] space-y-1">
                    <div>目标: <span className="text-[#00f0ff] font-mono">{selectedScan.target || selectedScan.args || '--'}</span></div>
                    <div>工具: <span className="text-[#e2e8f0]">{selectedScan.tool}</span></div>
                    <div>时间: <span className="text-[#e2e8f0]">{formatTime(selectedScan.startedAt || selectedScan.createdAt)}</span></div>
                  </div>
                )}
              </>
            )}
          </div>

          {/* Report Type */}
          <div className="cyber-card p-5">
            <h2 className="text-sm uppercase tracking-wider text-[#94a3b8] mb-4">报告类型</h2>
            <div className="space-y-2">
              {reportTypes.map((rt) => (
                <label
                  key={rt.key}
                  className={`flex items-start gap-3 p-3 rounded border cursor-pointer transition-colors ${
                    reportType === rt.key
                      ? 'bg-[#00f0ff]/5 border-[#00f0ff]/40'
                      : 'bg-[#0a0a0f] border-[#1e293b] hover:border-[#4a5568]'
                  }`}
                >
                  <input
                    type="radio"
                    name="reportType"
                    value={rt.key}
                    checked={reportType === rt.key}
                    onChange={() => setReportType(rt.key)}
                    className="mt-1 accent-[#00f0ff]"
                  />
                  <div>
                    <div className={`text-sm ${reportType === rt.key ? 'text-[#00f0ff]' : 'text-[#e2e8f0]'}`}>
                      {rt.label}
                    </div>
                    <div className="text-xs text-[#94a3b8] mt-0.5">{rt.desc}</div>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Severity Filter */}
          <div className="cyber-card p-5">
            <h2 className="text-sm uppercase tracking-wider text-[#94a3b8] mb-4">严重性筛选</h2>
            <div className="flex flex-wrap gap-3">
              {severityOptions.map((opt) => (
                <label
                  key={opt.key}
                  className="flex items-center gap-2 cursor-pointer select-none"
                >
                  <input
                    type="checkbox"
                    checked={severityFilters[opt.key]}
                    onChange={() => toggleSeverity(opt.key)}
                    className="accent-[#00f0ff]"
                  />
                  <span
                    className="text-xs px-2 py-0.5 rounded border"
                    style={{
                      color: opt.color,
                      borderColor: opt.color + '66',
                      background: opt.color + '15',
                    }}
                  >
                    {opt.label}
                  </span>
                </label>
              ))}
            </div>
          </div>

          {/* Export Buttons */}
          <div className="cyber-card p-5">
            <h2 className="text-sm uppercase tracking-wider text-[#94a3b8] mb-4">导出格式</h2>
            <div className="flex items-center gap-3">
              <button
                onClick={() => handleExport('html')}
                disabled={!selectedScanId || exporting}
                className="flex items-center gap-2 px-5 py-2.5 rounded text-sm border border-[#00f0ff]/40 bg-[#00f0ff]/10 text-[#00f0ff] hover:bg-[#00f0ff]/20 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <Download size={14} />
                HTML
              </button>
              <button
                onClick={() => handleExport('csv')}
                disabled={!selectedScanId || exporting}
                className="flex items-center gap-2 px-5 py-2.5 rounded text-sm border border-[#00ff88]/40 bg-[#00ff88]/10 text-[#00ff88] hover:bg-[#00ff88]/20 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <Download size={14} />
                CSV
              </button>
              <button
                onClick={() => handleExport('json')}
                disabled={!selectedScanId || exporting}
                className="flex items-center gap-2 px-5 py-2.5 rounded text-sm border border-[#bf00ff]/40 bg-[#bf00ff]/10 text-[#bf00ff] hover:bg-[#bf00ff]/20 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <Download size={14} />
                JSON
              </button>
              <button
                onClick={handlePreview}
                disabled={!selectedScanId}
                className="flex items-center gap-2 px-5 py-2.5 rounded text-sm border border-[#ffd000]/40 bg-[#ffd000]/10 text-[#ffd000] hover:bg-[#ffd000]/20 transition-colors disabled:opacity-40 disabled:cursor-not-allowed ml-auto"
              >
                <Eye size={14} />
                预览
              </button>
            </div>
            {exporting && (
              <div className="mt-3 text-xs text-[#94a3b8]">正在生成报告...</div>
            )}
          </div>
        </div>

        {/* Right: Preview Panel */}
        <div className="cyber-card flex flex-col min-h-0">
          <div className="px-4 py-2.5 border-b border-[#1e293b] flex items-center gap-2">
            <FileText size={14} className="text-[#bf00ff]" />
            <span className="text-xs uppercase tracking-wider text-[#94a3b8]">报告预览</span>
            {previewContent && (
              <span className="ml-auto text-xs text-[#4a5568]">
                {previewFormat === 'html' ? 'HTML 格式' : '纯文本格式'}
              </span>
            )}
          </div>
          <div className="flex-1 overflow-auto p-4 min-h-[400px] max-h-[calc(100vh-300px)]">
            {previewContent ? (
              previewFormat === 'html' ? (
                <div
                  className="prose-invert"
                  dangerouslySetInnerHTML={{
                    __html: previewContent.replace(/<html[^>]*>/, '').replace(/<\/html>/, '').replace(/<head>[\s\S]*?<\/head>/, '').replace(/<body[^>]*>/, '').replace(/<\/body>/, ''),
                  }}
                />
              ) : (
                <pre className="text-xs text-[#94a3b8] whitespace-pre-wrap break-all font-mono leading-relaxed">
                  {previewContent}
                </pre>
              )
            ) : (
              <div className="flex flex-col items-center justify-center h-full text-[#4a5568]">
                <FileText size={36} className="mb-3" />
                <p className="text-sm">选择扫描任务并点击预览或导出</p>
                <p className="text-xs mt-1">报告将在此处显示</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Previous Completed Scans */}
      <div className="cyber-card p-5">
        <h2 className="text-sm uppercase tracking-wider text-[#94a3b8] mb-4">已完成扫描记录</h2>
        {scans.length === 0 ? (
          <div className="text-center py-8 text-[#94a3b8] text-sm">
            暂无已完成的扫描任务，请先执行扫描。
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e293b]">
                  <th className="text-left py-3 px-4 text-[#94a3b8] font-normal text-xs uppercase tracking-wider">目标</th>
                  <th className="text-left py-3 px-4 text-[#94a3b8] font-normal text-xs uppercase tracking-wider">工具</th>
                  <th className="text-left py-3 px-4 text-[#94a3b8] font-normal text-xs uppercase tracking-wider">完成时间</th>
                  <th className="text-left py-3 px-4 text-[#94a3b8] font-normal text-xs uppercase tracking-wider">操作</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr
                    key={scan.id}
                    className={`border-b border-[#1e293b]/50 hover:bg-[#1e293b]/20 transition-colors ${
                      selectedScanId === scan.id ? 'bg-[#00f0ff]/5' : ''
                    }`}
                  >
                    <td className="py-3 px-4 text-[#e2e8f0] font-mono text-xs">
                      {scan.target || scan.args || scan.id}
                    </td>
                    <td className="py-3 px-4 text-[#94a3b8]">{scan.tool}</td>
                    <td className="py-3 px-4 text-[#94a3b8] text-xs">
                      {formatTime(scan.startedAt || scan.createdAt)}
                    </td>
                    <td className="py-3 px-4">
                      <button
                        className="flex items-center gap-1 px-3 py-1 bg-[#00f0ff]/10 text-[#00f0ff] border border-[#00f0ff]/30 rounded text-xs hover:bg-[#00f0ff]/20 transition-colors"
                        onClick={() => {
                          setSelectedScanId(scan.id)
                        }}
                      >
                        <ChevronDown size={12} />
                        选择
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

export default Reports
