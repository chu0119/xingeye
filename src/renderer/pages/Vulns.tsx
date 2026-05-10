import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, RefreshCw, ChevronDown, ChevronUp, AlertTriangle, Info, Download } from 'lucide-react'
import { translateVulnName, translateSeverity } from '../utils/translateVuln'

interface Vuln {
  id: number
  name: string
  severity: string
  host: string
  matchedAt: string
  description: string
  rawData: string
  status: string
  discoveredAt: string
  scanId: string
  templateId: string
  type: string
  [key: string]: any
}

const severityConfig: Record<string, { label: string; color: string; bg: string; border: string; badgeBg: string }> = {
  critical: {
    label: '严重',
    color: 'text-[#ff0044]',
    bg: 'bg-[#ff0044]/5',
    border: 'border-[#ff0044]/30',
    badgeBg: 'bg-[#ff0044]/15 text-[#ff0044] border-[#ff0044]/40',
  },
  high: {
    label: '高危',
    color: 'text-[#ff0066]',
    bg: 'bg-[#ff0066]/5',
    border: 'border-[#ff0066]/30',
    badgeBg: 'bg-[#ff0066]/15 text-[#ff0066] border-[#ff0066]/40',
  },
  medium: {
    label: '中危',
    color: 'text-[#ffd000]',
    bg: 'bg-[#ffd000]/5',
    border: 'border-[#ffd000]/30',
    badgeBg: 'bg-[#ffd000]/15 text-[#ffd000] border-[#ffd000]/40',
  },
  low: {
    label: '低危',
    color: 'text-[#00f0ff]',
    bg: 'bg-[#00f0ff]/5',
    border: 'border-[#00f0ff]/30',
    badgeBg: 'bg-[#00f0ff]/15 text-[#00f0ff] border-[#00f0ff]/40',
  },
  info: {
    label: '信息',
    color: 'text-[#94a3b8]',
    bg: 'bg-[#94a3b8]/5',
    border: 'border-[#94a3b8]/30',
    badgeBg: 'bg-[#94a3b8]/15 text-[#94a3b8] border-[#94a3b8]/40',
  },
}

const statusOptions = [
  { value: 'pending', label: '待处理' },
  { value: 'fixed', label: '已修复' },
  { value: 'false_positive', label: '误报' },
  { value: 'accepted', label: '已接受' },
]

const statusLabels: Record<string, string> = {
  pending: '待处理',
  fixed: '已修复',
  false_positive: '误报',
  accepted: '已接受',
}

const statusColorMap: Record<string, string> = {
  pending: 'text-[#ffd000]',
  fixed: 'text-[#00ff88]',
  false_positive: 'text-[#94a3b8]',
  accepted: 'text-[#00f0ff]',
}

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info'

const filterButtons: { key: SeverityFilter; label: string; color: string }[] = [
  { key: 'all', label: '全部', color: 'text-[#e2e8f0]' },
  { key: 'critical', label: '严重', color: 'text-[#ff0044]' },
  { key: 'high', label: '高危', color: 'text-[#ff0066]' },
  { key: 'medium', label: '中危', color: 'text-[#ffd000]' },
  { key: 'low', label: '低危', color: 'text-[#00f0ff]' },
  { key: 'info', label: '信息', color: 'text-[#94a3b8]' },
]

const Vulns: React.FC = () => {
  const navigate = useNavigate()
  const [vulns, setVulns] = useState<Vuln[]>([])
  const [scans, setScans] = useState<any[]>([])
  const [selectedScanId, setSelectedScanId] = useState<string>('')
  const [loading, setLoading] = useState(true)
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all')
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [updatingId, setUpdatingId] = useState<number | null>(null)

  const fetchVulns = async () => {
    setLoading(true)
    try {
      const [vulnsData, scansData] = await Promise.all([
        window.electronAPI.getAllVulns(),
        window.electronAPI.getScans()
      ])
      setVulns(vulnsData || [])
      setScans(scansData || [])
    } catch (err) {
      console.error('获取漏洞数据失败:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchVulns()
  }, [])

  const filteredVulns = vulns.filter((v) => {
    if (selectedScanId && v.scanId !== selectedScanId) return false
    if (severityFilter === 'all') return true
    const sev = (v.severity || 'info').toLowerCase()
    return sev === severityFilter
  })

  const handleExportCSV = () => {
    const esc = (s: string) => '"' + s.replace(/"/g, '""').replace(/\r?\n/g, ' ') + '"'
    const header = '严重级别,漏洞名称,目标,匹配URL,模板ID,状态,发现时间\n'
    const rows = filteredVulns.map(v =>
      [translateSeverity(v.severity), translateVulnName(v.name), v.host || '', v.matchedAt || '', v.templateId || '', v.status || '', formatTime(v.discoveredAt || v.createdAt || '')]
        .map(esc).join(',')
    ).join('\n')
    const blob = new Blob(['﻿' + header + rows], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = 'vulnerabilities_export.csv'; a.click()
    URL.revokeObjectURL(url)
  }

  const handleExportJSON = () => {
    const data = filteredVulns.map(v => ({
      severity: translateSeverity(v.severity),
      name: translateVulnName(v.name),
      host: v.host,
      matchedAt: v.matchedAt,
      description: v.description,
      templateId: v.templateId,
      status: v.status,
      discoveredAt: v.discoveredAt || v.createdAt
    }))
    const blob = new Blob(['﻿' + JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = 'vulnerabilities_export.json'; a.click()
    URL.revokeObjectURL(url)
  }

  const handleStatusChange = async (vulnId: number, newStatus: string) => {
    setUpdatingId(vulnId)
    try {
      await window.electronAPI.updateVulnStatus(vulnId, newStatus)
      setVulns((prev) =>
        prev.map((v) => (v.id === vulnId ? { ...v, status: newStatus } : v))
      )
    } catch (err) {
      console.error('更新漏洞状态失败:', err)
    } finally {
      setUpdatingId(null)
    }
  }

  const formatTime = (timeStr: string) => {
    if (!timeStr) return '--'
    try {
      const d = new Date(timeStr)
      return d.toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
      })
    } catch {
      return timeStr
    }
  }

  const getSeverityConfig = (severity: string) => {
    const sev = (severity || 'info').toLowerCase()
    return severityConfig[sev] || severityConfig.info
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold neon-text">漏洞管理</h1>
          <span className="px-3 py-1 bg-[#00f0ff]/10 text-[#00f0ff] border border-[#00f0ff]/30 rounded-full text-xs">
            共 {filteredVulns.length} 个漏洞
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={handleExportCSV} className="flex items-center gap-1.5 text-xs px-3 py-1.5 border border-[#1e293b] text-[#94a3b8] rounded hover:border-[#00ff88] hover:text-[#00ff88] transition-colors">
            <Download size={12} /> CSV
          </button>
          <button onClick={handleExportJSON} className="flex items-center gap-1.5 text-xs px-3 py-1.5 border border-[#1e293b] text-[#94a3b8] rounded hover:border-[#00ff88] hover:text-[#00ff88] transition-colors">
            <Download size={12} /> JSON
          </button>
          <button
            onClick={fetchVulns}
            className="px-4 py-2 bg-[#00f0ff]/10 text-[#00f0ff] border border-[#00f0ff]/30 rounded hover:bg-[#00f0ff]/20 transition-colors flex items-center gap-2 text-sm"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            刷新
          </button>
        </div>
      </div>

      {/* Scan Filter */}
      <div className="flex items-center gap-3 mb-2">
        <span className="text-xs text-[#94a3b8]">扫描:</span>
        <select
          value={selectedScanId}
          onChange={(e) => setSelectedScanId(e.target.value)}
          className="bg-[#0a0a0f] border border-[#1e293b] rounded px-3 py-1.5 text-sm text-[#e2e8f0] focus:border-[#00f0ff] outline-none"
        >
          <option value="">全部扫描</option>
          {scans.slice(0, 50).map((s: any) => (
            <option key={s.id} value={s.id}>
              {s.name || s.target || s.id?.slice(0, 8)} ({s.status === 'completed' ? '已完成' : s.status})
            </option>
          ))}
        </select>
      </div>

      {/* Severity Filter Buttons */}
      <div className="flex items-center gap-2">
        {filterButtons.map((btn) => (
          <button
            key={btn.key}
            onClick={() => setSeverityFilter(btn.key)}
            className={`px-4 py-1.5 rounded text-xs border transition-colors ${
              severityFilter === btn.key
                ? `bg-[#111827] ${btn.color} border-current`
                : 'bg-transparent text-[#94a3b8] border-[#1e293b] hover:border-[#4a5568]'
            }`}
          >
            {btn.label}
          </button>
        ))}
      </div>

      {/* Vulnerability Cards */}
      {loading ? (
        <div className="text-center py-12 text-[#94a3b8] text-sm">加载中...</div>
      ) : filteredVulns.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-[#94a3b8]">
          <Shield size={36} className="mb-3 text-[#4a5568]" />
          <p className="text-sm">暂无漏洞数据</p>
          <p className="text-xs text-[#4a5568] mt-1">扫描完成后，发现的漏洞将在此处展示。</p>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredVulns.map((vuln) => {
            const sev = getSeverityConfig(vuln.severity)
            const isExpanded = expandedId === vuln.id
            const currentStatus = vuln.status || 'pending'

            return (
              <div
                key={vuln.id}
                className={`bg-[#111827] border ${sev.border} rounded overflow-hidden transition-all`}
              >
                {/* Card Header */}
                <div
                  className="p-4 cursor-pointer hover:bg-[#1e293b]/30 transition-colors"
                  onClick={() => setExpandedId(isExpanded ? null : vuln.id)}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-start gap-3 flex-1 min-w-0">
                      <div className={`mt-0.5 ${sev.color}`}>
                        {vuln.severity === 'critical' || vuln.severity === 'high' ? (
                          <AlertTriangle size={16} />
                        ) : (
                          <Info size={16} />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`inline-block px-2 py-0.5 text-xs rounded border ${sev.badgeBg}`}>
                            {sev.label}
                          </span>
                          <h3 className="text-sm font-medium text-[#e2e8f0] truncate">
                            {translateVulnName(vuln.name || vuln.templateId)}
                          </h3>
                        </div>
                        <div className="flex items-center gap-4 text-xs text-[#94a3b8]">
                          <span className="font-mono">{vuln.host || vuln.matchedAt || '--'}</span>
                          <span>{formatTime(vuln.discoveredAt || vuln.createdAt || '')}</span>
                          <span className={`${statusColorMap[currentStatus] || 'text-[#94a3b8]'}`}>
                            {statusLabels[currentStatus] || currentStatus}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="text-[#94a3b8] flex-shrink-0">
                      {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                    </div>
                  </div>
                </div>

                {/* Expanded Detail */}
                {isExpanded && (
                  <div className="px-4 pb-4 border-t border-[#1e293b]/50">
                    <div className="mt-3 space-y-3">
                      {/* Description */}
                      {vuln.description && (
                        <div>
                          <span className="text-[#94a3b8] text-xs block mb-1">漏洞描述</span>
                          <p className="text-sm text-[#e2e8f0] leading-relaxed">
                            {vuln.description}
                          </p>
                        </div>
                      )}

                      {/* Solution / Remediation */}
                      <div>
                        <span className="text-[#94a3b8] text-xs block mb-1">修复建议</span>
                        <div className="text-sm text-[#e2e8f0] leading-relaxed">
                          {vuln.solution ? (
                            <div>
                              <p>{vuln.solution}</p>
                              {vuln.solution.includes('http') && (
                                <div className="mt-2 flex flex-wrap gap-1">
                                  {vuln.solution.match(/https?:\/\/\S+/g)?.map((url: string, i: number) => (
                                    <span key={i}
                                      className="text-xs text-[#00f0ff] cursor-pointer hover:underline"
                                      onClick={() => window.electronAPI.openExternal(url)}
                                    >
                                      {url.length > 60 ? url.slice(0, 60) + '...' : url}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          ) : (
                            <div>
                              <p>参考以下通用修复建议：</p>
                              <ul className="list-disc list-inside mt-1 space-y-1 text-xs text-[#94a3b8]">
                                <li>确保软件/服务已更新至最新版本</li>
                                <li>检查并修复相关配置项</li>
                                <li>限制不必要的网络访问权限</li>
                                <li>定期进行安全审计和漏洞扫描</li>
                              </ul>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Matched URL */}
                      {vuln.matchedAt && (
                        <div>
                          <span className="text-[#94a3b8] text-xs block mb-1">匹配 URL</span>
                          <span
                            className="text-xs text-[#00f0ff] font-mono break-all cursor-pointer hover:underline"
                            onClick={() => window.electronAPI.openExternal(vuln.matchedAt)}
                          >
                            {vuln.matchedAt}
                          </span>
                        </div>
                      )}

                      {/* Template ID */}
                      {vuln.templateId && (
                        <div>
                          <span className="text-[#94a3b8] text-xs block mb-1">模板 ID</span>
                          <span className="text-xs text-[#e2e8f0] font-mono">{vuln.templateId}</span>
                        </div>
                      )}

                      {/* Type */}
                      {vuln.type && (
                        <div>
                          <span className="text-[#94a3b8] text-xs block mb-1">类型</span>
                          <span className="text-xs text-[#e2e8f0]">{vuln.type}</span>
                        </div>
                      )}

                      {/* Raw Data */}
                      {vuln.rawData && (
                        <div>
                          <span className="text-[#94a3b8] text-xs block mb-1">原始数据</span>
                          <pre className="bg-[#0a0a0f] border border-[#1e293b] rounded p-3 text-xs text-[#94a3b8] overflow-x-auto max-h-48 overflow-y-auto font-mono">
                            {typeof vuln.rawData === 'string'
                              ? vuln.rawData
                              : JSON.stringify(vuln.rawData, null, 2)}
                          </pre>
                        </div>
                      )}

                      {/* Status Dropdown */}
                      <div className="flex items-center gap-3 pt-2 border-t border-[#1e293b]/30">
                        <span className="text-[#94a3b8] text-xs">状态:</span>
                        <select
                          value={currentStatus}
                          onChange={(e) => handleStatusChange(vuln.id, e.target.value)}
                          disabled={updatingId === vuln.id}
                          className="bg-[#0a0a0f] border border-[#1e293b] rounded px-3 py-1.5 text-xs text-[#e2e8f0] focus:border-[#00f0ff] outline-none cursor-pointer disabled:opacity-50"
                        >
                          {statusOptions.map((opt) => (
                            <option key={opt.value} value={opt.value}>
                              {opt.label}
                            </option>
                          ))}
                        </select>
                        {updatingId === vuln.id && (
                          <span className="text-[#94a3b8] text-xs">更新中...</span>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

export default Vulns
