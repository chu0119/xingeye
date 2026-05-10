import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Activity, Server, Shield, AlertTriangle, RefreshCw, Eye, Trash2 } from 'lucide-react'
import { useScanStore } from '../stores/scanStore'

interface ScanStats {
  totalScans: number
  totalHosts: number
  totalVulns: number
  criticalVulns: number
}

interface Scan {
  id: string
  target: string
  tool: string
  status: string
  startedAt: string
  [key: string]: any
}

const statusConfig: Record<string, { label: string; color: string; bg: string }> = {
  running: { label: '运行中', color: 'text-[#00f0ff]', bg: 'bg-[#00f0ff]/10 border-[#00f0ff]/30' },
  completed: { label: '已完成', color: 'text-[#00ff88]', bg: 'bg-[#00ff88]/10 border-[#00ff88]/30' },
  failed: { label: '失败', color: 'text-[#ff0066]', bg: 'bg-[#ff0066]/10 border-[#ff0066]/30' },
  cancelled: { label: '已取消', color: 'text-[#94a3b8]', bg: 'bg-[#94a3b8]/10 border-[#94a3b8]/30' },
}

const Dashboard: React.FC = () => {
  const navigate = useNavigate()
  const [stats, setStats] = useState<ScanStats | null>(null)
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [lastUpdated, setLastUpdated] = useState<string>('')

  const fetchData = async () => {
    setLoading(true)
    try {
      const [statsData, scansData] = await Promise.all([
        window.electronAPI.getScanStats(),
        window.electronAPI.getScans(),
      ])
      setStats(statsData)
      setScans(scansData || [])
      setLastUpdated(new Date().toLocaleTimeString('zh-CN'))
    } catch (err) {
      console.error('获取数据失败:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  const statCards = [
    {
      label: '扫描任务',
      value: stats?.totalScans ?? 0,
      icon: Activity,
      color: '#00f0ff',
      glowClass: 'neon-glow',
    },
    {
      label: '发现主机',
      value: stats?.totalHosts ?? 0,
      icon: Server,
      color: '#bf00ff',
      glowClass: 'neon-glow-purple',
    },
    {
      label: '发现漏洞',
      value: stats?.totalVulns ?? 0,
      icon: Shield,
      color: '#ffd000',
      glowClass: '',
    },
    {
      label: '高危漏洞',
      value: stats?.criticalVulns ?? 0,
      icon: AlertTriangle,
      color: '#ff0066',
      glowClass: 'neon-glow-pink',
    },
  ]

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
        second: '2-digit',
      })
    } catch {
      return timeStr
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold neon-text glitch-text">控制台</h1>
        <div className="flex items-center gap-3">
          <span className="text-xs text-[#94a3b8]">
            最后更新: {lastUpdated || '--'}
          </span>
          <button
            onClick={fetchData}
            className="p-2 text-[#00f0ff] hover:bg-[#00f0ff]/10 rounded transition-colors"
            title="刷新数据"
          >
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-4 gap-4">
        {statCards.map((card) => {
          const Icon = card.icon
          return (
            <div
              key={card.label}
              className={`cyber-card p-5 ${card.glowClass} cursor-pointer hover:border-[#00f0ff]/40 transition-colors`}
              onClick={() => {
                if (card.label === '发现主机') navigate('/assets')
                if (card.label === '发现漏洞' || card.label === '高危漏洞') navigate('/vulns')
              }}
            >
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs uppercase tracking-wider text-[#94a3b8]">
                  {card.label}
                </span>
                <Icon size={18} style={{ color: card.color }} />
              </div>
              <div
                className="text-3xl font-bold"
                style={{ color: card.color }}
              >
                {stats ? card.value : '--'}
              </div>
              <div className="mt-2 text-xs text-[#94a3b8]">
                {stats ? `共 ${card.value} 条记录` : '加载中...'}
              </div>
            </div>
          )
        })}
      </div>

      {/* Recent Scans Table */}
      <div className="cyber-card p-5">
        <h2 className="text-sm uppercase tracking-wider text-[#94a3b8] mb-4">
          最近扫描
        </h2>
        {scans.length === 0 ? (
          <div className="text-center py-8 text-[#94a3b8] text-sm">
            暂无扫描数据，请先新建扫描任务。
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e293b]">
                  <th className="text-left py-3 px-4 text-[#94a3b8] font-normal text-xs uppercase tracking-wider">任务名称</th>
                  <th className="text-left py-3 px-4 text-[#94a3b8] font-normal text-xs uppercase tracking-wider">目标</th>
                  <th className="text-left py-3 px-4 text-[#94a3b8] font-normal text-xs uppercase tracking-wider">工具</th>
                  <th className="text-left py-3 px-4 text-[#94a3b8] font-normal text-xs uppercase tracking-wider">状态</th>
                  <th className="text-left py-3 px-4 text-[#94a3b8] font-normal text-xs uppercase tracking-wider">开始时间</th>
                  <th className="text-left py-3 px-4 text-[#94a3b8] font-normal text-xs uppercase tracking-wider">操作</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => {
                  const s = scan.status || 'unknown'
                  const cfg = statusConfig[s] || statusConfig.failed
                  return (
                    <tr
                      key={scan.id}
                      className="border-b border-[#1e293b]/50 hover:bg-[#1e293b]/20 transition-colors"
                    >
                      <td className="py-3 px-4 text-[#00f0ff] text-xs">
                        {scan.name || '--'}
                      </td>
                      <td className="py-3 px-4 text-[#e2e8f0] font-mono text-xs">
                        {scan.target || scan.args || '--'}
                      </td>
                      <td className="py-3 px-4 text-[#94a3b8]">
                        {scan.tool === 'pipeline' ? '扫描' : (scan.tool || '--')}
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`inline-block px-2 py-0.5 text-xs rounded border ${cfg.bg} ${cfg.color}`}
                        >
                          {cfg.label}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-[#94a3b8] text-xs">
                        {formatTime(scan.startedAt || scan.createdAt || '')}
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <button
                            className="flex items-center gap-1 px-3 py-1 bg-[#00f0ff]/10 text-[#00f0ff] border border-[#00f0ff]/30 rounded text-xs hover:bg-[#00f0ff]/20 transition-colors"
                            onClick={() => navigate(`/scan/${scan.id}`)}
                          >
                            <Eye size={12} />
                            查看
                          </button>
                          <button
                            className="flex items-center gap-1 px-3 py-1 bg-[#ff0044]/10 text-[#ff0044] border border-[#ff0044]/30 rounded text-xs hover:bg-[#ff0044]/20 transition-colors"
                            onClick={async () => {
                              if (confirm('确认删除此扫描记录？')) {
                                await window.electronAPI.deleteScan(scan.id)
                                if (useScanStore.getState().activeScanId === scan.id) {
                                  useScanStore.getState().clearActiveScan()
                                }
                                fetchData()
                              }
                            }}
                          >
                            <Trash2 size={12} />
                            删除
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Quick Actions */}
      <div className="flex gap-3">
        <button
          onClick={() => navigate('/scan/new')}
          className="flex-1 py-3 bg-[#00f0ff]/10 text-[#00f0ff] border border-[#00f0ff]/30 rounded text-sm hover:bg-[#00f0ff]/20 transition-colors"
        >
          新建扫描
        </button>
        <button
          onClick={() => navigate('/reports')}
          className="flex-1 py-3 bg-[#bf00ff]/10 text-[#bf00ff] border border-[#bf00ff]/30 rounded text-sm hover:bg-[#bf00ff]/20 transition-colors"
        >
          生成报告
        </button>
      </div>
    </div>
  )
}

export default Dashboard
