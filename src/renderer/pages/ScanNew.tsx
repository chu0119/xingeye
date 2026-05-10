import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Crosshair, Zap, Shield, Globe, Sliders } from 'lucide-react'
import { useScanStore } from '../stores/scanStore'

interface TemplateConfig {
  id: string
  label: string
  icon: React.FC<{ size?: number; className?: string }>
  description: string
  time: string
  features: string[]
  preset: string
  portRange: string
  bruteForce: boolean
  exploitDetection: boolean
  threads: number
}

const scanTemplates: TemplateConfig[] = [
  {
    id: 'quick',
    label: '快速扫描',
    icon: Zap,
    description: '快速探测存活主机和常见服务',
    time: '~30s',
    features: ['Top 400 端口', '高速线程', '轻量指纹'],
    preset: 'top100',
    portRange: '',
    bruteForce: false,
    exploitDetection: false,
    threads: 100,
  },
  {
    id: 'full',
    label: '全面扫描',
    icon: Shield,
    description: '全端口扫描 + 暴力破解 + 漏洞探测',
    time: '~5-10min',
    features: ['全端口 65535', '暴力破解', '漏洞探测'],
    preset: 'all',
    portRange: '1-65535',
    bruteForce: true,
    exploitDetection: true,
    threads: 50,
  },
  {
    id: 'web',
    label: 'Web深度扫描',
    icon: Globe,
    description: 'Web 服务发现 + Nuclei 漏洞扫描',
    time: '~3-15min',
    features: ['Web 常见端口', '指纹识别', 'Nuclei 联动'],
    preset: 'web',
    portRange: '22,80,443,445,1433,3306,3389,5432,6379,8080,8443,8888,9090,9200,27017',
    bruteForce: false,
    exploitDetection: true,
    threads: 50,
  },
  {
    id: 'custom',
    label: '自定义扫描',
    icon: Sliders,
    description: '完全自定义所有扫描参数',
    time: '视情况而定',
    features: ['自由配置', '高级选项', '手动调优'],
    preset: 'highRisk',
    portRange: '22,80,443,445,1433,1521,3306,3389,5432,6379,8080,8443,8888,9090,9200,11211,27017',
    bruteForce: false,
    exploitDetection: false,
    threads: 50,
  },
]

const PORT_PRESETS: Record<string, { label: string; value: string; desc: string }> = {
  'highRisk': { label: '常见高危端口', value: '22,80,443,445,1433,1521,3306,3389,5432,6379,8080,8443,8888,9090,9200,11211,27017', desc: 'SSH,HTTP,HTTPS,SMB,MSSQL,Oracle,MySQL,RDP,PostgreSQL,Redis...' },
  'all': { label: '全端口', value: '1-65535', desc: '扫描所有 65535 个端口' },
  'top100': { label: 'Top 100', value: '', desc: '使用引擎内置 Top100 端口列表' },
  'web': { label: 'Web 端口', value: '22,80,443,8080,8443,8888,9090,3000,5000,8000,9000', desc: '常见 Web 服务端口' },
  'custom': { label: '自定义端口', value: '', desc: '输入自定义端口范围' },
}

const ScanNew: React.FC = () => {
  const navigate = useNavigate()
  const [taskName, setTaskName] = useState('')
  const [target, setTarget] = useState('')
  const [template, setTemplate] = useState('quick')
  const [selectedPreset, setSelectedPreset] = useState('top100')
  const [portRange, setPortRange] = useState('')
  const [bruteForce, setBruteForce] = useState(false)
  const [exploitDetection, setExploitDetection] = useState(false)
  const [threads, setThreads] = useState(100)
  const [isStarting, setIsStarting] = useState(false)
  const [startError, setStartError] = useState('')

  const applyTemplate = (id: string) => {
    setTemplate(id)
    const t = scanTemplates.find(t => t.id === id)
    if (!t) return
    setSelectedPreset(t.preset)
    setPortRange(t.portRange)
    setBruteForce(t.bruteForce)
    setExploitDetection(t.exploitDetection)
    setThreads(t.threads)
  }

  const handleStartScan = async () => {
    if (!target.trim()) return
    setIsStarting(true)
    try {
      const scanId = crypto.randomUUID()
      const args: string[] = ['-t', target]
      if (portRange.trim() !== '') {
        args.push('-p', portRange)
      }
      const name = taskName || `扫描 ${target.split(',').map(t => t.trim()).filter(Boolean).join(', ')}`
      await window.electronAPI.startScan(scanId, 'pipeline', args, { name })
      useScanStore.getState().getOrCreateSession(scanId, target)
      useScanStore.getState().setActiveScan(scanId, target)
      navigate(`/scan/${scanId}`)
    } catch {
      setIsStarting(false)
      setStartError('扫描启动失败，请检查目标格式和网络连接。')
      setTimeout(() => setStartError(''), 5000)
    }
  }

  const selectedTemplate = scanTemplates.find((t) => t.id === template)!

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <h1 className="text-2xl font-bold neon-text glitch-text">新建扫描</h1>

      {/* Task Name */}
      <div className="mb-4">
        <label className="block text-sm text-[#94a3b8] mb-2">任务名称</label>
        <input
          type="text"
          value={taskName}
          onChange={(e) => setTaskName(e.target.value)}
          placeholder="可选，例如：研发网段例行扫描"
          className="w-full bg-[#0a0a0f] border border-[#1e293b] rounded px-4 py-2.5 text-[#e2e8f0] focus:border-[#00f0ff] outline-none"
        />
      </div>

      {/* Target Input */}
      <div className="cyber-card p-6">
        <label className="block text-xs uppercase tracking-wider text-[#94a3b8] mb-2">
          扫描目标
        </label>
        <div className="relative">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="输入目标，多个用逗号分隔，如：192.168.1.0/24,10.0.0.1"
            className="w-full bg-[#050510] border border-[#1e293b] rounded px-4 py-3 text-lg text-[#e2e8f0] placeholder-[#4a5568] focus:outline-none focus:border-[#00f0ff] focus:shadow-[0_0_10px_rgba(0,240,255,0.2)] transition-all font-mono"
          />
          {target && (
            <span className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-[#00ff88]">
              {target.split(',').filter(t => t.trim()).length} 个目标
            </span>
          )}
        </div>
      </div>

      {/* Scan Templates */}
      <div className="cyber-card p-6">
        <label className="block text-xs uppercase tracking-wider text-[#94a3b8] mb-3">
          扫描模板
        </label>
        <div className="grid grid-cols-4 gap-3">
          {scanTemplates.map((t) => {
            const Icon = t.icon
            const isSelected = template === t.id
            return (
              <button
                key={t.id}
                onClick={() => applyTemplate(t.id)}
                className={`p-4 rounded border text-left transition-all duration-200 ${
                  isSelected
                    ? 'border-[#00f0ff] bg-[#00f0ff]/10 neon-glow'
                    : 'border-[#1e293b] bg-[#050510] hover:border-[#1e293b]/80'
                }`}
              >
                <Icon
                  size={20}
                  className={isSelected ? 'text-[#00f0ff]' : 'text-[#94a3b8]'}
                />
                <div
                  className={`mt-2 text-sm font-bold ${
                    isSelected ? 'text-[#00f0ff]' : 'text-[#e2e8f0]'
                  }`}
                >
                  {t.label}
                </div>
                <div className="mt-1 text-xs text-[#94a3b8]">
                  {t.description}
                </div>
                <div className="mt-2 text-xs text-[#4a5568]">{t.time}</div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {t.features.map(f => (
                    <span
                      key={f}
                      className={`text-[10px] px-1.5 py-0.5 rounded ${
                        isSelected
                          ? 'bg-[#00f0ff]/10 text-[#00f0ff] border border-[#00f0ff]/20'
                          : 'bg-[#1e293b]/50 text-[#4a5568]'
                      }`}
                    >
                      {f}
                    </span>
                  ))}
                </div>
              </button>
            )
          })}
        </div>
      </div>

      {/* Port Range & Options */}
      <div className="grid grid-cols-2 gap-4">
        {/* Port Range */}
        <div className="cyber-card p-6">
          <label className="block text-xs uppercase tracking-wider text-[#94a3b8] mb-2">
            端口范围
          </label>
          {selectedPreset === 'custom' ? (
            <input
              type="text"
              value={portRange}
              onChange={(e) => setPortRange(e.target.value)}
              placeholder="例如 1-1000 或 80,443,8080"
              className="w-full bg-[#050510] border border-[#1e293b] rounded px-3 py-2 text-sm text-[#e2e8f0] placeholder-[#4a5568] focus:outline-none focus:border-[#00f0ff] transition-all font-mono"
            />
          ) : (
            <div className="w-full bg-[#050510] border border-[#1e293b] rounded px-3 py-2 text-sm font-mono min-h-[34px] max-h-[80px] overflow-y-auto break-all">
              <span className={portRange ? 'text-[#00f0ff]' : 'text-[#4a5568]'}>
                {portRange || '引擎内置列表'}
              </span>
            </div>
          )}
          <div className="flex gap-2 mt-2 flex-wrap">
            {Object.entries(PORT_PRESETS).map(([key, preset]) => (
              <button
                key={key}
                onClick={() => {
                  setSelectedPreset(key)
                  setPortRange(preset.value)
                }}
                className={`text-xs px-2 py-1 rounded border transition-colors ${
                  selectedPreset === key
                    ? 'border-[#00f0ff] text-[#00f0ff] bg-[#00f0ff]/10'
                    : 'border-[#1e293b] text-[#94a3b8] hover:border-[#1e293b]/80'
                }`}
              >
                {preset.label}
              </button>
            ))}
          </div>
          <p className="text-xs text-[#00f0ff] mt-2">
            {PORT_PRESETS[selectedPreset]?.desc}
          </p>
        </div>

        {/* Toggle Options */}
        <div className="cyber-card p-6">
          <label className="block text-xs uppercase tracking-wider text-[#94a3b8] mb-3">
            扫描选项
          </label>
          <div className="space-y-3">
            {[
              { label: '网络漏洞检测', desc: 'Nmap NSE 自动检测 MS17-010/BlueKeep 等', value: true, setter: () => {} },
              { label: '弱口令探测', desc: 'Nmap 自动检测 SSH/FTP/RDP/MySQL 弱口令', value: true, setter: () => {} },
            ].map((opt) => (
              <div key={opt.label} className="flex items-center justify-between">
                <div>
                  <span className="text-sm text-[#e2e8f0]">{opt.label}</span>
                  <span className="text-xs text-[#4a5568] ml-2">{opt.desc}</span>
                </div>
                <button
                  className="relative w-10 h-5 rounded-full bg-[#00ff88]/30 flex-shrink-0 cursor-default"
                >
                  <div
                    className="absolute top-0.5 right-0.5 w-4 h-4 rounded-full bg-[#00ff88]"
                  />
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Thread Slider */}
      <div className="cyber-card p-6">
        <div className="flex items-center justify-between mb-2">
          <label className="text-xs uppercase tracking-wider text-[#94a3b8]">
            性能配置
          </label>
          <span className="text-sm font-bold text-[#00f0ff]">{threads}</span>
        </div>
        <input
          type="range"
          min={1}
          max={200}
          value={threads}
          onChange={(e) => setThreads(Number(e.target.value))}
          className="w-full h-1 bg-[#1e293b] rounded-full appearance-none cursor-pointer
            [&::-webkit-slider-thumb]:appearance-none
            [&::-webkit-slider-thumb]:w-4
            [&::-webkit-slider-thumb]:h-4
            [&::-webkit-slider-thumb]:rounded-full
            [&::-webkit-slider-thumb]:bg-[#00f0ff]
            [&::-webkit-slider-thumb]:shadow-[0_0_8px_rgba(0,240,255,0.5)]"
        />
        <div className="flex justify-between text-xs text-[#4a5568] mt-1">
          <span>低负载</span>
          <span>高性能</span>
        </div>
        <p className="text-xs text-[#4a5568] mt-2">用于未来自定义参数，当前由引擎自动优化。</p>
      </div>

      {/* Error message */}
      {startError && (
        <div className="cyber-card p-3 border-[#ff0044]/40 bg-[#ff0044]/5 text-[#ff0044] text-sm text-center">
          {startError}
        </div>
      )}

      {/* Start Button */}
      <button
        onClick={handleStartScan}
        disabled={!target.trim() || isStarting}
        className={`w-full py-4 rounded text-lg font-bold tracking-widest transition-all duration-300 relative overflow-hidden ${
          !target.trim()
            ? 'bg-[#1e293b] text-[#4a5568] cursor-not-allowed'
            : isStarting
            ? 'bg-[#00f0ff]/20 text-[#00f0ff] border border-[#00f0ff]'
            : 'bg-[#00f0ff]/10 text-[#00f0ff] border border-[#00f0ff] neon-glow hover:bg-[#00f0ff]/20 hover:shadow-[0_0_30px_rgba(0,240,255,0.3)]'
        }`}
      >
        <div className="flex items-center justify-center gap-3">
          <Crosshair
            size={20}
            className={isStarting ? 'animate-spin' : ''}
          />
          <span>{isStarting ? '初始化中...' : `开始${selectedTemplate.label}`}</span>
        </div>
        {isStarting && (
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-[#00f0ff]/10 to-transparent animate-pulse" />
        )}
      </button>
    </div>
  )
}

export default ScanNew
