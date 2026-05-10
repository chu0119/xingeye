import React, { useState, useEffect } from 'react'
import {
  Settings as SettingsIcon,
  Cpu,
  Globe,
  FileCode,
  Database,
  Palette,
  Save,
  CheckCircle,
  AlertTriangle,
  RefreshCw,
  Trash2,
  Download,
  Upload,
} from 'lucide-react'

interface AppSettings {
  qscanPath: string
  nucleiPath: string
  proxyEnabled: boolean
  proxyAddress: string
  theme: 'cyberpunk' | 'deepblue' | 'greenmatrix'
}

const defaultSettings: AppSettings = {
  qscanPath: 'D:\\qscan.exe',
  nucleiPath: 'D:\\netscan\\nuclei\\nuclei.exe',
  proxyEnabled: false,
  proxyAddress: 'http://127.0.0.1:7897',
  theme: 'cyberpunk',
}

const STORAGE_KEY = 'cyberscan_settings'

const loadSettings = (): AppSettings => {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored) {
      return { ...defaultSettings, ...JSON.parse(stored) }
    }
  } catch {
    // ignore
  }
  return defaultSettings
}

const saveSettings = (settings: AppSettings) => {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings))
  } catch {
    // ignore
  }
}

const themes: { key: AppSettings['theme']; label: string; desc: string; colors: string }[] = [
  {
    key: 'cyberpunk',
    label: '赛博朋克',
    desc: '霓虹青色 + 紫色风格',
    colors: 'linear-gradient(90deg, #00f0ff, #bf00ff)',
  },
  {
    key: 'deepblue',
    label: '深蓝终端',
    desc: '深蓝色科技终端风',
    colors: 'linear-gradient(90deg, #1e40af, #3b82f6)',
  },
  {
    key: 'greenmatrix',
    label: '绿色矩阵',
    desc: '经典黑客帝国绿色风格',
    colors: 'linear-gradient(90deg, #166534, #22c55e)',
  },
]

const SettingsPage: React.FC = () => {
  const [settings, setSettings] = useState<AppSettings>(defaultSettings)
  const [saved, setSaved] = useState(false)
  const [testResult, setTestResult] = useState<{ path: string; status: 'ok' | 'fail' } | null>(null)
  const [scanCount, setScanCount] = useState<number>(0)
  const [showConfirmClear, setShowConfirmClear] = useState(false)

  useEffect(() => {
    const loaded = loadSettings()
    setSettings(loaded)
    // Try to get scan count
    window.electronAPI.getScans().then((scans) => {
      setScanCount(scans?.length || 0)
    }).catch(() => {})
  }, [])

  const updateSetting = <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => {
    const next = { ...settings, [key]: value }
    setSettings(next)
    saveSettings(next)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const handleTestConnection = async (path: string) => {
    if (!path.trim()) {
      setTestResult({ path, status: 'fail' })
      setTimeout(() => setTestResult(null), 4000)
      return
    }
    try {
      const exists = await window.electronAPI.checkFileExists(path)
      setTestResult({ path, status: exists ? 'ok' : 'fail' })
    } catch {
      setTestResult({ path, status: 'fail' })
    }
    setTimeout(() => setTestResult(null), 4000)
  }

  const handleClearDatabase = async () => {
    setShowConfirmClear(false)
    try {
      await window.electronAPI.clearDatabase()
      setScanCount(0)
    } catch (err) {
      console.error('清理数据库失败:', err)
    }
  }

  const handleExportData = async () => {
    try {
      const scans = await window.electronAPI.getScans()
      const data = JSON.stringify({ scans, exportedAt: new Date().toISOString() }, null, 2)
      const blob = new Blob([data], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `cyberscan_export_${new Date().toISOString().slice(0, 10)}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error('导出失败:', err)
    }
  }

  const handleImportData = () => {
    const input = document.createElement('input')
    input.type = 'file'
    input.accept = '.json'
    input.onchange = (e) => {
      const file = (e.target as HTMLInputElement).files?.[0]
      if (!file) return
      const reader = new FileReader()
      reader.onload = () => {
        try {
          const data = JSON.parse(reader.result as string)
          console.log('导入数据:', data)
          // Actual import would go through IPC
        } catch {
          console.error('导入文件格式错误')
        }
      }
      reader.readAsText(file)
    }
    input.click()
  }

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold neon-text">系统设置</h1>
          {saved && (
            <span className="flex items-center gap-1 px-3 py-1 bg-[#00ff88]/10 text-[#00ff88] border border-[#00ff88]/30 rounded-full text-xs">
              <CheckCircle size={12} />
              已保存
            </span>
          )}
        </div>
        <SettingsIcon size={20} className="text-[#94a3b8]" />
      </div>

      {/* 1. Scan Engine */}
      <div className="cyber-card p-5">
        <div className="flex items-center gap-2 mb-5">
          <Cpu size={16} className="text-[#00f0ff]" />
          <h2 className="text-sm uppercase tracking-wider text-[#94a3b8]">扫描引擎</h2>
        </div>
        <div className="space-y-4">
          {/* Tool Paths (informational) */}
          <div>
            <label className="block text-xs text-[#94a3b8] mb-2">扫描引擎 (当前使用)</label>
            <div className="space-y-2 text-xs text-[#94a3b8]">
              <div className="p-2 bg-[#0a0a0f] rounded border border-[#1e293b] font-mono">
                <span className="text-[#00f0ff]">naabu</span> — 端口发现
              </div>
              <div className="p-2 bg-[#0a0a0f] rounded border border-[#1e293b] font-mono">
                <span className="text-[#ffd000]">nmap</span> — 服务识别 + 漏洞检测 + 弱口令
              </div>
              <div className="p-2 bg-[#0a0a0f] rounded border border-[#1e293b] font-mono">
                <span className="text-[#00ff88]">httpx</span> — Web 指纹识别
              </div>
              <div className="p-2 bg-[#0a0a0f] rounded border border-[#1e293b] font-mono">
                <span className="text-[#bf00ff]">nuclei</span> — 深度漏洞扫描
              </div>
            </div>
            <p className="text-xs text-[#4a5568] mt-2">路径配置功能即将推出。</p>
          </div>
          {/* Nuclei Path */}
          <div>
            <label className="block text-xs text-[#94a3b8] mb-2">Nuclei 路径</label>
            <div className="flex items-center gap-3">
              <input
                type="text"
                value={settings.nucleiPath}
                onChange={(e) => updateSetting('nucleiPath', e.target.value)}
                className="flex-1 bg-[#0a0a0f] border border-[#1e293b] rounded px-4 py-2.5 text-sm text-[#e2e8f0] focus:border-[#00f0ff] outline-none font-mono"
                placeholder="D:\netscan\nuclei\nuclei.exe"
              />
              <button
                onClick={() => handleTestConnection(settings.nucleiPath)}
                className="px-4 py-2.5 bg-[#00f0ff]/10 text-[#00f0ff] border border-[#00f0ff]/30 rounded text-xs hover:bg-[#00f0ff]/20 transition-colors whitespace-nowrap"
              >
                测试连接
              </button>
            </div>
          </div>
          {/* Test Result */}
          {testResult && (
            <div
              className={`flex items-center gap-2 px-4 py-2 rounded text-xs ${
                testResult.status === 'ok'
                  ? 'bg-[#00ff88]/10 text-[#00ff88] border border-[#00ff88]/30'
                  : 'bg-[#ff0044]/10 text-[#ff0044] border border-[#ff0044]/30'
              }`}
            >
              {testResult.status === 'ok' ? (
                <CheckCircle size={14} />
              ) : (
                <AlertTriangle size={14} />
              )}
              <span>
                {testResult.status === 'ok'
                  ? `路径已配置: ${testResult.path}`
                  : '路径不能为空'}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* 2. Proxy Settings */}
      <div className="cyber-card p-5">
        <div className="flex items-center gap-2 mb-5">
          <Globe size={16} className="text-[#bf00ff]" />
          <h2 className="text-sm uppercase tracking-wider text-[#94a3b8]">代理设置</h2>
        </div>
        <div className="space-y-4">
          {/* Enable Proxy Toggle */}
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-[#e2e8f0]">启用代理</div>
              <div className="text-xs text-[#94a3b8] mt-0.5">通过代理服务器转发扫描流量</div>
            </div>
            <button
              onClick={() => updateSetting('proxyEnabled', !settings.proxyEnabled)}
              className={`relative w-12 h-6 rounded-full transition-colors ${
                settings.proxyEnabled ? 'bg-[#00f0ff]/30' : 'bg-[#1e293b]'
              }`}
            >
              <div
                className={`absolute top-0.5 w-5 h-5 rounded-full transition-all ${
                  settings.proxyEnabled
                    ? 'left-6.5 bg-[#00f0ff] shadow-[0_0_8px_rgba(0,240,255,0.5)]'
                    : 'left-0.5 bg-[#4a5568]'
                }`}
                style={{
                  left: settings.proxyEnabled ? '26px' : '2px',
                  background: settings.proxyEnabled ? '#00f0ff' : '#4a5568',
                  boxShadow: settings.proxyEnabled ? '0 0 8px rgba(0,240,255,0.5)' : 'none',
                }}
              />
            </button>
          </div>
          {/* Proxy Address */}
          <div>
            <label className="block text-xs text-[#94a3b8] mb-2">代理地址</label>
            <input
              type="text"
              value={settings.proxyAddress}
              onChange={(e) => updateSetting('proxyAddress', e.target.value)}
              disabled={!settings.proxyEnabled}
              className="w-full bg-[#0a0a0f] border border-[#1e293b] rounded px-4 py-2.5 text-sm text-[#e2e8f0] focus:border-[#00f0ff] outline-none font-mono disabled:opacity-40 disabled:cursor-not-allowed"
              placeholder="http://127.0.0.1:7897"
            />
          </div>
        </div>
      </div>

      {/* 3. Template Management */}
      <div className="cyber-card p-5">
        <div className="flex items-center gap-2 mb-5">
          <FileCode size={16} className="text-[#ffd000]" />
          <h2 className="text-sm uppercase tracking-wider text-[#94a3b8]">模板管理</h2>
        </div>
        <div className="space-y-4">
          <div className="flex items-center justify-between p-3 bg-[#0a0a0f] rounded border border-[#1e293b]">
            <div>
              <div className="text-xs text-[#94a3b8]">当前模板版本</div>
              <div className="text-sm text-[#e2e8f0] font-mono mt-1">v9.8.1 (最新)</div>
            </div>
            <button disabled className="flex items-center gap-2 px-4 py-2 bg-[#ffd000]/5 text-[#4a5568] border border-[#1e293b] rounded text-xs cursor-not-allowed" title="即将推出">
              <RefreshCw size={12} />
              更新模板 (即将推出)
            </button>
          </div>
          <div className="p-3 bg-[#0a0a0f] rounded border border-[#1e293b]">
            <div className="text-xs text-[#94a3b8]">模板路径</div>
            <div className="text-sm text-[#e2e8f0] font-mono mt-1 break-all">
              D:\netscan\nuclei\templates
            </div>
          </div>
        </div>
      </div>

      {/* 4. Data Management */}
      <div className="cyber-card p-5">
        <div className="flex items-center gap-2 mb-5">
          <Database size={16} className="text-[#ff0066]" />
          <h2 className="text-sm uppercase tracking-wider text-[#94a3b8]">数据管理</h2>
        </div>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="p-3 bg-[#0a0a0f] rounded border border-[#1e293b]">
              <div className="text-xs text-[#94a3b8]">数据库路径</div>
              <div className="text-sm text-[#e2e8f0] font-mono mt-1 break-all">
                D:\netscan\cyberscan\data\cyberscan.db
              </div>
            </div>
            <div className="p-3 bg-[#0a0a0f] rounded border border-[#1e293b]">
              <div className="text-xs text-[#94a3b8]">扫描记录数</div>
              <div className="text-sm text-[#00f0ff] font-bold mt-1">{scanCount} 条</div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleExportData}
              className="flex items-center gap-2 px-4 py-2 bg-[#00f0ff]/10 text-[#00f0ff] border border-[#00f0ff]/30 rounded text-xs hover:bg-[#00f0ff]/20 transition-colors"
            >
              <Download size={12} />
              导出数据
            </button>
            <button
              disabled
              className="flex items-center gap-2 px-4 py-2 bg-[#00ff88]/5 text-[#4a5568] border border-[#1e293b] rounded text-xs cursor-not-allowed"
              title="即将推出"
            >
              <Upload size={12} />
              导入数据 (即将推出)
            </button>
            <button
              onClick={() => setShowConfirmClear(true)}
              className="flex items-center gap-2 px-4 py-2 bg-[#ff0044]/10 text-[#ff0044] border border-[#ff0044]/30 rounded text-xs hover:bg-[#ff0044]/20 transition-colors ml-auto"
            >
              <Trash2 size={12} />
              清理数据库
            </button>
          </div>
          {/* Confirm Clear Dialog */}
          {showConfirmClear && (
            <div className="p-4 bg-[#ff0044]/5 border border-[#ff0044]/30 rounded">
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle size={16} className="text-[#ff0044]" />
                <span className="text-sm text-[#ff0044]">确认清理数据库？</span>
              </div>
              <p className="text-xs text-[#94a3b8] mb-3">
                此操作将删除所有扫描记录、主机、漏洞数据，且不可恢复。
              </p>
              <div className="flex items-center gap-3">
                <button
                  onClick={handleClearDatabase}
                  className="px-4 py-2 bg-[#ff0044] text-white rounded text-xs hover:bg-[#ff0044]/80 transition-colors"
                >
                  确认清理
                </button>
                <button
                  onClick={() => setShowConfirmClear(false)}
                  className="px-4 py-2 bg-[#1e293b] text-[#94a3b8] rounded text-xs hover:bg-[#1e293b]/80 transition-colors"
                >
                  取消
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* 5. Interface Settings */}
      <div className="cyber-card p-5">
        <div className="flex items-center gap-2 mb-5">
          <Palette size={16} className="text-[#00ff88]" />
          <h2 className="text-sm uppercase tracking-wider text-[#94a3b8]">界面设置</h2>
        </div>
        <div>
          <label className="block text-xs text-[#94a3b8] mb-3">主题选择</label>
          <p className="text-xs text-[#4a5568]">目前仅支持暗色主题（赛博朋克风格）。更多内置主题即将推出。</p>
        </div>
      </div>
    </div>
  )
}

export default SettingsPage
