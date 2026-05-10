import React, { type ReactNode } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import {
  Radar,
  Crosshair,
  Server,
  Shield,
  FileText,
  GitCompare,
  Network,
  Settings,
  Minus,
  Square,
  X,
} from 'lucide-react'
import { useScanStore } from '../../stores/scanStore'

const navItems = [
  { to: '/', label: '控制台', icon: Radar },
  { to: '/scan/new', label: '新建扫描', icon: Crosshair },
  { to: '/assets', label: '资产管理', icon: Server },
  { to: '/vulns', label: '漏洞管理', icon: Shield },
  { to: '/reports', label: '报告中心', icon: FileText },
  { to: '/compare', label: '结果对比', icon: GitCompare },
  { to: '/topology', label: '主机地图', icon: Network },
  { to: '/settings', label: '系统设置', icon: Settings },
]

const TitleBar: React.FC = () => {
  const handleMinimize = () => {
    window.electronAPI?.minimize()
  }

  const handleMaximize = () => {
    window.electronAPI?.maximize()
  }

  const handleClose = () => {
    window.electronAPI?.close()
  }

  return (
    <div className="h-10 flex items-center justify-between bg-[#07070d] border-b border-[#1e293b] select-none titlebar-drag">
      <div className="flex items-center gap-2 px-4">
        <Radar size={18} className="text-[#00f0ff]" />
        <span className="text-base font-bold tracking-wider text-[#00f0ff] neon-text">
          星川之眼
        </span>
        <span className="text-xs text-[#94a3b8] ml-1">v1.0.0</span>
      </div>
      <div className="flex h-full titlebar-no-drag">
        <button
          onClick={handleMinimize}
          className="h-full w-10 flex items-center justify-center hover:bg-[#1e293b] transition-colors"
        >
          <Minus size={14} className="text-[#94a3b8]" />
        </button>
        <button
          onClick={handleMaximize}
          className="h-full w-10 flex items-center justify-center hover:bg-[#1e293b] transition-colors"
        >
          <Square size={12} className="text-[#94a3b8]" />
        </button>
        <button
          onClick={handleClose}
          className="h-full w-10 flex items-center justify-center hover:bg-[#ff0044] transition-colors"
        >
          <X size={14} className="text-[#94a3b8]" />
        </button>
      </div>
    </div>
  )
}

const Sidebar: React.FC = () => {
  const { activeScanId, activeScanTarget } = useScanStore()
  const navigate = useNavigate()

  return (
    <aside className="w-[260px] h-full bg-[#0d0d14] border-r border-[#1e293b] flex flex-col">
      <div className="flex-1 py-4 px-2 space-y-1">
        {navItems.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-3 rounded text-[15px] transition-all duration-200 group ${
                isActive
                  ? 'bg-[#00f0ff]/10 text-[#00f0ff] neon-glow'
                  : 'text-[#94a3b8] hover:bg-[#1e293b]/50 hover:text-[#e2e8f0]'
              }`
            }
          >
            <Icon size={20} />
            <span>{label}</span>
            {to === '/scan/new' && (
              <span className="ml-auto w-2 h-2 rounded-full bg-[#00f0ff] cyber-pulse" />
            )}
          </NavLink>
        ))}
      </div>

      {activeScanId && (
        <div className="px-3 py-2 border-t border-[#1e293b]">
          <button
            onClick={() => navigate(`/scan/${activeScanId}`)}
            className="w-full flex items-center gap-2 px-3 py-2 rounded bg-[#00f0ff]/10 text-[#00f0ff] text-sm neon-glow cyber-pulse"
          >
            <Crosshair size={16} />
            <span className="truncate">正在扫描: {activeScanTarget}</span>
          </button>
        </div>
      )}

      <div className="p-4 border-t border-[#1e293b]">
        <div className="text-sm text-[#94a3b8] space-y-1">
          <div className="flex justify-between">
            <span>状态</span>
            <span className={activeScanId ? 'text-[#00f0ff] cyber-pulse' : 'text-[#00ff88]'}>
              {activeScanId ? '扫描中' : '就绪'}
            </span>
          </div>
          <div className="flex justify-between">
            <span>引擎</span>
            <span className="text-[#00f0ff]">Nmap + Nuclei</span>
          </div>
        </div>
      </div>
    </aside>
  )
}

interface AppShellProps {
  children: ReactNode
}

const AppShell: React.FC<AppShellProps> = ({ children }) => {
  return (
    <div className="h-screen w-screen flex flex-col overflow-hidden">
      <TitleBar />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>
      <div className="scanline-overlay" />
    </div>
  )
}

export default AppShell
