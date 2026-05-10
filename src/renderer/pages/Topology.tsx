import React, { useState, useEffect, useCallback, useMemo } from 'react'
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  type NodeProps,
  Handle,
  Position,
  BackgroundVariant,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { Network, RefreshCw, X } from 'lucide-react'
import { translateVulnName } from '../utils/translateVuln'

interface HostData {
  ip: string
  port: string
  service: string
  fingerprint: string
  scanId: string
  [key: string]: any
}

interface VulnData {
  id: number
  name: string
  severity: string
  host: string
  matchedAt: string
  [key: string]: any
}

function getSubnet(ip: string): string {
  if (!ip) return ''
  const parts = ip.split('.')
  if (parts.length < 4) return ip
  return `${parts[0]}.${parts[1]}.${parts[2]}.0`
}

function getNodeColor(vulnCount: number): string {
  if (vulnCount === 0) return '#00ff88'
  if (vulnCount <= 2) return '#ffd000'
  if (vulnCount <= 5) return '#ff6600'
  return '#ff0044'
}

function getGlowColor(vulnCount: number): string {
  if (vulnCount === 0) return 'rgba(0,255,136,0.3)'
  if (vulnCount <= 2) return 'rgba(255,208,0,0.3)'
  if (vulnCount <= 5) return 'rgba(255,102,0,0.3)'
  return 'rgba(255,0,68,0.4)'
}

function HostNode({ data }: NodeProps) {
  const color = data.color as string || '#00ff88'
  const glow = data.glow as string || 'rgba(0,255,136,0.3)'
  const vulnCount = data.vulnCount as number || 0

  return (
    <div
      style={{
        background: '#111827',
        border: `2px solid ${color}`,
        borderRadius: '6px',
        padding: '10px 18px',
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: '13px',
        color: '#e2e8f0',
        boxShadow: `0 0 12px ${glow}, inset 0 0 8px rgba(0,0,0,0.5)`,
        minWidth: '120px',
        textAlign: 'center',
        position: 'relative',
        cursor: 'pointer',
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: color, width: 6, height: 6 }} />
      <Handle type="source" position={Position.Right} style={{ background: color, width: 6, height: 6 }} />
      <Handle type="target" position={Position.Top} style={{ background: color, width: 6, height: 6 }} />
      <Handle type="source" position={Position.Bottom} style={{ background: color, width: 6, height: 6 }} />
      <div style={{ color, fontWeight: 'bold', letterSpacing: '0.5px' }}>
        {data.label as string}
      </div>
      {vulnCount > 0 && (
        <div style={{ fontSize: '10px', color: '#94a3b8', marginTop: '4px' }}>
          {vulnCount} 个漏洞
        </div>
      )}
      {vulnCount === 0 && (
        <div style={{ fontSize: '10px', color: '#00ff88', marginTop: '4px' }}>
          安全
        </div>
      )}
    </div>
  )
}

const nodeTypes = { hostNode: HostNode }

const Topology: React.FC = () => {
  const [loading, setLoading] = useState(true)
  const [hosts, setHosts] = useState<HostData[]>([])
  const [vulns, setVulns] = useState<VulnData[]>([])
  const [selectedIp, setSelectedIp] = useState<string | null>(null)

  const fetchData = async () => {
    setLoading(true)
    try {
      const [hostsData, vulnsData] = await Promise.all([
        window.electronAPI.getAllHosts(),
        window.electronAPI.getAllVulns(),
      ])
      setHosts(hostsData || [])
      setVulns(vulnsData || [])
    } catch (err) {
      console.error('获取拓扑数据失败:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  // Build IP → ports/services map for detail panel
  const ipDetails = useMemo(() => {
    const map = new Map<string, { ports: { port: string; service: string; fingerprint: string; url: string }[]; vulns: VulnData[] }>()
    hosts.forEach(h => {
      if (!h.ip) return
      if (!map.has(h.ip)) map.set(h.ip, { ports: [], vulns: [] })
      map.get(h.ip)!.ports.push({
        port: String(h.port || ''),
        service: h.service || '',
        fingerprint: h.fingerprint || '',
        url: h.url || ''
      })
    })
    vulns.forEach(v => {
      const ip = v.host || v.matchedAt?.split(/[:/]/)[0] || ''
      if (!ip) return
      if (!map.has(ip)) map.set(ip, { ports: [], vulns: [] })
      map.get(ip)!.vulns.push(v)
    })
    return map
  }, [hosts, vulns])

  const { nodes: initialNodes, edges: initialEdges } = useMemo(() => {
    const ipSet = new Map<string, { ip: string; vulnCount: number }>()
    hosts.forEach((h) => {
      if (!h.ip) return
      const existing = ipSet.get(h.ip)
      if (!existing) {
        ipSet.set(h.ip, { ip: h.ip, vulnCount: 0 })
      }
    })

    vulns.forEach((v) => {
      const extractIp = (s: string) => s?.match(/\d+\.\d+\.\d+\.\d+/)?.[0] || ''
      const ip = extractIp(v.host) || extractIp(v.matchedAt) || ''
      if (!ip) return
      const entry = ipSet.get(ip)
      if (entry) {
        entry.vulnCount++
      } else {
        ipSet.set(ip, { ip, vulnCount: 1 })
      }
    })

    const ipList = Array.from(ipSet.values())
    if (ipList.length === 0) {
      return { nodes: [], edges: [] }
    }

    const cols = Math.ceil(Math.sqrt(ipList.length))
    const nodeSpacingX = 220
    const nodeSpacingY = 120

    const builtNodes: Node[] = ipList.map((item, idx) => {
      const col = idx % cols
      const row = Math.floor(idx / cols)
      const color = getNodeColor(item.vulnCount)
      const glow = getGlowColor(item.vulnCount)
      return {
        id: item.ip,
        type: 'hostNode',
        position: { x: col * nodeSpacingX + 50, y: row * nodeSpacingY + 50 },
        data: {
          label: item.ip,
          color,
          glow,
          vulnCount: item.vulnCount,
        },
      }
    })

    // Group by subnet for visual layout (NO fake edges — just proximity grouping)
    const subnetMap = new Map<string, string[]>()
    ipList.forEach((item) => {
      const subnet = getSubnet(item.ip)
      if (!subnetMap.has(subnet)) subnetMap.set(subnet, [])
      subnetMap.get(subnet)!.push(item.ip)
    })

    return { nodes: builtNodes, edges: [] }
  }, [hosts, vulns])

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges)

  useEffect(() => {
    setNodes(initialNodes)
    setEdges(initialEdges)
  }, [initialNodes, initialEdges, setNodes, setEdges])

  const onInit = useCallback((instance: any) => {
    instance.fitView({ padding: 0.2 })
  }, [])

  const onNodeClick = useCallback((event: React.MouseEvent, node: Node) => {
    setSelectedIp(node.id)
  }, [])

  const totalIps = hosts.length > 0
    ? new Set(hosts.filter((h) => h.ip).map((h) => h.ip)).size
    : 0

  const selectedDetail = selectedIp ? ipDetails.get(selectedIp) : null

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold neon-text">主机地图</h1>
          <span className="px-3 py-1 bg-[#bf00ff]/10 text-[#bf00ff] border border-[#bf00ff]/30 rounded-full text-xs">
            {totalIps} 个节点
          </span>
        </div>
        <button
          onClick={fetchData}
          className="px-4 py-2 bg-[#00f0ff]/10 text-[#00f0ff] border border-[#00f0ff]/30 rounded hover:bg-[#00f0ff]/20 transition-colors flex items-center gap-2 text-sm"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          刷新
        </button>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-6">
        <span className="text-xs text-[#94a3b8]">节点状态:</span>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-sm" style={{ background: '#00ff88' }} />
            <span className="text-xs text-[#94a3b8]">安全 (0)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-sm" style={{ background: '#ffd000' }} />
            <span className="text-xs text-[#94a3b8]">低危 (1-2)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-sm" style={{ background: '#ff6600' }} />
            <span className="text-xs text-[#94a3b8]">中危 (3-5)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-sm" style={{ background: '#ff0044' }} />
            <span className="text-xs text-[#94a3b8]">高危 (6+)</span>
          </div>
        </div>
        <div className="ml-auto text-xs text-[#94a3b8]">
          点击节点查看详情
        </div>
      </div>

      {/* Topology Canvas */}
      <div className="flex gap-4" style={{ height: 'calc(100vh - 200px)' }}>
        <div className="flex-1 cyber-card overflow-hidden">
          {loading ? (
            <div className="flex flex-col items-center justify-center h-full text-[#94a3b8]">
              <RefreshCw size={24} className="animate-spin mb-3" />
              <p className="text-sm">加载拓扑数据...</p>
            </div>
          ) : initialNodes.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-[#4a5568]">
              <Network size={48} className="mb-3" />
              <p className="text-sm">暂无主机数据</p>
              <p className="text-xs mt-1">完成扫描后，发现的主机将按子网分组在此展示。</p>
            </div>
          ) : (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onInit={onInit}
              onNodeClick={onNodeClick}
              nodeTypes={nodeTypes}
              fitView
              fitViewOptions={{ padding: 0.2 }}
              minZoom={0.2}
              maxZoom={3}
              proOptions={{ hideAttribution: true }}
              style={{ background: '#0a0a0f' }}
              defaultEdgeOptions={{
                animated: true,
                style: { stroke: '#1e293b', strokeWidth: 1 },
              }}
            >
              <Background
                variant={BackgroundVariant.Dots}
                gap={20}
                size={1}
                color="#1e293b"
              />
              <Controls
                showInteractive={false}
                style={{
                  background: '#111827',
                  border: '1px solid #1e293b',
                  borderRadius: '4px',
                }}
              />
              <MiniMap
                style={{
                  background: '#0a0a0f',
                  border: '1px solid #1e293b',
                  borderRadius: '4px',
                }}
                nodeColor={(node) => {
                  const data = node.data as any
                  return data?.color || '#00ff88'
                }}
                maskColor="rgba(0,0,0,0.7)"
              />
            </ReactFlow>
          )}
        </div>

        {/* Detail Panel */}
        {selectedIp && selectedDetail && (
          <div className="w-[320px] cyber-card p-4 overflow-y-auto flex-shrink-0">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-bold text-[#00f0ff] font-mono">{selectedIp}</h3>
              <button
                onClick={() => setSelectedIp(null)}
                className="text-[#94a3b8] hover:text-[#e2e8f0] transition-colors"
              >
                <X size={16} />
              </button>
            </div>

            {/* Ports */}
            <div className="mb-4">
              <div className="text-xs uppercase tracking-wider text-[#94a3b8] mb-2">
                开放端口 ({selectedDetail.ports.length})
              </div>
              <div className="space-y-1">
                {selectedDetail.ports.map((p, i) => (
                  <div key={i} className="px-3 py-2 bg-[#050510] rounded text-xs">
                    <div className="flex items-center justify-between">
                      <span className="text-[#00f0ff] font-mono">:{p.port}</span>
                      <span className="text-[#e2e8f0]">{p.service || '--'}</span>
                    </div>
                    {p.fingerprint && (
                      <div className="text-[#94a3b8] mt-1 truncate">{p.fingerprint}</div>
                    )}
                    {p.url && (
                      <div
                        className="text-[#00f0ff] mt-1 truncate cursor-pointer hover:underline"
                        onClick={() => window.electronAPI.openExternal(p.url)}
                      >
                        {p.url}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Vulnerabilities */}
            {selectedDetail.vulns.length > 0 && (
              <div>
                <div className="text-xs uppercase tracking-wider text-[#94a3b8] mb-2">
                  漏洞 ({selectedDetail.vulns.length})
                </div>
                <div className="space-y-1">
                  {selectedDetail.vulns.map((v, i) => {
                    const sevColor = v.severity === 'critical' ? '#ff0044'
                      : v.severity === 'high' ? '#ff6600'
                      : v.severity === 'medium' ? '#ffd000'
                      : v.severity === 'low' ? '#00ff88' : '#94a3b8'
                    return (
                      <div key={i} className="px-3 py-2 bg-[#050510] rounded text-xs">
                        <div className="flex items-center gap-2">
                          <span style={{ color: sevColor }} className="font-bold uppercase text-[10px]">
                            {v.severity}
                          </span>
                          <span className="text-[#e2e8f0] truncate">{translateVulnName(v.name)}</span>
                        </div>
                        <div className="text-[#4a5568] mt-1 truncate">{v.matchedAt}</div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}

            {selectedDetail.vulns.length === 0 && (
              <div className="text-center py-4 text-xs text-[#00ff88]">
                未发现漏洞
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export default Topology
