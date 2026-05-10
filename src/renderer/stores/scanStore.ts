import { create } from 'zustand'

interface TerminalLine {
  id: number
  text: string
  type: 'stdout' | 'stderr' | 'info' | 'error'
}

interface DiscoveredHost {
  ip: string
  port: string
  service: string
  fingerprint: string
}

interface DiscoveredVuln {
  name: string
  url: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  templateId?: string
}

interface WebUrl {
  url: string
  ip: string
  port: string
  keyword: string
  fingerprint: string
}

export type ScanPhase = 'naabu' | 'nmap' | 'httpx' | 'nuclei' | 'pipeline' | 'cancelled'

interface ScanSession {
  scanId: string
  target: string
  isScanning: boolean
  progress: number
  phase: ScanPhase
  elapsed: number
  completedCode: number | null
  terminalLines: TerminalLine[]
  hosts: DiscoveredHost[]
  vulns: DiscoveredVuln[]
  webUrls: WebUrl[]
  nextLineId: number
}

interface ScanState {
  activeScanId: string | null
  activeScanTarget: string | null

  // Full session state keyed by scanId
  sessions: Map<string, ScanSession>

  setActiveScan: (id: string, target: string) => void
  clearActiveScan: () => void

  // Session operations
  getOrCreateSession: (scanId: string, target: string) => ScanSession
  updateSession: (scanId: string, partial: Partial<ScanSession>) => void
  addTerminalLine: (scanId: string, text: string, type: TerminalLine['type']) => void
  addHost: (scanId: string, host: DiscoveredHost) => void
  addVuln: (scanId: string, vuln: DiscoveredVuln) => void
  addWebUrl: (scanId: string, webUrl: WebUrl) => void
  completeSession: (scanId: string, code: number) => void
}

export type { TerminalLine, DiscoveredHost, DiscoveredVuln, WebUrl, ScanSession }

export const useScanStore = create<ScanState>((set, get) => ({
  activeScanId: null,
  activeScanTarget: null,
  sessions: new Map(),

  setActiveScan: (id, target) => set({ activeScanId: id, activeScanTarget: target }),
  clearActiveScan: () => set({ activeScanId: null, activeScanTarget: null }),

  getOrCreateSession: (scanId, target) => {
    const sessions = new Map(get().sessions)
    let session = sessions.get(scanId)
    if (!session) {
      session = {
        scanId,
        target,
        isScanning: true,
        progress: 0,
        phase: 'naabu',
        elapsed: 0,
        completedCode: null,
        terminalLines: [],
        hosts: [],
        vulns: [],
        webUrls: [],
        nextLineId: 0
      }
      sessions.set(scanId, session)
      set({ sessions })
    }
    return sessions.get(scanId)!
  },

  updateSession: (scanId, partial) => {
    const sessions = new Map(get().sessions)
    const session = sessions.get(scanId)
    if (!session) return
    sessions.set(scanId, { ...session, ...partial })
    set({ sessions })
  },

  addTerminalLine: (scanId, text, type) => {
    const sessions = new Map(get().sessions)
    const session = sessions.get(scanId)
    if (!session) return
    const nextLineId = session.nextLineId + 1
    sessions.set(scanId, {
      ...session,
      nextLineId,
      terminalLines: [...session.terminalLines, { id: nextLineId, text, type }]
    })
    set({ sessions })
  },

  addHost: (scanId, host) => {
    const sessions = new Map(get().sessions)
    const session = sessions.get(scanId)
    if (!session) return
    const existingIdx = session.hosts.findIndex(h => h.ip === host.ip && h.port === host.port)
    if (existingIdx >= 0) {
      // Update with richer data if new entry has more info
      const existing = session.hosts[existingIdx]
      const updated = { ...existing }
      if (host.service && !existing.service) updated.service = host.service
      if (host.fingerprint && !existing.fingerprint) updated.fingerprint = host.fingerprint
      const newHosts = [...session.hosts]
      newHosts[existingIdx] = updated
      sessions.set(scanId, { ...session, hosts: newHosts })
    } else {
      sessions.set(scanId, { ...session, hosts: [...session.hosts, host] })
    }
    set({ sessions })
  },

  addVuln: (scanId, vuln) => {
    const sessions = new Map(get().sessions)
    const session = sessions.get(scanId)
    if (!session) return
    sessions.set(scanId, { ...session, vulns: [...session.vulns, vuln] })
    set({ sessions })
  },

  addWebUrl: (scanId, webUrl) => {
    const sessions = new Map(get().sessions)
    const session = sessions.get(scanId)
    if (!session) return
    sessions.set(scanId, { ...session, webUrls: [...session.webUrls, webUrl] })
    set({ sessions })
  },

  completeSession: (scanId, code) => {
    const sessions = new Map(get().sessions)
    const session = sessions.get(scanId)
    if (!session) return
    sessions.set(scanId, {
      ...session,
      isScanning: false,
      progress: 100,
      completedCode: code
    })
    set({ sessions })
    // Clear active scan from sidebar
    if (get().activeScanId === scanId) {
      set({ activeScanId: null, activeScanTarget: null })
    }
  }
}))
