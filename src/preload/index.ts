import { contextBridge, ipcRenderer } from 'electron'

const electronAPI = {
  // Scan operations
  startScan: (scanId: string, tool: string, args: string[], options?: { name?: string }): Promise<{ pid: number }> => {
    return ipcRenderer.invoke('scan:start', scanId, tool, args, options)
  },

  cancelScan: (scanId: string): Promise<{ success: boolean }> => {
    return ipcRenderer.invoke('scan:cancel', scanId)
  },

  // Scan events
  onScanStdout: (callback: (data: { scanId: string; line: string }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, data: { scanId: string; line: string }) => callback(data)
    ipcRenderer.on('scan:stdout', handler)
    return () => ipcRenderer.removeListener('scan:stdout', handler)
  },

  onScanStderr: (callback: (data: { scanId: string; line: string }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, data: { scanId: string; line: string }) => callback(data)
    ipcRenderer.on('scan:stderr', handler)
    return () => ipcRenderer.removeListener('scan:stderr', handler)
  },

  onScanResult: (callback: (data: { scanId: string; result: unknown; tool?: string }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, data: { scanId: string; result: unknown; tool?: string }) => callback(data)
    ipcRenderer.on('scan:result', handler)
    return () => ipcRenderer.removeListener('scan:result', handler)
  },

  onScanComplete: (callback: (data: { scanId: string; code: number }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, data: { scanId: string; code: number }) => callback(data)
    ipcRenderer.on('scan:complete', handler)
    return () => ipcRenderer.removeListener('scan:complete', handler)
  },

  onUpdateProgress: (callback: (data: { scanId: string; progress: number; phase?: string }) => void): (() => void) => {
    const handler = (_event: Electron.IpcRendererEvent, data: { scanId: string; progress: number; phase?: string }) => callback(data)
    ipcRenderer.on('scan:progress', handler)
    return () => ipcRenderer.removeListener('scan:progress', handler)
  },

  // Window controls
  minimize: (): void => {
    ipcRenderer.invoke('window:minimize')
  },

  maximize: (): void => {
    ipcRenderer.invoke('window:maximize')
  },

  close: (): void => {
    ipcRenderer.invoke('window:close')
  },

  // Database queries
  getScans: (): Promise<any[]> => ipcRenderer.invoke('db:getScans'),
  getScanById: (id: string): Promise<any> => ipcRenderer.invoke('db:getScanById', id),
  getHostsByScanId: (scanId: string): Promise<any[]> => ipcRenderer.invoke('db:getHostsByScanId', scanId),
  getVulnsByScanId: (scanId: string): Promise<any[]> => ipcRenderer.invoke('db:getVulnsByScanId', scanId),
  getWebUrlsByScanId: (scanId: string): Promise<any[]> => ipcRenderer.invoke('db:getWebUrlsByScanId', scanId),
  getScanStats: (): Promise<{ totalScans: number; totalHosts: number; totalVulns: number; criticalVulns: number }> => ipcRenderer.invoke('db:getScanStats'),
  getAllHosts: (): Promise<any[]> => ipcRenderer.invoke('db:getAllHosts'),
  getAllVulns: (): Promise<any[]> => ipcRenderer.invoke('db:getAllVulns'),
  updateVulnStatus: (id: number, status: string): Promise<void> => ipcRenderer.invoke('db:updateVulnStatus', id, status),
  getWebFingerprintsByScanId: (scanId: string): Promise<any[]> => ipcRenderer.invoke('db:getWebFingerprintsByScanId', scanId),
  getAllWebFingerprints: (): Promise<any[]> => ipcRenderer.invoke('db:getAllWebFingerprints'),
  deleteScan: (id: string): Promise<void> => ipcRenderer.invoke('db:deleteScan', id),

  clearDatabase: (): Promise<void> => ipcRenderer.invoke('db:clearDatabase'),
  checkFileExists: (path: string): Promise<boolean> => ipcRenderer.invoke('util:checkFileExists', path),
  openExternal: (url: string): Promise<void> => ipcRenderer.invoke('util:openExternal', url),
  isScanRunning: (scanId: string): Promise<boolean> => ipcRenderer.invoke('scan:isRunning', scanId)
}

contextBridge.exposeInMainWorld('electronAPI', electronAPI)
