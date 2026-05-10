export {}

declare global {
  interface Window {
    electronAPI: {
      startScan(scanId: string, tool: string, args: string[], options?: { name?: string }): Promise<{ pid: number }>
      cancelScan(scanId: string): Promise<{ success: boolean }>
      onScanStdout(callback: (data: { scanId: string; line: string }) => void): () => void
      onScanStderr(callback: (data: { scanId: string; line: string }) => void): () => void
      onScanResult(callback: (data: { scanId: string; result: unknown; tool?: string }) => void): () => void
      onScanComplete(callback: (data: { scanId: string; code: number }) => void): () => void
      onUpdateProgress(callback: (data: { scanId: string; progress: number; phase?: string }) => void): () => void
      minimize(): void
      maximize(): void
      close(): void
      focusWindow(): void
      getScans(): Promise<any[]>
      getScanById(id: string): Promise<any>
      getHostsByScanId(scanId: string): Promise<any[]>
      getVulnsByScanId(scanId: string): Promise<any[]>
      getWebUrlsByScanId(scanId: string): Promise<any[]>
      getScanStats(): Promise<{ totalScans: number; totalHosts: number; totalVulns: number; criticalVulns: number }>
      getAllHosts(): Promise<any[]>
      getAllVulns(): Promise<any[]>
      updateVulnStatus(id: number, status: string): Promise<void>
      getWebFingerprintsByScanId(scanId: string): Promise<any[]>
      getAllWebFingerprints(): Promise<any[]>
      deleteScan(id: string): Promise<void>
      clearDatabase(): Promise<void>
      checkFileExists(path: string): Promise<boolean>
      openExternal(url: string): Promise<void>
      isScanRunning(scanId: string): Promise<boolean>
    }
  }
}
