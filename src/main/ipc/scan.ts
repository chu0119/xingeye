import { ipcMain, BrowserWindow, shell } from 'electron'
import * as fs from 'fs'
import * as scanner from '../services/scanner'
import {
  insertScan,
  updateScanStatus,
  insertHost,
  insertVulnerability,
  insertWebUrl,
  getScans,
  getScanById,
  getHostsByScanId,
  getVulnerabilitiesByScanId,
  getWebUrlsByScanId,
  getScanStats,
  getAllHosts,
  getAllVulnerabilities,
  updateVulnerabilityStatus,
  clearDatabase,
  deleteScan,
  insertWebFingerprint,
  getWebFingerprintsByScanId,
  getAllWebFingerprints
} from '../services/database'

export function registerScanIPC(mainWindow: BrowserWindow): void {
  // Scan lifecycle
  ipcMain.handle('scan:start', async (_event, scanId: string, _tool: string, args: string[], options?: { name?: string }) => {
    insertScan({
      id: scanId,
      name: options?.name,
      target: args[args.indexOf('-t') + 1] || 'unknown',
      status: 'running',
      tool: 'pipeline',
      args: JSON.stringify(args),
      started_at: new Date().toISOString()
    })
    const pid = scanner.startScan(mainWindow, scanId, 'pipeline', args)
    return { pid }
  })

  ipcMain.handle('scan:cancel', async (_event, scanId: string) => {
    const success = scanner.cancelScan(scanId)
    if (!success) {
      updateScanStatus(scanId, 'cancelled')
    }
    return { success }
  })

  // Database queries
  ipcMain.handle('db:getScans', async () => getScans())
  ipcMain.handle('db:getScanById', async (_e, id: string) => getScanById(id))
  ipcMain.handle('db:getHostsByScanId', async (_e, scanId: string) => getHostsByScanId(scanId))
  ipcMain.handle('db:getVulnsByScanId', async (_e, scanId: string) => getVulnerabilitiesByScanId(scanId))
  ipcMain.handle('db:getWebUrlsByScanId', async (_e, scanId: string) => getWebUrlsByScanId(scanId))
  ipcMain.handle('db:getScanStats', async () => getScanStats())
  ipcMain.handle('db:getAllHosts', async () => getAllHosts())
  ipcMain.handle('db:getAllVulns', async () => getAllVulnerabilities())
  ipcMain.handle('db:updateVulnStatus', async (_e, id: number, status: string) => updateVulnerabilityStatus(id, status))
  ipcMain.handle('db:getWebFingerprintsByScanId', async (_e, scanId: string) => getWebFingerprintsByScanId(scanId))
  ipcMain.handle('db:getAllWebFingerprints', async () => getAllWebFingerprints())

  ipcMain.handle('db:deleteScan', async (_e, id: string) => deleteScan(id))

  // Window controls
  ipcMain.handle('window:minimize', async () => {
    mainWindow.minimize()
  })

  ipcMain.handle('window:maximize', async () => {
    if (mainWindow.isMaximized()) {
      mainWindow.unmaximize()
    } else {
      mainWindow.maximize()
    }
  })

  ipcMain.handle('window:close', async () => {
    mainWindow.close()
  })

  // Database management
  ipcMain.handle('db:clearDatabase', async () => {
    clearDatabase()
  })

  // Utility
  ipcMain.handle('util:checkFileExists', async (_e, filePath: string) => {
    return fs.existsSync(filePath)
  })

  ipcMain.handle('util:openExternal', async (_e, url: string) => {
    if (url.startsWith('http://') || url.startsWith('https://')) {
      await shell.openExternal(url)
    }
  })

  ipcMain.handle('scan:isRunning', async (_e, scanId: string) => {
    return scanner.isScanRunning(scanId)
  })
}
