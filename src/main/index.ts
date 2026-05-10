import { app, BrowserWindow, Menu } from 'electron'
import { join } from 'path'
import { registerScanIPC } from './ipc/scan'
import { initDatabase } from './services/database'

app.commandLine.appendSwitch('enable-gpu-rasterization')
app.commandLine.appendSwitch('enable-zero-copy')
app.commandLine.appendSwitch('ignore-gpu-blocklist')

let mainWindow: BrowserWindow | null = null

function createWindow(): void {
  mainWindow = new BrowserWindow({
    title: '星川之眼 XingEye',
    width: 1400,
    height: 900,
    minWidth: 1200,
    minHeight: 700,
    frame: false,
    backgroundColor: '#0a0a0f',
    backgroundThrottling: false,
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  })

  registerScanIPC(mainWindow)

  if (process.env.ELECTRON_RENDERER_URL) {
    mainWindow.loadURL(process.env.ELECTRON_RENDERER_URL)
  } else {
    mainWindow.loadFile(join(__dirname, '../renderer/index.html'))
  }

  // Fix: ensure window gets focus on startup (frameless windows need explicit focus)
  mainWindow.once('ready-to-show', () => {
    mainWindow?.focus()
    mainWindow?.webContents.focus()
  })

  // Enable right-click context menu for copy/paste
  mainWindow.webContents.on('context-menu', (_event, params) => {
    const { editFlags } = params
    const canCopy = editFlags.canCopy
    const canPaste = editFlags.canPaste
    const canCut = editFlags.canCut
    const canSelectAll = editFlags.canSelectAll

    const menuItems: Electron.MenuItemConstructorOptions[] = []

    if (canCut) {
      menuItems.push({ label: '剪切', role: 'cut', accelerator: 'Ctrl+X', enabled: canCut })
    }
    if (canCopy) {
      menuItems.push({ label: '复制', role: 'copy', accelerator: 'Ctrl+C', enabled: canCopy })
    }
    if (canPaste) {
      menuItems.push({ label: '粘贴', role: 'paste', accelerator: 'Ctrl+V', enabled: canPaste })
    }
    if (canSelectAll) {
      menuItems.push({ label: '全选', role: 'selectAll', accelerator: 'Ctrl+A', enabled: canSelectAll })
    }

    if (menuItems.length > 0) {
      Menu.buildFromTemplate(menuItems).popup({ window: mainWindow! })
    }
  })

  mainWindow.on('closed', () => {
    mainWindow = null
  })
}

app.whenReady().then(() => {
  initDatabase()
  createWindow()

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow()
    }
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit()
  }
})
