import { join, dirname } from 'path'
import { app } from 'electron'
import { existsSync } from 'fs'

// In development, look for tools in the project root's 'tools' directory
// or in standard system paths
function findDevBinary(name: string, fallbackPaths: string[]): string {
  // Check fallback paths first (user-configured or common locations)
  for (const p of fallbackPaths) {
    if (existsSync(p)) return p
  }
  // Check in project-relative tools directory
  const projectRoot = app.isPackaged ? process.resourcesPath : join(dirname(__dirname), '..', '..', '..')
  const projectPath = join(projectRoot, 'tools', name + '.exe')
  if (existsSync(projectPath)) return projectPath
  // Return the first fallback path anyway (spawn will error if it doesn't exist)
  return fallbackPaths[0] || projectPath
}

const devFallbacks: Record<string, string[]> = {
  naabu: [
    'D:\\netscan\\naabu\\naabu.exe',
    join(app.getPath('home'), 'netscan', 'naabu', 'naabu.exe'),
  ],
  nmap: [
    'C:\\Program Files (x86)\\Nmap\\nmap.exe',
    'C:\\Program Files\\Nmap\\nmap.exe',
  ],
  httpx: [
    'D:\\netscan\\httpx\\httpx.exe',
    join(app.getPath('home'), 'netscan', 'httpx', 'httpx.exe'),
  ],
  nuclei: [
    'D:\\netscan\\nuclei\\nuclei.exe',
    join(app.getPath('home'), 'netscan', 'nuclei', 'nuclei.exe'),
  ],
}

export function getBinaryPath(tool: 'naabu' | 'nmap' | 'httpx' | 'nuclei'): string {
  if (!app.isPackaged) {
    return findDevBinary(tool, devFallbacks[tool] || [])
  }
  return join(process.resourcesPath, 'binaries', tool + (process.platform === 'win32' ? '.exe' : ''))
}
