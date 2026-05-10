import { join } from 'path'
import { app } from 'electron'

const devBinaries: Record<string, string> = {
  naabu: 'D:\\netscan\\naabu\\naabu.exe',
  nmap: 'C:\\Program Files (x86)\\Nmap\\nmap.exe',
  httpx: 'D:\\netscan\\httpx\\httpx.exe',
  nuclei: 'D:\\netscan\\nuclei\\nuclei.exe',
}

export function getBinaryPath(tool: 'naabu' | 'nmap' | 'httpx' | 'nuclei'): string {
  if (!app.isPackaged) {
    return devBinaries[tool]
  }
  return join(process.resourcesPath, 'binaries', tool + (process.platform === 'win32' ? '.exe' : ''))
}
