# XingEye (星川之眼) — Enterprise Network Security Scanner

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-00f0ff" alt="Version">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2B-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/electron-35-blue" alt="Electron">
</p>

XingEye is an **internal network security scanning tool** designed for enterprise security engineers. It provides a visual, real-time pipeline for discovering network assets, identifying services, detecting vulnerabilities, and generating professional reports — all from a single desktop application.

**English Name:** XingEye  
**Chinese Name:** 星川之眼 (Star River Eye)

---

## Features

- **One-Click Network Discovery** — Scan entire subnets with a single click using the integrated tool pipeline
- **Automatic Service Identification** — nmap-powered version detection for 3000+ services
- **Vulnerability Detection** — NSE scripts + Nuclei templates (11,000+) for comprehensive CVE coverage
- **Weak Password Detection** — Automatic brute-force checks on SSH, FTP, RDP, MySQL, and more
- **Web Technology Fingerprinting** — Wappalyzer-powered detection of 3000+ web technologies
- **Real-Time Dashboard** — Color-coded terminal output during scans with live host/vuln discovery
- **Asset Tree View** — IP-grouped asset browser with parsed service fingerprints
- **Vulnerability Management** — Severity classification, status tracking, and Chinese translation
- **Report Generation** — HTML/CSV/JSON export with executive summaries and technical details
- **Dark Cyberpunk UI** — Custom frameless window with neon aesthetic designed for security tools

---

## Technology Stack

| Component | Tool | Version | Purpose |
|-----------|------|---------|---------|
| GUI | Electron 35 + React 19 | — | Desktop application framework |
| Phase 1 | [naabu](https://github.com/projectdiscovery/naabu) | 2.6+ | Fast port discovery |
| Phase 2 | [nmap](https://nmap.org) | 7.95 | Service/version detection + NSE vulnerability & brute-force scripts |
| Phase 3 | [httpx](https://github.com/projectdiscovery/httpx) | 1.9+ | Web probing + Wappalyzer tech detection |
| Phase 4 | [nuclei](https://github.com/projectdiscovery/nuclei) | 3.8+ | Template-based vulnerability scanning |
| Database | SQLite (better-sqlite3) | — | Local data persistence |

---

## Installation

### Prerequisites

- **Windows 10/11** (64-bit)
- **Node.js 18+**
- **Git**

### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/chu0119/xingeye.git
cd xingeye

# 2. Install dependencies
npm install

# 3. Download required tools
#    See the Tools Setup section below

# 4. Start the application
npm run dev
```

### Tools Setup

XingEye requires four external tools. Download and place them in the following locations:

| Tool | Download Link | Target Path |
|------|--------------|-------------|
| **nmap** | [nmap.org/download](https://nmap.org/download.html) | `C:\Program Files (x86)\Nmap\nmap.exe` |
| **naabu** | [GitHub Releases](https://github.com/projectdiscovery/naabu/releases) | `D:\netscan\naabu\naabu.exe` |
| **httpx** | [GitHub Releases](https://github.com/projectdiscovery/httpx/releases) | `D:\netscan\httpx\httpx.exe` |
| **nuclei** | [GitHub Releases](https://github.com/projectdiscovery/nuclei/releases) | `D:\netscan\nuclei\nuclei.exe` |

**Or use the automated setup script (Windows PowerShell, run as Administrator):**

```powershell
.\scripts\setup-tools.ps1
```

This script will automatically download and install all four tools to the correct locations.

### Build for Production

```bash
npm run build
```

The packaged application will be in the `release/` directory.

---

## Usage

### Basic Workflow

1. **Launch** XingEye
2. **New Scan** — Enter target (e.g., `192.168.1.0/24`) and select a scan template
3. **Start** — Watch real-time terminal output and live host/vuln discovery
4. **Browse Assets** — View discovered hosts grouped by IP with service fingerprints
5. **Review Vulnerabilities** — Filter by severity, change status, export to CSV/JSON
6. **Generate Report** — Create HTML/CSV/JSON reports with Chinese vulnerability translations

### Scan Templates

| Template | Ports | Use Case |
|----------|-------|----------|
| Quick Scan | Top 100 | Fast reconnaissance, ~30s |
| Full Scan | 1-65535 | Comprehensive asset discovery, ~5-10min |
| Web Deep Scan | Web ports | Web service + Nuclei scanning, ~3-15min |
| Custom | User-defined | Flexible configuration |

### Target Formats

```
192.168.1.1                  # Single IP
192.168.1.0/24               # CIDR subnet
192.168.1.1,10.0.0.1         # Multiple targets (comma-separated)
192.168.1.0/24,10.0.0.0/16   # Multiple subnets
```

---

## Architecture

```
┌────────────────────────────────────────────┐
│              Electron Main Process          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │  naabu   │→│   nmap   │→│  httpx   │→┐  │
│  │  ports   │ │ svc+vuln │ │ web tech │ │  │
│  └──────────┘ └──────────┘ └──────────┘ │  │
│                                          ↓  │
│                    ┌──────────┐              │
│                    │  nuclei  │              │
│                    │ CVEs/exp │              │
│                    └──────────┘              │
│                         │                    │
│                    ┌────↓────┐              │
│                    │ SQLite  │              │
│                    │   DB    │              │
│                    └─────────┘              │
├────────────────────────────────────────────┤
│           Electron Renderer Process         │
│  Dashboard │ ScanNew │ ScanResult │ Assets  │
│  Vulns     │ Reports │ Topology   │Settings │
└────────────────────────────────────────────┘
```

---

## Project Structure

```
xingeye/
├── src/
│   ├── main/              # Electron main process
│   │   ├── index.ts       # Window creation, context menu
│   │   ├── ipc/           # IPC handlers
│   │   ├── services/      # Scanner engine, database
│   │   └── utils/         # Binary path resolution
│   ├── preload/           # Context bridge
│   └── renderer/          # React frontend
│       ├── pages/         # All UI pages
│       ├── components/    # Shared components
│       ├── stores/        # Zustand state management
│       ├── utils/         # Translation utilities
│       └── styles/        # CSS and themes
├── scripts/               # Setup and utility scripts
├── electron.vite.config.ts
├── electron-builder.yml
└── package.json
```

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

The bundled tools (nmap, naabu, httpx, nuclei) are subject to their respective licenses:
- **nmap** — [Nmap Public Source License](https://nmap.org/npsl/)
- **naabu** — [MIT](https://github.com/projectdiscovery/naabu/blob/main/LICENSE.md)
- **httpx** — [MIT](https://github.com/projectdiscovery/httpx/blob/main/LICENSE.md)
- **nuclei** — [MIT](https://github.com/projectdiscovery/nuclei/blob/main/LICENSE.md)

---

## Acknowledgments

- [ProjectDiscovery](https://projectdiscovery.io) — naabu, httpx, nuclei
- [Nmap](https://nmap.org) — The gold standard for network discovery
- [Wappalyzer](https://www.wappalyzer.com) — Web technology identification database
- [Lucide](https://lucide.dev) — Beautiful open-source icons
- [ReactFlow](https://reactflow.dev) — Node-based visualization library
