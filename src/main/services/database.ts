import { app } from 'electron'
import Database from 'better-sqlite3'
import * as path from 'path'
import * as fs from 'fs'

let db: Database.Database | null = null

function getDbPath(): string {
  // In dev mode, use a fixed path under the project data directory.
  // In production, use Electron's userData directory.
  if (process.env.NODE_ENV === 'development' || !app.isPackaged) {
    const devDir = 'D:\\netscan\\cyberscan\\data'
    fs.mkdirSync(devDir, { recursive: true })
    return path.join(devDir, 'cyberscan.db')
  }
  return path.join(app.getPath('userData'), 'cyberscan.db')
}

function getDb(): Database.Database {
  if (!db) {
    throw new Error('Database not initialized. Call initDatabase() first.')
  }
  return db
}

export function initDatabase(): void {
  if (db) return

  const dbPath = getDbPath()
  const dir = path.dirname(dbPath)
  fs.mkdirSync(dir, { recursive: true })

  db = new Database(dbPath)

  // Enable WAL mode for better concurrent read performance.
  db.pragma('journal_mode = WAL')
  db.pragma('foreign_keys = ON')

  db.exec(`
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      name TEXT,
      target TEXT NOT NULL,
      status TEXT DEFAULT 'pending',
      tool TEXT NOT NULL,
      args TEXT,
      started_at DATETIME,
      completed_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS hosts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id TEXT NOT NULL,
      ip TEXT NOT NULL,
      port TEXT,
      service TEXT,
      url TEXT,
      keyword TEXT,
      fingerprint TEXT,
      os TEXT,
      discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id TEXT NOT NULL,
      template_id TEXT,
      name TEXT,
      severity TEXT,
      host TEXT,
      matched_at TEXT,
      description TEXT,
      solution TEXT,
      raw_data TEXT,
      status TEXT DEFAULT 'open',
      discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS web_urls (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id TEXT NOT NULL,
      url TEXT NOT NULL,
      title TEXT,
      tech_stack TEXT,
      status_code INTEGER,
      discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );
  `)

  // Indexes for performance
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_hosts_scan_id ON hosts(scan_id);
    CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
    CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulnerabilities(scan_id);
    CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
    CREATE INDEX IF NOT EXISTS idx_weburls_scan_id ON web_urls(scan_id);
  `)

  // web_fingerprints table
  db.exec(`
    CREATE TABLE IF NOT EXISTS web_fingerprints (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id TEXT NOT NULL,
      url TEXT NOT NULL,
      tech_name TEXT NOT NULL,
      category TEXT,
      version TEXT,
      confidence INTEGER DEFAULT 0,
      discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_wf_scan_id ON web_fingerprints(scan_id);
    CREATE INDEX IF NOT EXISTS idx_wf_url ON web_fingerprints(url);
  `)

  // Migration: add 'name' column to existing scans table
  try {
    db.exec(`ALTER TABLE scans ADD COLUMN name TEXT`)
  } catch {
    // Column already exists — ignore
  }
}

// ---------------------------------------------------------------------------
// Insert operations (prepared statements)
// ---------------------------------------------------------------------------

const stmtCache = new Map<string, Database.Statement>()

function toCamelCase(row: any): any {
  if (!row || typeof row !== 'object') return row
  const out: any = {}
  for (const key of Object.keys(row)) {
    const camel = key.replace(/_([a-z])/g, (_, c) => c.toUpperCase())
    out[camel] = row[key]
  }
  return out
}

function toCamelCaseArray(rows: any[]): any[] {
  return rows.map(toCamelCase)
}

function prepare(sql: string): Database.Statement {
  const database = getDb()
  let stmt = stmtCache.get(sql)
  if (!stmt) {
    stmt = database.prepare(sql)
    stmtCache.set(sql, stmt)
  }
  return stmt
}

export function insertScan(scan: {
  id: string
  name?: string
  target: string
  status: string
  tool: string
  args?: string
  started_at?: string
}): void {
  prepare(
    `INSERT INTO scans (id, name, target, status, tool, args, started_at)
     VALUES (@id, @name, @target, @status, @tool, @args, @started_at)`
  ).run({
    id: scan.id,
    name: scan.name ?? null,
    target: scan.target,
    status: scan.status,
    tool: scan.tool,
    args: scan.args ?? null,
    started_at: scan.started_at ?? null
  })
}

export function updateScanStatus(
  id: string,
  status: string,
  completed_at?: string
): void {
  prepare(
    `UPDATE scans SET status = @status, completed_at = @completed_at WHERE id = @id`
  ).run({
    id,
    status,
    completed_at: completed_at ?? null
  })
}

export function insertHost(host: {
  scan_id: string
  ip: string
  port?: string
  service?: string
  url?: string
  keyword?: string
  fingerprint?: string
  os?: string
}): void {
  prepare(
    `INSERT INTO hosts (scan_id, ip, port, service, url, keyword, fingerprint, os)
     VALUES (@scan_id, @ip, @port, @service, @url, @keyword, @fingerprint, @os)`
  ).run({
    scan_id: host.scan_id,
    ip: host.ip,
    port: host.port ?? null,
    service: host.service ?? null,
    url: host.url ?? null,
    keyword: host.keyword ?? null,
    fingerprint: host.fingerprint ?? null,
    os: host.os ?? null
  })
}

export function insertVulnerability(vuln: {
  scan_id: string
  template_id?: string
  name?: string
  severity?: string
  host?: string
  matched_at?: string
  description?: string
  solution?: string
  raw_data?: string
}): void {
  prepare(
    `INSERT INTO vulnerabilities (scan_id, template_id, name, severity, host, matched_at, description, solution, raw_data)
     VALUES (@scan_id, @template_id, @name, @severity, @host, @matched_at, @description, @solution, @raw_data)`
  ).run({
    scan_id: vuln.scan_id,
    template_id: vuln.template_id ?? null,
    name: vuln.name ?? null,
    severity: vuln.severity ?? null,
    host: vuln.host ?? null,
    matched_at: vuln.matched_at ?? null,
    description: vuln.description ?? null,
    solution: vuln.solution ?? null,
    raw_data: vuln.raw_data ?? null
  })
}

export function insertWebUrl(wu: {
  scan_id: string
  url: string
  title?: string
  tech_stack?: string
  status_code?: number
}): void {
  prepare(
    `INSERT INTO web_urls (scan_id, url, title, tech_stack, status_code)
     VALUES (@scan_id, @url, @title, @tech_stack, @status_code)`
  ).run({
    scan_id: wu.scan_id,
    url: wu.url,
    title: wu.title ?? null,
    tech_stack: wu.tech_stack ?? null,
    status_code: wu.status_code ?? null
  })
}

export function insertWebFingerprint(fp: {
  scan_id: string
  url: string
  tech_name: string
  category?: string
  version?: string
  confidence?: number
}): void {
  prepare(
    `INSERT INTO web_fingerprints (scan_id, url, tech_name, category, version, confidence)
     VALUES (@scan_id, @url, @tech_name, @category, @version, @confidence)`
  ).run({
    scan_id: fp.scan_id,
    url: fp.url,
    tech_name: fp.tech_name,
    category: fp.category ?? null,
    version: fp.version ?? null,
    confidence: fp.confidence ?? 0
  })
}

export function getWebFingerprintsByScanId(scanId: string): any[] {
  return toCamelCaseArray(prepare(
    'SELECT * FROM web_fingerprints WHERE scan_id = @scan_id ORDER BY confidence DESC'
  ).all({ scan_id: scanId }))
}

export function getAllWebFingerprints(): any[] {
  return toCamelCaseArray(prepare(
    'SELECT * FROM web_fingerprints ORDER BY discovered_at DESC'
  ).all())
}

// ---------------------------------------------------------------------------
// Query operations
// ---------------------------------------------------------------------------

export function getScans(): any[] {
  return toCamelCaseArray(prepare('SELECT * FROM scans ORDER BY created_at DESC').all())
}

export function getScanById(id: string): any {
  return toCamelCase(prepare('SELECT * FROM scans WHERE id = @id').get({ id }))
}

export function getHostsByScanId(scanId: string): any[] {
  return toCamelCaseArray(prepare('SELECT * FROM hosts WHERE scan_id = @scan_id ORDER BY discovered_at DESC').all({
    scan_id: scanId
  }))
}

export function getVulnerabilitiesByScanId(scanId: string): any[] {
  return toCamelCaseArray(prepare('SELECT * FROM vulnerabilities WHERE scan_id = @scan_id ORDER BY discovered_at DESC').all({
    scan_id: scanId
  }))
}

export function getWebUrlsByScanId(scanId: string): any[] {
  return toCamelCaseArray(prepare('SELECT * FROM web_urls WHERE scan_id = @scan_id ORDER BY discovered_at DESC').all({
    scan_id: scanId
  }))
}

export function getScanStats(): {
  totalScans: number
  totalHosts: number
  totalVulns: number
  criticalVulns: number
} {
  const database = getDb()

  const totalScans = (
    database.prepare('SELECT COUNT(*) AS count FROM scans').get() as { count: number }
  ).count

  const totalHosts = (
    database.prepare('SELECT COUNT(DISTINCT ip) AS count FROM hosts').get() as { count: number }
  ).count

  const totalVulns = (
    database.prepare('SELECT COUNT(*) AS count FROM vulnerabilities').get() as { count: number }
  ).count

  const criticalVulns = (
    database.prepare(
      "SELECT COUNT(*) AS count FROM vulnerabilities WHERE severity = 'critical'"
    ).get() as { count: number }
  ).count

  return { totalScans, totalHosts, totalVulns, criticalVulns }
}

export function getAllHosts(): any[] {
  return toCamelCaseArray(prepare(
    `SELECT h.*,
       (SELECT COUNT(*) FROM vulnerabilities v WHERE v.host = h.ip) AS vulnCount
     FROM hosts h
     ORDER BY h.ip, h.port`
  ).all())
}

export function getAllVulnerabilities(): any[] {
  return toCamelCaseArray(prepare('SELECT * FROM vulnerabilities ORDER BY discovered_at DESC').all())
}

export function updateVulnerabilityStatus(id: number, status: string): void {
  prepare('UPDATE vulnerabilities SET status = @status WHERE id = @id').run({ id, status })
}

export function clearDatabase(): void {
  const database = getDb()
  database.prepare('DELETE FROM web_fingerprints').run()
  database.prepare('DELETE FROM web_urls').run()
  database.prepare('DELETE FROM vulnerabilities').run()
  database.prepare('DELETE FROM hosts').run()
  database.prepare('DELETE FROM scans').run()
}

export function deleteScan(id: string): void {
  const database = getDb()
  database.prepare('DELETE FROM web_fingerprints WHERE scan_id = @id').run({ id })
  database.prepare('DELETE FROM web_urls WHERE scan_id = @id').run({ id })
  database.prepare('DELETE FROM vulnerabilities WHERE scan_id = @id').run({ id })
  database.prepare('DELETE FROM hosts WHERE scan_id = @id').run({ id })
  database.prepare('DELETE FROM scans WHERE id = @id').run({ id })
}
