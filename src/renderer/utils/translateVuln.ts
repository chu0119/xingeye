// Vulnerability name translation map (English → Chinese)
// Covers the most common Nuclei template categories

const nameMap: Record<string, string> = {
  // Version disclosure
  'version disclosure': '版本信息泄露',
  'version detect': '版本检测',
  'version detection': '版本检测',
  'tech detect': '技术栈识别',
  'technology detection': '技术栈识别',

  // Exposed panels & pages
  'exposed panel': '管理面板暴露',
  'login page': '登录页面暴露',
  'admin panel': '管理后台暴露',
  'admin login': '管理员登录',
  'dashboard exposure': '控制面板暴露',
  'debug mode': '调试模式开启',
  'phpinfo': 'PHP 信息泄露',
  'server status': '服务器状态页暴露',
  'directory listing': '目录列表泄露',
  'exposed configuration': '配置文件暴露',
  'configuration file': '配置文件暴露',
  'config file': '配置文件暴露',
  'backup file': '备份文件暴露',
  'database backup': '数据库备份暴露',
  'source code disclosure': '源码泄露',
  'source code': '源码泄露',
  'error page': '错误页面信息泄露',
  'stack trace': '堆栈跟踪泄露',
  'trace method': 'TRACE 方法启用',

  // Authentication & credentials
  'default credentials': '默认凭证',
  'default password': '默认密码',
  'default login': '默认登录凭证',
  'weak password': '弱口令',
  'weak credentials': '弱口令',
  'brute force': '暴力破解',
  'authentication bypass': '认证绕过',
  'auth bypass': '认证绕过',
  'unauthorized access': '未授权访问',

  // Injection
  'sql injection': 'SQL 注入',
  'sqli': 'SQL 注入',
  'blind sql': 'SQL 盲注',
  'nosql injection': 'NoSQL 注入',
  'command injection': '命令注入',
  'code injection': '代码注入',
  'template injection': '模板注入',
  'ssti': '服务端模板注入',
  'ldap injection': 'LDAP 注入',
  'xpath injection': 'XPath 注入',
  'xml injection': 'XML 注入',
  'xxe': 'XML 外部实体注入',
  'xml external entity': 'XML 外部实体注入',

  // XSS
  'xss': '跨站脚本攻击',
  'cross site scripting': '跨站脚本攻击',
  'reflected xss': '反射型 XSS',
  'stored xss': '存储型 XSS',
  'dom xss': 'DOM 型 XSS',

  // CSRF & SSRF
  'csrf': '跨站请求伪造',
  'cross site request forgery': '跨站请求伪造',
  'ssrf': '服务端请求伪造',
  'server side request forgery': '服务端请求伪造',

  // File inclusion
  'lfi': '本地文件包含',
  'local file inclusion': '本地文件包含',
  'rfi': '远程文件包含',
  'remote file inclusion': '远程文件包含',
  'path traversal': '路径遍历',
  'directory traversal': '目录遍历',

  // RCE
  'rce': '远程代码执行',
  'remote code execution': '远程代码执行',
  'arbitrary file read': '任意文件读取',
  'arbitrary file upload': '任意文件上传',
  'file upload': '文件上传漏洞',

  // CORS & security headers
  'cors': '跨域资源共享配置不当',
  'cors misconfiguration': 'CORS 配置不当',
  'csp': '内容安全策略缺失',
  'hsts': 'HSTS 未启用',
  'security header': '安全响应头缺失',
  'missing header': '安全响应头缺失',
  'x frame options': 'X-Frame-Options 缺失',
  'x content type': 'X-Content-Type-Options 缺失',
  'content type options': 'Content-Type-Options 缺失',
  'xss protection': 'XSS 保护头缺失',

  // SSL/TLS
  'ssl certificate': 'SSL 证书问题',
  'tls version': 'TLS 版本过旧',
  'ssl expired': 'SSL 证书过期',
  'self signed': '自签名证书',
  'weak cipher': '弱加密算法',
  'heartbleed': 'Heartbleed 漏洞',
  'poodle': 'POODLE 漏洞',

  // CMS specific
  'wordpress': 'WordPress 漏洞',
  'wp content': 'WordPress 内容泄露',
  'wp json': 'WordPress REST API 暴露',
  'xmlrpc': 'XML-RPC 接口暴露',
  'joomla': 'Joomla 漏洞',
  'drupal': 'Drupal 漏洞',

  // Web servers
  'apache': 'Apache 漏洞',
  'nginx': 'Nginx 漏洞',
  'iis': 'IIS 漏洞',
  'tomcat': 'Tomcat 漏洞',
  'weblogic': 'WebLogic 漏洞',
  'jboss': 'JBoss 漏洞',

  // Common vulnerability patterns
  'open redirect': '开放重定向',
  'openredirect': '开放重定向',
  'redirect': '重定向漏洞',
  'clickjacking': '点击劫持',
  'cookie': 'Cookie 安全问题',
  'httpOnly': 'HttpOnly 标志缺失',
  'secure flag': 'Secure 标志缺失',
  'samesite': 'SameSite 属性缺失',
  'cache control': '缓存控制不当',
  'rate limiting': '速率限制缺失',
  'rate limit': '速率限制缺失',
  'dos': '拒绝服务',
  'denial of service': '拒绝服务',

  // Database
  'mysql': 'MySQL 漏洞',
  'mongodb': 'MongoDB 漏洞',
  'redis': 'Redis 漏洞',
  'elasticsearch': 'Elasticsearch 漏洞',
  'memcached': 'Memcached 漏洞',
  'postgresql': 'PostgreSQL 漏洞',

  // DevOps & infrastructure
  'docker': 'Docker 安全风险',
  'kubernetes': 'Kubernetes 安全风险',
  'k8s': 'Kubernetes 安全风险',
  'etcd': 'etcd 暴露',
  'jenkins': 'Jenkins 漏洞',
  'gitlab': 'GitLab 漏洞',
  'github': 'GitHub 信息泄露',
  'git exposure': 'Git 仓库暴露',
  'svn exposure': 'SVN 仓库暴露',
  'env file': '环境变量文件暴露',
  'dotenv': '.env 文件暴露',
  'npmrc': 'npm 配置文件暴露',

  // Miscellaneous
  'waf': 'WAF 检测',
  'cdn': 'CDN 检测',
  'fingerprint': '指纹识别',
  'takeover': '子域名接管',
  'subdomain takeover': '子域名接管',
  'dangling': '悬挂 DNS 记录',

  // Nuclei info level
  'http missing': 'HTTP 安全头缺失',
  'allowed methods': 'HTTP 方法检测',
  'options method': 'OPTIONS 方法启用',
  'put method': 'PUT 方法启用',
  'delete method': 'DELETE 方法启用',

  // Crack/brute related
  'crack': '弱口令/爆破',
  'cracksuccess': '爆破成功',
  'default': '默认配置',
  'exposure': '信息暴露',
  'disclosure': '信息泄露',
  'detection': '信息检测',
  'misconfiguration': '配置不当',
  'missing': '缺失检测',
  'deprecated': '已弃用版本',
  'outdated': '版本过旧',
}

const severityMap: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
  unknown: '未知',
}

// Common phrase replacements within longer names
const phraseReplacements: [RegExp, string][] = [
  [/exposed\s+to/i, '暴露'],
  [/detected/i, '检测到'],
  [/discovered/i, '发现'],
  [/found/i, '发现'],
  [/possible/i, '可能存在'],
  [/potential/i, '潜在'],
  [/vulnerable/i, '存在漏洞'],
  [/vulnerability/i, '漏洞'],
  [/misconfigured/i, '配置不当'],
  [/missing\s+secure\s+flag/i, 'Secure 标志缺失'],
  [/missing\s+httponly\s+flag/i, 'HttpOnly 标志缺失'],
  [/without\s+secure/i, '缺少 Secure'],
  [/without\s+httponly/i, '缺少 HttpOnly'],
  [/insecure/i, '不安全'],
  [/unauthenticated/i, '未认证'],
  [/unauthorized/i, '未授权'],
  [/bypass/i, '绕过'],
  [/overflow/i, '溢出'],
  [/outdated\s+version/i, '版本过旧'],
  [/end\s+of\s+life/i, '已停止维护'],
  [/not\s+properly/i, '未正确配置'],
]

export function translateVulnName(name: string): string {
  if (!name) return '未知漏洞'

  const lower = name.toLowerCase().trim()

  // Direct match first
  for (const [en, zh] of Object.entries(nameMap)) {
    if (lower.includes(en)) return zh
  }

  // Phrase replacement
  let result = name
  for (const [regex, replacement] of phraseReplacements) {
    result = result.replace(regex, replacement)
  }

  // If no translation applied, add prefix for Chinese readability
  if (result === name) {
    // Try to extract meaningful part from common patterns like:
    // "tech-detect: nginx" → "技术栈识别: nginx"
    // "exposed-panel: phpmyadmin" → "管理面板暴露: phpmyadmin"
    const colonIdx = name.indexOf(':')
    if (colonIdx > 0) {
      const prefix = name.substring(0, colonIdx).toLowerCase().trim()
      const detail = name.substring(colonIdx + 1).trim()
      // Try translating the prefix
      for (const [en, zh] of Object.entries(nameMap)) {
        if (prefix.includes(en)) return `${zh}: ${detail}`
      }
      // Known prefixes
      if (prefix.includes('tech')) return `技术栈识别: ${detail}`
      if (prefix.includes('panel') || prefix.includes('exposed')) return `面板暴露: ${detail}`
      if (prefix.includes('detect')) return `检测: ${detail}`
      if (prefix.includes('cve')) return `CVE 漏洞: ${detail}`
    }
    // Return with generic label for unnamed vulns
    return `安全风险: ${name}`
  }

  return result
}

export function translateSeverity(severity: string): string {
  return severityMap[severity.toLowerCase()] || severity
}

export function translateDescription(desc: string): string {
  if (!desc) return ''
  const lower = desc.toLowerCase()
  // Translate common description fragments
  let result = desc
    .replace(/this template detects/i, '此模板检测')
    .replace(/this vulnerability allows/i, '此漏洞允许攻击者')
    .replace(/an attacker could/i, '攻击者可能')
    .replace(/it is recommended/i, '建议')
    .replace(/update to the latest version/i, '更新到最新版本')
    .replace(/apply the security patch/i, '应用安全补丁')
    .replace(/restrict access/i, '限制访问权限')
    .replace(/disable unnecessary features/i, '禁用不必要的功能')
    .replace(/use strong passwords/i, '使用强密码')
    .replace(/enable authentication/i, '启用身份认证')
    .replace(/configure firewall rules/i, '配置防火墙规则')
    .replace(/regular security audits/i, '定期安全审计')
  return result
}
