'use strict'

const fs = require('fs')
const path = require('path')
const express = require('express')
const yaml = require('js-yaml')
const { buildLoonConfig } = require('./lib/convert')

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data')
const DATA_FILE = path.join(DATA_DIR, 'settings.json')
const PORT = process.env.PORT || 8787

const DEFAULT_SETTINGS = {
  sourceUrl: '',
  plugins: [],
  general: {
    'ip-mode': 'dual',
    'dns-server': 'system,8.8.8.8,1.1.1.1',
    'sni-sniffing': true,
    'disable-stun': true,
    'udp-fallback-mode': 'REJECT',
    'test-timeout': 5,
    'internet-test-url': 'http://connectivitycheck.platform.hicloud.com/generate_204',
    'proxy-test-url': 'http://www.gstatic.com/generate_204',
  },
  remoteProxies: [],
  proxyChains: [],
  remoteRules: [],
  hosts: [],
  rewrites: [],
  scripts: [],
  mitm: { hostname: [] },
  advancedTemplates: {
    general: '',
    remoteProxy: '',
    proxyChain: '',
    remoteRule: '',
    host: '',
    rewrite: '',
    script: '',
    mitm: '',
  },
  cachedConfig: null,
}

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true })
if (!fs.existsSync(DATA_FILE)) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(DEFAULT_SETTINGS, null, 2))
}

function loadSettings() {
  let s
  try {
    s = JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'))
  } catch (e) {
    console.error('settings.json 解析失败，重置为默认:', e.message)
    s = JSON.parse(JSON.stringify(DEFAULT_SETTINGS))
    saveSettings(s)
  }
  return migrateSettings(s)
}

function saveSettings(s) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(s, null, 2))
}

function migrateSettings(s) {
  // 补齐根级字段
  for (const key of Object.keys(DEFAULT_SETTINGS)) {
    if (s[key] === undefined) s[key] = DEFAULT_SETTINGS[key]
  }
  if (!Array.isArray(s.plugins)) s.plugins = []
  for (const p of s.plugins) {
    if (!p.meta || typeof p.meta !== 'object') {
      p.meta = { name: '', desc: '', author: '', icon: '' }
    }
  }
  if (!s.general || typeof s.general !== 'object') s.general = DEFAULT_SETTINGS.general
  if (!Array.isArray(s.remoteProxies)) s.remoteProxies = []
  if (!Array.isArray(s.proxyChains)) s.proxyChains = []
  if (!Array.isArray(s.remoteRules)) s.remoteRules = []
  if (!Array.isArray(s.hosts)) s.hosts = []
  if (!Array.isArray(s.rewrites)) s.rewrites = []
  if (!Array.isArray(s.scripts)) s.scripts = []
  if (!s.mitm || typeof s.mitm !== 'object') s.mitm = DEFAULT_SETTINGS.mitm
  if (!Array.isArray(s.mitm.hostname)) s.mitm.hostname = []
  if (!s.advancedTemplates || typeof s.advancedTemplates !== 'object') s.advancedTemplates = DEFAULT_SETTINGS.advancedTemplates
  if (!s.cachedConfig || typeof s.cachedConfig !== 'object') s.cachedConfig = DEFAULT_SETTINGS.cachedConfig

  // 旧版纯文本模板迁移：如果有旧模板字段，优先放进 advancedTemplates
  const legacyMap = {
    generalTemplate: 'general',
    remoteProxyTemplate: 'remoteProxy',
    proxyChainTemplate: 'proxyChain',
    hostTemplate: 'host',
    rewriteTemplate: 'rewrite',
    scriptTemplate: 'script',
    mitmTemplate: 'mitm',
    remoteRuleTemplate: 'remoteRule',
  }
  for (const [oldKey, newKey] of Object.entries(legacyMap)) {
    if (typeof s[oldKey] === 'string' && s[oldKey].trim()) {
      s.advancedTemplates[newKey] = s[oldKey]
      delete s[oldKey]
    }
  }
  return s
}

function pluginsToLines(plugins) {
  if (!Array.isArray(plugins)) return []
  return plugins
    .filter((p) => p && p.enabled !== false && p.url)
    .map((p) => {
      const name = p.name && p.name !== p.url ? p.name : null
      return name ? `${p.url}, tag=${name}, enabled=true` : `${p.url}, enabled=true`
    })
}

async function fetchAndConvert(sourceUrl) {
  if (!sourceUrl) throw new Error('未配置 Mihomo 配置源链接（source URL）')
  const res = await fetch(sourceUrl, { redirect: 'follow' })
  if (!res.ok) throw new Error(`拉取源配置失败: HTTP ${res.status}`)
  const text = await res.text()
  let doc
  try {
    doc = yaml.load(text)
  } catch (e) {
    throw new Error(`YAML 解析失败: ${e.message}`)
  }
  if (!doc || typeof doc !== 'object') throw new Error('源配置不是合法的 YAML')

  const proxies = Array.isArray(doc.proxies) ? doc.proxies : []
  const groups = Array.isArray(doc['proxy-groups']) ? doc['proxy-groups'] : []
  const rules = Array.isArray(doc.rules) ? doc.rules : []
  const ruleProviders = (doc['rule-providers'] && typeof doc['rule-providers'] === 'object') ? doc['rule-providers'] : {}

  const settings = loadSettings()
  const pluginLines = pluginsToLines(settings.plugins || [])

  const { text: loonText, skipped } = buildLoonConfig({
    proxies,
    groups,
    rules,
    ruleProviders,
    pluginLines,
    general: settings.general,
    remoteProxies: settings.remoteProxies,
    proxyChains: settings.proxyChains,
    remoteRules: settings.remoteRules,
    hosts: settings.hosts,
    rewrites: settings.rewrites,
    scripts: settings.scripts,
    mitm: settings.mitm,
    advancedTemplates: settings.advancedTemplates,
  })

  return { loonText, skipped, counts: { proxies: proxies.length, groups: groups.length, rules: rules.length } }
}

const app = express()
app.use(express.json())
app.use(express.static(path.join(__dirname, 'public')))

// ---- settings ---------------------------------------------------------------
app.get('/api/settings', (req, res) => {
  res.json(loadSettings())
})

app.post('/api/settings', (req, res) => {
  const settings = loadSettings()
  if (typeof req.body.sourceUrl === 'string') settings.sourceUrl = req.body.sourceUrl.trim()
  if (req.body.general && typeof req.body.general === 'object') settings.general = req.body.general
  if (req.body.mitm && typeof req.body.mitm === 'object') settings.mitm = req.body.mitm
  if (req.body.advancedTemplates && typeof req.body.advancedTemplates === 'object') {
    settings.advancedTemplates = { ...settings.advancedTemplates, ...req.body.advancedTemplates }
  }
  saveSettings(settings)
  res.json(settings)
})

// ---- plugin management ------------------------------------------------------
app.get('/api/plugins', (req, res) => {
  const settings = loadSettings()
  const plugins = settings.plugins || []
  // 后台刷新没有 meta 的插件信息（不阻塞响应）
  for (const p of plugins) {
    if (!p.meta || !p.meta.name) {
      fetchPluginMeta(p.url).then((meta) => {
        if (meta && meta.name) {
          const current = loadSettings()
          const plugin = current.plugins.find((x) => x.id === p.id)
          if (plugin) {
            plugin.meta = meta
            saveSettings(current)
          }
        }
      }).catch(() => {})
    }
  }
  res.json(plugins)
})

function makeId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8)
}

async function fetchPluginMeta(url) {
  try {
    const res = await fetch(url, { redirect: 'follow' })
    if (!res.ok) return null
    const text = await res.text()
    const meta = { name: '', desc: '', author: '', icon: '' }
    const lines = text.split('\n').slice(0, 30)

    // Loon plugin 标准格式
    for (const line of lines) {
      const trimmed = line.trim()
      if (trimmed.startsWith('#!name=')) meta.name = trimmed.slice(7).trim()
      else if (trimmed.startsWith('#!desc=')) meta.desc = trimmed.slice(7).trim()
      else if (trimmed.startsWith('#!author=')) meta.author = trimmed.slice(9).trim()
      else if (trimmed.startsWith('#!icon=')) meta.icon = trimmed.slice(7).trim()
    }

    // 如果标准格式没找到，尝试从注释中提取
    if (!meta.name) {
      for (const line of lines) {
        const trimmed = line.trim()
        // 脚本功能：xxx
        const m1 = trimmed.match(/脚本功能[：:]\s*(.+)/)
        if (m1) {
          meta.name = m1[1].trim()
          continue
        }
        // 功能：xxx
        const m2 = trimmed.match(/功能[：:]\s*(.+)/)
        if (m2 && !meta.name) {
          meta.name = m2[1].trim()
        }
      }
    }

    return meta
  } catch (e) {
    return null
  }
}

app.post('/api/plugins', async (req, res) => {
  const { name, url } = req.body
  if (!url) return res.status(400).json({ error: 'url 必填（插件/模块的订阅链接）' })
  const settings = loadSettings()
  if (!Array.isArray(settings.plugins)) settings.plugins = []
  const meta = await fetchPluginMeta(url)
  settings.plugins.push({
    id: makeId(),
    name: name || (meta && meta.name) || url,
    url,
    enabled: true,
    meta: meta || { name: '', desc: '', author: '', icon: '' },
  })
  saveSettings(settings)
  res.json(settings.plugins)
})

app.patch('/api/plugins/:id', async (req, res) => {
  const settings = loadSettings()
  const plugin = settings.plugins.find((p) => p.id === req.params.id)
  if (!plugin) return res.status(404).json({ error: 'not found' })
  if (typeof req.body.enabled === 'boolean') plugin.enabled = req.body.enabled
  if (typeof req.body.name === 'string') plugin.name = req.body.name
  if (typeof req.body.url === 'string') {
    plugin.url = req.body.url
    const meta = await fetchPluginMeta(plugin.url)
    if (meta) plugin.meta = meta
  }
  saveSettings(settings)
  res.json(settings.plugins)
})

app.delete('/api/plugins/:id', (req, res) => {
  const settings = loadSettings()
  settings.plugins = settings.plugins.filter((p) => p.id !== req.params.id)
  saveSettings(settings)
  res.json(settings.plugins)
})

// ---- structured list resources ---------------------------------------------
const LIST_KEYS = ['remoteProxies', 'proxyChains', 'remoteRules', 'hosts', 'rewrites', 'scripts']

function getList(settings, key) {
  return Array.isArray(settings[key]) ? settings[key] : []
}

function validateItem(key, item) {
  switch (key) {
    case 'remoteProxies':
      if (!item.url) throw new Error('Remote Proxy 必须填写 url')
      break
    case 'proxyChains':
      if (!item.name || !item.chain) throw new Error('Proxy Chain 必须填写 name 和 chain')
      break
    case 'remoteRules':
      if (!item.url || !item.policy) throw new Error('Remote Rule 必须填写 url 和 policy')
      break
    case 'hosts':
      if (!item.domain || !item.ip) throw new Error('Host 必须填写 domain 和 ip')
      break
    case 'rewrites':
      if (!item.match || !item.target) throw new Error('Rewrite 必须填写 match 和 target')
      break
    case 'scripts':
      if (!item.type || !item.match || !item.scriptPath) throw new Error('Script 必须填写 type、match、scriptPath')
      break
  }
}

for (const key of LIST_KEYS) {
  app.get(`/api/${key}`, (req, res) => {
    res.json(getList(loadSettings(), key))
  })

  app.post(`/api/${key}`, (req, res) => {
    const settings = loadSettings()
    const item = { ...req.body, id: req.body.id || makeId() }
    try {
      validateItem(key, item)
    } catch (e) {
      return res.status(400).json({ error: e.message })
    }
    settings[key] = settings[key] || []
    settings[key].push(item)
    saveSettings(settings)
    res.json(settings[key])
  })

  app.patch(`/api/${key}/:id`, (req, res) => {
    const settings = loadSettings()
    if (!Array.isArray(settings[key])) settings[key] = []
    const item = settings[key].find((x) => x && x.id === req.params.id)
    if (!item) return res.status(404).json({ error: 'not found' })
    for (const k of Object.keys(req.body)) {
      if (k !== 'id') item[k] = req.body[k]
    }
    saveSettings(settings)
    res.json(settings[key])
  })

  app.delete(`/api/${key}/:id`, (req, res) => {
    const settings = loadSettings()
    if (!Array.isArray(settings[key])) settings[key] = []
    settings[key] = settings[key].filter((x) => x && x.id !== req.params.id)
    saveSettings(settings)
    res.json(settings[key])
  })
}

function parseGeneralLines(lines) {
  const general = {}
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) continue
    const idx = trimmed.indexOf('=')
    const key = trimmed.slice(0, idx).trim()
    let value = trimmed.slice(idx + 1).trim()
    if (value.toLowerCase() === 'true') value = true
    else if (value.toLowerCase() === 'false') value = false
    else {
      const num = Number(value)
      if (!Number.isNaN(num) && String(num) === value && !value.includes('.')) value = num
    }
    general[key] = value
  }
  return general
}

function parsePlugins(lines) {
  const plugins = []
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const parts = trimmed.split(',').map((p) => p.trim())
    const url = parts[0]
    if (!url) continue
    let name = null
    let enabled = true
    for (const p of parts.slice(1)) {
      if (p.startsWith('tag=')) name = p.slice(4)
      else if (p === 'enabled=false') enabled = false
    }
    plugins.push({ id: makeId(), name: name || url, url, enabled })
  }
  return plugins
}

function parseRemoteProxies(lines) {
  const list = []
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) continue
    const idx = trimmed.indexOf('=')
    const name = trimmed.slice(0, idx).trim()
    const rest = trimmed.slice(idx + 1).trim()
    const parts = rest.split(',').map((p) => p.trim())
    const url = parts[0]
    const options = parts.slice(1).join(',')
    list.push({ id: makeId(), name, url, options, enabled: true })
  }
  return list
}

function parseProxyChains(lines) {
  const list = []
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) continue
    const idx = trimmed.indexOf('=')
    const name = trimmed.slice(0, idx).trim()
    const rest = trimmed.slice(idx + 1).trim()
    const parts = rest.split(',').map((p) => p.trim())
    const chain = parts[0]
    let udp = true
    for (const p of parts.slice(1)) {
      if (p === 'udp=false') udp = false
    }
    list.push({ id: makeId(), name, chain, udp, enabled: true })
  }
  return list
}

function parseRemoteRules(lines) {
  const list = []
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const parts = trimmed.split(',').map((p) => p.trim())
    const url = parts[0]
    if (!url) continue
    let policy = ''
    let tag = ''
    let enabled = true
    for (const p of parts.slice(1)) {
      if (p.startsWith('policy=')) policy = p.slice(7)
      else if (p.startsWith('tag=')) tag = p.slice(4)
      else if (p === 'enabled=false') enabled = false
    }
    list.push({ id: makeId(), url, policy, tag, enabled })
  }
  return list
}

function parseHosts(lines) {
  const list = []
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) continue
    const idx = trimmed.indexOf('=')
    const domain = trimmed.slice(0, idx).trim()
    const ip = trimmed.slice(idx + 1).trim()
    list.push({ id: makeId(), domain, ip })
  }
  return list
}

function parseRewrites(lines) {
  const list = []
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const parts = trimmed.split(/\s+/)
    if (parts.length < 2) continue
    const match = parts[0]
    const type = parts[1]
    const target = parts.slice(2).join(' ') || ''
    list.push({ id: makeId(), match, type, target, enabled: true })
  }
  return list
}

function parseScripts(lines) {
  const list = []
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const parts = trimmed.split(/\s+/)
    if (parts.length < 3) continue
    const type = parts[0]
    const match = parts[1]
    let scriptPath = ''
    let requiresBody = false
    let enabled = true
    for (const p of parts.slice(2)) {
      if (p.startsWith('script-path=')) scriptPath = p.slice(12)
      else if (p === 'requires-body=true') requiresBody = true
      else if (p === 'enabled=false') enabled = false
    }
    list.push({ id: makeId(), type, match, scriptPath, requiresBody, enabled })
  }
  return list
}

function parseMitm(lines) {
  const mitm = { hostname: [] }
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    if (trimmed.startsWith('hostname')) {
      const value = trimmed.split('=').slice(1).join('=').trim()
      mitm.hostname = value.split(',').map((h) => h.trim()).filter(Boolean)
    } else if (trimmed.startsWith('ca-passphrase')) {
      mitm.caPassphrase = trimmed.split('=').slice(1).join('=').trim()
    } else if (trimmed.startsWith('skip-server-cert-verify')) {
      mitm.skipServerCertVerify = trimmed.split('=').slice(1).join('=').trim().toLowerCase() === 'true'
    }
  }
  return mitm
}

function parseLcf(text) {
  const sections = ['General','Proxy','Remote Proxy','Proxy Chain','Remote Filter','Proxy Group','Rule','Remote Rule','Host','Rewrite','Script','Plugin','Mitm']
  const escaped = sections.map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')
  const pattern = new RegExp(`^\\[(${escaped})\\]\\s*$`, 'm')
  const parts = text.split(pattern)
  const content = {}
  for (let i = 1; i < parts.length; i += 2) {
    const sec = parts[i]
    const body = (parts[i + 1] || '').trim()
    content[sec] = body
  }

  return {
    general: parseGeneralLines((content.General || '').split('\n')),
    remoteProxies: parseRemoteProxies((content['Remote Proxy'] || '').split('\n')),
    proxyChains: parseProxyChains((content['Proxy Chain'] || '').split('\n')),
    remoteRules: parseRemoteRules((content['Remote Rule'] || '').split('\n')),
    hosts: parseHosts((content.Host || '').split('\n')),
    rewrites: parseRewrites((content.Rewrite || '').split('\n')),
    scripts: parseScripts((content.Script || '').split('\n')),
    plugins: parsePlugins((content.Plugin || '').split('\n')),
    mitm: parseMitm((content.Mitm || '').split('\n')),
  }
}

// ---- import lcf -------------------------------------------------------------
app.post('/api/import-lcf', (req, res) => {
  const { text, mode = 'merge' } = req.body
  if (!text || typeof text !== 'string') {
    return res.status(400).json({ error: '请粘贴 Loon 配置文件内容' })
  }
  try {
    const parsed = parseLcf(text)
    const settings = loadSettings()

    if (mode === 'replace') {
      settings.general = parsed.general
      settings.remoteProxies = parsed.remoteProxies
      settings.proxyChains = parsed.proxyChains
      settings.remoteRules = parsed.remoteRules
      settings.hosts = parsed.hosts
      settings.rewrites = parsed.rewrites
      settings.scripts = parsed.scripts
      settings.plugins = parsed.plugins
      settings.mitm = parsed.mitm
    } else {
      // merge: only overwrite non-empty parsed sections
      if (Object.keys(parsed.general).length) settings.general = parsed.general
      if (parsed.remoteProxies.length) settings.remoteProxies = parsed.remoteProxies
      if (parsed.proxyChains.length) settings.proxyChains = parsed.proxyChains
      if (parsed.remoteRules.length) settings.remoteRules = parsed.remoteRules
      if (parsed.hosts.length) settings.hosts = parsed.hosts
      if (parsed.rewrites.length) settings.rewrites = parsed.rewrites
      if (parsed.scripts.length) settings.scripts = parsed.scripts
      if (parsed.plugins.length) settings.plugins = parsed.plugins
      if (parsed.mitm.hostname.length || parsed.mitm.caPassphrase) settings.mitm = parsed.mitm
    }

    saveSettings(settings)
    res.json({ ok: true, parsed: {
      generalKeys: Object.keys(parsed.general).length,
      remoteProxies: parsed.remoteProxies.length,
      proxyChains: parsed.proxyChains.length,
      remoteRules: parsed.remoteRules.length,
      hosts: parsed.hosts.length,
      rewrites: parsed.rewrites.length,
      scripts: parsed.scripts.length,
      plugins: parsed.plugins.length,
      mitmHostnames: parsed.mitm.hostname.length,
    }})
  } catch (e) {
    res.status(400).json({ error: e.message })
  }
})

// ---- lcf editor -------------------------------------------------------------
app.get('/api/current-lcf', async (req, res) => {
  try {
    const settings = loadSettings()
    const { loonText } = await fetchAndConvert(settings.sourceUrl)
    res.type('text/plain; charset=utf-8').send(loonText)
  } catch (e) {
    res.status(400).type('text/plain; charset=utf-8').send(`# 生成失败: ${e.message}`)
  }
})

app.post('/api/save-lcf', (req, res) => {
  const { text } = req.body
  if (!text || typeof text !== 'string') {
    return res.status(400).json({ error: '请提供 Loon 配置文件内容' })
  }
  try {
    const parsed = parseLcf(text)
    const settings = loadSettings()
    settings.general = parsed.general
    settings.remoteProxies = parsed.remoteProxies
    settings.proxyChains = parsed.proxyChains
    settings.remoteRules = parsed.remoteRules
    settings.hosts = parsed.hosts
    settings.rewrites = parsed.rewrites
    settings.scripts = parsed.scripts
    settings.plugins = parsed.plugins
    settings.mitm = parsed.mitm
    saveSettings(settings)
    res.json({ ok: true })
  } catch (e) {
    res.status(400).json({ error: e.message })
  }
})

// ---- preview ----------------------------------------------------------------
app.get('/api/preview', async (req, res) => {
  try {
    const settings = loadSettings()
    const result = await fetchAndConvert(settings.sourceUrl)
    res.json(result)
  } catch (e) {
    res.status(400).json({ error: e.message })
  }
})

// ---- the actual link you paste into Loon as a remote config -----------------
app.get('/loon.conf', async (req, res) => {
  const settings = loadSettings()
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate')
  res.set('Pragma', 'no-cache')
  res.set('Expires', '0')
  try {
    const { loonText } = await fetchAndConvert(settings.sourceUrl)
    // 缓存最近一次成功的配置
    settings.cachedConfig = { text: loonText, updatedAt: new Date().toISOString() }
    saveSettings(settings)
    res.type('text/plain; charset=utf-8').send(loonText)
  } catch (e) {
    if (settings.cachedConfig && settings.cachedConfig.text) {
      const cachedText = settings.cachedConfig.text
      const fallback = `# 上游拉取失败 (${e.message})，此配置为缓存版本，生成时间: ${settings.cachedConfig.updatedAt}\n` + cachedText
      res.type('text/plain; charset=utf-8').send(fallback)
    } else {
      res.status(400).type('text/plain; charset=utf-8').send(`# 生成失败: ${e.message}`)
    }
  }
})

app.listen(PORT, () => {
  console.log(`loon-forge listening on :${PORT}`)
})
