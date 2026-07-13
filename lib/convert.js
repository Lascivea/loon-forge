'use strict'

// ---------------------------------------------------------------------------
// Best-effort Mihomo/Clash YAML -> Loon .conf converter.
//
// Honest scope: this covers the common node types (ss / vmess / trojan /
// hysteria2 / socks5), the four common proxy-group types (select / url-test /
// fallback / load-balance) and the common rule types (DOMAIN*, IP-CIDR*,
// GEOIP, RULE-SET, MATCH). Anything outside that (relay chains, DOMAIN-REGEX,
// logic rules, script rules, compiled .mrs rule-providers, DNS/fake-ip, TUN)
// has no Loon equivalent and is skipped with a comment rather than silently
// dropped, so you can see what didn't make it across.
// ---------------------------------------------------------------------------

function esc(v) {
  return v === undefined || v === null ? '' : String(v)
}

function truthy(v) {
  return v === true || v === 'true' || v === 'on' || v === 1
}

function convertProxy(p) {
  const name = esc(p.name)
  const type = esc(p.type).toLowerCase()
  const server = esc(p.server)
  const port = esc(p.port)
  const udp = p.udp === false ? 'false' : 'true'

  try {
    switch (type) {
      case 'ss': {
        const method = esc(p.cipher)
        const password = esc(p.password)
        return `${name} = Shadowsocks,${server},${port},${method},"${password}",fast-open=false,udp=${udp}`
      }
      case 'vmess': {
        const uuid = esc(p.uuid)
        const alterId = p.alterId ?? 0
        const network = esc(p.network || 'tcp').toLowerCase()
        let extra = `username=${uuid},alterId=${alterId},transport=${network === 'tcp' ? 'tcp' : network}`
        if (p.tls) {
          extra += `,over-tls=true,tls-name=${esc(p['servername'] || server)},skip-cert-verify=${p['skip-cert-verify'] ? 'true' : 'false'}`
        }
        if (network === 'ws' && p['ws-opts']) {
          const path = esc(p['ws-opts'].path || '/')
          const host = p['ws-opts'].headers && p['ws-opts'].headers.Host
          extra += `,path=${path}`
          if (host) extra += `,ws-headers=Host:${esc(host)}`
        }
        return `${name} = Vmess,${server},${port},${extra},fast-open=false,udp=${udp}`
      }
      case 'trojan': {
        const password = esc(p.password)
        let extra = `password=${password}`
        if (p.sni) extra += `,tls-name=${esc(p.sni)}`
        extra += `,over-tls=true,skip-cert-verify=${p['skip-cert-verify'] ? 'true' : 'false'}`
        if (esc(p.network).toLowerCase() === 'ws' && p['ws-opts']) {
          const path = esc(p['ws-opts'].path || '/')
          extra += `,transport=ws,path=${path}`
        }
        return `${name} = Trojan,${server},${port},${extra},fast-open=false,udp=${udp}`
      }
      case 'hysteria2': {
        const password = esc(p.password || p.auth)
        let extra = `password=${password}`
        if (p.sni) extra += `,sni=${esc(p.sni)}`
        extra += `,skip-cert-verify=${p['skip-cert-verify'] ? 'true' : 'false'}`
        return `${name} = Hysteria2,${server},${port},${extra},udp=${udp}`
      }
      case 'socks5': {
        let extra = ''
        if (p.username) extra += `,username=${esc(p.username)}`
        if (p.password) extra += `,password=${esc(p.password)}`
        return `${name} = Socks5,${server},${port}${extra},udp=${udp}`
      }
      default:
        return null
    }
  } catch (e) {
    return null
  }
}

function convertProxyGroup(g) {
  const name = esc(g.name)
  const type = esc(g.type).toLowerCase()
  const members = (g.proxies || []).join(',')
  const url = esc(g.url || 'http://www.gstatic.com/generate_204')
  const interval = g.interval || 600
  const uses = g.use || []
  const filter = g.filter ? String(g.filter) : ''

  let line
  switch (type) {
    case 'select':
      line = `${name} = select,${members}`
      break
    case 'url-test':
      line = `${name} = url-test,${members},url=${url},interval=${interval}`
      break
    case 'fallback':
      line = `${name} = fallback,${members},url=${url},interval=${interval}`
      break
    case 'load-balance':
      line = `${name} = load-balance,${members},url=${url},interval=${interval},algorithm=round-robin`
      break
    default:
      return null
  }

  let remoteFilter = null
  if (uses.length && filter) {
    const filterName = `${name}Filter`
    remoteFilter = `${filterName} = NameRegex, FilterKey = "${filter.replace(/"/g, '\\"')}"`
    if (members) {
      line += `,${filterName}`
    } else {
      line = line.replace(`${name} = ${type},,`, `${name} = ${type},${filterName},`)
    }
  }

  return { line, remoteFilter }
}

function convertRule(fields, ruleProviders) {
  const type = fields[0]
  const SUPPORTED = new Set(['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6', 'GEOIP'])

  if (SUPPORTED.has(type)) {
    return fields.join(',')
  }
  if (type === 'MATCH') {
    return `FINAL,${fields[1]}`
  }
  if (type === 'RULE-SET') {
    const providerName = fields[1]
    const policy = fields[2]
    const provider = ruleProviders && ruleProviders[providerName]
    if (!provider) return `// skipped: RULE-SET,${providerName},${policy} (provider not found)`
    if (!provider.url) {
      return `// skipped: RULE-SET,${providerName},${policy} (no remote url — likely a local/compiled .mrs provider, can't be re-hosted)`
    }
    if (provider.behavior === 'classical') {
      return `RULE-SET,${provider.url},${policy} // classical behavior — verify this file is a plain list, not mixed rule syntax`
    }
    return `RULE-SET,${provider.url},${policy}`
  }
  return `// skipped: ${fields.join(',')} (no Loon equivalent for ${type})`
}

// ---------------------------------------------------------------------------
// Template renderers: turn the structured UI settings into Loon section lines.
// ---------------------------------------------------------------------------

function sectionFromRaw(raw) {
  if (!raw) return []
  return String(raw)
    .split('\n')
    .map((l) => l.trimEnd())
    .filter((l) => l !== '')
}

function renderGeneral(general = {}) {
  const lines = []
  if (general['ip-mode']) lines.push(`ip-mode = ${general['ip-mode']}`)
  if (general['ipv6-vif']) lines.push(`ipv6-vif = ${general['ipv6-vif']}`)
  if (general['dns-server']) lines.push(`dns-server = ${general['dns-server']}`)
  if (general['sni-sniffing'] !== undefined) lines.push(`sni-sniffing = ${truthy(general['sni-sniffing']) ? 'true' : 'false'}`)
  if (general['disable-stun'] !== undefined) lines.push(`disable-stun = ${truthy(general['disable-stun']) ? 'true' : 'false'}`)
  if (general['dns-reject-mode']) lines.push(`dns-reject-mode = ${general['dns-reject-mode']}`)
  if (general['domain-reject-mode']) lines.push(`domain-reject-mode = ${general['domain-reject-mode']}`)
  if (general['udp-fallback-mode']) lines.push(`udp-fallback-mode = ${general['udp-fallback-mode']}`)
  if (general['wifi-access-http-port']) lines.push(`wifi-access-http-port = ${general['wifi-access-http-port']}`)
  if (general['wifi-access-socks5-port']) lines.push(`wifi-access-socks5-port = ${general['wifi-access-socks5-port']}`)
  if (general['allow-wifi-access'] !== undefined) lines.push(`allow-wifi-access = ${truthy(general['allow-wifi-access']) ? 'true' : 'false'}`)
  if (general['interface-mode']) lines.push(`interface-mode = ${general['interface-mode']}`)
  if (general['test-timeout'] !== undefined) lines.push(`test-timeout = ${general['test-timeout']}`)
  if (general['disconnect-on-policy-change'] !== undefined) lines.push(`disconnect-on-policy-change = ${truthy(general['disconnect-on-policy-change']) ? 'true' : 'false'}`)
  if (general['internet-test-url']) lines.push(`internet-test-url = ${general['internet-test-url']}`)
  if (general['proxy-test-url']) lines.push(`proxy-test-url = ${general['proxy-test-url']}`)
  if (general['resource-parser']) lines.push(`resource-parser = ${general['resource-parser']}`)
  if (general['geoip-url']) lines.push(`geoip-url = ${general['geoip-url']}`)
  if (general['ipasn-url']) lines.push(`ipasn-url = ${general['ipasn-url']}`)
  if (general['skip-proxy']) lines.push(`skip-proxy = ${general['skip-proxy']}`)
  if (general['bypass-tun']) lines.push(`bypass-tun = ${general['bypass-tun']}`)
  return lines
}

function renderRemoteProxies(list = []) {
  return list
    .filter((p) => p.enabled !== false)
    .map((p) => {
      const name = esc(p.name || 'sub')
      const opts = esc(p.options || '')
      return opts ? `${name} = ${p.url},${opts}` : `${name} = ${p.url}`
    })
}

function renderProxyChains(list = []) {
  return list
    .filter((p) => p.enabled !== false)
    .map((p) => {
      const udp = truthy(p.udp) ? 'true' : 'false'
      return `${esc(p.name)} = ${p.chain}, udp=${udp}`
    })
}

function renderRemoteRules(list = []) {
  return list
    .filter((r) => r.enabled !== false)
    .map((r) => {
      const tag = r.tag ? `, tag=${esc(r.tag)}` : ''
      return `${r.url}, policy=${esc(r.policy)}${tag}, enabled=true`
    })
}

function renderHosts(list = []) {
  return list.map((h) => `${esc(h.domain)} = ${esc(h.ip)}`)
}

function renderRewrites(list = []) {
  return list
    .filter((r) => r.enabled !== false)
    .map((r) => {
      const type = esc(r.type || '302')
      return `${esc(r.match)} ${type} ${esc(r.target)}`
    })
}

function renderScripts(list = []) {
  return list
    .filter((s) => s.enabled !== false)
    .map((s) => {
      const parts = [esc(s.type), esc(s.match), `script-path=${esc(s.scriptPath)}`]
      if (truthy(s.requiresBody)) parts.push('requires-body=true')
      if (truthy(s.enabled)) parts.push('enabled=true')
      return parts.join(' ')
    })
}

function renderMitm(mitm = {}) {
  const lines = []
  const hosts = Array.isArray(mitm.hostname) ? mitm.hostname.filter(Boolean) : []
  if (hosts.length) lines.push(`hostname = ${hosts.join(',')}`)
  if (mitm.caPassphrase) lines.push(`ca-passphrase = ${mitm.caPassphrase}`)
  if (mitm.caP12) lines.push(`ca-p12 = ${mitm.caP12}`)
  if (mitm.skipServerCertVerify !== undefined) lines.push(`skip-server-cert-verify = ${truthy(mitm.skipServerCertVerify) ? 'true' : 'false'}`)
  return lines
}

function buildLoonConfig({
  proxies = [],
  groups = [],
  rules = [],
  ruleProviders = {},
  pluginLines = [],
  general = {},
  remoteProxies = [],
  proxyChains = [],
  remoteRules = [],
  hosts = [],
  rewrites = [],
  scripts = [],
  mitm = {},
  advancedTemplates = {},
}) {
  const skipped = { proxies: [], groups: [], rules: [] }

  // 1. 扫描 dialer-proxy，生成 chain 映射
  const chainMap = {} // original proxy name -> chain name
  const autoProxyChains = []
  for (const p of proxies) {
    const dialer = p['dialer-proxy']
    if (!dialer) continue
    const chainName = `${p.name}-Chain`
    chainMap[p.name] = chainName
    const udp = p.udp === false ? 'false' : 'true'
    autoProxyChains.push(`${chainName} = ${esc(dialer)},${esc(p.name)}, udp=${udp}`)
  }

  // 2. 转换节点
  const proxyLines = []
  for (const p of proxies) {
    const line = convertProxy(p)
    if (line) proxyLines.push(line)
    else skipped.proxies.push(`${p.name} (${p.type})`)
  }

  // 3. 转换策略组，把引用到有 dialer-proxy 的节点名替换为 chain 名
  const groupLines = []
  const remoteFilterLines = []
  for (const g of groups) {
    const result = convertProxyGroup(g)
    if (!result) {
      skipped.groups.push(`${g.name} (${g.type})`)
      continue
    }
    let line = result.line
    // 替换策略组成员：如果成员是带 dialer-proxy 的节点，改用 chain
    for (const [originalName, chainName] of Object.entries(chainMap)) {
      // 简单字符串替换，加边界逗号处理
      line = line.split(',').map(part => {
        const trimmed = part.trim()
        return trimmed === originalName ? chainName : part
      }).join(',')
    }
    groupLines.push(line)
    if (result.remoteFilter) remoteFilterLines.push(result.remoteFilter)
  }

  // 4. 转换规则
  const ruleLines = []
  for (const r of rules) {
    const fields = String(r).split(',').map((s) => s.trim())
    const line = convertRule(fields, ruleProviders)
    ruleLines.push(line)
    if (line.startsWith('//')) skipped.rules.push(r)
  }

  const generalLines = advancedTemplates.general
    ? sectionFromRaw(advancedTemplates.general)
    : renderGeneral(general)
  const remoteProxyLines = advancedTemplates.remoteProxy
    ? sectionFromRaw(advancedTemplates.remoteProxy)
    : renderRemoteProxies(remoteProxies)
  const customProxyChainLines = advancedTemplates.proxyChain
    ? sectionFromRaw(advancedTemplates.proxyChain)
    : renderProxyChains(proxyChains)
  // 自动 dialer-proxy chain 放在前面
  const proxyChainLines = [...autoProxyChains, ...customProxyChainLines]
  const remoteRuleLines = advancedTemplates.remoteRule
    ? sectionFromRaw(advancedTemplates.remoteRule)
    : renderRemoteRules(remoteRules)
  const hostLines = advancedTemplates.host
    ? sectionFromRaw(advancedTemplates.host)
    : renderHosts(hosts)
  const rewriteLines = advancedTemplates.rewrite
    ? sectionFromRaw(advancedTemplates.rewrite)
    : renderRewrites(rewrites)
  const scriptLines = advancedTemplates.script
    ? sectionFromRaw(advancedTemplates.script)
    : renderScripts(scripts)
  const mitmLines = advancedTemplates.mitm
    ? sectionFromRaw(advancedTemplates.mitm)
    : renderMitm(mitm)

  const parts = []
  parts.push(`#!name = Mihomo -> Loon (auto-generated)`)
  parts.push(`#!desc = Generated by loon-forge on ${new Date().toISOString()}`)

  if (generalLines.length) {
    parts.push('')
    parts.push('[General]')
    parts.push(...generalLines)
  }

  parts.push('')
  parts.push('[Proxy]')
  parts.push(...proxyLines)

  if (remoteProxyLines.length) {
    parts.push('')
    parts.push('[Remote Proxy]')
    parts.push(...remoteProxyLines)
  }

  if (proxyChainLines.length) {
    parts.push('')
    parts.push('[Proxy Chain]')
    parts.push(...proxyChainLines)
  }

  if (remoteFilterLines.length) {
    parts.push('')
    parts.push('[Remote Filter]')
    parts.push(...remoteFilterLines)
  }

  parts.push('')
  parts.push('[Proxy Group]')
  parts.push(...groupLines)

  parts.push('')
  parts.push('[Rule]')
  parts.push(...ruleLines)

  if (remoteRuleLines.length) {
    parts.push('')
    parts.push('[Remote Rule]')
    parts.push(...remoteRuleLines)
  }

  if (hostLines.length) {
    parts.push('')
    parts.push('[Host]')
    parts.push(...hostLines)
  }

  if (rewriteLines.length) {
    parts.push('')
    parts.push('[Rewrite]')
    parts.push(...rewriteLines)
  }

  if (scriptLines.length) {
    parts.push('')
    parts.push('[Script]')
    parts.push(...scriptLines)
  }

  parts.push('')
  parts.push('[Plugin]')
  parts.push(...pluginLines)

  if (mitmLines.length) {
    parts.push('')
    parts.push('[Mitm]')
    parts.push(...mitmLines)
  }

  return { text: parts.join('\n'), skipped }
}

module.exports = {
  convertProxy,
  convertProxyGroup,
  convertRule,
  buildLoonConfig,
  renderGeneral,
  renderRemoteProxies,
  renderProxyChains,
  renderRemoteRules,
  renderHosts,
  renderRewrites,
  renderScripts,
  renderMitm,
}
