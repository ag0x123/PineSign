// Spike 6 — anon-RPC: route an Arkiv read and a devnet read through worker.fetch.
// Browser only, so this runs the harness in real Chrome under Playwright.
import fs from 'node:fs'
import http from 'node:http'
import { chromium } from 'playwright'

const BUNDLE = fs.readFileSync(new URL('./anon-bundle.js', import.meta.url))
const ARKIV = `https://rpc.rabdi.db-chain.testnet.arkiv.network`
const DEVNET = 'https://altmempoolgateway.forshtat.com/rpc'
const MAINNET = 'https://ethereum-rpc.publicnode.com'

// Specifier addresses from the anon-rpc wallets page.
const SPECIFIERS = {
  passthrough: { address: '0x4fd77be300f31c5fe6ab266d35d27750a3478d27', config: {}, note: 'mainnet, non-anonymizing reference' },
  _tor_disabled: { address: '0x700dA3193D35fA54Cd3fBf29B66f2a2A0385659e', config: { gateways: ['152.236.3.22:12298:uEiCH0VdbhryzJcMtCfB0vLA4sOvHdQ4hq5w7CopcwU59bQ'] }, note: 'mainnet, demo gateway that may be gone' },
}

const PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>anon</title></head><body>
<script>${BUNDLE}</script>
<script>
window.probe = async (address, config, targets, mainnetRpc) => {
  const out = { address, note: null, logs: [] }
  let worker
  try {
    worker = new window.AnonRpcWorker({
      address, config,
      preExisting: { rpcProvider: { request: async ({ method, params }) => {
        const r = await fetch(mainnetRpc, { method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: params ?? [] }) })
        const j = await r.json()
        if (j.error) throw new Error(JSON.stringify(j.error))
        return j.result
      } } },
    })
    const t0 = Date.now()
    await Promise.race([worker.ready, new Promise((_, rej) => setTimeout(() => rej(new Error('ready timed out after 150s')), 150000))])
    out.readyMs = Date.now() - t0
    out.ready = true
    for (const [name, url] of Object.entries(targets)) {
      const t = Date.now()
      try {
        const res = await worker.fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }) })
        const text = await res.text()
        out[name] = { ok: true, ms: Date.now() - t, status: res.status, body: text.slice(0, 160) }
      } catch (e) {
        out[name] = { ok: false, ms: Date.now() - t, error: String(e && e.message || e).slice(0, 200), code: e && e.code }
      }
    }
  } catch (e) {
    out.ready = false
    out.error = String(e && e.message || e).slice(0, 300)
  } finally { try { worker && worker.close() } catch {} }
  return out
}
</script></body></html>`

const server = http.createServer((_, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(PAGE) })
await new Promise((r) => server.listen(0, '127.0.0.1', r))
const port = server.address().port

const out = {}
let browser
try {
  browser = await chromium.launch({ channel: 'chrome', headless: true })
  out.browser = browser.version()
  const page = await (await browser.newContext()).newPage()
  const consoleLines = []
  page.on('console', (m) => consoleLines.push(m.type() + ': ' + m.text().slice(0, 160)))
  page.on('pageerror', (e) => consoleLines.push('pageerror: ' + e.message.slice(0, 160)))
  await page.goto(`http://localhost:${port}/`)
  for (const [name, spec] of Object.entries(SPECIFIERS)) {
    if (name.startsWith('_')) continue
    out[name] = await page.evaluate(
      ([a, c, t, m]) => window.probe(a, c, t, m),
      [spec.address, spec.config, { arkiv: ARKIV, devnet: DEVNET }, MAINNET]
    )
    out[name].note = spec.note
  }
  out.console = consoleLines
} catch (e) {
  out.error = (e?.message ?? String(e)).split('\n').slice(0, 3).join(' | ').slice(0, 300)
} finally { await browser?.close(); server.close() }

const ok = (n) => out[n]?.arkiv?.ok === true && out[n]?.devnet?.ok === true
out.PASS = ok('passthrough') || ok('tor')
out.VERDICT = out.PASS
  ? `Routing works through ${ok('passthrough') ? 'passthrough' : ''}${ok('tor') ? ' tor' : ''}`
  : 'Neither specifier routed both reads; see per-specifier errors'
console.log(JSON.stringify(out, null, 2))
