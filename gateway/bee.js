/**
 * The Bee node.
 *
 * Everything the admin panel needs to get a node from "just started" to "can
 * pay for uploads": where to send funds, what it holds, and how to buy postage.
 *
 * The node is the only thing here holding BZZ, and it is a separate wallet from
 * the server's Sepolia deployer — one pays for storage on Gnosis, the other for
 * names and receipts on Sepolia. Confusing them is the easiest way to send
 * money somewhere it does nothing.
 */

// An empty BEE_URL is a half-filled .env, not a choice — ?? would keep the
// empty string and every request would be made against a relative path.
export const BEE_URL = process.env.BEE_URL || 'http://localhost:1633'

async function call(path, { method = 'GET', timeout = 8000 } = {}) {
  const res = await fetch(BEE_URL + path, { method, signal: AbortSignal.timeout(timeout) })
  const body = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw new Error(body.message ?? body.reason ?? `bee ${res.status} on ${path}`)
  }
  return body
}

/** Is the node up, and has it finished getting ready? */
export async function health() {
  try {
    const [health, readiness] = await Promise.all([
      call('/health'),
      call('/readiness').catch(() => null),
    ])
    return {
      reachable: true,
      version: health.version,
      status: health.status,
      ready: readiness?.status === 'ready',
    }
  } catch (err) {
    return { reachable: false, error: err.message }
  }
}

/** The node's own addresses. The Ethereum one is what gets funded. */
export function addresses() {
  return call('/addresses')
}

/** BZZ for postage and retrieval, xDAI for gas. Both are needed. */
export async function wallet() {
  const w = await call('/wallet')
  return {
    address: w.walletAddress,
    // Bee reports these as base-16 strings in some versions, decimal in others.
    bzz: normalise(w.bzzBalance, 16),
    xdai: normalise(w.nativeTokenBalance, 18),
  }
}

function normalise(value, decimals) {
  if (value === undefined || value === null) return null
  const raw = BigInt(value)
  const divisor = 10n ** BigInt(decimals)
  const whole = raw / divisor
  const frac = (raw % divisor).toString().padStart(decimals, '0').slice(0, 6)
  return { raw: raw.toString(), formatted: `${whole}.${frac}` }
}

export async function chequebook() {
  try {
    const c = await call('/chequebook/balance')
    return { totalBalance: c.totalBalance, availableBalance: c.availableBalance }
  } catch {
    // A node without swap enabled, or one still deploying its chequebook.
    return null
  }
}

export function stamps() {
  return call('/stamps')
}

/** Gnosis block time, which is what postage lifetime is actually measured in. */
const BLOCK_SECONDS = 5

export function chainstate() {
  return call('/chainstate')
}

/**
 * What a batch costs, and how long it lasts.
 *
 * Postage is priced per chunk per block, so lifetime and capacity are separate
 * purchases: `amount` buys time, `depth` buys space. Both come from the chain
 * rather than from a constant, because the price moves and the node enforces a
 * minimum validity that a stale figure will fall foul of.
 */
export async function quoteStamp({ ttlSeconds = 3 * 24 * 60 * 60, depth = 17 } = {}) {
  const state = await chainstate()
  const price = BigInt(state.currentPrice)
  const minBlocks = BigInt(state.minimumValidityBlocks ?? 17280)

  const wantedBlocks = BigInt(Math.ceil(ttlSeconds / BLOCK_SECONDS))
  // Never below what the node will accept, whatever was asked for.
  const blocks = wantedBlocks > minBlocks ? wantedBlocks : minBlocks
  const amount = blocks * price

  const plur = amount * (2n ** BigInt(depth))
  return {
    amount: amount.toString(),
    depth,
    ttlSeconds: Number(blocks) * BLOCK_SECONDS,
    ttlDays: (Number(blocks) * BLOCK_SECONDS) / 86400,
    costBzz: Number(plur) / 1e16,
    capacityBytes: 2 ** depth * 4096,
    minimumTtlSeconds: Number(minBlocks) * BLOCK_SECONDS,
  }
}

/**
 * Buy postage.
 *
 * Depth is capacity and amount is time: the batch can hold 2^depth chunks and
 * survives while its per-chunk balance lasts. Both cost BZZ, which is why this
 * is a deliberate purchase rather than something the server does on demand.
 */
export async function buyStamp({ ttlSeconds, depth } = {}) {
  const quote = await quoteStamp({ ttlSeconds, depth })
  const result = await call(`/stamps/${quote.amount}/${quote.depth}`, { method: 'POST', timeout: 180000 })
  return { batchID: result.batchID ?? result.batchId, ...quote }
}

export async function stamp(batchId) {
  return call(`/stamps/${batchId}`)
}

/**
 * What the panel shows for the Swarm step. Assembled with individual failures
 * tolerated, because a node that is merely still starting should report that
 * rather than an error.
 */
export async function overview() {
  const state = await health()
  if (!state.reachable) return { ...state, wallet: null, stamps: [] }

  const [addr, funds, cheque, batches] = await Promise.all([
    addresses().catch(() => null),
    wallet().catch(() => null),
    chequebook(),
    stamps().catch(() => ({ stamps: [] })),
  ])

  const usable = (batches.stamps ?? []).filter((b) => b.usable)

  // A syncing node refuses /wallet, but it already knows its own address — and
  // that address is exactly what the operator needs in order to fund it. Making
  // them wait for the sync before showing it wastes the sync.
  const walletInfo = funds ?? (addr?.ethereum ? { address: addr.ethereum, bzz: null, xdai: null } : null)

  const quote = await quoteStamp().catch(() => null)

  return {
    ...state,
    quote,
    overlay: addr?.overlay ?? null,
    wallet: walletInfo,
    balancesKnown: Boolean(funds),
    chequebook: cheque,
    stamps: batches.stamps ?? [],
    usableStamp: usable[0] ?? null,
  }
}
