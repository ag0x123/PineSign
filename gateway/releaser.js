/**
 * Releasing on the sender's behalf, once the acceptance is final.
 *
 * By default a sender hands their key half to this gateway rather than keeping
 * it, because the alternative is being reachable at whatever moment the
 * recipient happens to accept. The cost is stated in the README and is real:
 * a gateway that holds `B` could give it to a recipient who never accepted. A
 * sender who will not accept that releases herself instead.
 *
 * Why finality matters here more than usual
 * -----------------------------------------
 * `release` puts `B` in transaction calldata, and calldata is public the moment
 * the transaction is broadcast — whether or not it ends up succeeding. So a
 * release submitted against an acceptance that is later reorged out does not
 * simply fail; it publishes the sender's half for a delivery nobody accepted,
 * and no revert takes that back.
 *
 * Hence nothing is released until the block holding the acceptance is final.
 * That is slower than watching for the event and acting on it, and the
 * slowness is the point.
 */

import { createWalletClient, createPublicClient, http } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { sepolia } from 'viem/chains'
import { secp256k1 } from '@noble/curves/secp256k1'
import { toHex } from '../shared/crypto.js'
import { openHalfFrom } from '../shared/keysplit.js'
import { RPC_URL } from './chain.js'
import * as setup from './setup.js'
import * as delivery from './delivery.js'
import * as deliveries from './deliveries.js'

/**
 * How final is final.
 *
 * `finalized` is the honest answer where a chain offers it: two epochs, and
 * not reorganisable without a consensus failure. A number of confirmations is
 * the fallback for chains that do not, and is weaker — it is a guess about how
 * deep a reorg could be.
 */
const MODE = process.env.RELEASE_FINALITY ?? 'finalized'
const CONFIRMATIONS = Number(process.env.RELEASE_CONFIRMATIONS ?? 12)
const EVERY_MS = Number(process.env.RELEASE_POLL_MS ?? 30_000)

let secretKey = null

/** The key the gateway releases with, and that senders seal their half to. */
export async function key() {
  if (secretKey) return secretKey
  const configured = process.env.RELEASE_PRIVATE_KEY ?? (await setup.deployerKey())
  if (!configured) return null
  secretKey = configured
  return secretKey
}

export async function publicKey() {
  const k = await key()
  if (!k) return null
  return toHex(secp256k1.getPublicKey(k.replace(/^0x/, ''), true))
}

export async function address() {
  const k = await key()
  return k ? privateKeyToAccount(k).address : null
}

const client = () => createPublicClient({ chain: sepolia, transport: http(RPC_URL) })

/**
 * Is the block holding this acceptance beyond reorganisation?
 *
 * Returns a reason when it is not, so the log says what it is waiting for
 * rather than going quiet for twenty minutes.
 */
export async function isFinal(blockNumber) {
  const at = BigInt(blockNumber)

  if (MODE === 'finalized') {
    try {
      const finalized = await client().getBlock({ blockTag: 'finalized' })
      if (finalized.number >= at) return { final: true }
      return { final: false, why: `block ${at} is not finalized yet (finalized is ${finalized.number})` }
    } catch {
      // A chain or RPC without the finalized tag falls back rather than
      // releasing on no check at all.
    }
  }

  const head = await client().getBlockNumber()
  const deep = head - at + 1n
  if (deep >= BigInt(CONFIRMATIONS)) return { final: true }
  return { final: false, why: `${deep} of ${CONFIRMATIONS} confirmations` }
}

/**
 * One pass: release whatever is accepted, final, and ours to release.
 *
 * Deliberately idempotent and stateless beyond the record. A missed tick, a
 * restart or two of these running at once costs a reverted transaction, not a
 * leaked half — `release` only works once, and only from the releaser.
 */
export async function sweep({ log = console.log } = {}) {
  if (!delivery.configured) return { released: [], waiting: [] }

  const me = await address()
  if (!me) return { released: [], waiting: [] }

  const released = []
  const waiting = []

  for (const record of await deliveries.list()) {
    if (record.releaseMode !== 'releaser' || record.releasedTx) continue

    let onChain
    try {
      onChain = await delivery.get(record.id)
    } catch (err) {
      log(`  release: cannot read ${record.id}: ${err.message}`)
      continue
    }

    if (onChain.state !== 'Accepted') continue
    if (onChain.releaser.toLowerCase() !== me.toLowerCase()) continue

    // Where the acceptance landed. Recorded when this gateway relayed it; read
    // from the chain's own logs when somebody else did.
    const block = record.acceptBlock ?? (await acceptBlockOf(record.id))
    if (!block) {
      waiting.push({ id: record.id, why: 'cannot tell which block the acceptance is in' })
      continue
    }

    const final = await isFinal(block)
    if (!final.final) {
      waiting.push({ id: record.id, why: final.why })
      continue
    }

    try {
      const half = openHalfFrom({
        secretKey: await key(),
        theirPublicKey: record.senderPubKey,
        transferId: record.id,
        blob: Uint8Array.from(record.keptHalf),
      })
      // From the release key, which is the address the record names as
      // releaser — not whichever key relays everything else.
      const sent = await delivery.release(record.id, `0x${toHex(half)}`, { as: await key() })
      await deliveries.markReleased(record.id, sent.tx)
      released.push({ id: record.id, tx: sent.tx })
      log(`  released ${record.id} ${sent.tx}`)
    } catch (err) {
      log(`  release: ${record.id} failed: ${err.message}`)
    }
  }

  return { released, waiting }
}

/** Which block an acceptance is in, from the contract's own event. */
async function acceptBlockOf(id) {
  try {
    const logs = await client().getLogs({
      address: delivery.ADDRESS,
      event: {
        type: 'event',
        name: 'Accepted',
        inputs: [
          { name: 'id', type: 'bytes32', indexed: true },
          { name: 'passkeyX', type: 'bytes32', indexed: false },
          { name: 'at', type: 'uint64', indexed: false },
        ],
      },
      args: { id },
      fromBlock: 'earliest',
    })
    return logs.at(-1)?.blockNumber ?? null
  } catch {
    return null
  }
}

let timer = null

/** Start sweeping. Harmless to call twice; does nothing without a contract. */
export function start({ log = console.log } = {}) {
  if (timer || !delivery.configured) return false
  const tick = () =>
    sweep({ log }).catch((err) => log(`  release sweep failed: ${err.message}`))
  timer = setInterval(tick, EVERY_MS)
  timer.unref()
  tick()
  return true
}

export function stop() {
  if (timer) clearInterval(timer)
  timer = null
}

export const settings = { mode: MODE, confirmations: CONFIRMATIONS, everyMs: EVERY_MS }
