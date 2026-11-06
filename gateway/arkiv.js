/**
 * Arkiv: where invites and accepts live.
 *
 * v0.2 kept these in a file on this server, which made the gateway the thing
 * that decided whether a delivery existed. Now they are entities on Arkiv:
 * public, signed by the passkey that made them, queryable by anyone, and gone
 * on their own when they expire. The gateway pays for the write and can refuse
 * to make one, but it cannot forge one and cannot quietly drop one that is
 * already there.
 *
 * Reads go through this module rather than the browser because the Rabdi
 * endpoint wants an access key in the URL. Putting that key in a bundle would
 * hand it to everyone who loads the page, so the browser asks us instead.
 *
 * The gateway runs fine unconfigured — client() returns null and the routes
 * say so, the same way the chain and mail modules behave.
 */

import { createPublicClient, createWalletClient, defineSchema, str, bytes, ExpirationTime } from '@arkiv-network/sdk'
import { rabdi } from '@arkiv-network/sdk/chains'
import { eq } from '@arkiv-network/sdk/query'
import { http } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { KIND, verify } from '../shared/arkiv-payload.js'

export const CHAIN_ID = Number(process.env.ARKIV_CHAIN_ID ?? 7794095)

/**
 * Two schemas, not one with a kind column, because Arkiv queries are per
 * schema: asking "has anyone accepted this?" should not have to read invites
 * and filter them out.
 */
export const Invite = defineSchema('pinesign.invite', {
  fingerprint: str().indexed(),
  emailHash: str().indexed(),
  payload: bytes(),
})

export const Accept = defineSchema('pinesign.accept', {
  fingerprint: str().indexed(),
  emailHash: str().indexed(),
  payload: bytes(),
})

const INVITE_DAYS = Number(process.env.ARKIV_INVITE_DAYS ?? 7)
const ACCEPT_DAYS = Number(process.env.ARKIV_ACCEPT_DAYS ?? 30)

let cached = null

function client() {
  if (cached !== null) return cached
  const accessKey = process.env.ARKIV_ACCESS_KEY
  const privateKey = process.env.ARKIV_PRIVATE_KEY
  if (!accessKey || !privateKey) return (cached = false)
  const chain = rabdi({ accessKey })
  const account = privateKeyToAccount(privateKey)
  return (cached = {
    account,
    read: createPublicClient({ chain, transport: http() }),
    write: createWalletClient({ chain, transport: http(), account }),
  })
}

export function configured() {
  return client() !== false
}

export function writerAddress() {
  const c = client()
  return c === false ? null : c.account.address
}

/**
 * Query results wrap every value as { type, value } rather than returning it
 * raw. Reading a field straight off the row gives you an object, and
 * new Uint8Array(object) is a silently empty array rather than an error — a
 * payload that looks lost when it was only never unwrapped.
 */
const unwrap = (v) => (v && typeof v === 'object' && 'value' in v ? v.value : v)

/**
 * The indexed fields are stored 0x-prefixed, and the signature covers that
 * exact string — so a query for the bare form would find nothing and a payload
 * signed over the bare form would not verify. The HTTP API speaks bare hex
 * because that is what the gateway's own hex validator accepts, so both forms
 * meet here and nowhere else.
 */
const prefixed = (value) => (String(value).startsWith('0x') ? String(value) : '0x' + value)

function bytesFrom(value) {
  const hex = String(unwrap(value))
  return Uint8Array.from(Buffer.from(hex.startsWith('0x') ? hex.slice(2) : hex, 'hex'))
}

/**
 * Rows as the rest of the gateway wants them, with the payload checked against
 * the fields it arrived with. An entity whose signature does not cover its own
 * row is dropped here rather than passed on with a warning: there is no use
 * for one, and letting it through would mean every caller had to remember.
 */
function hydrate(rows, kind) {
  const out = []
  for (const row of rows ?? []) {
    const fingerprint = String(unwrap(row.fingerprint))
    const emailHash = String(unwrap(row.emailHash))
    let payload
    try {
      payload = bytesFrom(row.payload)
      if (!verify(payload, { fingerprint, emailHash })) continue
    } catch {
      continue
    }
    out.push({
      entityKey: unwrap(row.$key),
      expiresAt: Number(unwrap(row.$expiresAt) ?? 0) || null,
      fingerprint,
      emailHash,
      kind,
      payload: '0x' + Buffer.from(payload).toString('hex'),
    })
  }
  return out
}

const SELECT = { $key: true, $expiresAt: true, fingerprint: true, emailHash: true, payload: true }

async function create(schema, { fingerprint, emailHash, payload, kind, days }) {
  const c = client()
  if (c === false) throw new Error('arkiv not configured')
  fingerprint = prefixed(fingerprint)
  emailHash = prefixed(emailHash)
  if (!verify(payload, { fingerprint, emailHash })) throw new Error('payload signature does not cover this row')
  const started = Date.now()
  const created = await c.write.createEntity(
    schema,
    { fingerprint, emailHash, payload },
    { expiration: ExpirationTime.fromDays(days) }
  )
  return { entityKey: created.entityKey, txHash: created.txHash, kind, ms: Date.now() - started }
}

export function createInvite({ fingerprint, emailHash, payload }) {
  return create(Invite, { fingerprint, emailHash, payload, kind: KIND.INVITE, days: INVITE_DAYS })
}

export function createAccept({ fingerprint, emailHash, payload }) {
  return create(Accept, { fingerprint, emailHash, payload, kind: KIND.ACCEPT, days: ACCEPT_DAYS })
}

async function query(schema, kind, field, value) {
  const c = client()
  if (c === false) throw new Error('arkiv not configured')
  // fetch() answers with { entities }, not the array itself.
  const { entities } = await c.read.select(SELECT).from(schema).where(eq(field, prefixed(value))).fetch()
  return hydrate(entities, kind)
}

export const invitesForEmail = (emailHash) => query(Invite, KIND.INVITE, 'emailHash', emailHash)
export const invitesForFile = (fingerprint) => query(Invite, KIND.INVITE, 'fingerprint', fingerprint)
export const acceptsForFile = (fingerprint) => query(Accept, KIND.ACCEPT, 'fingerprint', fingerprint)
export const acceptsForEmail = (emailHash) => query(Accept, KIND.ACCEPT, 'emailHash', emailHash)

/** For the health endpoint and the status badge: is Arkiv reachable, and can we still pay? */
export async function status() {
  const c = client()
  if (c === false) return { configured: false }
  try {
    const [balance, block] = await Promise.all([
      c.read.getBalance({ address: c.account.address }),
      c.read.getBlockNumber(),
    ])
    return {
      configured: true,
      writer: c.account.address,
      chainId: CHAIN_ID,
      block: Number(block),
      balanceWei: balance.toString(),
      funded: balance > 0n,
    }
  } catch (error) {
    return { configured: true, writer: c.account.address, chainId: CHAIN_ID, reachable: false, error: error.message }
  }
}
