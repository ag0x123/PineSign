/**
 * Bob's reply, arriving.
 *
 * A provider's inbound webhook hands us the message; we verify its DKIM
 * signature here and keep the raw bytes on disk. Nothing about this step is
 * trusted: the webhook could be anyone, so the only thing that makes a reply
 * count is that the signature over its headers checks out against the signing
 * domain's own DNS key.
 *
 * The .eml files stay on the server. They hold addresses and message bodies and
 * must never reach the repository, which is why they live under .storage/ —
 * already gitignored — and are written with a name derived from the message,
 * not from anything a sender chose.
 */

import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import { mkdir, writeFile } from 'node:fs/promises'
import { createPublicKey } from 'node:crypto'
import { dkimVerify } from 'mailauth'
import { storagePath } from './paths.js'
import * as v3 from './v3.js'

const DIR = storagePath('inbound')

/** How many of the most recent arrivals the status endpoint will show. */
const RECENT = 25
const recent = []

/**
 * Pull the raw message out of whatever shape the provider posted.
 *
 * Providers disagree, and a provider can change its mind in a minor version, so
 * take the first field that looks like a MIME message rather than hard-coding
 * one path. A body posted as message/rfc822 is already the message.
 */
export function rawFrom(body, contentType = '') {
  if (Buffer.isBuffer(body)) return body
  if (typeof body === 'string') return Buffer.from(body)
  if (!body || typeof body !== 'object') return null
  const candidates = [
    body.raw,
    body.rawEmail,
    body.raw_email,
    body.email,
    body.message,
    body.mime,
    body.data?.raw,
    body.data?.email,
    body.data?.raw_email,
  ]
  for (const value of candidates) {
    if (typeof value === 'string' && value.includes(':')) return Buffer.from(value)
    if (Buffer.isBuffer(value)) return value
  }
  // Some providers send the parsed message with the original base64'd beside it.
  const b64 = body.rawBase64 ?? body.data?.rawBase64
  if (typeof b64 === 'string') return Buffer.from(b64, 'base64')
  return null
}

/**
 * Only the signing domain is kept, never the address.
 *
 * The local part is the one piece of this we have promised not to hold on to
 * any longer than the verification needs it, and a log line lives much longer
 * than that.
 */
function domainOf(header) {
  const match = String(header ?? '').match(/@([A-Za-z0-9.-]+)/)
  return match ? match[1].toLowerCase() : null
}

/**
 * The address that replied, needed to check the salted hash in the invite.
 *
 * Used and not stored: the record below keeps the domain only.
 */
function addressOf(raw) {
  const from = headerValue(raw, 'from') ?? ''
  const match = from.match(/<([^>]+)>/) ?? from.match(/([^\s<>]+@[^\s<>]+)/)
  return match ? match[1] : ''
}

function headerValue(raw, name) {
  const text = raw.toString('utf8').split(/\r?\n\r?\n/)[0]
  const line = text.split(/\r?\n(?![ \t])/).find((l) => l.toLowerCase().startsWith(name + ':'))
  return line ? line.slice(name.length + 1).trim() : null
}

/**
 * Verifies the signature and records what happened.
 *
 * The DNS lookup this makes asks the signing domain for its public key. It
 * carries the domain and nothing else — not the local part, not a byte of the
 * message — which is the one thing that leaves this machine during a check.
 */
export async function accept(raw) {
  const result = await dkimVerify(raw)
  const signatures = (result.results ?? []).map((s) => ({
    signingDomain: s.signingDomain,
    selector: s.selector,
    algo: s.algo,
    result: s.status?.result,
    comment: s.status?.comment || undefined,
  }))
  const pass = signatures.some((s) => s.result === 'pass')

  /**
   * Everything the frame transaction will need, taken from the signature that
   * passed: the modulus the provider signed with, the signature itself, and the
   * exact canonicalized header bytes it covers. The contract recomputes
   * sha256 over those bytes, so they have to be the ones mailauth verified and
   * not a re-canonicalisation of our own.
   */
  const verified = (result.results ?? []).find((s) => s.status?.result === 'pass')
  let dkim = null
  if (verified?.publicKey) {
    try {
      const { n } = createPublicKey({
        key: Buffer.from(verified.publicKey, 'base64'),
        format: 'der',
        type: 'spki',
      }).export({ format: 'jwk' })
      dkim = {
        signingDomain: verified.signingDomain,
        selector: verified.selector,
        modulus: '0x' + Buffer.from(n, 'base64url').toString('hex'),
        signature: '0x' + Buffer.from(verified.signature, 'base64').toString('hex'),
        signedHeaders: '0x' + Buffer.from(verified.signingHeaders.canonicalizedHeader, 'base64').toString('hex'),
      }
    } catch (error) {
      dkim = { error: error.message }
    }
  }

  // Named after the message, so the same mail delivered twice is one file and a
  // sender cannot choose where it lands.
  const id = createHash('sha256').update(raw).digest('hex').slice(0, 32)
  await mkdir(DIR, { recursive: true })
  const file = `${id}.eml`
  await writeFile(storagePath('inbound', file), raw)

  const record = {
    id,
    at: new Date().toISOString(),
    bytes: raw.length,
    fromDomain: domainOf(headerValue(raw, 'from')),
    toDomain: domainOf(headerValue(raw, 'to')),
    dkim: pass ? 'pass' : 'fail',
    signatures,
    file,
  }

  /**
   * Does this reply belong to a transfer? Only asked once the signature has
   * passed — an unsigned mail saying it is Bob is just a mail.
   */
  if (pass) {
    try {
      record.transfer = await v3.acceptFromReply({ text: raw.toString('utf8'), from: addressOf(raw), dkim })
    } catch (error) {
      record.transfer = { matched: false, reason: error.message }
    }
  }
  recent.unshift(record)
  recent.length = Math.min(recent.length, RECENT)

  // One line per arrival, no addresses in it.
  const linked = record.transfer?.matched
    ? `transfer=${record.transfer.transferId} accepted`
    : record.transfer
      ? `unlinked (${record.transfer.reason})`
      : 'not linked'
  console.log(`  inbound ${record.id} from ${record.fromDomain ?? 'unknown'} dkim=${record.dkim} ${record.bytes}b ${linked}`)
  return record
}

export function recentArrivals() {
  return recent
}

/**
 * Was this really the provider?
 *
 * Resend signs with Svix headers: the signed string is `id.timestamp.body` and
 * the secret is base64 after a `whsec_` prefix. Unset secret means we cannot
 * tell, and the route says so in its answer rather than implying it checked.
 */
export function verifySignature({ secret, id, timestamp, signature, body }) {
  if (!secret) return { checked: false }
  if (!id || !timestamp || !signature) return { checked: true, valid: false, reason: 'missing svix headers' }
  const key = Buffer.from(secret.replace(/^whsec_/, ''), 'base64')
  const expected = createHmac('sha256', key).update(`${id}.${timestamp}.${body}`).digest('base64')
  // The header can carry several space-separated versioned signatures.
  const offered = String(signature)
    .split(' ')
    .map((part) => part.split(',').pop())
    .filter(Boolean)
  const valid = offered.some((candidate) => {
    const a = Buffer.from(candidate)
    const b = Buffer.from(expected)
    return a.length === b.length && timingSafeEqual(a, b)
  })
  return { checked: true, valid }
}
