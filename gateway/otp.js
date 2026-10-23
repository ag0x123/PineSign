/**
 * Email codes.
 *
 * A six-digit code emailed to an address, good for ten minutes and one use.
 * It proves one thing — that whoever is signing in can read that mailbox —
 * and that is all it is asked to prove: the key itself comes from the passkey
 * step that follows, and the code's only job is to say which address the
 * passkey is being bound to.
 *
 * In memory on purpose. A code is valid for minutes, so persisting it buys
 * nothing a restart does not already handle by asking for a new one.
 */

import { randomBytes, randomInt, createHash } from 'node:crypto'
import { normaliseEmail } from './secrets.js'

const TTL_MS = 10 * 60 * 1000
/** Enough tries for a typo and a fat-fingered paste, not enough to search. */
const MAX_ATTEMPTS = 5

/** One pending code per address: asking again replaces the one before it. */
const sessions = new Map()

/**
 * Per-address and per-IP windows, so neither a single mailbox nor a single
 * client can be used to pump mail through the gateway.
 */
const WINDOW_MS = 60 * 60 * 1000
const MAX_PER_EMAIL = 5
const MAX_PER_IP = 20
const counters = new Map()

function hit(kind, who, max) {
  const key = `${kind}:${who}`
  const now = Date.now()
  const entry = counters.get(key)
  if (!entry || now > entry.resetAt) {
    counters.set(key, { count: 1, resetAt: now + WINDOW_MS })
    return { ok: true }
  }
  entry.count += 1
  if (entry.count > max) {
    return { ok: false, retryAfter: Math.ceil((entry.resetAt - now) / 1000) }
  }
  return { ok: true }
}

function sessionId() {
  return randomBytes(12).toString('hex')
}

function digest(code) {
  return createHash('sha256').update(code).digest('hex')
}

export const VALID_EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/

/**
 * Issue a code for an address. Returns the session id the browser carries
 * through the rest of sign-in, and the code itself for the caller to mail —
 * it is never returned over HTTP.
 */
export function issue(email, ip) {
  const address = normaliseEmail(email)
  if (!VALID_EMAIL.test(address)) throw new Error('that does not look like an email address')

  const perEmail = hit('email', address, MAX_PER_EMAIL)
  if (!perEmail.ok) {
    throw Object.assign(new Error(`too many codes for that address — try again in ${perEmail.retryAfter}s`), { status: 429, retryAfter: perEmail.retryAfter })
  }
  const perIp = hit('ip', ip ?? 'unknown', MAX_PER_IP)
  if (!perIp.ok) {
    throw Object.assign(new Error(`too many codes from here — try again in ${perIp.retryAfter}s`), { status: 429, retryAfter: perIp.retryAfter })
  }

  const code = String(randomInt(0, 1_000_000)).padStart(6, '0')
  const id = sessionId()

  sessions.set(id, {
    email: address,
    // Stored as a hash: a heap dump or a log line should not hand over a
    // live code, even one with minutes left on it.
    codeHash: digest(code),
    attempts: 0,
    verifiedAt: null,
    expiresAt: Date.now() + TTL_MS,
  })

  // One address, one pending code. An older session for the same address is
  // dropped, so a code from two requests ago cannot still be used.
  for (const [otherId, other] of sessions) {
    if (otherId !== id && other.email === address) sessions.delete(otherId)
  }

  return { sessionId: id, code, expiresInMs: TTL_MS }
}

/** Check a code. One session, one success; a wrong code burns an attempt. */
export function verify(id, code) {
  const session = sessions.get(id)
  if (!session) return { ok: false, error: 'that code has expired — ask for a new one' }
  if (Date.now() > session.expiresAt) {
    sessions.delete(id)
    return { ok: false, error: 'that code has expired — ask for a new one' }
  }
  if (session.verifiedAt) return { ok: false, error: 'that code has already been used' }

  session.attempts += 1
  if (session.attempts > MAX_ATTEMPTS) {
    sessions.delete(id)
    return { ok: false, error: 'too many wrong codes — ask for a new one' }
  }
  if (digest(String(code ?? '')) !== session.codeHash) {
    return { ok: false, error: 'that code is not right' }
  }

  session.verifiedAt = Date.now()
  return { ok: true, email: session.email }
}

/**
 * The address a verified session belongs to. Everything after the code step
 * asks for this rather than taking an address from the request body.
 */
export function verifiedEmail(id) {
  const session = sessions.get(id)
  if (!session || !session.verifiedAt) return null
  if (Date.now() > session.expiresAt) {
    sessions.delete(id)
    return null
  }
  return session.email
}

/** Spend the session. Called once the key has been bound to the address. */
export function close(id) {
  sessions.delete(id)
}

setInterval(() => {
  const now = Date.now()
  for (const [id, s] of sessions) if (now > s.expiresAt) sessions.delete(id)
  for (const [k, v] of counters) if (now > v.resetAt) counters.delete(k)
}, 60_000).unref()
