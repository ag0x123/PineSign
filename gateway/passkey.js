/**
 * The passkey half of sign-in.
 *
 * The gateway never sees the key a passkey derives. What it does is issue the
 * challenge, and the challenge is what ties the ceremony to the address the
 * email code just proved:
 *
 *   challenge = HMAC(email, server secret) ‖ OTP session id
 *
 * Both halves matter. The HMAC means a challenge cannot be moved to another
 * address — only this server can produce the tag for an address, and it only
 * produces it for a session that has already answered a code. The session id
 * means it cannot be moved to another sign-in either, including a later one by
 * the same person.
 *
 * On the way back, `clientDataJSON` carries the challenge the authenticator
 * actually signed over, and the origin the browser was on. Checking both is
 * what makes the binding worth having: a ceremony driven from some other page
 * does not match, and neither does one driven for some other address.
 */

import { emailTag } from './secrets.js'

/**
 * The relying party the passkey belongs to.
 *
 * Deliberately a subdomain, and deliberately not the apex. A credential scoped
 * to `id.example.com` can be used by that host and anything under it, but not
 * by `example.com` — so the lander, which the gateway serves, cannot ask for an
 * assertion and read the key out of it. Only the static sign-in pages can.
 */
export const RP_ID = process.env.PASSKEY_RP_ID ?? null
export const RP_NAME = process.env.PASSKEY_RP_NAME ?? 'PineSign'

/**
 * Which origins may drive a ceremony. These are the published sign-in pages;
 * anything else presenting a valid challenge is a page that should not have it.
 */
export const ORIGINS = (process.env.SIGNIN_ORIGINS ?? '')
  .split(',')
  .map((o) => o.trim().replace(/\/$/, ''))
  .filter(Boolean)

export const configured = Boolean(RP_ID && ORIGINS.length)

function base64url(bytes) {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** The challenge for a verified session, as the browser will receive it. */
export async function challengeFor(email, sessionId) {
  const tag = Buffer.from(await emailTag(email), 'hex')
  const session = Buffer.from(sessionId, 'utf8')
  return base64url(Buffer.concat([tag, session]))
}

/**
 * Check what came back. Returns `{ ok }` or `{ ok: false, error }` — the error
 * is for the operator's log as much as the user, so it says which check failed.
 */
export async function checkCeremony({ email, sessionId, clientDataJSON, expectedType }) {
  if (!configured) {
    return { ok: false, error: 'this server has no passkey configuration (PASSKEY_RP_ID, SIGNIN_ORIGINS)' }
  }

  let clientData
  try {
    clientData = JSON.parse(Buffer.from(String(clientDataJSON ?? ''), 'base64').toString('utf8'))
  } catch {
    return { ok: false, error: 'clientDataJSON is not valid base64 JSON' }
  }

  if (clientData.type !== expectedType) {
    return { ok: false, error: `expected a ${expectedType} ceremony, got ${clientData.type}` }
  }

  const expected = await challengeFor(email, sessionId)
  if (clientData.challenge !== expected) {
    return { ok: false, error: 'the signed challenge is not the one this session was issued' }
  }

  const origin = String(clientData.origin ?? '').replace(/\/$/, '')
  if (!ORIGINS.includes(origin)) {
    return { ok: false, error: `${origin || 'that origin'} is not an allowed sign-in page` }
  }

  return { ok: true }
}
