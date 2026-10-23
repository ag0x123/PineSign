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
 * On the way back, the authenticator's signature over `clientDataJSON` and
 * `authenticatorData` is verified against the credential's own public key —
 * recorded at sign-up, and the same key the delivery contract verifies on
 * chain. Reading the challenge and origin out of `clientDataJSON` without
 * checking that signature would be worth nothing: the browser writes that blob.
 */

import { emailTag } from './secrets.js'
import { verifyAssertion, credentialKey } from './webauthn.js'

export { credentialKey }

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
export async function checkCeremony({
  email, sessionId, clientDataJSON, authenticatorData, signature,
  credentialPublicKey, expectedType, previousSignCount = 0,
}) {
  if (!configured) {
    return { ok: false, error: 'this server has no passkey configuration (PASSKEY_RP_ID, SIGNIN_ORIGINS)' }
  }
  if (!credentialPublicKey) {
    return { ok: false, error: 'no credential public key — the page must send the one it registered' }
  }

  return verifyAssertion({
    credentialPublicKey,
    clientDataJSON,
    authenticatorData,
    signature,
    expectedChallenge: await challengeFor(email, sessionId),
    expectedOrigins: ORIGINS,
    expectedRpId: RP_ID,
    expectedType,
    previousSignCount,
  })
}
