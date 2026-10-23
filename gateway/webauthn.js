/**
 * WebAuthn assertion verification.
 *
 * Until now the gateway read the challenge and the origin out of
 * `clientDataJSON` and checked those — but `clientDataJSON` arrives from the
 * browser, so a page could simply write the right origin into it. What was
 * missing is the only thing that makes any of it binding: the authenticator's
 * signature over that exact blob.
 *
 * So the credential's public key is recorded at sign-up and every assertion
 * after it is verified against that key. A forged `clientDataJSON` now fails,
 * because producing a signature over it needs the private half, which lives in
 * the authenticator and has never been anywhere else.
 *
 * The same stored key is what the delivery contract will verify on chain, so
 * this is also where that becomes possible at all.
 */

import { createHash } from 'node:crypto'
import { p256 } from '@noble/curves/p256'

/** Flags in authenticatorData byte 32. */
const UP = 0x01 // user was present — someone touched it
const UV = 0x04 // user was verified — biometric or PIN, not just presence

export function fromBase64url(value) {
  const padded = String(value ?? '').replace(/-/g, '+').replace(/_/g, '/')
  return Buffer.from(padded + '='.repeat((4 - (padded.length % 4)) % 4), 'base64')
}

export function toBase64url(bytes) {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const sha256 = (bytes) => createHash('sha256').update(bytes).digest()

/**
 * The raw P-256 point out of an SPKI key.
 *
 * `getPublicKey()` in the browser hands back SPKI DER, which is an algorithm
 * identifier followed by the uncompressed point. Rather than walk the ASN.1,
 * take the trailing 65 bytes and insist they start with 0x04 — if they do not,
 * this is not the key shape we accept and guessing further would be worse.
 */
export function pointFromSpki(spki) {
  const bytes = Buffer.from(spki)
  if (bytes.length < 65) throw new Error('that public key is too short to be a P-256 key')
  const point = bytes.subarray(bytes.length - 65)
  if (point[0] !== 0x04) throw new Error('expected an uncompressed P-256 public key')
  // Rejects a point that is not on the curve, which an attacker would like.
  p256.ProjectivePoint.fromHex(point.toString('hex')).assertValidity()
  return point
}

/** Is this a P-256 credential key we can verify, and store for on-chain use? */
export function credentialKey(spkiBase64url) {
  const point = pointFromSpki(fromBase64url(spkiBase64url))
  return {
    spki: spkiBase64url,
    // x and y separately, because that is the form the P-256 precompile and
    // therefore the delivery contract takes.
    x: `0x${point.subarray(1, 33).toString('hex')}`,
    y: `0x${point.subarray(33, 65).toString('hex')}`,
  }
}

/**
 * Verify one assertion, completely.
 *
 * Every check is here rather than spread across callers, because a WebAuthn
 * verification that is missing one of them usually still passes the happy path
 * — which is exactly how this was wrong before.
 */
export function verifyAssertion({
  credentialPublicKey,
  clientDataJSON,
  authenticatorData,
  signature,
  expectedChallenge,
  expectedOrigins,
  expectedRpId,
  expectedType = 'webauthn.get',
  previousSignCount = 0,
}) {
  const fail = (error) => ({ ok: false, error })

  let clientData
  const clientDataBytes = fromBase64url(clientDataJSON)
  try {
    clientData = JSON.parse(clientDataBytes.toString('utf8'))
  } catch {
    return fail('clientDataJSON is not valid JSON')
  }

  if (clientData.type !== expectedType) {
    return fail(`expected a ${expectedType} ceremony, got ${clientData.type}`)
  }
  if (clientData.challenge !== expectedChallenge) {
    return fail('the signed challenge is not the one this session was issued')
  }
  // A cross-origin ceremony is one driven from inside an iframe on some other
  // site. Nothing here ever needs that, so it is refused rather than reasoned
  // about.
  if (clientData.crossOrigin === true) {
    return fail('a cross-origin ceremony is not accepted')
  }
  const origin = String(clientData.origin ?? '').replace(/\/$/, '')
  if (!expectedOrigins.includes(origin)) {
    return fail(`${origin || 'that origin'} is not an allowed sign-in page`)
  }

  const authData = fromBase64url(authenticatorData)
  if (authData.length < 37) return fail('authenticatorData is too short')

  // The rpIdHash is what binds the credential to the domain. Checking it here
  // as well as trusting the browser means a mismatch is caught even if the
  // assertion was obtained somewhere we did not expect.
  const rpIdHash = authData.subarray(0, 32)
  if (!rpIdHash.equals(sha256(Buffer.from(expectedRpId, 'utf8')))) {
    return fail('this assertion is for a different relying party')
  }

  const flags = authData[32]
  if (!(flags & UP)) return fail('the authenticator reported no user presence')
  if (!(flags & UV)) return fail('the authenticator did not verify the user')

  const signCount = authData.readUInt32BE(33)

  // The signature is over authenticatorData followed by the hash of the exact
  // clientDataJSON bytes — not over a re-serialisation of the parsed object,
  // which would not match.
  const signed = Buffer.concat([authData, sha256(clientDataBytes)])
  const sigBytes = fromBase64url(signature)

  let verified = false
  try {
    // WebAuthn ES256 signatures are ASN.1 DER. Some authenticators have been
    // known to emit raw r‖s, so a compact signature is accepted as a fallback
    // rather than rejected as malformed.
    const point = pointFromSpki(fromBase64url(credentialPublicKey))
    const digest = sha256(signed)
    try {
      verified = p256.verify(p256.Signature.fromDER(sigBytes), digest, point)
    } catch {
      verified = sigBytes.length === 64 && p256.verify(sigBytes, digest, point)
    }
  } catch (err) {
    return fail(`that credential key cannot be used: ${err.message}`)
  }

  if (!verified) return fail('the authenticator signature does not verify')

  // A counter that goes backwards means two things are using one credential —
  // a clone. Authenticators that do not count at all report zero forever, and
  // that is allowed, because insisting otherwise would lock out most passkeys.
  if (signCount !== 0 && signCount <= previousSignCount) {
    return fail('this credential has been used out of order — it may be cloned')
  }

  return { ok: true, signCount, origin }
}
