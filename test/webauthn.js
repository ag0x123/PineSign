/**
 * WebAuthn verification, against forgeries.
 *
 * No browser and no authenticator: a real P-256 key stands in for the
 * authenticator and signs real DER signatures, which is the part that matters.
 * Every check in verifyAssertion gets its own case, because a WebAuthn
 * verifier missing one of them still passes the happy path — which is how this
 * was wrong before it was written down.
 */

import { p256 } from '@noble/curves/p256'
import { createHash } from 'node:crypto'
import { verifyAssertion, credentialKey, toBase64url } from '../gateway/webauthn.js'

const sha256 = (b) => createHash('sha256').update(b).digest()
const RP_ID = 'id.test.local'
const ORIGIN = 'https://v1.id.test.local'
const CHALLENGE = toBase64url(Buffer.from('a'.repeat(44)))

// Stand in for the authenticator: a real P-256 key, real DER signatures.
const priv = p256.utils.randomPrivateKey()
const pointHex = p256.getPublicKey(priv, false)
// SPKI, as getPublicKey() would hand back: prefix + uncompressed point.
const SPKI_PREFIX = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex')
const spki = toBase64url(Buffer.concat([SPKI_PREFIX, Buffer.from(pointHex)]))

function authData({ rpId = RP_ID, flags = 0x05, signCount = 1 } = {}) {
  const buf = Buffer.alloc(37)
  sha256(Buffer.from(rpId, 'utf8')).copy(buf, 0)
  buf[32] = flags
  buf.writeUInt32BE(signCount, 33)
  return buf
}

function assert({ type = 'webauthn.get', challenge = CHALLENGE, origin = ORIGIN, crossOrigin = false,
                  ad = authData(), key = priv } = {}) {
  const clientDataJSON = Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin }))
  const signed = Buffer.concat([ad, sha256(clientDataJSON)])
  const sig = p256.sign(sha256(signed), key)
  return {
    credentialPublicKey: spki,
    clientDataJSON: toBase64url(clientDataJSON),
    authenticatorData: toBase64url(ad),
    signature: toBase64url(sig.toDERRawBytes()),
    expectedChallenge: CHALLENGE,
    expectedOrigins: [ORIGIN],
    expectedRpId: RP_ID,
  }
}

let pass = 0, fail = 0
const check = (label, cond) => { console.log(`${cond ? '  ok  ' : ' FAIL '} ${label}`); cond ? pass++ : fail++ }

const key = credentialKey(spki)
check('an SPKI key yields x and y', key.x.length === 66 && key.y.length === 66)
check('x matches the point', key.x.slice(2) === Buffer.from(pointHex).subarray(1, 33).toString('hex'))

check('a genuine assertion verifies', verifyAssertion(assert()).ok)

check('a forged clientDataJSON is refused', !verifyAssertion({
  ...assert(),
  clientDataJSON: toBase64url(Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: CHALLENGE, origin: ORIGIN, crossOrigin: false, extra: 'tampered' }))),
}).ok)

check('another key cannot sign for this credential', !verifyAssertion(assert({ key: p256.utils.randomPrivateKey() })).ok)
check('a wrong origin is refused', !verifyAssertion(assert({ origin: 'https://evil.example' })).ok)
check('a wrong challenge is refused', !verifyAssertion(assert({ challenge: toBase64url(Buffer.from('b'.repeat(44))) })).ok)
check('a cross-origin ceremony is refused', !verifyAssertion(assert({ crossOrigin: true })).ok)
check('a create blob is not a get', !verifyAssertion(assert({ type: 'webauthn.create' })).ok)
check('another rp is refused', !verifyAssertion(assert({ ad: authData({ rpId: 'id.evil.example' }) })).ok)
check('no user presence is refused', !verifyAssertion(assert({ ad: authData({ flags: 0x04 }) })).ok)
check('no user verification is refused', !verifyAssertion(assert({ ad: authData({ flags: 0x01 }) })).ok)
check('short authenticatorData is refused', !verifyAssertion({ ...assert(), authenticatorData: toBase64url(Buffer.alloc(10)) }).ok)

const counted = verifyAssertion(assert({ ad: authData({ signCount: 5 }) }))
check('the counter comes back', counted.ok && counted.signCount === 5)
check('a replayed counter is refused', !verifyAssertion({ ...assert({ ad: authData({ signCount: 5 }) }), previousSignCount: 5 }).ok)
check('a zero counter is always allowed', verifyAssertion({ ...assert({ ad: authData({ signCount: 0 }) }), previousSignCount: 9 }).ok)

check('a point off the curve is refused', (() => {
  const bad = Buffer.concat([SPKI_PREFIX, Buffer.from('04' + '11'.repeat(64), 'hex')])
  try { credentialKey(toBase64url(bad)); return false } catch { return true }
})())

console.log(`\n${pass} passed, ${fail} failed  (webauthn)`)
process.exit(fail === 0 ? 0 : 1)
