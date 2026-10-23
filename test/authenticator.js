/**
 * A stand-in authenticator.
 *
 * This is the one thing the suite cannot have: a real passkey being tapped.
 * So it holds a real P-256 key and produces real DER signatures over real
 * authenticatorData — everything an authenticator sends, correctly formed.
 * Nothing downstream of the tap is faked, which is the point: the gateway's
 * verification is exercised, not bypassed.
 */

import { p256 } from '@noble/curves/p256'
import { createHash } from 'node:crypto'

const sha256 = (b) => createHash('sha256').update(b).digest()

export const toBase64url = (bytes) =>
  Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

/** The DER prefix an SPKI P-256 key carries before its uncompressed point. */
const SPKI_PREFIX = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex')

export function authenticator({ rpId, origin }) {
  const priv = p256.utils.randomPrivateKey()
  const point = Buffer.from(p256.getPublicKey(priv, false))
  const credentialPublicKey = toBase64url(Buffer.concat([SPKI_PREFIX, point]))
  let signCount = 0

  function authData({ rp = rpId, flags = 0x05, count = null } = {}) {
    const buf = Buffer.alloc(37)
    sha256(Buffer.from(rp, 'utf8')).copy(buf, 0)
    buf[32] = flags
    buf.writeUInt32BE(count ?? ++signCount, 33)
    return buf
  }

  /** One assertion, as the browser would post it to /api/signin/finish. */
  function assert({ challenge, type = 'webauthn.get', as = origin, ad = null, key = priv, crossOrigin = false } = {}) {
    const data = ad ?? authData()
    const clientDataJSON = Buffer.from(JSON.stringify({ type, challenge, origin: as, crossOrigin }))
    const signature = p256.sign(sha256(Buffer.concat([data, sha256(clientDataJSON)])), key)
    return {
      credentialPublicKey,
      clientDataJSON: toBase64url(clientDataJSON),
      authenticatorData: toBase64url(data),
      signature: toBase64url(signature.toDERRawBytes()),
    }
  }

  return { credentialPublicKey, assert, authData, privateKey: priv }
}
