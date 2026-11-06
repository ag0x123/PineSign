/**
 * The bytes a Pinesign invite or accept carries in its Arkiv entity.
 *
 * Arkiv indexes the fields we need to search on — the fingerprint and the
 * salted email hash — and takes the rest as opaque bytes. That split is what
 * keeps the gateway honest: it can route an entity without being able to forge
 * one, because the payload is signed by a key only the passkey holder has.
 *
 * The signature covers the indexed fields too, so a gateway that rewrote the
 * fingerprint on an entity it was relaying would produce something that no
 * longer verifies. Reading an entity therefore means checking the payload
 * against the row it arrived in, never trusting the row alone.
 */

import { p256 } from '@noble/curves/p256'
import { sha256 } from '@noble/hashes/sha256'

export const VERSION = 1
export const KIND = { INVITE: 1, ACCEPT: 2 }

const ENC_KEY_BYTES = 32 // X25519 public key
const SIG_KEY_BYTES = 65 // P-256 public key, uncompressed
const SIG_BYTES = 64 // P-256 signature, compact r||s
export const PAYLOAD_BYTES = 2 + ENC_KEY_BYTES + SIG_KEY_BYTES + SIG_BYTES

const encoder = new TextEncoder()

/**
 * What the P-256 key signs.
 *
 * Both indexed fields are in here, and so is the kind: without it an accept
 * could be replayed as an invite for the same pair of values. The encryption
 * key is included because it is the thing the other side will encrypt to, and
 * a payload whose key could be swapped would be worthless.
 */
export function digest({ kind, fingerprint, emailHash, encPublicKey }) {
  const header = encoder.encode(`pinesign/v3/${kind}/${fingerprint}/${emailHash}/`)
  const message = new Uint8Array(header.length + encPublicKey.length)
  message.set(header, 0)
  message.set(encPublicKey, header.length)
  return sha256(message)
}

export function encode({ kind, encPublicKey, signPublicKey, signature }) {
  if (encPublicKey.length !== ENC_KEY_BYTES) throw new Error('encryption key must be 32 bytes')
  if (signPublicKey.length !== SIG_KEY_BYTES) throw new Error('signing key must be 65 bytes, uncompressed')
  if (signature.length !== SIG_BYTES) throw new Error('signature must be 64 bytes, compact')
  const out = new Uint8Array(PAYLOAD_BYTES)
  out[0] = VERSION
  out[1] = kind
  out.set(encPublicKey, 2)
  out.set(signPublicKey, 2 + ENC_KEY_BYTES)
  out.set(signature, 2 + ENC_KEY_BYTES + SIG_KEY_BYTES)
  return out
}

export function decode(bytes) {
  if (bytes.length !== PAYLOAD_BYTES) throw new Error(`payload must be ${PAYLOAD_BYTES} bytes, got ${bytes.length}`)
  if (bytes[0] !== VERSION) throw new Error(`unknown payload version ${bytes[0]}`)
  return {
    version: bytes[0],
    kind: bytes[1],
    encPublicKey: bytes.slice(2, 2 + ENC_KEY_BYTES),
    signPublicKey: bytes.slice(2 + ENC_KEY_BYTES, 2 + ENC_KEY_BYTES + SIG_KEY_BYTES),
    signature: bytes.slice(2 + ENC_KEY_BYTES + SIG_KEY_BYTES),
  }
}

/**
 * Does this payload belong to the row it came in?
 *
 * @noble/curves 1.x takes a digest and does not hash what it is given, which is
 * what we want here — the digest is the thing both sides agreed on. The 2.x
 * line hashes the message itself, so this is not portable to the spikes'
 * newer copy without passing the pre-image instead.
 */
export function verify(payloadBytes, { fingerprint, emailHash }) {
  const { kind, encPublicKey, signPublicKey, signature } = decode(payloadBytes)
  const expected = digest({ kind, fingerprint, emailHash, encPublicKey })
  return p256.verify(signature, expected, signPublicKey)
}

export function sign({ kind, fingerprint, emailHash, encPublicKey, signPrivateKey }) {
  const d = digest({ kind, fingerprint, emailHash, encPublicKey })
  return p256.sign(d, signPrivateKey).toCompactRawBytes()
}
