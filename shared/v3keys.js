/**
 * The three keys a passkey gives you, derived from one PRF output.
 *
 * All three come from the same secret by HKDF with different info strings, so a
 * passkey is the only thing anyone needs to carry: nothing is stored, and the
 * same passkey on a second device derives the same three keys. That property is
 * the whole reason the design works, and /prf exists to let a user check it.
 *
 * The salt and info strings here are load-bearing. The test page at web/src/prf.js
 * derives with WebCrypto and these exact strings; if they ever drift apart the
 * page will cheerfully report keys the app does not use. Change them in both or
 * in neither.
 */

import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'
import { x25519 } from '@noble/curves/ed25519'
import { secp256k1 } from '@noble/curves/secp256k1'
import { p256 } from '@noble/curves/p256'
import { keccak_256 } from '@noble/hashes/sha3'

export const SALT = 'pinesign/v1'

const encoder = new TextEncoder()
const info = (suffix) => encoder.encode(suffix)
const salt = encoder.encode(SALT)

const derive = (secret, suffix) => hkdf(sha256, secret, salt, info(suffix), 32)

/**
 * Some scalars are out of range, and a curve implementation that silently
 * repaired one would derive a different key elsewhere. The counter goes into
 * the info string and the first candidate in range wins: deterministic, and the
 * same answer in every implementation.
 */
function deriveValid(secret, suffix, isValid) {
  for (let counter = 0; counter < 256; counter++) {
    const candidate = derive(secret, `${suffix}/${counter}`)
    if (isValid(candidate)) return candidate
  }
  // 256 consecutive misses does not happen; a silent wrong answer would be worse.
  throw new Error(`could not derive a ${suffix} key from this passkey`)
}

const validP256 = (candidate) => {
  try {
    p256.getPublicKey(candidate, false)
    return true
  } catch {
    return false
  }
}

/**
 * @param {Uint8Array} prf 32 bytes of PRF output from the passkey
 * @returns {{
 *   enc: { privateKey: Uint8Array, publicKey: Uint8Array },
 *   arkiv: { privateKey: Uint8Array, publicKey: Uint8Array, address: string },
 *   sign: { privateKey: Uint8Array, publicKey: Uint8Array },
 * }}
 */
export function deriveKeys(prf) {
  const encPrivate = derive(prf, 'x25519')
  const arkivPrivate = deriveValid(prf, `${SALT}/key`, (c) => secp256k1.utils.isValidPrivateKey(c))
  const signPrivate = deriveValid(prf, `${SALT}/p256`, validP256)

  const arkivPublic = secp256k1.getPublicKey(arkivPrivate, false)
  return {
    // X25519, for sealing the file key to the recipient.
    enc: { privateKey: encPrivate, publicKey: x25519.getPublicKey(encPrivate) },
    // secp256k1, because an Arkiv entity is owned by an Ethereum address.
    arkiv: {
      privateKey: arkivPrivate,
      publicKey: secp256k1.getPublicKey(arkivPrivate, true),
      address: addressFromUncompressed(arkivPublic),
    },
    // P-256, because that is what the on-chain precompile verifies.
    sign: { privateKey: signPrivate, publicKey: p256.getPublicKey(signPrivate, false) },
  }
}

function addressFromUncompressed(publicKey) {
  const hash = keccak_256(publicKey.slice(1))
  return '0x' + Array.from(hash.slice(-20), (b) => b.toString(16).padStart(2, '0')).join('')
}
