/**
 * PineSign encryption module.
 *
 * Alice never sends a key to anyone. She derives it from her own private key
 * and Bob's public key; Bob derives the identical key from his private key and
 * hers. That is ECDH — the shared secret is computed independently on both
 * sides and never travels.
 *
 * secp256k1 throughout, so the same keypair that encrypts also signs the
 * on-chain receipt.
 */

import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import { hkdf } from '@noble/hashes/hkdf'
import { keccak_256 } from '@noble/hashes/sha3'
import { gcm } from '@noble/ciphers/aes'
import { randomBytes } from '@noble/ciphers/webcrypto'

export const INFO = new TextEncoder().encode('pinesign/v1')

// ---------- keys ----------

export function generatePrivateKey() {
  return secp256k1.utils.randomPrivateKey()
}

/** Compressed 33-byte public key, the form we publish and grant to. */
export function publicKeyFrom(privateKey) {
  return secp256k1.getPublicKey(privateKey, true)
}

/** Ethereum address, for the receipt contract. Derived from the uncompressed key. */
export function addressFrom(privateKey) {
  return addressFromPublicKey(secp256k1.getPublicKey(privateKey, false))
}

/**
 * The same address, for a key we were handed rather than one we hold. The
 * gateway derives a user's address from their published key instead of taking
 * an address on trust — a page can claim any address, but it cannot claim a
 * key it has no signature for.
 */
export function addressFromPublicKey(publicKey) {
  const point = secp256k1.ProjectivePoint.fromHex(asBytes(publicKey))
  return '0x' + toHex(keccak_256(point.toRawBytes(false).slice(1)).slice(-20))
}

// ---------- shared secret ----------

/**
 * ECDH + HKDF. Both directions produce the same 32 bytes:
 *   derive(alicePriv, bobPub) === derive(bobPriv, alicePub)
 *
 * The raw x-coordinate is not used directly as a key — HKDF spreads it into a
 * uniform 256-bit key, which is what AES expects.
 */
export function deriveSharedKey(privateKey, theirPublicKey) {
  const point = secp256k1.getSharedSecret(privateKey, theirPublicKey, true)
  const x = point.slice(1) // strip the parity byte, keep the x-coordinate
  return hkdf(sha256, x, undefined, INFO, 32)
}

// ---------- file encryption ----------

/**
 * AES-256-GCM. The nonce is random per file and prepended to the ciphertext,
 * so a transfer is one opaque blob: [12-byte nonce][ciphertext+tag].
 */
export function encrypt(plaintext, sharedKey) {
  const nonce = randomBytes(12)
  const sealed = gcm(sharedKey, nonce).encrypt(plaintext)
  const out = new Uint8Array(nonce.length + sealed.length)
  out.set(nonce, 0)
  out.set(sealed, nonce.length)
  return out
}

export function decrypt(blob, sharedKey) {
  const nonce = blob.slice(0, 12)
  const sealed = blob.slice(12)
  return gcm(sharedKey, nonce).decrypt(sealed)
}

// ---------- receipts ----------

/**
 * What both parties sign. Alice signs it at send time, Bob at claim time —
 * the same 32 bytes, so the two signatures are provably about one transfer
 * of one file to one recipient.
 */
export function transferDigest({ senderPubKey, recipientPubKey, plaintextHash }) {
  const parts = [
    INFO,
    asBytes(senderPubKey),
    asBytes(recipientPubKey),
    asBytes(plaintextHash),
  ]
  const total = parts.reduce((n, p) => n + p.length, 0)
  const buf = new Uint8Array(total)
  let offset = 0
  for (const p of parts) {
    buf.set(p, offset)
    offset += p.length
  }
  return keccak_256(buf)
}

export function hashPlaintext(plaintext) {
  return keccak_256(plaintext)
}

/** keccak of bytes, as 0x-hex — the form a commitment is published in. */
export function keccak256(bytes) {
  return '0x' + toHex(keccak_256(bytes))
}

export function sign(digest, privateKey) {
  const sig = secp256k1.sign(digest, privateKey)
  return sig.toCompactRawBytes()
}

export function verify(signature, digest, publicKey) {
  return secp256k1.verify(asBytes(signature), asBytes(digest), asBytes(publicKey))
}

// ---------- hex ----------

export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

export function fromHex(hex) {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

function asBytes(v) {
  return typeof v === 'string' ? fromHex(v) : v
}
