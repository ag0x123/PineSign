/**
 * The split key.
 *
 * A file is encrypted once, under a key nobody holds whole:
 *
 *   K = A XOR B
 *   A = HKDF(ECDH(e_A, pk_B), transferId)    the recipient's half
 *   B = K XOR A                              the sender's half
 *
 * `A` is an ECDH secret between a fresh per-transfer key and the recipient's
 * published key, so the recipient can compute it from the chain record alone
 * and nobody else can compute it at all. `B` is whatever it has to be for the
 * two to add up to `K`, and it is held back until the recipient's acceptance
 * is on chain.
 *
 * That is the whole mechanism. Neither half is a key: `A` alone decrypts
 * nothing, `B` alone decrypts nothing, and the ciphertext sits in public on
 * Swarm the entire time being useless.
 *
 * The ephemeral secret
 * -------------------
 * `e_A`'s private half is used once, to derive `A`, and then dropped. It is
 * never stored and never sent, so after a send there is no copy of it
 * anywhere — which matters because anyone holding it could recompute `A` for
 * that transfer and, with a released `B`, read the file. The contract refuses
 * a second use of the same ephemeral public key, so a sender who reused one
 * would be stopped rather than quietly weakening both transfers.
 */

import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import { hkdf } from '@noble/hashes/hkdf'
import { keccak_256 } from '@noble/hashes/sha3'
import { gcm } from '@noble/ciphers/aes'
import { randomBytes } from '@noble/ciphers/webcrypto'
import { toHex, fromHex } from './crypto.js'

const encoder = new TextEncoder()

/** Salt prefixed to the plaintext before encryption, so `keccak(salt‖F)`
 *  differs for the same file sent twice. */
export const SALT_BYTES = 16

const A_INFO = encoder.encode('pinesign/v1/A')
const DESC_INFO = encoder.encode('pinesign/v1/desc')

// ---- the halves ----

/** A fresh per-transfer keypair. The secret is the caller's to destroy. */
export function ephemeral() {
  const secretKey = secp256k1.utils.randomPrivateKey()
  return { secretKey, publicKey: secp256k1.getPublicKey(secretKey, true) }
}

/**
 * The recipient's half.
 *
 * Both sides reach the same 32 bytes: the sender from the ephemeral secret and
 * the recipient's published key, the recipient from their own key and the
 * ephemeral public key off the chain record. `transferId` goes in as the salt,
 * so the same two keys produce a different half for every transfer.
 */
export function recipientHalf({ secretKey, theirPublicKey, transferId }) {
  const point = secp256k1.getSharedSecret(secretKey, asBytes(theirPublicKey), true)
  // The parity byte is dropped and the x-coordinate kept, which is what makes
  // both directions agree.
  return hkdf(sha256, point.slice(1), asBytes(transferId), A_INFO, 32)
}

/** XOR of two 32-byte halves. Its own function so neither caller writes a loop. */
export function xor(left, right) {
  if (left.length !== right.length) throw new Error('halves must be the same length')
  const out = new Uint8Array(left.length)
  for (let i = 0; i < left.length; i++) out[i] = left[i] ^ right[i]
  return out
}

// ---- the file ----

/**
 * Encrypt a file under a fresh random key.
 *
 * The salt is prepended to the plaintext rather than kept beside it, so the
 * commitment `keccak(salt‖F)` is over exactly the bytes that come back out.
 * Sending the same file twice therefore commits to two different values, and
 * the commitment does not leak that the files were the same.
 */
export function encryptFile(plaintext) {
  const key = randomBytes(32)
  const salt = randomBytes(SALT_BYTES)

  const saltedPlaintext = new Uint8Array(salt.length + plaintext.length)
  saltedPlaintext.set(salt, 0)
  saltedPlaintext.set(plaintext, salt.length)

  const nonce = randomBytes(12)
  const sealed = gcm(key, nonce).encrypt(saltedPlaintext)
  const ciphertext = new Uint8Array(nonce.length + sealed.length)
  ciphertext.set(nonce, 0)
  ciphertext.set(sealed, nonce.length)

  return {
    key,
    salt,
    ciphertext,
    /** keccak(salt‖F) — the preimage the recipient recovers by decrypting. */
    plaintextHash: keccak_256(saltedPlaintext),
  }
}

/** Decrypt, and hand back both the file and the preimage that proves it. */
export function decryptFile(ciphertext, key) {
  const bytes = asBytes(ciphertext)
  const nonce = bytes.slice(0, 12)
  const saltedPlaintext = gcm(key, nonce).decrypt(bytes.slice(12))
  if (saltedPlaintext.length < SALT_BYTES) throw new Error('that plaintext is too short to carry a salt')
  return {
    plaintext: saltedPlaintext.slice(SALT_BYTES),
    salt: saltedPlaintext.slice(0, SALT_BYTES),
    plaintextHash: keccak_256(saltedPlaintext),
  }
}

// ---- the description ----

/**
 * The short description, encrypted so only the recipient can read it.
 *
 * Keyed from `A`, which the recipient can derive before accepting anything.
 * The point is that they are not asked to sign for an envelope they cannot
 * see the label of: "one invoice, 40kb" is readable first, the file itself
 * only after acceptance.
 */
export function encryptDescription(description, recipientHalfKey) {
  const key = hkdf(sha256, recipientHalfKey, undefined, DESC_INFO, 32)
  const nonce = randomBytes(12)
  const sealed = gcm(key, nonce).encrypt(encoder.encode(description))
  const out = new Uint8Array(nonce.length + sealed.length)
  out.set(nonce, 0)
  out.set(sealed, nonce.length)
  return out
}

export function decryptDescription(blob, recipientHalfKey) {
  const key = hkdf(sha256, recipientHalfKey, undefined, DESC_INFO, 32)
  const bytes = asBytes(blob)
  const plain = gcm(key, bytes.slice(0, 12)).decrypt(bytes.slice(12))
  return new TextDecoder().decode(plain)
}

// ---- commitments ----

/** keccak of bytes, 0x-prefixed. */
export function hash(bytes) {
  return '0x' + toHex(keccak_256(asBytes(bytes)))
}

/**
 * keccak over a single abi-encoded bytes32, which is what the contract
 * computes. Written once here so the two cannot drift: `keccak(abi.encode(x))`
 * is not `keccak(x)`, and getting that wrong fails only at release time.
 */
export function commitToWord(word) {
  const value = asBytes(word)
  if (value.length !== 32) throw new Error('a commitment is over exactly 32 bytes')
  return '0x' + toHex(keccak_256(value))
}

function asBytes(value) {
  return typeof value === 'string' ? fromHex(value) : value
}

// ---- the transfer id ----

/**
 * The transfer id, exactly as the contract derives it.
 *
 * It is `keccak256(abi.encode(...))` over static types only, which is nothing
 * more than each value as a 32-byte big-endian word, concatenated. Written out
 * by hand rather than pulling an ABI encoder into the signing page's bundle —
 * that page is the one thing a user has to trust the bytes of, so it stays as
 * small as it can be.
 *
 * `A` is salted with this, so a sender and a recipient who disagree about it
 * derive different halves and the file simply will not open. The live script
 * checks this function against the contract for exactly that reason.
 */
export function transferId({
  sender,
  passkeyX,
  passkeyY,
  pkBX,
  pkBOdd,
  ephemeralX,
  ephemeralOdd,
  ciphertextHash,
  plaintextCommitment,
  descriptionHash,
  acceptBy,
  releaseBy,
}) {
  const words = [
    word(sender, 20),
    word(passkeyX, 32),
    word(passkeyY, 32),
    word(pkBX, 32),
    boolWord(pkBOdd),
    word(ephemeralX, 32),
    boolWord(ephemeralOdd),
    word(ciphertextHash, 32),
    word(plaintextCommitment, 32),
    word(descriptionHash, 32),
    numberWord(acceptBy),
    numberWord(releaseBy),
  ]

  const buf = new Uint8Array(words.length * 32)
  words.forEach((w, i) => buf.set(w, i * 32))
  return '0x' + toHex(keccak_256(buf))
}

/** A fixed-width value, right-aligned in 32 bytes, as the ABI encodes it. */
function word(value, expectedBytes) {
  const bytes = asBytes(value)
  if (bytes.length !== expectedBytes) {
    throw new Error(`expected ${expectedBytes} bytes, got ${bytes.length}`)
  }
  const out = new Uint8Array(32)
  out.set(bytes, 32 - bytes.length)
  return out
}

function boolWord(value) {
  const out = new Uint8Array(32)
  out[31] = value ? 1 : 0
  return out
}

function numberWord(value) {
  const out = new Uint8Array(32)
  let n = BigInt(value)
  for (let i = 31; i >= 0 && n > 0n; i--) {
    out[i] = Number(n & 0xffn)
    n >>= 8n
  }
  return out
}

/**
 * A compressed secp256k1 public key split into the form the contract stores:
 * the x-coordinate as a word, and the parity as a bool.
 */
export function splitPublicKey(publicKey) {
  const bytes = asBytes(publicKey)
  if (bytes.length !== 33) throw new Error('expected a 33-byte compressed public key')
  if (bytes[0] !== 0x02 && bytes[0] !== 0x03) throw new Error('that is not a compressed public key')
  return { x: '0x' + toHex(bytes.slice(1)), odd: bytes[0] === 0x03 }
}

/** And back again, which is how a recipient reconstructs it from the chain. */
export function joinPublicKey({ x, odd }) {
  const bytes = asBytes(x)
  if (bytes.length !== 32) throw new Error('expected a 32-byte x coordinate')
  const out = new Uint8Array(33)
  out[0] = odd ? 0x03 : 0x02
  out.set(bytes, 1)
  return out
}
