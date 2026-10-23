/**
 * Where the user's key lives: in this browser tab, and nowhere else.
 *
 * The key is derived from the passkey when the user signs in, held in memory
 * for as long as the page is open, and never written to storage or sent over
 * the wire. Callers ask for an identity or a signer and get one; none of them
 * needs to know how it was produced.
 */

import { getIdentity } from './identity.js'
import { localSigner } from './client.js'
import {
  deriveSharedKey, decrypt, hashPlaintext, transferDigest, sign, toHex, fromHex, keccak256,
} from './crypto.js'

export async function identity() {
  const id = await getIdentity()
  return { publicKey: id.publicKeyHex, address: id.address }
}

export async function signer() {
  return localSigner(await getIdentity())
}

/** Decrypt a transfer and sign its receipt — one step, so the key stays here. */
export async function openTransfer({ ciphertext, senderPubKey, expectedCommitment }) {
  const id = await getIdentity()
  const sharedKey = deriveSharedKey(id.privateKey, fromHex(senderPubKey))
  const plaintext = decrypt(Uint8Array.from(ciphertext), sharedKey)

  const hash = toHex(hashPlaintext(plaintext))
  // The sender committed to keccak(hash), not to the hash itself — so the
  // check is against the commitment, and the hash stays ours to reveal.
  if (expectedCommitment && keccak256(fromHex(hash)) !== expectedCommitment.toLowerCase()) {
    throw new Error('the decrypted file does not match what the sender committed to')
  }

  const digest = transferDigest({ senderPubKey, recipientPubKey: id.publicKeyHex, plaintextHash: hash })
  return { plaintext: Array.from(plaintext), plaintextHash: hash, signature: toHex(sign(digest, id.privateKey)) }
}
