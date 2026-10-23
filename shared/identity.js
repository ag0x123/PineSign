/**
 * Identity storage.
 *
 * One secp256k1 keypair per browser. It is generated locally, never sent
 * anywhere, and is the only thing that can decrypt what was sent to it — the
 * gateway cannot recover a file even if it wanted to.
 */

import { generatePrivateKey, publicKeyFrom, addressFrom, toHex, fromHex } from './crypto.js'

const KEY = 'pinesign.identity'

function hydrate(privateKeyHex) {
  const privateKey = fromHex(privateKeyHex)
  return {
    privateKey,
    publicKey: publicKeyFrom(privateKey),
    publicKeyHex: toHex(publicKeyFrom(privateKey)),
    address: addressFrom(privateKey),
  }
}

/** The key this browser signs and decrypts with. */
export async function getIdentity() {
  const stored = localStorage.getItem(KEY)
  if (stored) return hydrate(stored)

  const privateKeyHex = toHex(generatePrivateKey())
  localStorage.setItem(KEY, privateKeyHex)
  return hydrate(privateKeyHex)
}
