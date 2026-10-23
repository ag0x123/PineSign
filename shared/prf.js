/**
 * The key, derived from the passkey.
 *
 * WebAuthn's PRF extension gives a page 32 bytes that only this passkey can
 * produce for this salt. It is not the credential's key and it cannot be used
 * to forge an assertion; it is a per-salt secret, and it is the same 32 bytes
 * on every device the passkey syncs to. That is what makes it usable as the
 * root of an encryption key: the user's files stay openable on their new
 * laptop without anything having been stored or sent anywhere.
 *
 * HKDF turns those bytes into a secp256k1 scalar. The private key exists in
 * this page's memory and nowhere else — not in storage, not in a cookie, and
 * never in a request.
 */

import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import { hkdf } from '@noble/hashes/hkdf'
import { publicKeyFrom, addressFrom, toHex } from './crypto.js'

/** The PRF salt. Changing it changes every key, so it is a constant for good. */
export const PRF_SALT = 'pinesign/v1'

const encoder = new TextEncoder()

export function base64urlToBytes(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4))
  return Uint8Array.from(binary, (c) => c.charCodeAt(0))
}

export function bytesToBase64url(bytes) {
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Password managers and platforms that implement PRF today. Named in the error
 * rather than left to the user to work out, because "your passkey provider does
 * not support this" is useless advice on its own.
 */
export const PRF_PROVIDERS = '1Password, Bitwarden, Proton Pass, Dashlane, or a Chrome profile passkey'

export class NoPrfError extends Error {
  constructor() {
    super(
      `This passkey cannot derive an encryption key: it does not support the WebAuthn PRF extension. ` +
      `Create your passkey with ${PRF_PROVIDERS} and try again.`,
    )
    this.name = 'NoPrfError'
  }
}

/**
 * The key, from the 32 bytes the passkey returned. HKDF to a valid scalar.
 *
 * Almost every 32-byte string is a valid secp256k1 private key, but not all of
 * them are, and a key that is silently clamped into range would be a different
 * key on a different implementation. So the counter goes into the info string
 * and we take the first value that is genuinely in range — deterministic, and
 * the same answer everywhere.
 */
export function keyFromPrfOutput(secret) {
  for (let counter = 0; counter < 256; counter++) {
    const info = encoder.encode(`${PRF_SALT}/key/${counter}`)
    const candidate = hkdf(sha256, secret, undefined, info, 32)
    if (secp256k1.utils.isValidPrivateKey(candidate)) return candidate
  }
  // 256 consecutive misses is not something that happens; a loop that cannot
  // end is worse than an error that says so.
  throw new Error('could not derive a key from this passkey')
}

function hydrate(privateKey) {
  return {
    privateKey,
    publicKey: publicKeyFrom(privateKey),
    publicKeyHex: toHex(publicKeyFrom(privateKey)),
    address: addressFrom(privateKey),
  }
}

function prfResult(credential) {
  const results = credential?.getClientExtensionResults?.()?.prf?.results
  if (!results?.first) throw new NoPrfError()
  return new Uint8Array(results.first)
}

/**
 * Create a passkey, then immediately assert it to get the PRF output.
 *
 * Two ceremonies, not one, because an authenticator is allowed to return no
 * PRF result on creation — and several do. Asking straight afterwards means a
 * brand-new passkey yields its key in the same sitting, rather than the user
 * finding out on their next visit that it cannot.
 */
export async function createAndDerive({ challenge, rpId, rpName, email, userHandle }) {
  const created = await navigator.credentials.create({
    publicKey: {
      challenge: base64urlToBytes(challenge),
      rp: { id: rpId, name: rpName },
      user: {
        id: base64urlToBytes(userHandle),
        name: email,
        displayName: email,
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 }, // ES256
        { type: 'public-key', alg: -257 }, // RS256
      ],
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
      },
      attestation: 'none',
      extensions: { prf: {} },
    },
  })
  if (!created) throw new Error('no passkey was created')

  // The created credential carries the clientDataJSON the gateway checks; the
  // assertion that follows is only how the PRF output is obtained.
  const clientDataJSON = bytesToBase64url(new Uint8Array(created.response.clientDataJSON))
  const identity = await derive({ challenge, rpId, credentialId: created.rawId })
  return { ...identity, clientDataJSON, created: true }
}

/** Assert an existing passkey and derive the key from its PRF output. */
export async function derive({ challenge, rpId, credentialId = null }) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: base64urlToBytes(challenge),
      rpId,
      userVerification: 'required',
      allowCredentials: credentialId
        ? [{ type: 'public-key', id: credentialId }]
        : [],
      extensions: { prf: { eval: { first: encoder.encode(PRF_SALT) } } },
    },
  })
  if (!assertion) throw new Error('no passkey was presented')

  const identity = hydrate(keyFromPrfOutput(prfResult(assertion)))
  return {
    ...identity,
    clientDataJSON: bytesToBase64url(new Uint8Array(assertion.response.clientDataJSON)),
    created: false,
  }
}
