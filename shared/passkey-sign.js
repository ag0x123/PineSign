/**
 * A passkey signature the contract can check.
 *
 * The recipient's acceptance is an EIP-712 digest signed by their passkey, and
 * the contract verifies it through the P-256 precompile. That means handing it
 * three things the browser does not volunteer in a usable shape: the signature
 * as a raw (r, s) pair rather than ASN.1, and the offsets of the fields inside
 * `clientDataJSON`.
 *
 * Why offsets rather than a JSON parser on chain: browsers disagree about key
 * order and about which optional fields they include, so a contract that
 * rebuilt the JSON and compared hashes would reject honest authenticators. The
 * caller says where each field is and the contract checks that what is at that
 * offset is exactly what it must be. A wrong offset fails closed.
 */

import { bytesToBase64url } from './prf.js'

const FIELD_TYPE = '"type":"webauthn.get"'
const FIELD_CHALLENGE = '"challenge":"'
const FIELD_ORIGIN = '"origin":"'

/**
 * Sign a 32-byte digest with the passkey.
 *
 * The digest goes in as the WebAuthn challenge, which is what binds the
 * ceremony to this one transfer: the contract recomputes the digest from its
 * own stored record and will only accept a signature over that exact value.
 */
export async function assertOverDigest({ digest, rpId, credentialId = null }) {
  const challengeBytes = asBytes(digest)
  if (challengeBytes.length !== 32) throw new Error('a digest is 32 bytes')

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: challengeBytes,
      rpId,
      userVerification: 'required',
      allowCredentials: credentialId ? [{ type: 'public-key', id: asBytes(credentialId) }] : [],
    },
  })
  if (!assertion) throw new Error('no passkey was presented')

  const clientDataBytes = new Uint8Array(assertion.response.clientDataJSON)
  const json = new TextDecoder().decode(clientDataBytes)

  // The challenge the authenticator actually signed over must be the digest we
  // asked for. Checking here means a mismatch is a clear error rather than an
  // unexplained revert later.
  const expected = bytesToBase64url(challengeBytes)
  if (!json.includes(`${FIELD_CHALLENGE}${expected}`)) {
    throw new Error('the authenticator signed a different challenge than the one given')
  }

  const indices = fieldOffsets(json)
  const { r, s } = fromDer(new Uint8Array(assertion.response.signature))

  return {
    authenticatorData: `0x${toHex(new Uint8Array(assertion.response.authenticatorData))}`,
    clientDataJSON: `0x${toHex(clientDataBytes)}`,
    ...indices,
    r: `0x${toHex(r)}`,
    s: `0x${toHex(s)}`,
    /** For showing the user what they just signed, and for the record. */
    origin: originFrom(json),
  }
}

/** Where each field the contract checks begins. */
export function fieldOffsets(json) {
  const typeIndex = json.indexOf(FIELD_TYPE)
  const challengeIndex = json.indexOf(FIELD_CHALLENGE)
  const originIndex = json.indexOf(FIELD_ORIGIN)
  if (typeIndex < 0) throw new Error('clientDataJSON is not a webauthn.get ceremony')
  if (challengeIndex < 0 || originIndex < 0) throw new Error('clientDataJSON is missing a required field')
  return { typeIndex, challengeIndex, originIndex }
}

export function originFrom(json) {
  const at = json.indexOf(FIELD_ORIGIN)
  if (at < 0) return null
  const start = at + FIELD_ORIGIN.length
  const end = json.indexOf('"', start)
  return end < 0 ? null : json.slice(start, end)
}

/**
 * ASN.1 DER to a raw (r, s) pair.
 *
 * WebAuthn's ES256 signatures are DER, and the precompile takes two 32-byte
 * words. DER integers are signed, so a value whose top bit is set carries a
 * leading zero byte that has to come off, and a short value has to be padded
 * back up to 32.
 *
 * No low-s normalisation: the precompile was checked against both forms and
 * accepts either, so an authenticator that emits high-s works. Normalising
 * would be the kind of fix that quietly breaks nothing and hides that this
 * was ever a question.
 */
export function fromDer(der) {
  let at = 0
  const take = (what) => {
    if (at >= der.length) throw new Error(`signature ended before its ${what}`)
    return der[at++]
  }

  if (take('sequence tag') !== 0x30) throw new Error('signature is not a DER sequence')
  take('sequence length') // not needed; the integers carry their own

  const integer = (which) => {
    if (take(`${which} tag`) !== 0x02) throw new Error(`signature is missing its ${which} integer`)
    const length = take(`${which} length`)
    if (at + length > der.length) throw new Error(`signature's ${which} integer runs past its end`)
    const value = der.subarray(at, at + length)
    at += length
    return unsigned(value)
  }

  const r = integer('first')
  const s = integer('second')
  return { r, s }
}

/** Strip DER's sign byte, then pad to 32. */
function unsigned(bytes) {
  let value = bytes
  while (value.length > 32 && value[0] === 0x00) value = value.subarray(1)
  if (value.length > 32) throw new Error('that integer is too large for a P-256 signature')
  const out = new Uint8Array(32)
  out.set(value, 32 - value.length)
  return out
}

function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

function asBytes(value) {
  if (typeof value !== 'string') return new Uint8Array(value)
  const clean = value.startsWith('0x') ? value.slice(2) : value
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}
