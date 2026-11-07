/**
 * Pinesign v0.3, as the UI sees it.
 *
 * Everything the pages do goes through this module, and nothing in here needs a
 * UI to be tested — scripts/v3-e2e.mjs drives the whole flow against the live
 * services through these same functions. If a page can do something this module
 * cannot, that is a bug in the layering, not a missing feature.
 *
 * What the gateway is and is not:
 *
 * It pays for the Arkiv writes, holds the Swarm postage, sends the notification
 * mail, receives Bob's reply and signs the gas sponsorship. It does not hold a
 * key that can read a file, cannot forge an invite or an accept (both are signed
 * by a passkey it does not have), and cannot stop a delivery that has been
 * released — the release is on chain and the file is on Swarm.
 *
 * What it does see, in the easy mode this version ships: Bob's reply, which
 * means his address and the salt in it. It stores neither as a field; the raw
 * mail it keeps on disk contains both. The honest summary is in the README.
 */

import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'
import { keccak_256 } from '@noble/hashes/sha3'
import { randomBytes } from '@noble/hashes/utils'
import { x25519 } from '@noble/curves/ed25519'
import { p256 } from '@noble/curves/p256'
import { gcm } from '@noble/ciphers/aes'
import { deriveKeys } from './v3keys.js'
import { KIND, encode as encodePayload, decode as decodePayload, digest as payloadDigest } from './arkiv-payload.js'

const encoder = new TextEncoder()

export const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
export const fromHex = (hex) => {
  const clean = String(hex).replace(/^0x/, '')
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}

/** Addresses differ in case and in the +tag part; two spellings must hash alike. */
export const normaliseEmail = (email) => String(email).trim().toLowerCase()

// ---------- identity ----------

/**
 * The three keys, from the PRF output of a passkey assertion.
 *
 * Nothing is stored. The caller holds the result for the session and derives it
 * again next time, which is why the same passkey must give the same answer on
 * every device — see /prf.
 */
export function createKeys(prfOutput) {
  if (!(prfOutput instanceof Uint8Array) || prfOutput.length < 32) {
    throw new Error('expected at least 32 bytes of PRF output')
  }
  return deriveKeys(prfOutput)
}

// ---------- per-transfer values ----------

/**
 * The salt for one transfer, derived from Alice's own key and the transfer id.
 *
 * Derived rather than random so Alice never has to store it: she can recompute
 * it from her passkey and the id. It is what makes the invite unlinkable —
 * without it the row shows only two hashes, and the same file to the same
 * person twice is two unrelated rows.
 */
export function saltFor(keys, transferId) {
  return hkdf(sha256, keys.arkiv.privateKey, encoder.encode('pinesign/v3/salt'), encoder.encode(transferId), 16)
}

export const newTransferId = () => toHex(randomBytes(12))

/**
 * What Alice commits to before she uploads anything.
 *
 * Salted, so the row does not say which file it is, and checked again at
 * release: if she picks a different file the second time, the fingerprints
 * disagree and the release is refused.
 */
export function fingerprintFile(salt, bytes) {
  const input = new Uint8Array(salt.length + bytes.length)
  input.set(salt, 0)
  input.set(bytes, salt.length)
  return '0x' + toHex(keccak_256(input)).slice(0, 16)
}

export function hashEmail(salt, email) {
  const address = encoder.encode(normaliseEmail(email))
  const input = new Uint8Array(salt.length + address.length)
  input.set(salt, 0)
  input.set(address, salt.length)
  return '0x' + toHex(keccak_256(input))
}

// ---------- file keys ----------

/** X25519 ECDH, then HKDF so AES gets a uniform key rather than a curve point. */
export function sharedKey(privateKey, theirPublicKey) {
  const secret = x25519.getSharedSecret(privateKey, theirPublicKey)
  return hkdf(sha256, secret, undefined, encoder.encode('pinesign/v3/file'), 32)
}

/**
 * The file is encrypted under a key of its own, and only that key is sealed to
 * Bob. So the same file can be sent to two people without encrypting it twice,
 * and the thing that goes on chain stays small.
 */
export function encryptFile(bytes) {
  const fileKey = randomBytes(32)
  const nonce = randomBytes(12)
  const sealed = gcm(fileKey, nonce).encrypt(bytes)
  const blob = new Uint8Array(nonce.length + sealed.length)
  blob.set(nonce, 0)
  blob.set(sealed, nonce.length)
  return { fileKey, ciphertext: blob }
}

export function decryptFile(blob, fileKey) {
  return gcm(fileKey, blob.slice(0, 12)).decrypt(blob.slice(12))
}

export function sealFileKey({ fileKey, mine, theirs }) {
  const nonce = randomBytes(12)
  const sealed = gcm(sharedKey(mine, theirs), nonce).encrypt(fileKey)
  const out = new Uint8Array(nonce.length + sealed.length)
  out.set(nonce, 0)
  out.set(sealed, nonce.length)
  return out
}

export function openFileKey({ sealedKey, mine, theirs }) {
  const key = sharedKey(mine, theirs)
  return gcm(key, sealedKey.slice(0, 12)).decrypt(sealedKey.slice(12))
}

// ---------- payloads ----------

function signPayload({ kind, fingerprint, emailHash, keys }) {
  const encPublicKey = keys.enc.publicKey
  const d = payloadDigest({ kind, fingerprint, emailHash, encPublicKey })
  const signature = p256.sign(d, keys.sign.privateKey).toCompactRawBytes()
  return encodePayload({ kind, encPublicKey, signPublicKey: keys.sign.publicKey, signature })
}

export const readPayload = (hex) => decodePayload(fromHex(hex))

// ---------- the gateway ----------

/**
 * A thin client. One place that knows the routes, so a page never builds a URL
 * and the e2e script talks to exactly what the UI will.
 */
export class Pinesign {
  constructor({ origin = '', fetch: f = globalThis.fetch.bind(globalThis) } = {}) {
    this.origin = String(origin).replace(/\/$/, '')
    this.fetch = f
  }

  async call(path, { method = 'GET', body } = {}) {
    const response = await this.fetch(this.origin + path, {
      method,
      headers: body ? { 'content-type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    })
    const text = await response.text()
    let json = null
    try {
      json = JSON.parse(text)
    } catch {
      // A proxy error page, not our JSON.
    }
    if (!response.ok) throw new Error(json?.error ?? `${path} failed with ${response.status}`)
    return json
  }

  /** Every service the UI shows a badge for, so a failure reads as the network and not as us. */
  status() {
    return this.call('/api/v3/status')
  }

  /**
   * Alice: commit to a file and invite Bob. Nothing is uploaded here — the
   * fingerprint is the commitment, and the file stays on her machine until Bob
   * has accepted.
   */
  async sendInvite({ keys, file, email }) {
    const transferId = newTransferId()
    const salt = saltFor(keys, transferId)
    const bytes = file instanceof Uint8Array ? file : new Uint8Array(await file.arrayBuffer())
    const fingerprint = fingerprintFile(salt, bytes)
    const emailHash = hashEmail(salt, email)
    const payload = signPayload({ kind: KIND.INVITE, fingerprint, emailHash, keys })

    const written = await this.call('/api/v3/invite', {
      method: 'POST',
      body: {
        transferId,
        fingerprint: fingerprint.replace(/^0x/, ''),
        emailHash: emailHash.replace(/^0x/, ''),
        payload: toHex(payload),
        email,
        fileName: file?.name ?? null,
      },
    })

    // Alice shares this herself. The salt is in it and nowhere else, which is
    // what keeps the Arkiv row from naming either the file or the recipient.
    return {
      transferId,
      fingerprint,
      emailHash,
      entityKey: written.entityKey,
      link: `${this.origin || ''}/claim?t=${transferId}&s=${toHex(salt)}`,
      salt: toHex(salt),
      notified: written.notified,
    }
  }

  /** Has Bob replied? Polled by Alice's page; returns null until he has. */
  async watchAccept({ fingerprint }) {
    const accepts = await this.call(`/api/v3/accepts/${String(fingerprint).replace(/^0x/, '')}`)
    if (!accepts?.length) return null
    const accept = accepts[0]
    return { ...accept, encPublicKey: readPayload(accept.payload).encPublicKey }
  }

  /**
   * Alice: the file, finally.
   *
   * She re-picks it, so the page never kept it. The fingerprint is checked
   * against the invite before anything is uploaded, and the gateway checks it
   * again — a mismatch means the wrong file and there is nothing to do but stop.
   */
  async release({ keys, file, transferId, accept }) {
    const salt = saltFor(keys, transferId)
    const bytes = file instanceof Uint8Array ? file : new Uint8Array(await file.arrayBuffer())
    const fingerprint = fingerprintFile(salt, bytes)
    if (fingerprint !== accept.fingerprint) {
      throw new Error('this is not the file you invited them to: the fingerprint does not match')
    }

    const { fileKey, ciphertext } = encryptFile(bytes)
    const sealedKey = sealFileKey({ fileKey, mine: keys.enc.privateKey, theirs: accept.encPublicKey })

    const upload = await this.call('/api/v3/upload', {
      method: 'POST',
      body: { transferId, ciphertext: toHex(ciphertext) },
    })

    return this.call('/api/v3/release', {
      method: 'POST',
      body: {
        transferId,
        fingerprint: fingerprint.replace(/^0x/, ''),
        acceptKey: accept.entityKey,
        sealedKey: toHex(sealedKey),
        swarmRef: upload.reference,
      },
    })
  }

  /** Bob: what is this link, and is there anything here for me? */
  async openTransfer({ link, email, keys }) {
    const url = new URL(link, this.origin || 'https://pinesign.xyz')
    const transferId = url.searchParams.get('t')
    const salt = fromHex(url.searchParams.get('s') ?? '')
    if (!transferId || salt.length !== 16) throw new Error('that link is not a Pinesign transfer')

    const emailHash = hashEmail(salt, email)
    const invites = await this.call(`/api/v3/invites/${emailHash.replace(/^0x/, '')}`)
    if (!invites?.length) throw new Error('no invitation for that address on this link')
    const invite = invites[0]

    // What Bob has to send back. He mails it himself: his provider's signature
    // over that mail is the only thing that authorises the release, and the
    // gateway cannot manufacture it.
    const reply = replyBody({
      transferId,
      salt: toHex(salt),
      fingerprint: invite.fingerprint,
      keys,
    })
    return { transferId, salt: toHex(salt), invite, reply, replyTo: 'verify@pinesign.xyz' }
  }

  /** Bob: the file. Read from the chain, fetched from Swarm, opened here. */
  async downloadAndDecrypt({ keys, transferId, salt }) {
    const released = await this.call(`/api/v3/release/${transferId}`)
    if (!released) return null
    const blob = fromHex(await this.call(`/api/v3/file/${released.swarmRef}`).then((r) => r.ciphertext))

    const invitePayload = readPayload(released.invitePayload)
    const fileKey = openFileKey({
      sealedKey: fromHex(released.sealedKey),
      mine: keys.enc.privateKey,
      theirs: invitePayload.encPublicKey,
    })
    const bytes = decryptFile(blob, fileKey)

    // The last check: is this the file that was committed to? Nobody has to be
    // trusted for this one, it is arithmetic on the bytes in hand.
    const fingerprint = fingerprintFile(fromHex(salt), bytes)
    return {
      bytes,
      fingerprint,
      fingerprintMatches: fingerprint === released.fingerprint,
      proof: {
        inviteEntity: released.inviteEntity,
        acceptEntity: released.acceptEntity,
        txHash: released.txHash,
        explorer: released.explorer,
        swarmRef: released.swarmRef,
      },
    }
  }
}

/**
 * The text Bob sends back.
 *
 * Deliberately a few plain lines rather than a structured attachment: it has to
 * survive being pasted into any mail client and re-encoded by any provider, and
 * the inbound side already knows how to find lines like these through
 * quoted-printable and base64.
 */
export function replyBody({ transferId, salt, fingerprint, keys }) {
  const emailHashNote = fingerprint
  const digest = sha256(encoder.encode(`pinesign/v3/accept/${transferId}/${emailHashNote}`))
  const signature = p256.sign(digest, keys.sign.privateKey).toCompactRawBytes()
  return [
    `pinesign-transfer: ${transferId}`,
    `pinesign-salt: ${salt}`,
    `pinesign-enc-key: 0x${toHex(keys.enc.publicKey)}`,
    `pinesign-sign-key: 0x${toHex(keys.sign.publicKey)}`,
    `pinesign-sig: 0x${toHex(signature)}`,
  ].join('\n')
}

/** The same digest, for the gateway to check what Bob signed. */
export function acceptDigest({ transferId, fingerprint }) {
  return sha256(encoder.encode(`pinesign/v3/accept/${transferId}/${fingerprint}`))
}
