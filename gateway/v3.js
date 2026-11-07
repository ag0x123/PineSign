/**
 * The v0.3 delivery, server side.
 *
 * Holds the small amount of bookkeeping a transfer needs — which Arkiv entity
 * is the invite, which the accept, what Bob's provider signed, where the
 * ciphertext landed — and orchestrates the one frame transaction that ends it.
 *
 * It deliberately holds no key that can read a file. The sealed file key passes
 * through on its way to the chain and is useless here: it is encrypted to Bob's
 * X25519 key, which only his passkey derives.
 *
 * It does not hold the salt as a field either. A reply carries the salt, the
 * gateway uses it to check that the hash in the invite really is the address
 * that replied, and then keeps the derived values and not the salt. The raw
 * mail on disk does contain it, which is the honest caveat in the README.
 */

import { createPublicKey } from 'node:crypto'
import { mkdir, readFile, writeFile, readdir } from 'node:fs/promises'
import { keccak256, toHex as viemToHex } from 'viem'
import { p256 } from '@noble/curves/p256'
import { sha256 } from '@noble/hashes/sha2'
import * as arkiv from './arkiv.js'
import * as frame from './frame.js'
import * as swarm from './swarm.js'
import { storagePath } from './paths.js'
import { KIND, encode as encodePayload, decode as decodePayload, digest as payloadDigest } from '../shared/arkiv-payload.js'

const DIR = storagePath('transfers')

const encoder = new TextEncoder()
const hex = (bytes) => '0x' + Buffer.from(bytes).toString('hex')
const bytes = (value) => Uint8Array.from(Buffer.from(String(value).replace(/^0x/, ''), 'hex'))

/** How many free sends an account gets. Gateway policy, not enforced on chain. */
export const FREE_SENDS = Number(process.env.PINESIGN_FREE_SENDS ?? 3)

// ---------- bookkeeping ----------

export async function load(transferId) {
  try {
    return JSON.parse(await readFile(storagePath('transfers', `${transferId}.json`), 'utf8'))
  } catch {
    return null
  }
}

async function save(transferId, patch) {
  const current = (await load(transferId)) ?? { transferId, createdAt: new Date().toISOString() }
  const next = { ...current, ...patch, updatedAt: new Date().toISOString() }
  await mkdir(DIR, { recursive: true })
  await writeFile(storagePath('transfers', `${transferId}.json`), JSON.stringify(next, null, 2))
  return next
}

/** Sends already made by one sender, for the free-send allowance. */
export async function sendsBy(senderKey) {
  try {
    const files = await readdir(DIR)
    let count = 0
    for (const file of files) {
      const record = JSON.parse(await readFile(storagePath('transfers', file), 'utf8'))
      if (record.senderKey === senderKey) count++
    }
    return count
  } catch {
    return 0
  }
}

// ---------- the invite ----------

export async function invite({ transferId, fingerprint, emailHash, payload, senderKey, fileName }) {
  const decoded = decodePayload(bytes(payload))
  if (decoded.kind !== KIND.INVITE) throw new Error('that payload is not an invite')

  const written = await arkiv.createInvite({ fingerprint, emailHash, payload: bytes(payload) })
  await save(transferId, {
    fingerprint: '0x' + String(fingerprint).replace(/^0x/, ''),
    emailHash: '0x' + String(emailHash).replace(/^0x/, ''),
    inviteEntity: written.entityKey,
    invitePayload: hex(bytes(payload)),
    senderKey,
    fileName: fileName ?? null,
    status: 'invited',
  })
  return written
}

// ---------- the accept, from Bob's reply ----------

/**
 * Pull the lines Bob's page told him to send.
 *
 * The inbound module has already dug the text out of whatever encoding the
 * provider chose; this only has to read it.
 */
export function parseReply(text) {
  const find = (name, pattern) => {
    const match = text.match(new RegExp(`pinesign-${name}:\\s*(${pattern})`, 'i'))
    return match ? match[1] : null
  }
  return {
    transferId: find('transfer', '[0-9a-f]{24}'),
    salt: find('salt', '(?:0x)?[0-9a-f]{32}'),
    encPublicKey: find('enc-key', '0x[0-9a-f]{64}'),
    signPublicKey: find('sign-key', '0x[0-9a-f]{130}'),
    signature: find('sig', '0x[0-9a-f]{128}'),
  }
}

/**
 * The DKIM key the provider actually signed with, as the modulus the frame
 * contract needs.
 *
 * mailauth hands back the SPKI DER it fetched from DNS; the contract wants the
 * raw 256-byte modulus, so it goes through a public key object to get there.
 * Doing it any other way would mean parsing DER by hand for no reason.
 */
export function modulusFrom(spkiBase64) {
  const key = createPublicKey({ key: Buffer.from(spkiBase64, 'base64'), format: 'der', type: 'spki' })
  const { n } = key.export({ format: 'jwk' })
  return Uint8Array.from(Buffer.from(n, 'base64url'))
}

/**
 * Bob replied. Does it belong to an invite, and did he sign it?
 *
 * Three things have to line up: his provider's signature over the mail (checked
 * by the inbound module before this runs), the salted hash of his address
 * matching the invite's, and his own P-256 signature over the transfer. The
 * first proves the address, the second proves the invite was for him, the third
 * proves the keys in the reply are his and not something the mail picked up on
 * the way.
 */
export async function acceptFromReply({ text, from, dkim }) {
  const reply = parseReply(text)
  if (!reply.transferId) return { matched: false, reason: 'no pinesign-transfer line' }
  if (!reply.salt || !reply.encPublicKey || !reply.signPublicKey || !reply.signature) {
    return { matched: false, reason: 'reply is missing one of the pinesign lines', transferId: reply.transferId }
  }

  const record = await load(reply.transferId)
  if (!record) return { matched: false, reason: 'no such transfer', transferId: reply.transferId }

  // The salt arrives in the reply and is used here and not kept.
  const salt = bytes(reply.salt)
  const address = encoder.encode(String(from).trim().toLowerCase())
  const input = new Uint8Array(salt.length + address.length)
  input.set(salt, 0)
  input.set(address, salt.length)
  if (keccak256(input) !== record.emailHash) {
    return { matched: false, reason: 'the address that replied is not the one invited', transferId: reply.transferId }
  }

  const digest = sha256(encoder.encode(`pinesign/v3/accept/${reply.transferId}/${record.fingerprint}`))
  if (!p256.verify(bytes(reply.signature), digest, bytes(reply.signPublicKey))) {
    return { matched: false, reason: 'the signature in the reply does not check out', transferId: reply.transferId }
  }

  // Bob's accept, signed by his key, written to Arkiv by us.
  const accept = encodePayload({
    kind: KIND.ACCEPT,
    encPublicKey: bytes(reply.encPublicKey),
    signPublicKey: bytes(reply.signPublicKey),
    signature: acceptSignature({ record, reply }),
  })

  const written = await arkiv.createAccept({
    fingerprint: record.fingerprint,
    emailHash: record.emailHash,
    payload: accept,
  })

  await save(reply.transferId, {
    acceptEntity: written.entityKey,
    acceptPayload: hex(accept),
    bobEncKey: reply.encPublicKey,
    dkim: dkim ?? null,
    status: 'accepted',
  })
  return { matched: true, transferId: reply.transferId, entityKey: written.entityKey }
}

/**
 * The accept entity's own signature.
 *
 * Bob signed the transfer, not the Arkiv row, so his signature cannot be reused
 * as the row's. The row is signed by the gateway's Arkiv key instead, and says
 * so: what makes the accept trustworthy is the DKIM signature on the mail and
 * Bob's signature over the transfer, both of which are checked above and both
 * of which the gateway cannot produce.
 */
function acceptSignature({ record, reply }) {
  const d = payloadDigest({
    kind: KIND.ACCEPT,
    fingerprint: record.fingerprint,
    emailHash: record.emailHash,
    encPublicKey: bytes(reply.encPublicKey),
  })
  return p256.sign(d, gatewaySigningKey()).toCompactRawBytes()
}

let signingKey = null

/**
 * A P-256 key for signing accept rows, kept beside the other server secrets.
 *
 * It is not authority over anything: an accept it signed still has to carry
 * Bob's own signature, and the release still has to carry his provider's.
 */
function gatewaySigningKey() {
  if (signingKey) return signingKey
  const configured = process.env.PINESIGN_ACCEPT_KEY
  if (configured) return (signingKey = bytes(configured))
  // Derived from the Arkiv key so one secret is one secret, and so restarting
  // does not invalidate rows written before it.
  const seed = process.env.ARKIV_PRIVATE_KEY
  if (!seed) throw new Error('set ARKIV_PRIVATE_KEY or PINESIGN_ACCEPT_KEY')
  for (let counter = 0; counter < 256; counter++) {
    const candidate = sha256(encoder.encode(`pinesign/v3/accept-key/${counter}/${seed}`))
    try {
      p256.getPublicKey(candidate, false)
      return (signingKey = candidate)
    } catch {
      // out of range, try the next
    }
  }
  throw new Error('could not derive an accept key')
}

// ---------- the release ----------

/**
 * Bob's account on the devnet, one per DKIM signing key.
 *
 * Deployed on demand and remembered, because a devnet reset wipes it and an
 * address with no code behind it would fail much later and much less clearly.
 */
export async function accountForModulus(modulus) {
  const modulusHash = keccak256(hex(modulus))
  const state = await frameState()
  const known = state.accounts?.[modulusHash]
  if (known && (await frame.rpc('eth_getCode', [known, 'latest'])) !== '0x') return known
  throw new Error(
    `no account deployed for DKIM key ${modulusHash}. ` +
      `run: node scripts/frame-deploy.mjs --modulus ${hex(modulus)}`
  )
}

async function frameState() {
  try {
    return JSON.parse(await readFile(storagePath('frame.json'), 'utf8'))
  } catch {
    return {}
  }
}

export async function upload({ transferId, ciphertext }) {
  const reference = await swarm.upload(bytes(ciphertext))
  await save(transferId, { swarmRef: reference, status: 'uploaded' })
  return { reference, mode: await swarm.mode() }
}

/**
 * The one transaction. Everything before it was preparation; this is the only
 * step that cannot be undone and the only one that gives Bob anything.
 */
export async function release({ transferId, fingerprint, sealedKey, swarmRef }) {
  const record = await load(transferId)
  if (!record) throw new Error('no such transfer')
  if (record.fingerprint !== '0x' + String(fingerprint).replace(/^0x/, '')) {
    throw new Error('that is not the file this transfer committed to')
  }
  if (!record.dkim) throw new Error('this transfer has no verified reply yet')
  if (record.txHash) return { already: true, ...record }

  const modulus = bytes(record.dkim.modulus)
  const account = await accountForModulus(modulus)
  const acceptHash = keccak256(record.dkim.signedHeaders)

  const sent = await frame.release({
    account,
    acceptHash,
    encryptedKey: '0x' + String(sealedKey).replace(/^0x/, ''),
    swarmRef: '0x' + String(swarmRef).replace(/^0x/, ''),
    dkim: {
      modulus: record.dkim.modulus,
      signature: record.dkim.signature,
      signedHeaders: record.dkim.signedHeaders,
    },
  })
  const receipt = await frame.waitForReceipt(sent.hash)
  if (!receipt.ok) throw new Error(`the release transaction failed: ${JSON.stringify(receipt.frames)}`)

  const explorer = process.env.FRAME_EXPLORER_URL
    ? `${process.env.FRAME_EXPLORER_URL.replace(/\/$/, '')}/tx/${sent.hash}`
    : null
  const next = await save(transferId, {
    txHash: sent.hash,
    acceptHash,
    sealedKey: '0x' + String(sealedKey).replace(/^0x/, ''),
    swarmRef,
    account,
    block: receipt.block,
    gasUsed: receipt.gasUsed,
    frameGas: receipt.frames.map((f) => f.gasUsed),
    explorer,
    status: 'released',
  })
  return next
}

/** What Bob needs, and the proof that goes with it. */
export async function released(transferId) {
  const record = await load(transferId)
  if (!record?.txHash) return null
  return {
    transferId,
    fingerprint: record.fingerprint,
    sealedKey: record.sealedKey,
    swarmRef: record.swarmRef,
    invitePayload: record.invitePayload,
    inviteEntity: record.inviteEntity,
    acceptEntity: record.acceptEntity,
    txHash: record.txHash,
    block: record.block,
    explorer: record.explorer,
  }
}

export async function file(reference) {
  return hex(await swarm.download(reference))
}

// ---------- status ----------

/**
 * One answer for every badge the UI shows. Each service says whether it is up
 * and why not, so a failure reads as that service being down rather than as
 * Pinesign being broken.
 */
export async function status() {
  const [arkivStatus, frameStatus, swarmMode] = await Promise.all([
    arkiv.status().catch((error) => ({ configured: arkiv.configured(), up: false, error: error.message })),
    frame.status(),
    swarm.mode().catch(() => 'unknown'),
  ])

  let stamp = null
  try {
    stamp = await swarm.stampInfo()
  } catch (error) {
    stamp = { error: error.message }
  }

  return {
    arkiv: {
      up: Boolean(arkivStatus.funded ?? arkivStatus.configured) && arkivStatus.reachable !== false,
      detail: arkivStatus,
    },
    swarm: { up: swarmMode === 'swarm' && stamp?.usable !== false, detail: { mode: swarmMode, stamp } },
    frameDevnet: { up: Boolean(frameStatus.up && frameStatus.configured), detail: frameStatus },
    anonRpc: { up: false, detail: { note: 'browser-side; the page reports which network it reached' } },
    ens: { up: null, detail: { parent: process.env.PINESIGN_PARENT ?? null } },
    freeSends: FREE_SENDS,
  }
}
