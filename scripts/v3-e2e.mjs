/**
 * Alice sends Bob a file, end to end, against the live services.
 *
 *   node scripts/v3-e2e.mjs                       # against a local gateway
 *   PINESIGN_ORIGIN=https://pinesign.xyz node scripts/v3-e2e.mjs
 *
 * Real Arkiv entities, real Swarm upload, a real frame transaction on the
 * devnet. One thing is stood in for: the provider's DKIM signature on Bob's
 * reply, which is signed here with a key of our own and an account deployed for
 * it. Everything downstream of that signature is the production path, and the
 * provider's own signature is covered separately by a reply you send by hand —
 * scripts/v3-e2e.mjs --await-reply <transferId> waits for it.
 *
 * The passkey is stood in for too: PRF output comes from a browser, so the keys
 * here are derived from fixed bytes. /prf is where the passkey itself is tested.
 */

import '../gateway/env.js'
import crypto from 'node:crypto'
import { keccak256 } from 'viem'
import { Pinesign, createKeys, replyBody, saltFor, toHex } from '../shared/v3.js'
import * as v3 from '../gateway/v3.js'
import * as frame from '../gateway/frame.js'

const ORIGIN = process.env.PINESIGN_ORIGIN ?? 'http://localhost:8788'
const BOB_EMAIL = process.env.E2E_BOB_EMAIL ?? 'bob@example.com'
const out = { origin: ORIGIN, bobEmail: BOB_EMAIL.replace(/^[^@]+/, '…') }
const hex = (b) => '0x' + Buffer.from(b).toString('hex')

const client = new Pinesign({ origin: ORIGIN })

/**
 * An Arkiv write is one block, roughly three to eight seconds, so a read that
 * follows a write immediately finds nothing. Bob opening a link minutes later
 * never notices; a script does.
 */
async function waitFor(what, attempt, { attempts = 15, intervalMs = 2000 } = {}) {
  let last = null
  for (let i = 0; i < attempts; i++) {
    try {
      const value = await attempt()
      if (value) return value
    } catch (error) {
      last = error
    }
    await new Promise((r) => setTimeout(r, intervalMs))
  }
  throw new Error(`${what} never appeared${last ? `: ${last.message}` : ''}`)
}

// --- the two parties
const alice = createKeys(new Uint8Array(32).fill(0xa1))
const bob = createKeys(new Uint8Array(32).fill(0xb0))

// A file that is different every run, so no two runs share a fingerprint.
const file = new TextEncoder().encode(`pinesign v0.3 end to end — ${crypto.randomUUID()}\n`)
out.fileBytes = file.length

out.status = await client.status()

// --- 1. Alice commits to the file and invites Bob
// No notification mail unless asked: the default recipient is a fixture
// address and a real send would bounce off a real provider.
const invite = await client.sendInvite({
  keys: alice,
  file,
  email: BOB_EMAIL,
  notify: process.env.E2E_NOTIFY === '1' ? BOB_EMAIL : null,
})
out.invite = {
  transferId: invite.transferId,
  fingerprint: invite.fingerprint,
  entityKey: invite.entityKey,
  notified: invite.notified,
  linkHasSalt: invite.link.includes('&s='),
}

// --- 2. Bob opens the link and is told what to reply
const opened = await waitFor('the invite on Arkiv', () =>
  client.openTransfer({ link: invite.link, email: BOB_EMAIL, keys: bob })
)
out.bobFoundInvite = opened.invite.fingerprint === invite.fingerprint
const reply = replyBody({
  transferId: invite.transferId,
  salt: toHex(saltFor(alice, invite.transferId)),
  fingerprint: invite.fingerprint,
  emailHash: invite.emailHash,
  keys: bob,
})

// --- 3. his provider signs the reply
//
// Stood in for, as the header says. The bytes below are shaped exactly like the
// ones a provider produces: the canonicalized headers, an RSA-2048 signature
// over their sha256, and the modulus that verifies it.
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
const modulus = Uint8Array.from(Buffer.from(publicKey.export({ format: 'jwk' }).n, 'base64url'))
const signedHeaders = Buffer.from(
  `from:${BOB_EMAIL}\r\nto:verify@pinesign.xyz\r\nmessage-id:<${crypto.randomUUID()}@mail.example.com>\r\n`
)
const dkim = {
  signingDomain: BOB_EMAIL.split('@')[1],
  selector: 'e2e',
  modulus: hex(modulus),
  signature: hex(crypto.sign('sha256', signedHeaders, privateKey)),
  signedHeaders: hex(signedHeaders),
}

// The account is pinned to this DKIM key, so it has to exist before the release.
const modulusHash = keccak256(hex(modulus))
out.account = { modulusHash }
try {
  out.account.address = await v3.accountForModulus(modulus)
} catch {
  const { deployAccount } = await import('./frame-account.mjs')
  out.account.address = await deployAccount(modulus)
  out.account.deployed = true
}

// --- 4. the gateway links the reply to the invite and writes the accept
const accepted = await v3.acceptFromReply({ text: reply, from: BOB_EMAIL, dkim })
out.accept = accepted
if (!accepted.matched) {
  console.log(JSON.stringify(out, null, 2))
  process.exit(1)
}

// --- 5. Alice sees the accept, re-picks the file, encrypts, uploads, releases
const seen = await waitFor('the accept on Arkiv', () => client.watchAccept({ fingerprint: invite.fingerprint }))
out.aliceSawAccept = Boolean(seen)
const released = await client.release({
  keys: alice,
  file,
  transferId: invite.transferId,
  accept: { ...seen, entityKey: accepted.entityKey },
})
out.release = {
  txHash: released.txHash,
  block: released.block,
  gasUsed: released.gasUsed,
  frameGas: released.frameGas,
  swarmRef: released.swarmRef,
  explorer: released.explorer,
}

// --- 6. Bob reads the key off the chain, fetches from Swarm, and opens the file
const opened2 = await client.downloadAndDecrypt({
  keys: bob,
  transferId: invite.transferId,
  salt: toHex(saltFor(alice, invite.transferId)),
})
out.claim = {
  bytes: opened2?.bytes?.length ?? null,
  fingerprintMatches: opened2?.fingerprintMatches ?? false,
  proof: opened2?.proof,
}
out.fileIdentical = Boolean(opened2 && Buffer.from(opened2.bytes).equals(Buffer.from(file)))

// --- 7. the negatives: a delivery nobody authorised must not be possible
const wrongFile = new TextEncoder().encode('a different file entirely\n')
try {
  await client.release({
    keys: alice,
    file: wrongFile,
    transferId: invite.transferId,
    accept: { ...seen, entityKey: accepted.entityKey },
  })
  out.wrongFileRefused = false
} catch (error) {
  out.wrongFileRefused = /fingerprint/.test(error.message)
}

// A reply from an address the invite was not for. acceptFromReply answers
// rather than throws, so the check is on what it answered.
const foreign = await v3.acceptFromReply({ text: reply, from: 'someone-else@example.com', dkim })
out.wrongSenderRefused = !foreign.matched
out.wrongSenderReason = foreign.reason

// Bob's own reply, but with his signature over someone else's keys.
const swapped = reply.replace(/pinesign-enc-key: 0x[0-9a-f]{64}/, `pinesign-enc-key: ${hex(alice.enc.publicKey)}`)
const tamperedReply = await v3.acceptFromReply({ text: swapped, from: BOB_EMAIL, dkim })
out.swappedKeyRefused = !tamperedReply.matched
out.swappedKeyReason = tamperedReply.reason

out.PASS = Boolean(
  out.invite.entityKey &&
    out.bobFoundInvite &&
    out.accept.matched &&
    out.aliceSawAccept &&
    out.release.txHash &&
    out.claim.fingerprintMatches &&
    out.fileIdentical &&
    out.wrongFileRefused &&
    out.wrongSenderRefused &&
    out.swappedKeyRefused
)
console.log(JSON.stringify(out, null, 2))
process.exit(out.PASS ? 0 : 1)
