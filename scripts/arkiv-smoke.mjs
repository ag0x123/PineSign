/**
 * Proves the invite/accept path on Arkiv end to end, without a browser.
 *
 *   node scripts/arkiv-smoke.mjs
 *
 * It signs an invite the way Alice's page will, writes it, reads it back by
 * both indexed fields, then does the same for Bob's accept — so a failure here
 * is the gateway or the chain, never the UI.
 */

import '../gateway/env.js'
import { p256 } from '@noble/curves/p256'
import { x25519 } from '@noble/curves/ed25519'
import { randomBytes } from '@noble/hashes/utils'
import { keccak_256 } from '@noble/hashes/sha3'
import * as arkiv from '../gateway/arkiv.js'
import { KIND, encode, sign } from '../shared/arkiv-payload.js'

const hex = (b) => '0x' + Buffer.from(b).toString('hex')

if (!arkiv.configured()) {
  console.error('ARKIV_ACCESS_KEY and ARKIV_PRIVATE_KEY are not set in .env')
  process.exit(1)
}

const out = { writer: arkiv.writerAddress(), status: await arkiv.status() }

// A fingerprint is a salted hash of the file, so the same file sent twice is
// two unrelated rows, and the salt lives only in the link Alice shares.
const salt = randomBytes(16)
const fingerprint = hex(keccak_256(new Uint8Array([...randomBytes(32), ...salt]))).slice(0, 18)
const emailHash = hex(keccak_256(new Uint8Array([...new TextEncoder().encode('bob@example.com'), ...salt])))

function party(kind) {
  const signPrivateKey = p256.utils.randomPrivateKey()
  const encPrivateKey = x25519.utils.randomPrivateKey()
  const encPublicKey = x25519.getPublicKey(encPrivateKey)
  const signPublicKey = p256.getPublicKey(signPrivateKey, false)
  const signature = sign({ kind, fingerprint, emailHash, encPublicKey, signPrivateKey })
  return { payload: encode({ kind, encPublicKey, signPublicKey, signature }), encPublicKey }
}

// With --http the write goes through the gateway's own route instead of this
// process, which is the only way to catch the two sides disagreeing about
// whether the indexed fields carry an 0x prefix.
const VIA = process.argv.includes('--http') ? (process.env.PINESIGN_ORIGIN ?? 'http://localhost:8788') : null
out.via = VIA ?? 'in process'
const bare = (v) => v.replace(/^0x/, '')

async function post(path, body) {
  const r = await fetch(VIA + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
  const json = await r.json()
  if (!r.ok) throw new Error(`${path} ${r.status}: ${json.error}`)
  return json
}

const alice = party(KIND.INVITE)
out.invite = VIA
  ? await post('/api/arkiv/invite', { fingerprint: bare(fingerprint), emailHash: bare(emailHash), payload: hex(alice.payload) })
  : await arkiv.createInvite({ fingerprint, emailHash, payload: alice.payload })
out.invitesByEmail = (await arkiv.invitesForEmail(emailHash)).length
out.invitesByFile = (await arkiv.invitesForFile(fingerprint)).length

const bob = party(KIND.ACCEPT)
out.accept = await arkiv.createAccept({ fingerprint, emailHash, payload: bob.payload })
const accepts = await arkiv.acceptsForFile(fingerprint)
out.acceptsByFile = accepts.length
// Alice encrypts to this. If it did not survive the round trip there is no
// delivery, so the check is on the bytes and not on the row existing.
out.bobKeySurvived = accepts.some((a) => a.payload.slice(6, 6 + 64) === hex(bob.encPublicKey).slice(2))

out.PASS = out.invitesByEmail > 0 && out.invitesByFile > 0 && out.acceptsByFile > 0 && out.bobKeySurvived
console.log(JSON.stringify(out, null, 2))
process.exit(out.PASS ? 0 : 1)
