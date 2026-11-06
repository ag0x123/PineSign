// Spike 2 — Swarm: upload encrypted bytes, download, verify reference with bmt-js
// independently of Bee. Run on the host that can reach Bee.
import crypto from 'node:crypto'
import { Bee } from '@ethersphere/bee-js'
import bmt from '@fairdatasociety/bmt-js'
const { makeChunkedFile } = bmt

const BEE = process.env.BEE_URL || 'http://localhost:1633'
const BATCH = process.env.POSTAGE_BATCH_ID
if (!BATCH) { console.error('set POSTAGE_BATCH_ID'); process.exit(1) }

const out = { endpoint: BEE, batch: BATCH }
const fail = (why) => { console.log(JSON.stringify({ ...out, PASS: false, why }, null, 2)); process.exit(1) }

const bee = new Bee(BEE)

// 0. batch must be usable
const batch = await bee.getPostageBatch(BATCH).catch(e => fail('getPostageBatch: ' + e.message))
out.batchUsable = batch.usable
out.batchDepth = batch.depth
if (!batch.usable) fail('batch not usable yet — wait for it to be mined')

// 1. encrypt a payload ourselves (Swarm never sees plaintext, and no Swarm-side
//    encryption, so the reference stays a plain BMT root we can recompute)
const plain = crypto.randomBytes(64 * 1024)
const key = crypto.randomBytes(32)
const iv = crypto.randomBytes(12)
const c = crypto.createCipheriv('aes-256-gcm', key, iv)
const ciphertext = Buffer.concat([iv, c.update(plain), c.final(), c.getAuthTag()])
out.plainBytes = plain.length
out.uploadBytes = ciphertext.length

// 2. upload
let t = Date.now()
// bee-js defaults to redundancy level 1 and silently drops `redundancyLevel: 0`
// because 0 is falsy, so its reference is an erasure-coded root, not a BMT root.
// Raw POST with the header is the only way to get a client-verifiable reference.
const up = { reference: (await (await fetch(BEE + "/bytes", { method: "POST", body: ciphertext, headers: { "content-type": "application/octet-stream", "swarm-postage-batch-id": BATCH, "swarm-redundancy-level": "0" } })).json()).reference }
out.uploadMs = Date.now() - t
out.reference = up.reference.toString()

// 3. download
t = Date.now()
const down = await bee.downloadData(out.reference).catch(e => fail('download: ' + e.message))
out.downloadMs = Date.now() - t
const got = Buffer.from(down.toUint8Array ? down.toUint8Array() : down)
out.roundTripIdentical = got.equals(ciphertext)

// 4. decrypt to prove it is the same payload end to end
let decrypted = false
try {
  const d = crypto.createDecipheriv('aes-256-gcm', key, got.subarray(0, 12))
  d.setAuthTag(got.subarray(got.length - 16))
  const p = Buffer.concat([d.update(got.subarray(12, got.length - 16)), d.final()])
  decrypted = p.equals(plain)
} catch (e) { out.decryptError = e.message }
out.decrypted = decrypted

// 5. recompute the reference with bmt-js — this is the independent check.
//    Bee is not consulted; if these agree, Bee gave us the real content hash.
t = Date.now()
const local = Buffer.from(makeChunkedFile(new Uint8Array(ciphertext)).address()).toString('hex')
out.bmtMs = Date.now() - t
out.bmtReference = local
out.referencesMatch = local === out.reference

out.PASS = out.roundTripIdentical && out.decrypted && out.referencesMatch
console.log(JSON.stringify(out, null, 2))
