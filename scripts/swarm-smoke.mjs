/**
 * Uploads bytes to Swarm, downloads them back, and checks the reference the
 * node gave us against one computed locally with bmt-js.
 *
 *   node scripts/swarm-smoke.mjs [bytes]
 *
 * The local check is the point. If Bee's answer and bmt-js ever disagree, the
 * claim that a recipient can verify the file against its reference is false,
 * and we would rather find that here than in a demo.
 */

import '../gateway/env.js'
import { randomBytes } from 'node:crypto'
import * as swarm from '../gateway/swarm.js'
import { BEE_URL } from '../gateway/bee.js'

const size = Number(process.argv[2] ?? 64 * 1024)
const payload = new Uint8Array(randomBytes(size))
const out = { bee: BEE_URL, mode: await swarm.mode(), bytes: size }

const t = () => Date.now()
let m = t()
out.reference = await swarm.upload(payload)
out.uploadMs = t() - m

out.bmtReference = swarm.referenceFor(payload)
out.referencesMatch = out.reference === out.bmtReference

m = t()
const back = await swarm.download(out.reference)
out.downloadMs = t() - m
out.byteIdentical = Buffer.from(back).equals(Buffer.from(payload))

out.PASS = out.referencesMatch && out.byteIdentical
console.log(JSON.stringify(out, null, 2))
process.exit(out.PASS ? 0 : 1)
