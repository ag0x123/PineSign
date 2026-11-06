/**
 * Swarm storage.
 *
 * The gateway is the only party holding Swarm credentials — users never learn
 * what a postage stamp is. Once the admin panel has bought a batch, uploads go
 * to the real network; until then blobs land in .storage/ so the rest of the
 * system can be worked on without a funded node.
 */

import { Bee } from '@ethersphere/bee-js'
import bmt from '@fairdatasociety/bmt-js'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { BEE_URL } from './bee.js'
import * as setup from './setup.js'
import { storagePath } from './paths.js'

const LOCAL_DIR = storagePath('blobs')

let bee = null

/**
 * The batch comes from configuration rather than the environment, so buying one
 * in the admin panel is enough to switch modes — no restart, no env editing.
 */
async function batchId() {
  return (await setup.get()).postageBatchId ?? process.env.POSTAGE_BATCH_ID ?? null
}

export async function mode() {
  return (await batchId()) ? 'swarm' : 'local'
}

function client() {
  bee ??= new Bee(BEE_URL)
  return bee
}

/**
 * bee-js uploads at redundancy level 1 by default, and drops an explicit 0
 * because 0 is falsy — so the reference it hands back is an erasure-coded root
 * rather than a BMT root, and no client can reproduce it. We claim the file is
 * verifiable against its reference, so the upload has to go through a raw POST
 * carrying the header.
 */
async function uploadToSwarm(batch, bytes) {
  const response = await fetch(BEE_URL.replace(/\/$/, '') + '/bytes', {
    method: 'POST',
    body: bytes,
    headers: {
      'content-type': 'application/octet-stream',
      'swarm-postage-batch-id': batch,
      'swarm-redundancy-level': '0',
    },
  })
  if (!response.ok) throw new Error(`bee refused the upload: ${response.status} ${await response.text()}`)
  const { reference } = await response.json()
  return reference
}

/**
 * The reference these bytes must have, computed here and owing nothing to what
 * Bee said. Anyone can run the same check against a download, which is what
 * makes the gateway unable to serve a different file than the one it promised.
 */
export function referenceFor(bytes) {
  const { makeChunkedFile } = bmt
  return Buffer.from(makeChunkedFile(new Uint8Array(bytes)).address()).toString('hex')
}

export async function upload(bytes) {
  const batch = await batchId()

  if (batch) {
    const reference = await uploadToSwarm(batch, bytes)
    const expected = referenceFor(bytes)
    if (reference !== expected) throw new Error(`bee returned ${reference}, bmt says ${expected}`)
    return reference
  }

  // Local fallback: address the blob by the reference Swarm would give it, so
  // a reference means the same thing in both modes and switching to a funded
  // node changes where the bytes live rather than what they are called.
  const ref = referenceFor(bytes)
  await mkdir(LOCAL_DIR, { recursive: true })
  await writeFile(path.join(LOCAL_DIR, ref), bytes)
  return ref
}

export async function download(reference) {
  if (await batchId()) {
    const data = await client().downloadData(reference)
    const bytes = new Uint8Array(data.toUint8Array ? data.toUint8Array() : data)
    // Check what came back against the address we asked for, rather than
    // trusting the node that served it.
    const actual = referenceFor(bytes)
    if (actual !== String(reference).replace(/^0x/, '')) {
      throw new Error(`downloaded bytes hash to ${actual}, not ${reference}`)
    }
    return bytes
  }
  return new Uint8Array(await readFile(path.join(LOCAL_DIR, reference)))
}

/** What the health endpoint reports about storage. */
export async function stampInfo() {
  const current = await mode()
  if (current !== 'swarm') return { mode: current, usable: true, batchTTL: null }

  const batch = await client().getPostageBatch(await batchId())
  return {
    mode: current,
    usable: batch.usable,
    batchTTL: batch.batchTTL,
    utilization: batch.utilization,
    depth: batch.depth,
  }
}
