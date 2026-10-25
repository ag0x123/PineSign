/**
 * What the gateway keeps about a delivery, which is deliberately not much.
 *
 * The contract holds everything that decides anything. This file holds the two
 * things the chain is the wrong place for — the ciphertext's whereabouts and
 * the sender's sealed key half — plus enough to find a delivery by the people
 * involved rather than by its hash.
 *
 * The sealed half is the interesting entry. It is encrypted under the sender's
 * own key, so this process stores it and cannot read it. That is what keeps the
 * gateway from being able to release: it has the blob and no way to open it.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { storagePath } from './paths.js'

const FILE = storagePath('deliveries.json')

let deliveries = null

async function load() {
  if (deliveries) return deliveries
  try {
    deliveries = JSON.parse(await readFile(FILE, 'utf8'))
  } catch {
    deliveries = {}
  }
  return deliveries
}

async function persist() {
  await mkdir(path.dirname(FILE), { recursive: true })
  await writeFile(FILE, JSON.stringify(deliveries, null, 2))
}

export async function create({
  id, senderPubKey, senderName, recipientPubKey, recipientName, recipientEmail,
  filename, size, swarmRef, descriptionRef, keptHalf, sentTx,
}) {
  const all = await load()
  if (all[id]) throw new Error('that delivery is already recorded')

  all[id] = {
    id,
    senderPubKey,
    senderName,
    recipientPubKey,
    recipientName,
    // Supplied by the sender so the recipient can be told; the gateway never
    // learns an address any other way.
    recipientEmail: recipientEmail ?? null,
    filename,
    size,
    swarmRef,
    descriptionRef,
    // Opaque here. Only the sender's key opens it.
    keptHalf,
    sentTx,
    createdAt: Date.now(),
  }
  await persist()
  return all[id]
}

export async function get(id) {
  return (await load())[id] ?? null
}

export async function bySender(pubKey) {
  const all = await load()
  return Object.values(all).filter((d) => d.senderPubKey === pubKey)
}

export async function byRecipient(pubKey) {
  const all = await load()
  return Object.values(all).filter((d) => d.recipientPubKey === pubKey)
}

export async function list() {
  return Object.values(await load())
}
