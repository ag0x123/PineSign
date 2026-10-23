/**
 * Name directory.
 *
 * A name is how one person addresses another — `alice.pinesign.eth` instead of
 * sixty-six hex characters — and its records carry the encryption public key.
 * That makes the name load-bearing: no name, no published key, nothing to send
 * to. Key discovery and access control are the same lookup.
 *
 * Backed by a local file today and by ENS subnames tomorrow. The shape of the
 * record is already the shape of a set of ENS text records, so the swap is a
 * change of backend, not of callers.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { storagePath } from './paths.js'

/** Set from the server's configuration once setup has chosen a name. */
let PARENT = process.env.PINESIGN_PARENT ?? 'pinesign.eth'

export function setParent(name) {
  if (name) PARENT = name
}

export function getParent() {
  return PARENT
}
const FILE = storagePath('names.json')
const LABEL = /^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$/

let names = null

async function load() {
  if (names) return names
  try {
    names = JSON.parse(await readFile(FILE, 'utf8'))
  } catch {
    names = {}
  }
  return names
}

async function persist() {
  await mkdir(path.dirname(FILE), { recursive: true })
  await writeFile(FILE, JSON.stringify(names, null, 2))
}

export function fullName(label) {
  return `${label}.${PARENT}`
}

export function validLabel(label) {
  return LABEL.test(label)
}

/**
 * Claim a name. First come, first served, and a label cannot be reassigned —
 * a name that could change hands would make every past receipt ambiguous.
 */
export async function register(label, { pubKey, address }) {
  if (!validLabel(label)) {
    throw new Error('a label is 3-32 characters: lowercase letters, digits and hyphens')
  }
  const all = await load()
  const name = fullName(label)
  const existing = all[name]

  // A name is bound to one key for good. The key is derived from the passkey,
  // so the same person signing in again arrives with the same key — and anyone
  // else arrives with a different one and is turned away.
  if (existing && existing.pubKey !== pubKey) throw new Error('that name is taken')

  all[name] = {
    name,
    label,
    // The text records an ENS resolver would hold.
    pubKey,
    address: address ?? null,
    registeredAt: existing?.registeredAt ?? Date.now(),
  }
  await persist()
  return all[name]
}

export async function resolve(nameOrLabel) {
  const all = await load()
  const name = nameOrLabel.includes('.') ? nameOrLabel : fullName(nameOrLabel)
  return all[name.toLowerCase()] ?? null
}

/** The name a key answers to, if it has claimed one. */
export async function reverse(pubKey) {
  const all = await load()
  return Object.values(all).find((n) => n.pubKey === pubKey) ?? null
}

export async function byAddress(address) {
  const all = await load()
  return Object.values(all).find((n) => n.address && n.address.toLowerCase() === address.toLowerCase()) ?? null
}

export async function list() {
  return Object.values(await load())
}
