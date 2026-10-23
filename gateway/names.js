/**
 * Name directory.
 *
 * A name is how one person addresses another — `alice.example.eth` instead of
 * sixty-six hex characters — and its records carry the encryption public key.
 * That makes the name load-bearing: no name, no published key, nothing to send
 * to. Key discovery and access control are the same lookup.
 *
 * ENS is where the records live. A name resolves through the resolver this
 * server deployed, by ENSIP-10 wildcard, so `alice.example.eth` has records
 * without a token being minted for it.
 *
 * names.json is a cache, and it is honest about being one. Two things make it
 * worth keeping: a chain call on every lookup would be slow and rate-limited,
 * and ENS cannot be searched by value — a resolver answers "what are this
 * name's records", never "which name holds this key". Reverse lookups are
 * therefore the cache's own answer, and a cache that has lost a name is a
 * cache that cannot find it again until its owner signs in.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { storagePath } from './paths.js'
import * as ens from './ens.js'

/** Set from the server's configuration once setup has chosen a name. */
let PARENT = process.env.PINESIGN_PARENT ?? null

export function setParent(name) {
  if (name) PARENT = name
}

export function getParent() {
  return PARENT
}

/** Where to read records from. Set once the resolver is known. */
let RESOLVER = null

export function setResolver(address) {
  RESOLVER = address ?? null
}

const FILE = storagePath('names.json')
const LABEL = /^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$/

/** The text records a user's name carries. */
export const KEY_RECORD = 'pinesign.key'
export const EMAIL_RECORD = 'pinesign.email'
export const ADDRESS_RECORD = 'pinesign.address'
export const SINCE_RECORD = 'pinesign.since'

let cache = null

async function load() {
  if (cache) return cache
  try {
    cache = JSON.parse(await readFile(FILE, 'utf8'))
  } catch {
    cache = {}
  }
  return cache
}

async function persist() {
  await mkdir(path.dirname(FILE), { recursive: true })
  await writeFile(FILE, JSON.stringify(cache, null, 2))
}

export function fullName(label) {
  return PARENT ? `${label}.${PARENT}` : label
}

export function validLabel(label) {
  return LABEL.test(label)
}

/** What the chain says about a name, or null if it says nothing. */
async function fromChain(name) {
  if (!RESOLVER) return null
  try {
    const [pubKey, emailHash, address, since] = await Promise.all([
      ens.readRecord(RESOLVER, name, KEY_RECORD),
      ens.readRecord(RESOLVER, name, EMAIL_RECORD),
      ens.readRecord(RESOLVER, name, ADDRESS_RECORD),
      ens.readRecord(RESOLVER, name, SINCE_RECORD),
    ])
    if (!pubKey) return null
    return {
      name,
      label: name.split('.')[0],
      pubKey,
      emailHash: emailHash || null,
      address: address || null,
      registeredAt: since ? Date.parse(since) : null,
      source: 'ens',
    }
  } catch {
    // An unreachable RPC must not look like a free name.
    return undefined
  }
}

/**
 * Claim a name. First come, first served, and a label cannot be reassigned —
 * a name that could change hands would make every past receipt ambiguous.
 *
 * The chain is asked first, so a name taken on a server that has since lost
 * its cache is still taken.
 */
export async function register(label, { pubKey, address, emailHash }) {
  if (!validLabel(label)) {
    throw new Error('a label is 3-32 characters: lowercase letters, digits and hyphens')
  }
  const name = fullName(label)
  const all = await load()

  const onChain = await fromChain(name)
  if (onChain === undefined) throw new Error('could not reach the chain to check that name')

  // A name is bound to one key for good. The key is derived from the passkey,
  // so the same person signing in again arrives with the same key — and anyone
  // else arrives with a different one and is turned away.
  const existing = onChain ?? all[name]
  if (existing && existing.pubKey !== pubKey) throw new Error('that name is taken')

  const record = {
    name,
    label,
    pubKey,
    emailHash: emailHash ?? existing?.emailHash ?? null,
    address: address ?? null,
    registeredAt: existing?.registeredAt ?? Date.now(),
  }
  all[name] = record
  await persist()
  return record
}

/** The records to publish for a name, in the form the resolver takes. */
export function recordsFor({ pubKey, address, emailHash, registeredAt }) {
  return {
    [KEY_RECORD]: pubKey,
    [EMAIL_RECORD]: emailHash ?? '',
    [ADDRESS_RECORD]: address ?? '',
    [SINCE_RECORD]: new Date(registeredAt ?? Date.now()).toISOString(),
  }
}

export async function resolve(nameOrLabel) {
  const name = (nameOrLabel.includes('.') ? nameOrLabel : fullName(nameOrLabel)).toLowerCase()

  const onChain = await fromChain(name)
  if (onChain) {
    // Seen on chain and not in the cache: remember it, so the next reverse
    // lookup for that key can be answered without a name to ask about.
    const all = await load()
    if (!all[name]) {
      all[name] = onChain
      await persist()
    }
    return onChain
  }
  if (onChain === undefined) throw new Error('could not reach the chain')

  return (await load())[name] ?? null
}

/**
 * The name a key answers to.
 *
 * Only the cache can answer this. A resolver maps a name to its records, never
 * a record back to its name, so there is nothing on chain to ask.
 */
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
