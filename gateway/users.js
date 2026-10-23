/**
 * Who has signed in, and with which key.
 *
 * Keyed by the keyed hash of the email address, never by the address itself:
 * the gateway has to recognise a returning user, but it does not have to keep
 * a list of its users' mailboxes to do it.
 *
 * This is a cache. For a user who has claimed a name, the same two facts — the
 * public key and the keyed email hash — are text records on their name, and
 * those are the copy anyone can read and nobody here can quietly edit. What
 * this file buys is recognising a returning user before any name exists, and
 * not making a chain call on every sign-in.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { storagePath } from './paths.js'

const FILE = storagePath('users.json')

let users = null

async function load() {
  if (users) return users
  try {
    users = JSON.parse(await readFile(FILE, 'utf8'))
  } catch {
    users = {}
  }
  return users
}

async function persist() {
  await mkdir(path.dirname(FILE), { recursive: true })
  await writeFile(FILE, JSON.stringify(users, null, 2), { mode: 0o600 })
}

export async function byEmailHash(hash) {
  return (await load())[hash] ?? null
}

export async function byPubKey(pubKey) {
  const all = await load()
  return Object.values(all).find((u) => u.pubKey === pubKey) ?? null
}

/**
 * Record the key an address signs in with.
 *
 * The first key wins. A passkey derives the same key every time, so a second,
 * different key for the same address means either a second passkey or a
 * different person holding the mailbox — and in both cases the files already
 * encrypted to the first key would become unopenable. Better to say so.
 */
export async function bind({ emailHash, pubKey, address, credential, signCount = 0 }) {
  const all = await load()
  const existing = all[emailHash]

  if (existing && existing.pubKey !== pubKey) {
    throw new Error(
      'that address already signs in with a different passkey. Use the passkey you signed up with — a new one derives a new key, and files sent to the old one could no longer be opened.',
    )
  }
  // Same reasoning one level down: the credential is what the delivery
  // contract verifies against, so it is fixed at sign-up too.
  if (existing?.credential && credential && existing.credential.spki !== credential.spki) {
    throw new Error('that address is already registered to a different passkey credential')
  }

  all[emailHash] = {
    emailHash,
    pubKey,
    address,
    // The credential's P-256 public key, in both the form WebAuthn hands over
    // and the x/y form the precompile takes.
    credential: existing?.credential ?? credential ?? null,
    signCount: Math.max(signCount, existing?.signCount ?? 0),
    name: existing?.name ?? null,
    firstSeenAt: existing?.firstSeenAt ?? Date.now(),
    lastSeenAt: Date.now(),
  }
  await persist()
  return all[emailHash]
}

/** Remember the name a user claimed, so sign-in can hand it straight back. */
export async function setName(pubKey, name) {
  const all = await load()
  const user = Object.values(all).find((u) => u.pubKey === pubKey)
  if (!user) return null
  user.name = name
  await persist()
  return user
}

export async function emailHashFor(pubKey) {
  return (await byPubKey(pubKey))?.emailHash ?? null
}
