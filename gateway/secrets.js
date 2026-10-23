/**
 * The server's own secrets.
 *
 * Two keys, both HMAC keys, neither of them ever sent anywhere:
 *
 *   - `challenge` binds a passkey ceremony to the email address that was just
 *     proved, so a challenge issued for one address cannot be spent on another.
 *   - `emailHash` is what turns an address into the keyed hash published on
 *     chain. Without the key, the published hash cannot be run backwards
 *     through a list of likely addresses — which an unkeyed hash of an email
 *     always can be.
 *
 * Set them in the environment on a real deployment, so they survive a lost
 * disk and are the same across replicas. Unset, they are generated once and
 * kept in .storage/ — fine for one box, and the records written under an
 * `emailHash` key that is later lost become unmatchable, so it is worth setting.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import path from 'node:path'
import { storagePath } from './paths.js'

const FILE = storagePath('secrets.json')

let secrets = null

async function load() {
  if (secrets) return secrets

  const fromEnv = {
    challenge: process.env.PASSKEY_CHALLENGE_SECRET ?? null,
    emailHash: process.env.EMAIL_HASH_KEY ?? null,
  }
  if (fromEnv.challenge && fromEnv.emailHash) {
    secrets = fromEnv
    return secrets
  }

  let stored = {}
  try {
    stored = JSON.parse(await readFile(FILE, 'utf8'))
  } catch (err) {
    if (err.code !== 'ENOENT') {
      throw new Error(`${FILE} exists but could not be read: ${err.message}`)
    }
  }

  let changed = false
  for (const which of ['challenge', 'emailHash']) {
    if (fromEnv[which]) continue
    if (!stored[which]) {
      stored[which] = randomBytes(32).toString('hex')
      changed = true
    }
  }
  if (changed) {
    await mkdir(path.dirname(FILE), { recursive: true })
    await writeFile(FILE, JSON.stringify(stored, null, 2), { mode: 0o600 })
  }

  secrets = {
    challenge: fromEnv.challenge ?? stored.challenge,
    emailHash: fromEnv.emailHash ?? stored.emailHash,
  }
  return secrets
}

/** An email address, normalised, so the same person always hashes the same. */
export function normaliseEmail(email) {
  return String(email ?? '').trim().toLowerCase()
}

/** HMAC(email), hex. Published on chain; reversible only with the key. */
export async function emailHash(email) {
  const { emailHash: key } = await load()
  return createHmac('sha256', key).update(normaliseEmail(email)).digest('hex')
}

/** HMAC(email) under the challenge key — the half of a challenge that binds it. */
export async function emailTag(email) {
  const { challenge } = await load()
  return createHmac('sha256', challenge).update(normaliseEmail(email)).digest('hex')
}

/** Constant-time comparison, for anything an attacker gets to guess at. */
export function sameSecret(a, b) {
  const left = Buffer.from(String(a ?? ''), 'utf8')
  const right = Buffer.from(String(b ?? ''), 'utf8')
  return left.length === right.length && timingSafeEqual(left, right)
}
