/**
 * The published sign-in pages, and which of them this gateway will serve.
 *
 * The sign-in page is static and lives on Swarm. A Swarm reference is a hash,
 * so a reference pins exactly one set of bytes — nobody, including whoever runs
 * this gateway, can change what a published version contains.
 *
 * What a gateway does decide is which references it is willing to serve, and
 * under which name. That is this allow-list. A version in it is reachable at
 * `<version>.<signin domain>`; anything else under that domain is a 404, not a
 * fallback — a page that holds the user's key is not something to be lenient
 * about serving.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { storagePath } from './paths.js'

const FILE = storagePath('pages.json')

/**
 * The domain the sign-in pages are served under, e.g. `id.example.com`.
 *
 * Deliberately below the apex. The passkey is scoped to this domain, and a
 * credential scoped here cannot be asserted by the parent — which is what
 * keeps the lander, served by this same gateway, away from the key.
 */
export const SIGNIN_DOMAIN = process.env.SIGNIN_DOMAIN ?? null

const VERSION = /^v[0-9]+$/

export function validVersion(version) {
  return typeof version === 'string' && VERSION.test(version)
}

let config = null

async function load() {
  if (config) return config
  try {
    config = JSON.parse(await readFile(FILE, 'utf8'))
  } catch {
    config = { current: null, versions: {} }
  }
  return config
}

async function persist() {
  await mkdir(path.dirname(FILE), { recursive: true })
  await writeFile(FILE, JSON.stringify(config, null, 2))
}

export async function all() {
  return load()
}

/** The reference for a version, or null if this gateway will not serve it. */
export async function referenceFor(version) {
  if (!validVersion(version)) return null
  return (await load()).versions[version]?.reference ?? null
}

export async function current() {
  const c = await load()
  return c.current ? { version: c.current, ...c.versions[c.current] } : null
}

/** Add a published version to the list, and make it the one the apex points at. */
export async function publish({ version, reference, files, bytes }) {
  if (!validVersion(version)) throw new Error('a version is v followed by digits, e.g. v1')
  const c = await load()

  const existing = c.versions[version]
  if (existing && existing.reference !== reference) {
    // A version that could be repointed is a version whose name means nothing.
    // Publish the next one instead.
    throw new Error(
      `${version} is already published at ${existing.reference}. A published version is fixed — publish ${nextVersion(c)} instead.`,
    )
  }

  c.versions[version] = { reference, files, bytes, publishedAt: new Date().toISOString() }
  c.current = version
  await persist()
  return c.versions[version]
}

export function nextVersion(c) {
  const used = Object.keys(c.versions)
    .filter(validVersion)
    .map((v) => Number(v.slice(1)))
  return `v${used.length ? Math.max(...used) + 1 : 1}`
}

/**
 * Which version a host is asking for, if it is asking under the sign-in domain.
 *
 * Returns `{ version }` for `v1.id.example.com`, `{ apex: true }` for
 * `id.example.com` itself, and null for anything that is not this domain at all.
 */
export function routeFor(host) {
  if (!SIGNIN_DOMAIN) return null
  const name = String(host ?? '').toLowerCase().split(':')[0]
  if (name === SIGNIN_DOMAIN) return { apex: true }
  if (!name.endsWith(`.${SIGNIN_DOMAIN}`)) return null
  return { version: name.slice(0, -(SIGNIN_DOMAIN.length + 1)) }
}
