/**
 * Publish the sign-in page to Swarm.
 *
 * The page is static on purpose: it is the only thing that ever holds the
 * user's key, so what it contains has to be something a user can pin rather
 * than something a server can change under them. A Swarm reference is a hash
 * of the bytes, which is exactly that.
 *
 * Publishing is therefore: build it, upload it, and add the reference to the
 * gateway's allow-list under the next version name. Versions are never
 * repointed — v1 is a set of bytes for good, and a change becomes v2.
 */

import '../gateway/env.js'
import { Bee } from '@ethersphere/bee-js'
import { execFileSync } from 'node:child_process'
import { readdir, stat } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import * as pages from '../gateway/pages.js'
import * as setup from '../gateway/setup.js'
import { BEE_URL } from '../gateway/bee.js'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const DIR = path.join(ROOT, 'signin')

const fail = (message) => {
  console.error(message)
  process.exit(1)
}

const requested = process.argv[2] ?? null
if (requested && !pages.validVersion(requested)) {
  fail('usage: npm run publish-page [v2]\n       a version is v followed by digits')
}

// The batch can come from the admin panel's configuration or the environment;
// either way, without one there is nothing to pay for the upload with.
const batch = (await setup.get()).postageBatchId ?? process.env.POSTAGE_BATCH_ID ?? null
if (!batch) {
  fail('No postage batch. Buy one in the admin panel, or set POSTAGE_BATCH_ID in .env.')
}

console.log('building…')
execFileSync('node', [path.join(ROOT, 'build.mjs')], { cwd: ROOT, stdio: 'inherit' })

const files = (await readdir(DIR, { withFileTypes: true }))
  .filter((entry) => entry.isFile())
  .map((entry) => entry.name)
if (!files.includes('index.html')) fail(`${DIR} has no index.html to serve`)

let bytes = 0
for (const name of files) bytes += (await stat(path.join(DIR, name))).size

const config = await pages.all()
const version = requested ?? pages.nextVersion(config)

console.log(`\nuploading ${files.length} files (${(bytes / 1024).toFixed(0)}kb) as ${version}`)
for (const name of files) console.log(`  ${name}`)

const bee = new Bee(BEE_URL)
const result = await bee.uploadFilesFromDirectory(batch, DIR, {
  // Without this, the version's bare hostname would list the directory rather
  // than serve the page.
  indexDocument: 'index.html',
})
const reference = result.reference.toString()

const published = await pages.publish({ version, reference, files: files.length, bytes })

console.log(`\npublished ${version}`)
console.log(`  reference ${reference}`)
console.log(`  allow-list ${path.relative(ROOT, path.join(ROOT, '.storage', 'pages.json'))}`)
if (pages.SIGNIN_DOMAIN) {
  console.log(`\nserved at https://${version}.${pages.SIGNIN_DOMAIN}/`)
  console.log(`  and https://${pages.SIGNIN_DOMAIN}/ now redirects there`)
  console.log(`\nSet SIGNIN_PAGE_URL=https://${version}.${pages.SIGNIN_DOMAIN}/ and SIGNIN_ORIGINS`)
  console.log('to match, then rebuild so the app opens this version.')
} else {
  console.log('\nSIGNIN_DOMAIN is not set, so nothing will serve it yet — see .env.example.')
}
console.log(`\npublished at ${published.publishedAt}`)
