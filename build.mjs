/**
 * Bundles the browser code.
 *
 * Two bundles that matter, from two different trust positions. The app's
 * bundles are served by the gateway. The sign-in bundle is published to Swarm
 * and served from its own origin, and it is the only one that ever holds a key
 * — so the origins it will talk to are compiled into it rather than read from
 * a page it was loaded by.
 */

import './gateway/env.js' // deployment values come from .env, never from here
import { build } from 'esbuild'

const need = (name, hint) => {
  const value = process.env[name]
  if (value) return value
  console.error(`${name} is not set in .env. ${hint}`)
  process.exit(1)
}

const SIGNIN_URL = need('SIGNIN_PAGE_URL', 'The published sign-in page, e.g. https://v1.id.example.com/')
const GATEWAY = need('PUBLIC_ORIGIN', 'Where this gateway is reached, e.g. https://example.com')
const APP_ORIGINS = need('APP_ORIGINS', 'Origins allowed to drive the sign-in page, comma separated')
  .split(',')
  .map((o) => o.trim().replace(/\/$/, ''))
  .filter(Boolean)

const define = {
  __PINESIGN_GATEWAY__: JSON.stringify(GATEWAY),
  __PINESIGN_SIGNIN_URL__: JSON.stringify(SIGNIN_URL.replace(/\/$/, '') + '/'),
  __PINESIGN_APP_ORIGINS__: JSON.stringify(APP_ORIGINS),
}

const targets = [
  { in: 'web/src/claim.js', out: 'web/claim.bundle.js' },
  { in: 'web/src/setup.js', out: 'web/setup.bundle.js' },
  { in: 'web/src/lander.js', out: 'web/lander.bundle.js' },
  { in: 'web/src/nav.js', out: 'web/nav.bundle.js' },
  { in: 'signin/src/signin.js', out: 'signin/signin.bundle.js' },
]

console.log(`  gateway:   ${GATEWAY}`)
console.log(`  sign-in:   ${SIGNIN_URL}`)
console.log(`  app origins: ${APP_ORIGINS.join(', ')}`)

for (const target of targets) {
  const result = await build({
    entryPoints: [target.in],
    outfile: target.out,
    bundle: true,
    format: 'esm',
    metafile: true,
    define,
  })
  const bytes = Object.values(result.metafile.outputs)[0].bytes
  console.log(`  ${target.out}  ${(bytes / 1024).toFixed(0)}kb`)
}
