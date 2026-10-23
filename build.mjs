/** Bundles the browser code. */

import { build } from 'esbuild'

const targets = [
  { in: 'web/src/claim.js', out: 'web/claim.bundle.js' },
  { in: 'web/src/setup.js', out: 'web/setup.bundle.js' },
  { in: 'web/src/lander.js', out: 'web/lander.bundle.js' },
  { in: 'web/src/nav.js', out: 'web/nav.bundle.js' },
]

for (const target of targets) {
  const result = await build({
    entryPoints: [target.in],
    outfile: target.out,
    bundle: true,
    format: 'esm',
    metafile: true,
  })
  const bytes = Object.values(result.metafile.outputs)[0].bytes
  console.log(`  ${target.out}  ${(bytes / 1024).toFixed(0)}kb`)
}
