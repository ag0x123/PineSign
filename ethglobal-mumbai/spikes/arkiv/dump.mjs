import { createPublicClient, defineSchema, str, bytes } from '@arkiv-network/sdk'
import { rabdi } from '@arkiv-network/sdk/chains'
import { eq } from '@arkiv-network/sdk/query'
import { http, keccak256, toHex } from 'viem'
const chain = rabdi({ accessKey: process.env.ARKIV_ACCESS_KEY })
const c = createPublicClient({ chain, transport: http() })
const Invite = defineSchema('pinesign.invite', { fingerprint: str().indexed(), emailHash: str().indexed(), payload: bytes() })
const emailHash = keccak256(toHex('alice@example.com'))
const r = await c.select({ $key: true, fingerprint: true, emailHash: true, payload: true }).from(Invite).where(eq('emailHash', emailHash)).fetch()
for (const e of r.entities) {
  console.log('key', e.$key)
  for (const [k, v] of Object.entries(e)) {
    console.log('  ', k, '=>', v?.constructor?.name, Array.isArray(v) || v instanceof Uint8Array ? `len=${v.length}` : JSON.stringify(v)?.slice(0, 80))
  }
}
console.log('--- select * ---')
const all = await c.select().from(Invite).where(eq('emailHash', emailHash)).fetch()
console.log(JSON.stringify(all.entities[0], (k, v) => (v instanceof Uint8Array ? `U8(${v.length})` : typeof v === 'bigint' ? String(v) : v), 1).slice(0, 900))
