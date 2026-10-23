/** Is the P-256 verify precompile live? Asked with real vectors, not by version sniffing. */
import { p256 } from '@noble/curves/p256'
import { sha256 } from '@noble/hashes/sha256'

const RPCS = {
  sepolia: process.env.RPC_URL ?? 'https://ethereum-sepolia-rpc.publicnode.com',
  mainnet: 'https://ethereum-rpc.publicnode.com',
  'arbitrum-sepolia': 'https://sepolia-rollup.arbitrum.io/rpc',
  'optimism-sepolia': 'https://sepolia.optimism.io',
  'base-sepolia': 'https://sepolia.base.org',
}

const PRECOMPILES = {
  'EIP-7951 (0x100)': '0x0000000000000000000000000000000000000100',
  'RIP-7212 (0x0b)': '0x000000000000000000000000000000000000000b',
}

const hex = (b) => Buffer.from(b).toString('hex')

// A real signature over a real message, made here so the vector cannot be stale.
const priv = p256.utils.randomPrivateKey()
const pub = p256.getPublicKey(priv, false).slice(1) // drop 0x04 → x||y
const msgHash = sha256(new TextEncoder().encode('pinesign p256 probe'))
const sig = p256.sign(msgHash, priv)
const good = `0x${hex(msgHash)}${sig.toCompactHex()}${hex(pub)}`
// Same thing with one bit of r flipped: must NOT verify.
const badSig = Buffer.from(sig.toCompactRawBytes())
badSig[0] ^= 0x01
const bad = `0x${hex(msgHash)}${hex(badSig)}${hex(pub)}`

console.log(`input length ${(good.length - 2) / 2} bytes (expect 160)\n`)

async function call(rpc, to, data) {
  const res = await fetch(rpc, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to, data }, 'latest'] }),
    signal: AbortSignal.timeout(15000),
  })
  const body = await res.json()
  if (body.error) return { error: body.error.message }
  return { result: body.result }
}

for (const [chain, rpc] of Object.entries(RPCS)) {
  console.log(chain)
  for (const [name, address] of Object.entries(PRECOMPILES)) {
    try {
      const ok = await call(rpc, address, good)
      const no = await call(rpc, address, bad)
      if (ok.error) {
        console.log(`  ${name}  rpc error: ${ok.error}`)
        continue
      }
      const verified = ok.result === `0x${'00'.repeat(31)}01`
      const rejected = no.result === '0x' || no.result === `0x${'00'.repeat(32)}`
      const verdict = verified && rejected ? 'LIVE' : verified ? 'returns 1 but accepts a bad sig (?)' : 'not active'
      console.log(`  ${name}  ${verdict}   good=${ok.result}  bad=${no.result}`)
    } catch (err) {
      console.log(`  ${name}  unreachable: ${err.message}`)
    }
  }
  console.log()
}

/**
 * Cost is not measured here.
 *
 * eth_estimateGas on a top-level call to a precompile reports intrinsic gas
 * and will not separate the precompile's own charge, so the numbers it gives
 * are meaningless for this question. EIP-7951 sets P256VERIFY at 6,900 gas,
 * and what a delivery actually costs is dominated by storage anyway — so that
 * gets measured in the Foundry suite, against the real contract.
 */
console.log('P256VERIFY is 6,900 gas per EIP-7951. Real per-delivery cost: see the contract tests.')
