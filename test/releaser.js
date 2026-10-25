/**
 * The finality gate on automatic release.
 *
 * This is the part worth testing without a chain, because the consequence of
 * getting it wrong is not a failed transaction. `release` puts the sender's
 * half in calldata, and calldata is public from the moment a transaction is
 * broadcast — so releasing against an acceptance that is later reorganised
 * away publishes the half for a delivery nobody accepted, and the revert does
 * not take it back.
 */

import { isFinal, settings } from '../gateway/releaser.js'

let pass = 0, fail = 0
const check = (label, condition) => {
  console.log(`${condition ? '  ok  ' : ' FAIL '} ${label}`)
  condition ? pass++ : fail++
}

console.log('\nsettings')
check('finality defaults to the chain\'s own finalized tag', settings.mode === 'finalized')
check('with a confirmation count as the fallback', settings.confirmations > 0)
check('and a poll interval', settings.everyMs > 0)

console.log('\nthe gate')
// Against a real chain, because what "finalized" means is the chain's answer
// and not ours. A block far behind the head is final; the head is not.
const head = await fetch(process.env.RPC_URL ?? 'https://ethereum-sepolia-rpc.publicnode.com', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_blockNumber', params: [] }),
})
  .then((r) => r.json())
  .then((b) => BigInt(b.result))
  .catch(() => null)

if (head === null) {
  console.log('  skip  no chain reachable, so the gate cannot be exercised')
} else {
  const old = await isFinal(head - 1000n)
  check('a block a thousand deep is final', old.final === true)

  const now = await isFinal(head)
  check('the head is not', now.final === false)
  check('and it says what it is waiting for', typeof now.why === 'string' && now.why.length > 0)

  const future = await isFinal(head + 100n)
  check('a block that does not exist yet is certainly not final', future.final === false)
}

console.log(`\n${pass} passed, ${fail} failed  (releaser)\n`)
process.exit(fail === 0 ? 0 : 1)
