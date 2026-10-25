/**
 * Prove the passkey path on a real chain.
 *
 * This exists because the contract test suite cannot run it. Foundry's EVM has
 * no P-256 precompile at any evm_version, and forking does not help — Foundry
 * executes with its own EVM rather than the remote node's. Mocking the
 * precompile would have made every assertion in that suite verify against
 * nothing, so it was not mocked and this script covers the gap instead.
 *
 * What is real here: the P-256 key, the DER signature, the authenticatorData,
 * the clientDataJSON, the precompile, the contract, the chain. What is stood
 * in for: the tap. An authenticator cannot be driven from a script, so a
 * software P-256 key plays its part — which is cryptographically the same
 * thing from the contract's side, and the contract is what is under test.
 *
 *   node scripts/accept-onchain.mjs
 */

import '../gateway/env.js'
import { createWalletClient, createPublicClient, http, keccak256, encodeAbiParameters, toHex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { sepolia } from 'viem/chains'
import { p256 } from '@noble/curves/p256'
import { createHash, randomBytes } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import * as setup from '../gateway/setup.js'
import * as keysplit from '../shared/keysplit.js'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const sha256 = (b) => createHash('sha256').update(b).digest()
const RPC = process.env.RPC_URL ?? 'https://ethereum-sepolia-rpc.publicnode.com'

const RP_ID = 'id.pinesign.test'
const ORIGIN = 'https://v1.id.pinesign.test'

let step = 0
const say = (message) => console.log(`\n${++step}. ${message}`)
const ok = (message) => console.log(`   ok   ${message}`)
const fail = (message) => {
  console.error(`\nFAILED: ${message}`)
  process.exit(1)
}

// ---- the deployer ----

const key = process.env.DELIVERY_DEPLOYER_KEY ?? (await setup.deployerKey())
if (!key) {
  fail('No deployer key. Set DELIVERY_DEPLOYER_KEY in .env, or run setup so one exists in .storage/.')
}
const account = privateKeyToAccount(key)
const wallet = createWalletClient({ account, chain: sepolia, transport: http(RPC) })
const client = createPublicClient({ chain: sepolia, transport: http(RPC) })

say(`Deployer ${account.address}`)
const balance = await client.getBalance({ address: account.address })
console.log(`   balance ${Number(balance) / 1e18} ETH`)
if (balance === 0n) fail('that account has no Sepolia ETH')

// ---- the precompile, before anything is spent on it ----

say('P-256 precompile')
{
  const priv = p256.utils.randomPrivateKey()
  const point = Buffer.from(p256.getPublicKey(priv, false))
  const digest = sha256(Buffer.from('precompile liveness'))
  const sig = p256.sign(digest, priv)
  const input = Buffer.concat([
    digest,
    Buffer.from(sig.toCompactRawBytes()),
    point.subarray(1, 33),
    point.subarray(33, 65),
  ])
  const out = await client.call({ to: '0x0000000000000000000000000000000000000100', data: toHex(input) })
  if (out.data !== `0x${'00'.repeat(31)}01`) {
    fail(`the precompile at 0x100 did not verify a good signature (returned ${out.data})`)
  }
  ok('verifies a genuine signature')
}

// ---- deploy ----

const artifact = JSON.parse(
  await readFile(path.join(ROOT, 'contracts', 'out', 'PineSignDelivery.sol', 'PineSignDelivery.json'), 'utf8'),
)
const libArtifact = JSON.parse(
  await readFile(path.join(ROOT, 'contracts', 'out', 'WebAuthn.sol', 'WebAuthn.json'), 'utf8'),
)

/**
 * Link the library into the bytecode.
 *
 * WebAuthn's entry points are `public`, so it deploys on its own and the
 * delivery contract reaches it by delegatecall. Solidity leaves a placeholder
 * in the bytecode where the address goes, and the artifact says where; Foundry
 * fills this in for its own tests, but a deployment from here has to do it.
 */
function link(bytecode, references, address) {
  let out = bytecode
  for (const file of Object.values(references ?? {})) {
    for (const positions of Object.values(file)) {
      for (const { start, length } of positions) {
        if (length !== 20) throw new Error(`unexpected link reference length ${length}`)
        const head = out.slice(0, 2 + start * 2)
        const tail = out.slice(2 + (start + length) * 2)
        out = head + address.slice(2).toLowerCase() + tail
      }
    }
  }
  if (out.includes('__$')) throw new Error('bytecode still has an unlinked placeholder')
  return out
}

const rpIdHash = toHex(sha256(Buffer.from(RP_ID, 'utf8')))
const originHash = keccak256(Buffer.from(ORIGIN, 'utf8'))

say('Deploying the WebAuthn library')
const libHash = await wallet.deployContract({
  abi: libArtifact.abi,
  bytecode: libArtifact.bytecode.object,
})
const libDeployed = await client.waitForTransactionReceipt({ hash: libHash })
if (libDeployed.status !== 'success') fail(`library deployment reverted (${libHash})`)
ok(`${libDeployed.contractAddress}  ${gasOf(libDeployed, 'library')} gas`)

say('Deploying PineSignDelivery')
const deployHash = await wallet.deployContract({
  abi: artifact.abi,
  bytecode: link(artifact.bytecode.object, artifact.bytecode.linkReferences, libDeployed.contractAddress),
  args: [rpIdHash, [originHash]],
})
const deployed = await client.waitForTransactionReceipt({ hash: deployHash })
if (deployed.status !== 'success') fail(`deployment reverted (${deployHash})`)
const address = deployed.contractAddress
ok(`${address}  ${gasOf(deployed, 'deploy')} gas`)

const contract = { address, abi: artifact.abi }

// ---- the authenticator, and the recipient's keys ----

const authPriv = p256.utils.randomPrivateKey()
const authPoint = Buffer.from(p256.getPublicKey(authPriv, false))
const passkeyX = toHex(authPoint.subarray(1, 33))
const passkeyY = toHex(authPoint.subarray(33, 65))

// ---- send ----

const B = toHex(randomBytes(32))
const params = {
  releaser: account.address,
  passkeyX,
  passkeyY,
  pkBX: toHex(randomBytes(32)),
  pkBOdd: false,
  ephemeralX: toHex(randomBytes(32)),
  ephemeralOdd: true,
  swarmRef: keccak256(Buffer.from('a swarm reference')),
  ciphertextHash: keccak256(Buffer.from('the ciphertext')),
  plaintextCommitment: keccak256(encodeAbiParameters([{ type: 'bytes32' }], [keccak256(Buffer.from('salt||F'))])),
  releaseCommitment: keccak256(encodeAbiParameters([{ type: 'bytes32' }], [B])),
  descriptionHash: keccak256(Buffer.from('one invoice')),
  acceptBy: BigInt(Math.floor(Date.now() / 1000) + 3600),
  releaseBy: BigInt(Math.floor(Date.now() / 1000) + 7200),
}

say('the transfer id, computed both ways')
await checkTransferId(contract, account.address, params)
ok('shared/keysplit.js agrees with the contract')

say('send')
const sendHash = await wallet.writeContract({ ...contract, functionName: 'send', args: [params] })
const sent = await client.waitForTransactionReceipt({ hash: sendHash })
if (sent.status !== 'success') fail(`send reverted (${sendHash})`)
const id = await client.readContract({ ...contract, functionName: 'transferId', args: [account.address, params] })
ok(`id ${id}  ${gasOf(sent, 'send')} gas`)

/**
 * Gas this transaction actually used.
 *
 * A receipt carries both `gasUsed` and `cumulativeGasUsed`, and the second one
 * counts every transaction before it in the block — so reading the wrong field
 * makes cost depend on how busy the block was.
 */
function gasOf(receipt, label) {
  if (receipt.cumulativeGasUsed !== receipt.gasUsed) {
    console.log(`   (${label}: ${receipt.gasUsed} used, ${receipt.cumulativeGasUsed} cumulative in block)`)
  }
  return receipt.gasUsed
}

/** The custom error a revert carries, wherever viem happened to put it. */
function errorName(err) {
  for (let e = err; e; e = e.cause) {
    if (e.data?.errorName) return e.data.errorName
    if (e.errorName) return e.errorName
  }
  return null
}

/**
 * Does the browser agree with the contract about the id?
 *
 * It has to exactly, because `A` is salted with it. A disagreement would not
 * raise an error anywhere — the sender would derive one half, the recipient
 * another, and the file would simply never open. So it is checked against the
 * contract rather than against another copy of the same assumption.
 */
async function checkTransferId(contract, sender, params) {
  const onChain = await client.readContract({
    ...contract,
    functionName: 'transferId',
    args: [sender, params],
  })
  const inJs = keysplit.transferId({
    sender,
    passkeyX: params.passkeyX,
    passkeyY: params.passkeyY,
    pkBX: params.pkBX,
    pkBOdd: params.pkBOdd,
    ephemeralX: params.ephemeralX,
    ephemeralOdd: params.ephemeralOdd,
    ciphertextHash: params.ciphertextHash,
    plaintextCommitment: params.plaintextCommitment,
    descriptionHash: params.descriptionHash,
    acceptBy: params.acceptBy,
    releaseBy: params.releaseBy,
  })
  if (inJs.toLowerCase() !== onChain.toLowerCase()) {
    fail(`the id does not match the contract\n   contract ${onChain}\n   browser  ${inJs}`)
  }
  return onChain
}

const stateNames = ['None', 'Sent', 'Accepted', 'Released', 'Expired', 'SenderAborted']

/**
 * Wait for the chain to agree that the state is what it should be.
 *
 * A public RPC load-balances across nodes, so a read straight after a
 * confirmed transaction can land on a replica that has not caught up. Reading
 * once and failing produced "expected Released, got Released" — two reads, two
 * replicas. So the check is a short retry, and the failure message reports the
 * value it actually settled on.
 */
async function expectState(id, want) {
  let seen
  for (let attempt = 0; attempt < 10; attempt++) {
    if (attempt) await new Promise((r) => setTimeout(r, 1000))
    seen = stateNames[await client.readContract({ ...contract, functionName: 'stateOf', args: [id] })]
    if (seen === want) return seen
  }
  fail(`expected ${want}, and after ten reads over ten seconds it is still ${seen}`)
}

await expectState(id, 'Sent')
ok('state is Sent')

const before = await client.readContract({ ...contract, functionName: 'get', args: [id] })
if (before.releasedKey !== `0x${'00'.repeat(32)}`) fail('B is on chain before any acceptance')
ok('B is not on chain yet')

// ---- accept, with a real assertion over the contract's own digest ----

say('accept')
const digest = await client.readContract({ ...contract, functionName: 'acceptDigest', args: [id] })
console.log(`   digest ${digest}`)

const challenge = Buffer.from(digest.slice(2), 'hex').toString('base64url')
const clientDataJSON = Buffer.from(
  JSON.stringify({ type: 'webauthn.get', challenge, origin: ORIGIN, crossOrigin: false }),
)

const authData = Buffer.alloc(37)
sha256(Buffer.from(RP_ID, 'utf8')).copy(authData, 0)
authData[32] = 0x05 // user present + user verified
authData.writeUInt32BE(1, 33)

const signature = p256.sign(sha256(Buffer.concat([authData, sha256(clientDataJSON)])), authPriv)
const json = clientDataJSON.toString()

const assertion = {
  authenticatorData: toHex(authData),
  clientDataJSON: toHex(clientDataJSON),
  typeIndex: BigInt(json.indexOf('"type":"webauthn.get"')),
  challengeIndex: BigInt(json.indexOf('"challenge":"')),
  originIndex: BigInt(json.indexOf('"origin":"')),
  r: toHex(Buffer.from(signature.toCompactRawBytes()).subarray(0, 32)),
  s: toHex(Buffer.from(signature.toCompactRawBytes()).subarray(32, 64)),
}

// Simulating first means a revert is named rather than paid for.
try {
  await client.simulateContract({ ...contract, functionName: 'accept', args: [id, assertion], account })
} catch (err) {
  fail(`accept would revert: ${err.shortMessage ?? err.message}`)
}

const acceptHash = await wallet.writeContract({ ...contract, functionName: 'accept', args: [id, assertion] })
const accepted = await client.waitForTransactionReceipt({ hash: acceptHash })
if (accepted.status !== 'success') fail(`accept reverted (${acceptHash})`)
ok(`verified on chain  ${gasOf(accepted, 'accept')} gas`)

await expectState(id, 'Accepted')
ok('state is Accepted')

const afterAccept = await client.readContract({ ...contract, functionName: 'get', args: [id] })
if (afterAccept.releasedKey !== `0x${'00'.repeat(32)}`) fail('accepting released B')
ok('accepting did not release B')

// ---- a tampered assertion must not pass ----

say('a tampered assertion')
{
  const other = p256.utils.randomPrivateKey()
  // On a fresh transfer, because this one is already accepted.
  const second = { ...params, ephemeralX: toHex(randomBytes(32)) }
  const h = await wallet.writeContract({ ...contract, functionName: 'send', args: [second] })
  const secondSent = await client.waitForTransactionReceipt({ hash: h })
  if (secondSent.status !== 'success') fail(`the second send reverted (${h})`)
  const id2 = await client.readContract({ ...contract, functionName: 'transferId', args: [account.address, second] })
  const digest2 = await client.readContract({ ...contract, functionName: 'acceptDigest', args: [id2] })
  const challenge2 = Buffer.from(digest2.slice(2), 'hex').toString('base64url')
  const cd2 = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: challenge2, origin: ORIGIN, crossOrigin: false }))
  const j2 = cd2.toString()
  const sig2 = p256.sign(sha256(Buffer.concat([authData, sha256(cd2)])), other) // wrong key
  const bad2 = {
    authenticatorData: toHex(authData),
    clientDataJSON: toHex(cd2),
    typeIndex: BigInt(j2.indexOf('"type":"webauthn.get"')),
    challengeIndex: BigInt(j2.indexOf('"challenge":"')),
    originIndex: BigInt(j2.indexOf('"origin":"')),
    r: toHex(Buffer.from(sig2.toCompactRawBytes()).subarray(0, 32)),
    s: toHex(Buffer.from(sig2.toCompactRawBytes()).subarray(32, 64)),
  }
  try {
    await client.simulateContract({ ...contract, functionName: 'accept', args: [id2, bad2], account })
    fail('a signature from another key was accepted')
  } catch (err) {
    // viem puts the decoded custom error in the cause rather than the summary
    // line, so matching the message alone reports the wrong revert reason.
    const named = errorName(err)
    if (named !== 'BadAssertion') {
      fail(`refused, but as ${named ?? 'an unnamed revert'}: ${err.shortMessage ?? err.message}`)
    }
    ok('a signature from another key is refused with BadAssertion')
  }
}

// ---- release ----

say('release')
const wrong = await client
  .simulateContract({ ...contract, functionName: 'release', args: [id, keccak256(Buffer.from('not B'))], account })
  .then(() => null)
  .catch(errorName)
if (wrong !== 'BadReleaseKey') fail(`a wrong B was refused as ${wrong ?? 'an unnamed revert'}`)
ok('a wrong B is refused with BadReleaseKey')

const releaseHash = await wallet.writeContract({ ...contract, functionName: 'release', args: [id, B] })
const released = await client.waitForTransactionReceipt({ hash: releaseHash })
if (released.status !== 'success') fail(`release reverted (${releaseHash})`)
ok(`${gasOf(released, 'release')} gas`)

await expectState(id, 'Released')
const final = await client.readContract({ ...contract, functionName: 'get', args: [id] })
if (final.releasedKey !== B) fail('the released key is not the committed B')
ok('state is Released, and B is on chain')

// ---- what it cost ----

/**
 * The gas schedule, reported alongside the costs.
 *
 * These numbers are several times what `forge test --gas-report` predicts, and
 * the reason is not the contract: this chain has been repriced. A plain
 * transfer here is not 21,000 gas and the block limit is not 30M, and the
 * Foundry in this repo models the older schedule. So the figures below are
 * what this chain charges today — and they say nothing reliable about what
 * mainnet would charge.
 */
const plain = await client.estimateGas({
  account,
  to: '0x000000000000000000000000000000000000dEaD',
  value: 0n,
})
const block = await client.getBlock()

console.log(`
This chain's gas schedule, for scale:
  a plain transfer   ${plain} gas
  block gas limit    ${block.gasLimit}
  base fee           ${block.baseFeePerGas} wei

Proven on Sepolia, not simulated:
  contract   ${address}
  deploy     ${deployed.gasUsed} gas
  send       ${sent.gasUsed} gas
  accept     ${accepted.gasUsed} gas   <- the P-256 assertion, verified by the contract
  release    ${released.gasUsed} gas
  per delivery ${sent.gasUsed + accepted.gasUsed + released.gasUsed} gas

  https://sepolia.etherscan.io/address/${address}

  Cost in ether at the current base fee:
  ${Number((sent.gasUsed + accepted.gasUsed + released.gasUsed) * (block.baseFeePerGas ?? 0n)) / 1e18} ETH per delivery
`)
