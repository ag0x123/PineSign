/**
 * Deploys the three contracts a delivery needs on the frame devnet.
 *
 *   node scripts/frame-deploy.mjs                     # reuse what is recorded
 *   node scripts/frame-deploy.mjs --fresh             # deploy new ones
 *   node scripts/frame-deploy.mjs --modulus <hex>     # Bob's account for that DKIM key
 *
 * The addresses are written to .storage/frame.json and printed as the .env
 * lines to keep, because a devnet reset wipes them and nothing should treat an
 * address from a previous run as still being there.
 *
 * Deployments are paid for by a throwaway key this script asks the devnet's own
 * faucet to fund. Nobody's real key touches this.
 */

import '../gateway/env.js'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { createWalletClient, createPublicClient, http, defineChain, encodeDeployData, keccak256 } from 'viem'
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts'
import * as frame from '../gateway/frame.js'
import { storagePath } from '../gateway/paths.js'

const STATE = storagePath('frame.json')
const fresh = process.argv.includes('--fresh')
const modulusAt = process.argv.indexOf('--modulus')
// indexOf gives -1 when the flag is absent, and argv[0] is the node binary — a
// truthy value that would deploy an account for nonsense.
const modulusArg = modulusAt === -1 ? null : process.argv[modulusAt + 1]

if (!frame.RPC) {
  console.error('FRAME_RPC is not set in .env')
  process.exit(1)
}

const chainId = Number(await frame.rpc('eth_chainId'))
const chain = defineChain({
  id: chainId,
  name: 'frame-devnet',
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: { default: { http: [frame.RPC] } },
})

const read = createPublicClient({ chain, transport: http(frame.RPC) })

async function state() {
  try {
    return JSON.parse(await readFile(STATE, 'utf8'))
  } catch {
    return {}
  }
}

async function save(patch) {
  const next = { ...(await state()), ...patch, chainId }
  await mkdir(storagePath(), { recursive: true })
  await writeFile(STATE, JSON.stringify(next, null, 2))
  return next
}

// A key that exists only to deploy. Kept in .storage so a second run does not
// have to go back to the faucet.
let recorded = await state()
if (recorded.chainId && recorded.chainId !== chainId) {
  console.log(`  chain changed (${recorded.chainId} -> ${chainId}); starting over`)
  recorded = {}
}
const deployerKey = recorded.deployerKey ?? generatePrivateKey()
const deployer = privateKeyToAccount(deployerKey)
const wallet = createWalletClient({ account: deployer, chain, transport: http(frame.RPC) })

// The devnet base fee is 7 wei; legacy transactions keep the deploy simple.
const DEPLOY_GAS = BigInt(process.env.FRAME_DEPLOY_GAS ?? 15_000_000)

async function fund() {
  const balance = await read.getBalance({ address: deployer.address })
  if (balance > 10n ** 16n) return balance
  // The devnet exposes its faucet over RPC, which is why no funded key is needed.
  await frame.rpc('skandha_explorer_faucet', [deployer.address])
  for (let i = 0; i < 30; i++) {
    const now = await read.getBalance({ address: deployer.address })
    if (now > balance) return now
    await new Promise((r) => setTimeout(r, 1000))
  }
  throw new Error('the faucet did not fund the deployer')
}

async function deploy(name, args = [], value = 0n) {
  const { abi, bytecode } = await frame.artifact(name)
  const hash = await wallet.sendTransaction({
    to: null,
    data: encodeDeployData({ abi, bytecode: bytecode.object, args }),
    value,
    gas: DEPLOY_GAS,
    type: 'legacy',
  })
  const receipt = await read.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success' || !receipt.contractAddress) {
    throw new Error(`${name} deployment reverted (gas used ${receipt.gasUsed})`)
  }
  console.log(`  ${name}  ${receipt.contractAddress}  (${receipt.gasUsed} gas)`)
  return receipt.contractAddress
}

const alive = async (address) => Boolean(address) && (await read.getCode({ address })) !== undefined

console.log(`  rpc:   ${frame.RPC}  chain ${chainId}  block ${Number(await frame.rpc('eth_blockNumber'))}`)
await save({ deployerKey })
console.log(`  payer: ${deployer.address}  ${(await fund()).toString()} wei`)

let { release, paymaster } = recorded
if (fresh || !(await alive(release))) release = await deploy('PineSignRelease')
if (fresh || !(await alive(paymaster))) {
  // Funded through its creation value: a plain transfer runs its fallback,
  // which calls APPROVE outside a frame and fails.
  const funding = BigInt(process.env.PINESIGN_PAYMASTER_FUNDING_WEI ?? 10n ** 16n)
  if (!frame.SPONSOR_ADDRESS) throw new Error('PINESIGN_SPONSOR_KEY is not set; the paymaster needs its signer')
  paymaster = await deploy('PineSignPaymaster', [frame.SPONSOR_ADDRESS, BigInt(chainId)], funding)
}
await save({ release, paymaster })

// Bob's account is per DKIM key, and the release contract is pinned into it, so
// it has to be deployed after the release contract exists.
let account = null
if (modulusArg) {
  const modulusHash = keccak256(modulusArg.startsWith('0x') ? modulusArg : `0x${modulusArg}`)
  account = await deploy('DkimWallet', [modulusHash, release])
  await save({ accounts: { ...(recorded.accounts ?? {}), [modulusHash]: account } })
}

console.log('\n  add to .env:\n')
console.log(`PINESIGN_RELEASE_ADDRESS=${release}`)
console.log(`PINESIGN_PAYMASTER_ADDRESS=${paymaster}`)
if (account) console.log(`# account for the DKIM key you passed: ${account}`)
