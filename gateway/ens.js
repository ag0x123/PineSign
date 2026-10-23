/**
 * ENSv2 registration.
 *
 * The legacy Sepolia stack no longer registers names — its controllers are not
 * authorised on the old registrar, and nothing has been registered through it
 * for days. ENSv2 replaces it, and differs in ways that matter here:
 *
 *   - names are priced in an ERC-20, not in ether. On this testnet that token
 *     is a mock USDC anyone can mint, so a name costs only gas.
 *   - registration takes a subregistry and a resolver, and returns a token id.
 *   - the flow is still commit, wait, reveal.
 *
 * The ABI is the verified one, read from the deployed contract rather than
 * transcribed.
 */

import { createWalletClient, http, formatUnits, parseAbi } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { sepolia } from 'viem/chains'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { publicClient, RPC_URL } from './chain.js'
import { keccak256, encodePacked, stringToBytes, toHex as viemHex } from 'viem'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

/**
 * The registrar and the token it charges in, both from the environment. They
 * differ per chain and per ENS deployment, so a value compiled in here would
 * be right for exactly one network and quietly wrong everywhere else.
 */
export const REGISTRAR = process.env.ENS_V2_REGISTRAR ?? null
export const PAYMENT_TOKEN = process.env.ENS_V2_PAYMENT_TOKEN ?? null

function registrarAddress() {
  if (!REGISTRAR) throw new Error('ENS_V2_REGISTRAR is not set — see .env.example')
  return REGISTRAR
}

function paymentToken() {
  if (!PAYMENT_TOKEN) throw new Error('ENS_V2_PAYMENT_TOKEN is not set — see .env.example')
  return PAYMENT_TOKEN
}

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'
const ZERO_BYTES32 = `0x${'00'.repeat(32)}`

/** Mock USDC: an ordinary ERC-20 whose mint is deliberately left open. */
const TOKEN_ABI = parseAbi([
  'function mint(address to, uint256 amount)',
  'function approve(address spender, uint256 amount) returns (bool)',
  'function balanceOf(address owner) view returns (uint256)',
  'function allowance(address owner, address spender) view returns (uint256)',
  'function decimals() view returns (uint8)',
  'function symbol() view returns (string)',
])

let abiCache = null
async function registrarAbi() {
  abiCache ??= JSON.parse(await readFile(path.join(__dirname, 'abi', 'ens-v2-registrar.json'), 'utf8'))
  return abiCache
}

async function read(functionName, args = []) {
  return publicClient.readContract({ address: registrarAddress(), abi: await registrarAbi(), functionName, args })
}

export async function isAvailable(label) {
  return read('isAvailable', [label])
}

/** Price in the payment token, for a duration in seconds. */
export async function registerPrice(label, duration) {
  const [base, premium] = await read('getRegisterPrice', [label, BigInt(duration), paymentToken()])
  const total = base + premium
  return { wei: total.toString(), formatted: formatUnits(total, 6), symbol: 'USDC' }
}

export async function limits() {
  const [minAge, maxAge, minDuration] = await Promise.all([
    read('MIN_COMMITMENT_AGE'),
    read('MAX_COMMITMENT_AGE'),
    read('MIN_REGISTER_DURATION'),
  ])
  return { minAge: Number(minAge), maxAge: Number(maxAge), minDuration: Number(minDuration) }
}

/** Is this registrar reachable and behaving? Reported before anything is spent. */
export async function health() {
  try {
    const registry = await read('ETH_REGISTRY')
    return { available: true, registrar: REGISTRAR, registry, reason: null }
  } catch (err) {
    return { available: false, registrar: REGISTRAR, reason: `ENSv2 registrar unreachable: ${err.message}` }
  }
}

/**
 * Register a name.
 *
 * Long-running by nature: two transactions with the registrar's minimum
 * commitment age between them, plus a mint and an approval the first time.
 */
export async function register(privateKey, label, { years = 1, onStep } = {}) {
  const abi = await registrarAbi()
  const account = privateKeyToAccount(privateKey)
  const wallet = createWalletClient({ account, chain: sepolia, transport: http(RPC_URL) })

  const { minAge, minDuration } = await limits()
  const duration = BigInt(Math.max(years * 31536000, minDuration))

  if (!(await isAvailable(label))) throw new Error(`${label}.eth is not available`)

  const price = await registerPrice(label, duration)
  const needed = BigInt(price.wei)

  // The fee is an ERC-20. On this testnet it can simply be minted, so a name
  // costs gas and nothing else — but the balance and allowance still have to
  // be there before the registrar will take it.
  const balance = await publicClient.readContract({
    address: paymentToken(), abi: TOKEN_ABI, functionName: 'balanceOf', args: [account.address],
  })
  if (balance < needed) {
    onStep?.('Minting the registration fee…')
    const mintHash = await wallet.writeContract({
      address: paymentToken(), abi: TOKEN_ABI, functionName: 'mint',
      args: [account.address, needed * 10n], // enough for renewals too
    })
    await publicClient.waitForTransactionReceipt({ hash: mintHash })
  }

  const allowance = await publicClient.readContract({
    address: paymentToken(), abi: TOKEN_ABI, functionName: 'allowance', args: [account.address, registrarAddress()],
  })
  if (allowance < needed) {
    onStep?.('Approving the registrar…')
    const approveHash = await wallet.writeContract({
      address: paymentToken(), abi: TOKEN_ABI, functionName: 'approve', args: [registrarAddress(), needed * 100n],
    })
    await publicClient.waitForTransactionReceipt({ hash: approveHash })
  }

  const secret = `0x${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('hex')}`
  const commitArgs = [label, account.address, secret, ZERO_ADDRESS, ZERO_ADDRESS, duration, ZERO_BYTES32]

  onStep?.('Committing…')
  const commitment = await read('makeCommitment', commitArgs)
  const commitHash = await wallet.writeContract({
    address: registrarAddress(), abi, functionName: 'commit', args: [commitment],
  })
  await publicClient.waitForTransactionReceipt({ hash: commitHash })

  // A reveal that arrives too early is rejected; a little margin costs nothing.
  onStep?.(`Waiting ${minAge + 5} seconds, as the registrar requires…`)
  await new Promise((r) => setTimeout(r, (minAge + 5) * 1000))

  const registerArgs = [
    label, account.address, secret, ZERO_ADDRESS, ZERO_ADDRESS, duration, paymentToken(), ZERO_BYTES32,
  ]

  // Simulating first means a failure costs nothing and explains itself.
  onStep?.('Registering…')
  await publicClient.simulateContract({
    address: registrarAddress(), abi, functionName: 'register', args: registerArgs, account: account.address,
  })

  const registerHash = await wallet.writeContract({
    address: registrarAddress(), abi, functionName: 'register', args: registerArgs,
  })
  const receipt = await publicClient.waitForTransactionReceipt({ hash: registerHash })
  if (receipt.status !== 'success') throw new Error('the registration transaction reverted')

  // The registry mints the name as an ERC-1155 token. Its id is what a later
  // transfer needs, so it is read from the mint event and kept with the record.
  const tokenId = tokenIdFromReceipt(receipt)

  return {
    name: `${label}.eth`,
    owner: account.address,
    tokenId: tokenId?.toString() ?? null,
    registry: await read('ETH_REGISTRY'),
    commitTx: commitHash,
    registerTx: registerHash,
    paid: `${price.formatted} ${price.symbol}`,
  }
}

const TRANSFER_SINGLE = '0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62'

function tokenIdFromReceipt(receipt) {
  // TransferSingle(operator, from, to, id, value): id is the first data word.
  const log = receipt.logs.find((l) => l.topics[0] === TRANSFER_SINGLE)
  return log ? BigInt(`0x${log.data.slice(2, 66)}`) : null
}

/**
 * Move a name to another address.
 *
 * The escape hatch: if the server has to be abandoned, the name goes with the
 * operator rather than with the box. Requires the wallet that owns it.
 */
export async function transferName(privateKey, { registry, tokenId, to }) {
  const account = privateKeyToAccount(privateKey)
  const wallet = createWalletClient({ account, chain: sepolia, transport: http(RPC_URL) })
  const abi = parseAbi([
    'function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes data)',
    'function ownerOf(uint256 id) view returns (address)',
  ])

  const owner = await publicClient.readContract({ address: registry, abi, functionName: 'ownerOf', args: [BigInt(tokenId)] })
  if (owner.toLowerCase() !== account.address.toLowerCase()) {
    throw new Error(`this wallet does not own the name (owner is ${owner})`)
  }

  const hash = await wallet.writeContract({
    address: registry, abi, functionName: 'safeTransferFrom',
    args: [account.address, to, BigInt(tokenId), 1n, '0x'],
  })
  const receipt = await publicClient.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new Error('the transfer reverted')
  return { tx: hash, to }
}


// ---- resolver: where the attestations live ----

const REGISTRY_ABI = parseAbi([
  'function setResolver(uint256 id, address resolver)',
  'function getResolver(string label) view returns (address)',
])

async function resolverArtifact() {
  return JSON.parse(await readFile(path.join(__dirname, '..', 'contracts', 'artifacts', 'PineSignResolver.json'), 'utf8'))
}

/**
 * Deploy the resolver and attach it to the server's name in the v2 registry.
 *
 * From then on every `<x>.tx.<name>` resolves through it by ENSIP-10 wildcard,
 * so per-transfer names carry records without a token being minted for each.
 */
export async function deployResolver(privateKey, { registry, tokenId }) {
  const account = privateKeyToAccount(privateKey)
  const wallet = createWalletClient({ account, chain: sepolia, transport: http(RPC_URL) })
  const artifact = await resolverArtifact()

  const deployHash = await wallet.deployContract({
    abi: artifact.abi, bytecode: artifact.bytecode, args: [account.address],
  })
  const deployed = await publicClient.waitForTransactionReceipt({ hash: deployHash })
  if (deployed.status !== 'success') throw new Error('resolver deployment reverted')

  const setHash = await wallet.writeContract({
    address: registry, abi: REGISTRY_ABI, functionName: 'setResolver',
    args: [BigInt(tokenId), deployed.contractAddress],
  })
  const set = await publicClient.waitForTransactionReceipt({ hash: setHash })
  if (set.status !== 'success') throw new Error('setResolver reverted')

  return { address: deployed.contractAddress, deployTx: deployHash, setResolverTx: setHash }
}

/** Standard ENS namehash. */
export function namehash(name) {
  let node = `0x${'00'.repeat(32)}`
  if (!name) return node
  for (const label of name.split('.').reverse()) {
    node = keccak256(encodePacked(['bytes32', 'bytes32'], [node, keccak256(stringToBytes(label))]))
  }
  return node
}

const RESOLVER_ABI = parseAbi([
  'function setText(bytes32 node, string key, string value)',
  'function setTexts(bytes32 node, string[] keys, string[] values)',
  'function finalize(bytes32 node, string[] keys, string[] values)',
  'function text(bytes32 node, string key) view returns (string)',
  'function frozen(bytes32 node) view returns (bool)',
])

/**
 * Write the sender's half of an attestation under `<id>.tx.<parent>`.
 * One transaction, so the record is either all there or not there.
 */
export async function writeRecords(privateKey, { resolver, name, records }) {
  const account = privateKeyToAccount(privateKey)
  const wallet = createWalletClient({ account, chain: sepolia, transport: http(RPC_URL) })
  const node = namehash(name)
  const keys = Object.keys(records)
  const values = keys.map((k) => String(records[k]))
  const hash = await wallet.writeContract({
    address: resolver, abi: RESOLVER_ABI, functionName: 'setTexts', args: [node, keys, values],
  })
  const receipt = await publicClient.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new Error('setTexts reverted')
  return { node, tx: hash }
}

/** Write the recipient's half and freeze the record: the receipt is final. */
export async function finalizeRecords(privateKey, { resolver, name, records }) {
  const account = privateKeyToAccount(privateKey)
  const wallet = createWalletClient({ account, chain: sepolia, transport: http(RPC_URL) })
  const node = namehash(name)
  const keys = Object.keys(records)
  const values = keys.map((k) => String(records[k]))
  const hash = await wallet.writeContract({
    address: resolver, abi: RESOLVER_ABI, functionName: 'finalize', args: [node, keys, values],
  })
  const receipt = await publicClient.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new Error('finalize reverted')
  return { node, tx: hash }
}

export async function readRecord(resolver, name, key) {
  return publicClient.readContract({
    address: resolver, abi: RESOLVER_ABI, functionName: 'text', args: [namehash(name), key],
  })
}
