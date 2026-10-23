/**
 * Chain access.
 *
 * Everything the gateway needs from Ethereum: whether a name is free, whether
 * the deployer has been funded, and how to put the receipt contract on chain.
 */

import {
  createPublicClient, createWalletClient, http,
  keccak256, toHex, stringToBytes, formatEther, labelhash,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { sepolia, mainnet } from 'viem/chains'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

export const RPC_URL = process.env.RPC_URL ?? 'https://ethereum-sepolia-rpc.publicnode.com'

/**
 * Anything whose address depends on which network this is pointed at comes
 * from the environment. A default here would be right for one chain and
 * quietly wrong on every other, which is the worst kind of wrong: it fails
 * late, in a transaction, after money has moved.
 */
function required(name, what) {
  const value = process.env[name]
  if (!value) throw new Error(`${name} is not set — ${what}. See .env.example.`)
  return value
}

/** The ENS registry sits at the same address on every chain it is deployed to. */
const ENS_REGISTRY = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e'

/**
 * The .eth registrar controller, per network.
 *
 * Worth getting from deployment records rather than guessing: an older
 * controller is usually still deployed and will happily quote prices and
 * accept commitments, but its registrations revert at the bottom of the stack.
 */
export const ETH_CONTROLLER = () => required('ENS_CONTROLLER', 'the .eth registrar controller for this network')

/** Registration parameters, which this controller takes as a single struct. */
const REGISTRATION_TUPLE = {
  name: 'registration',
  type: 'tuple',
  components: [
    { name: 'label', type: 'string' },
    { name: 'owner', type: 'address' },
    { name: 'duration', type: 'uint256' },
    { name: 'secret', type: 'bytes32' },
    { name: 'resolver', type: 'address' },
    { name: 'data', type: 'bytes[]' },
    { name: 'reverseRecord', type: 'uint8' },
    { name: 'referrer', type: 'bytes32' },
  ],
}

const CONTROLLER_ABI = [
  {
    name: 'rentPrice', type: 'function', stateMutability: 'view',
    inputs: [{ name: 'name', type: 'string' }, { name: 'duration', type: 'uint256' }],
    outputs: [{
      name: 'price', type: 'tuple',
      components: [{ name: 'base', type: 'uint256' }, { name: 'premium', type: 'uint256' }],
    }],
  },
  {
    name: 'available', type: 'function', stateMutability: 'view',
    inputs: [{ name: '', type: 'string' }], outputs: [{ name: '', type: 'bool' }],
  },
  { name: 'makeCommitment', type: 'function', stateMutability: 'pure', inputs: [REGISTRATION_TUPLE], outputs: [{ name: '', type: 'bytes32' }] },
  { name: 'commit', type: 'function', stateMutability: 'nonpayable', inputs: [{ name: 'commitment', type: 'bytes32' }], outputs: [] },
  { name: 'register', type: 'function', stateMutability: 'payable', inputs: [REGISTRATION_TUPLE], outputs: [] },
  { name: 'minCommitmentAge', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'uint256' }] },
]

export const YEAR = 31536000n

/** The public resolver a freshly registered name points at, per network. */
export const PUBLIC_RESOLVER = () => required('ENS_RESOLVER', "the public resolver for this network")


/**
 * Gas each recurring operation costs, measured from the contract test suite and
 * the ENS resolver calls. Approximate by nature — they exist so an admin can
 * see what funding the server actually commits them to, not to be exact.
 */
const GAS = {
  subnameMint: 75000n,   // setSubnodeRecord
  subnameRecord: 50000n, // setText, publishing the encryption key
  send: 95000n,
  claim: 60000n,
}
const REGISTRY_ABI = [
  {
    name: 'owner',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'node', type: 'bytes32' }],
    outputs: [{ name: '', type: 'address' }],
  },
]

export const publicClient = createPublicClient({ chain: sepolia, transport: http(RPC_URL) })

/**
 * Mainnet, read-only.
 *
 * A name free on Sepolia is very often already owned on mainnet, and an
 * operator who registers one here only discovers that when they try to take it
 * for real. So availability is answered for both chains, and a name counts as
 * available only when nobody holds it on either.
 */
export const MAINNET_RPC = process.env.MAINNET_RPC ?? 'https://ethereum-rpc.publicnode.com'
const mainnetClient = createPublicClient({ chain: mainnet, transport: http(MAINNET_RPC) })

/** The .eth base registrar, at the same address on both chains. */
const BASE_REGISTRAR = '0x57f1887a8BF19b14fC0dF6Fd9B2acc9Af147eA85'
const BASE_REGISTRAR_ABI = [
  { name: 'available', type: 'function', stateMutability: 'view', inputs: [{ name: 'id', type: 'uint256' }], outputs: [{ name: '', type: 'bool' }] },
  { name: 'nameExpires', type: 'function', stateMutability: 'view', inputs: [{ name: 'id', type: 'uint256' }], outputs: [{ name: '', type: 'uint256' }] },
]

async function registrarStatus(client, label) {
  const id = BigInt(labelhash(label))
  const [available, expires] = await Promise.all([
    client.readContract({ address: BASE_REGISTRAR, abi: BASE_REGISTRAR_ABI, functionName: 'available', args: [id] }),
    client.readContract({ address: BASE_REGISTRAR, abi: BASE_REGISTRAR_ABI, functionName: 'nameExpires', args: [id] }).catch(() => 0n),
  ])
  return {
    available,
    expires: expires > 0n ? new Date(Number(expires) * 1000).toISOString() : null,
  }
}

/** ENS namehash: fold the labels in from the right, hashing as you go. */
export function namehash(name) {
  let node = '0x' + '00'.repeat(32)
  if (!name) return node
  for (const label of name.split('.').reverse()) {
    node = keccak256(`${node}${keccak256(stringToBytes(label)).slice(2)}`)
  }
  return node
}

/**
 * Is a name available?
 *
 * For a .eth second-level name the registrar is the authority, not the registry:
 * a name can be registered — or sitting in its post-expiry grace period — while
 * its registry owner still reads as zero. Asking the registry alone reports such
 * a name as free, which it is not.
 *
 * The registry owner is still returned, because it says who controls a name that
 * is already taken.
 */
export async function nameStatus(name) {
  const label = name.replace(/\.eth$/, '')
  const isSecondLevel = name.endsWith('.eth') && !label.includes('.')

  const owner = await publicClient
    .readContract({
      address: ENS_REGISTRY,
      abi: REGISTRY_ABI,
      functionName: 'owner',
      args: [namehash(name)],
    })
    .catch(() => '0x0000000000000000000000000000000000000000')

  const ownedInRegistry = owner !== '0x0000000000000000000000000000000000000000'
  if (!isSecondLevel) return { name, owner, available: !ownedInRegistry }

  // Sepolia has moved to ENSv2, so its availability comes from the new
  // registrar. Mainnet still answers from the classic one, and is advisory: if
  // it cannot be reached, say so rather than quietly reporting a name as free.
  const { isAvailable } = await import('./ens.js')
  const [sepoliaFree, mainnetState] = await Promise.all([
    isAvailable(label).catch(() => null),
    registrarStatus(mainnetClient, label).catch(() => null),
  ])
  const sepoliaState = { available: sepoliaFree, expires: null }

  return {
    name,
    owner,
    ownedInRegistry,
    sepolia: sepoliaState,
    mainnet: mainnetState,
    mainnetChecked: mainnetState !== null,
    // Free here and unclaimed there, so the name is still worth building on.
    available: sepoliaState.available && mainnetState?.available !== false,
  }
}

/** What a name costs to register, straight from the registrar. */
export async function ensPrice(label, years = 1) {
  const price = await publicClient.readContract({
    address: ETH_CONTROLLER(),
    abi: CONTROLLER_ABI,
    functionName: 'rentPrice',
    args: [label, YEAR * BigInt(years)],
  })
  const wei = price.base + price.premium
  return { wei: wei.toString(), eth: formatEther(wei), years }
}

export async function ensAvailable(label) {
  return publicClient.readContract({
    address: ETH_CONTROLLER(),
    abi: CONTROLLER_ABI,
    functionName: 'available',
    args: [label],
  })
}

/**
 * What running this server costs, at the current gas price. Quoted per unit and
 * for a sample scale, so funding is a decision rather than a guess.
 */
export async function budget(label, currentBalanceWei = 0n) {
  const gasPrice = await publicClient.getGasPrice()
  const at = (gas) => ({ wei: (gas * gasPrice).toString(), eth: formatEther(gas * gasPrice) })

  const perUser = GAS.subnameMint + GAS.subnameRecord
  const perTransfer = GAS.send + GAS.claim
  const deployGas = 610000n

  // ENSv2 charges the registration fee in a token, not in ether, so the only
  // ETH a registration needs is gas. Quoting it as an ether cost would overstate
  // what an operator has to fund by an order of magnitude.
  const registration = null

  const total =
    (registration ? BigInt(registration.wei) : 0n) +
    deployGas * gasPrice +
    perUser * 100n * gasPrice +
    perTransfer * 100n * gasPrice

  /**
   * Funding packages.
   *
   * An operator cannot be expected to price gas themselves, so each package is
   * quoted as a whole: the one-off costs plus a stated number of users and
   * transfers, with a margin on top because gas moves between quote and spend.
   */
  // Register is a mint, an approve, a commit and a register — four transactions.
  const registrationGas = 420000n
  // The resolver is the larger contract, plus one call to attach it.
  const resolverGas = 1250000n
  const oneOff = (registrationGas + deployGas + resolverGas) * gasPrice
  const pack = (label, note, users, transfers, includeOneOff = true) => {
    const raw =
      (includeOneOff ? oneOff : 0n) +
      perUser * BigInt(users) * gasPrice +
      perTransfer * BigInt(transfers) * gasPrice
    const target = (raw * 130n) / 100n

    // Charge the shortfall, not the whole package: money already in the wallet
    // counts towards it, so paying twice never happens by accident.
    const held = BigInt(currentBalanceWei)
    const due = target > held ? target - held : 0n

    return {
      label, note, users, transfers,
      includesSetup: includeOneOff,
      target: target.toString(),
      targetEth: formatEther(target),
      wei: due.toString(),
      eth: formatEther(due),
      alreadyCovered: due === 0n,
    }
  }

  return {
    gasPriceGwei: (Number(gasPrice) / 1e9).toFixed(2),
    registration,
    deploy: at(deployGas),
    registrationGas: at(registrationGas),
    resolverGas: at(resolverGas),
    perUser: at(perUser),
    perTransfer: at(perTransfer),
    hundredUsers: at(perUser * 100n),
    hundredTransfers: at(perTransfer * 100n),
    suggested: formatEther(total),
    // Two ladders. Before the server is set up, the first rung is deliberately
    // small: pay for the name alone, see it work, then commit to capacity.
    setupPackages: [
      pack('Just the name', 'register the name — the fee is in test USDC, so this is gas only', 0, 0),
      pack('Test', 'the name, the contract, 2 users and a transfer', 2, 1),
      pack('Small', 'setup plus 20 users and 100 transfers', 20, 100),
      pack('Medium', 'setup plus 50 users and 300 transfers', 50, 300),
    ],
    topUpPackages: [
      pack('Top up 10', '10 users and 50 transfers', 10, 50, false),
      pack('Top up 50', '50 users and 200 transfers', 50, 200, false),
      pack('Top up 200', '200 users and 1000 transfers', 200, 1000, false),
    ],
  }
}

/**
 * Buy the server's own name.
 *
 * Two transactions with a mandated wait between them, so this is slow by
 * design — the caller is expected to be a long-running request or a job, not a
 * page waiting on a spinner.
 */
export async function registerEnsName(privateKey, label, years = 1) {
  const account = privateKeyToAccount(privateKey)
  const wallet = createWalletClient({ account, chain: sepolia, transport: http(RPC_URL) })

  // Recover from a crash between paying and recording it: if this wallet already
  // holds the name, the registration succeeded and only the bookkeeping was
  // lost. Charging for it twice would be the real failure.
  const existing = await ownerOf(`${label}.eth`).catch(() => null)
  if (existing && existing.toLowerCase() === account.address.toLowerCase()) {
    return { name: `${label}.eth`, owner: account.address, alreadyOwned: true }
  }

  if (!(await ensAvailable(label))) {
    throw new Error(
      existing
        ? `${label}.eth is owned by ${existing}, not by this server`
        : `${label}.eth is no longer available`,
    )
  }

  const registration = {
    label,
    owner: account.address,
    duration: YEAR * BigInt(years),
    secret: `0x${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('hex')}`,
    resolver: PUBLIC_RESOLVER(),
    data: [],
    reverseRecord: 0,
    referrer: `0x${'00'.repeat(32)}`,
  }

  const commitment = await publicClient.readContract({
    address: ETH_CONTROLLER(), abi: CONTROLLER_ABI, functionName: 'makeCommitment', args: [registration],
  })

  const commitHash = await wallet.writeContract({
    address: ETH_CONTROLLER(), abi: CONTROLLER_ABI, functionName: 'commit', args: [commitment],
  })
  await publicClient.waitForTransactionReceipt({ hash: commitHash })

  // The registrar refuses a reveal that comes too soon; a little margin on top
  // of the stated minimum costs nothing and avoids a wasted registration fee.
  const minAge = await publicClient
    .readContract({ address: ETH_CONTROLLER(), abi: CONTROLLER_ABI, functionName: 'minCommitmentAge' })
    .catch(() => 60n)
  await new Promise((r) => setTimeout(r, (Number(minAge) + 5) * 1000))

  const price = await ensPrice(label, years)
  // A few percent over, because the price can move between quote and reveal.
  const value = (BigInt(price.wei) * 105n) / 100n

  // Simulate first: a revert here is free, whereas a failed registration
  // transaction costs gas and leaves the operator guessing.
  await publicClient.simulateContract({
    address: ETH_CONTROLLER(), abi: CONTROLLER_ABI, functionName: 'register',
    args: [registration], value, account: account.address,
  })

  const registerHash = await wallet.writeContract({
    address: ETH_CONTROLLER(), abi: CONTROLLER_ABI, functionName: 'register',
    args: [registration], value,
  })
  const receipt = await publicClient.waitForTransactionReceipt({ hash: registerHash })
  if (receipt.status !== 'success') throw new Error('the registration transaction reverted')

  return {
    name: `${label}.eth`,
    owner: account.address,
    commitTx: commitHash,
    registerTx: registerHash,
    paid: formatEther(value),
  }
}

/** Who holds a name, according to the registry. Zero address reads as null. */
export async function ownerOf(name) {
  const owner = await publicClient.readContract({
    address: ENS_REGISTRY, abi: REGISTRY_ABI, functionName: 'owner', args: [namehash(name)],
  })
  return owner === '0x0000000000000000000000000000000000000000' ? null : owner
}

/**
 * Can this server actually register a name?
 *
 * The controller is only able to register if the .eth registrar recognises it.
 * On a network mid-migration it may not, and every registration then reverts
 * with no reason given — so the check is made up front and said plainly.
 */
export async function registrationAvailable() {
  const CONTROLLERS_ABI = [{
    name: 'controllers', type: 'function', stateMutability: 'view',
    inputs: [{ name: '', type: 'address' }], outputs: [{ name: '', type: 'bool' }],
  }]
  try {
    const authorised = await publicClient.readContract({
      address: BASE_REGISTRAR, abi: CONTROLLERS_ABI, functionName: 'controllers', args: [ETH_CONTROLLER()],
    })
    return {
      available: authorised,
      reason: authorised
        ? null
        : 'The .eth registrar on this network does not recognise the configured controller, so registrations cannot succeed. Set ENS_CONTROLLER to the current one.',
    }
  } catch (err) {
    return { available: false, reason: `Could not reach the registrar: ${err.message}` }
  }
}

export async function balanceOf(address) {
  const wei = await publicClient.getBalance({ address })
  return { wei: wei.toString(), eth: formatEther(wei) }
}

export async function loadArtifact() {
  const file = path.join(__dirname, '..', 'contracts', 'artifacts', 'PineSignReceipts.json')
  return JSON.parse(await readFile(file, 'utf8'))
}

/** Deploy the receipt contract and wait for it to be mined. */
export async function deployReceipts(privateKey) {
  const artifact = await loadArtifact()
  const account = privateKeyToAccount(privateKey)
  const wallet = createWalletClient({ account, chain: sepolia, transport: http(RPC_URL) })

  const hash = await wallet.deployContract({
    abi: artifact.abi,
    bytecode: artifact.bytecode,
  })
  const receipt = await publicClient.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new Error('the deployment transaction reverted')

  return { address: receipt.contractAddress, txHash: hash, blockNumber: Number(receipt.blockNumber) }
}

export async function estimateDeployCost() {
  const artifact = await loadArtifact()
  const gas = await publicClient.estimateGas({
    account: '0x0000000000000000000000000000000000000001',
    data: artifact.bytecode,
  })
  const price = await publicClient.getGasPrice()
  const wei = gas * price
  // Deployment is one transaction, but the deployer also sponsors subname
  // mints, so the suggested float is deliberately larger than the bare cost.
  return { gas: gas.toString(), wei: wei.toString(), eth: formatEther(wei), suggested: formatEther(wei * 20n) }
}

/** Wei to a readable ETH string, for messages about shortfalls. */
export function formatWei(wei) {
  return formatEther(wei)
}

export { toHex }
