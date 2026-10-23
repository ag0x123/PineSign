/**
 * First-run setup.
 *
 * A fresh server knows nothing: which name it issues subnames under, which key
 * pays for them, where the receipt contract lives. The admin supplies the first,
 * the server generates the second, and the third follows once there is gas.
 *
 * The deployer key is generated here and never leaves the box. It is written to
 * .storage/, which is not in the repository — if it were, every clone of this
 * project would share a wallet.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { randomBytes } from 'node:crypto'
import path from 'node:path'
import { privateKeyToAccount } from 'viem/accounts'
import * as chain from './chain.js'
import * as bee from './bee.js'
import * as ens from './ens.js'
import { backupDeployer, BACKUP_DIR } from './backup.js'
import * as admin from './admin.js'
import { storagePath } from './paths.js'

const FILE = storagePath('config.json')

/**
 * The admin token.
 *
 * Persisted rather than regenerated, because this is the only way back into the
 * admin panel — a token that changed on every restart would lock the operator
 * out of their own server. SETUP_TOKEN in the environment overrides it.
 */
let setupToken = null

export async function getSetupToken() {
  if (setupToken) return setupToken
  if (process.env.SETUP_TOKEN) {
    setupToken = process.env.SETUP_TOKEN
    return setupToken
  }
  const c = await load()
  if (!c.setupToken) {
    c.setupToken = randomBytes(16).toString('hex')
    await persist()
  }
  setupToken = c.setupToken
  return setupToken
}

let config = null

async function load() {
  if (config) return config
  try {
    config = JSON.parse(await readFile(FILE, 'utf8'))
  } catch (err) {
    // A file that exists but will not parse is a problem to report, not to
    // paper over: persisting defaults on top of it would destroy the key.
    if (err.code !== 'ENOENT') {
      throw new Error(`${FILE} exists but could not be read: ${err.message}`)
    }
    config = {
      parentName: null,
      deployer: null,
      receiptsAddress: null,
      deployTx: null,
      nameRegistered: false,
      postageBatchId: null,
      adminAddress: null,
    }
  }
  return config
}

async function persist() {
  await mkdir(path.dirname(FILE), { recursive: true })
  await writeFile(FILE, JSON.stringify(config, null, 2), { mode: 0o600 })
}

export async function get() {
  return load()
}

export { BACKUP_DIR }

export async function parentName() {
  return (await load()).parentName
}

export async function receiptsAddress() {
  return (await load()).receiptsAddress
}

/**
 * Where setup has got to. The page renders this and nothing else, so the server
 * stays the single source of truth about its own state.
 */
export async function status() {
  const c = await load()
  // The funding step is not finished until both things it pays for exist.
  // Deploying the contract alone used to advance the flow, quietly leaving the
  // server without the name every user's subname hangs from.
  const step = !c.parentName
    ? 'name'
    : !c.deployer
      ? 'keys'
      : !c.receiptsAddress || !c.nameRegistered || !c.resolver
        ? 'fund'
        : !c.postageBatchId
          ? 'swarm'
          : 'ready'

  const out = {
    step,
    parentName: c.parentName,
    deployer: c.deployer?.address ?? null,
    receiptsAddress: c.receiptsAddress,
    deployTx: c.deployTx,
    rpcUrl: chain.RPC_URL,
    balance: null,
    cost: null,
    fundedEnough: false,
  }

  // The balance and the budget are shown from the moment a key exists, so an
  // admin can see what they are funding before they send anything.
  if (c.deployer) {
    const label = c.parentName?.replace(/\.eth$/, '') ?? null
    // The balance is read first so packages can be quoted as a top-up.
    const balance = await chain.balanceOf(c.deployer.address).catch(() => null)
    const budget = await chain.budget(label, BigInt(balance?.wei ?? 0)).catch(() => null)
    out.balance = balance
    out.budget = budget

    if (!c.receiptsAddress && balance && budget) {
      // Enough for the deployment, with room left over to sponsor users.
      const needed = BigInt(budget.deploy.wei) * 2n
      out.fundedEnough = BigInt(balance.wei) > needed
    }

    // Under ENSv2 the fee is paid in a token the server mints, so registering
    // costs only gas — four transactions of it. The check is therefore against
    // the gas estimate, not against a price in ether.
    if (balance && budget) {
      const needed = (BigInt(budget.registrationGas.wei) * 150n) / 100n
      out.canRegisterName = BigInt(balance.wei) >= needed
      out.registrationShortfall = out.canRegisterName
        ? null
        : chain.formatWei(needed - BigInt(balance.wei))
    }
  }

  if (c.parentName && !c.nameRegistered) {
    const label = c.parentName.replace(/\.eth$/, '')
    const [available, registrar, price] = await Promise.all([
      ens.isAvailable(label).catch(() => null),
      ens.health(),
      ens.registerPrice(label, 31536000).catch(() => null),
    ])
    out.nameAvailable = available
    out.registrationAvailable = registrar.available
    out.registrationBlockedReason = registrar.reason
    // Priced in a token, not in ether — so the name itself costs no ETH.
    out.registrationFee = price ? `${Number(price.formatted).toFixed(2)} ${price.symbol}` : null
  }
  out.nameRegistered = Boolean(c.nameRegistered)
  out.resolver = c.resolver?.address ?? null
  out.canAttachResolver = Boolean(c.nameRegistered && c.nameRegistration?.tokenId && !c.resolver)
  if (out.canAttachResolver && out.balance && out.budget?.resolverGas) {
    const needed = (BigInt(out.budget.resolverGas.wei) * 130n) / 100n
    out.canAffordResolver = BigInt(out.balance.wei) >= needed
    out.resolverShortfall = out.canAffordResolver ? null : chain.formatWei(needed - BigInt(out.balance.wei))
  }
  // Going back is only meaningful while nothing is committed on chain.
  out.canChangeName = !c.nameRegistered
  out.postageBatchId = c.postageBatchId ?? null

  // The node is only worth asking about once there is a server to attach it to.
  if (c.receiptsAddress || c.postageBatchId) {
    out.bee = await bee.overview().catch((err) => ({ reachable: false, error: err.message }))
  }

  return out
}

/**
 * Choose, or change, the name this server issues subnames under.
 *
 * Changeable right up until it is registered on chain — an operator who picked
 * the wrong name should not have to wipe the server to fix it. Once registered
 * it is fixed, because subnames already issued hang beneath it.
 */
export async function chooseName(name) {
  const clean = String(name ?? '').trim().toLowerCase()
  if (!/^[a-z0-9-]{3,}\.eth$/.test(clean)) throw new Error('expected a name like example.eth')

  const c = await load()
  if (c.nameRegistered) {
    throw new Error(`${c.parentName} is already registered on chain and cannot be changed`)
  }

  c.parentName = clean
  await persist()
  return status()
}

/**
 * Generate the deployer. It pays for the contract and, afterwards, for every
 * subname the server issues on a user's behalf — which is what lets users never
 * hold gas.
 */
export async function generateDeployer() {
  const c = await load()
  if (c.deployer) throw new Error('a deployer key already exists')

  const privateKey = `0x${randomBytes(32).toString('hex')}`
  const account = privateKeyToAccount(privateKey)
  c.deployer = { address: account.address, privateKey }
  await persist()

  // Outside .storage, so deleting that directory does not destroy the wallet
  // along with it.
  const backup = await backupDeployer(c.deployer, { parentName: c.parentName })
  console.log(`  deployer key backed up to ${backup}`)

  return status()
}

/**
 * Buy the name this server issues subnames under.
 *
 * Slow on purpose — the registrar enforces a wait between committing and
 * revealing — so the request is held open for the better part of two minutes.
 */
export async function registerName() {
  const c = await load()
  if (!c.parentName) throw new Error('choose a name first')
  if (!c.deployer) throw new Error('generate a deployer key first')
  if (c.nameRegistered) throw new Error('already registered')

  const label = c.parentName.replace(/\.eth$/, '')
  const result = await ens.register(c.deployer.privateKey, label, {
    onStep: (m) => console.log(`  registering ${label}.eth: ${m}`),
  })

  // True whether we just bought it or discovered we already had.
  c.nameRegistered = true
  c.nameRegistration = result
  await persist()

  // The name is only useful once it can carry records. Attach the resolver
  // straight away so every transfer name beneath it resolves.
  if (result.tokenId && result.registry) {
    console.log(`  attaching resolver to ${c.parentName}…`)
    const resolver = await ens.deployResolver(c.deployer.privateKey, {
      registry: result.registry, tokenId: result.tokenId,
    })
    c.resolver = resolver
    await persist()
    console.log(`  resolver at ${resolver.address}`)
  }

  return status()
}

/** For a name registered before resolvers existed: attach one now. */
export async function attachResolver() {
  const c = await load()
  if (!c.nameRegistration?.tokenId) throw new Error('no token id recorded for this name')
  if (c.resolver) throw new Error('a resolver is already attached')
  c.resolver = await ens.deployResolver(c.deployer.privateKey, {
    registry: c.nameRegistration.registry, tokenId: c.nameRegistration.tokenId,
  })
  await persist()
  return status()
}

export async function resolverAddress() {
  return (await load()).resolver?.address ?? null
}

export async function deployerKey() {
  return (await load()).deployer?.privateKey ?? null
}

export async function deploy() {
  const c = await load()
  if (!c.deployer) throw new Error('generate a deployer key first')
  if (c.receiptsAddress) throw new Error('already deployed')

  const result = await chain.deployReceipts(c.deployer.privateKey)
  c.receiptsAddress = result.address
  c.deployTx = result.txHash
  await persist()
  return status()
}

/**
 * Buy postage, and remember the batch.
 *
 * Depth is capacity, amount is lifetime. The defaults are a small batch that
 * comfortably outlives a transfer window — enough to demonstrate the system
 * without committing much BZZ.
 */
export async function buyPostage({ ttlSeconds, depth } = {}) {
  const c = await load()
  // The batch is bought to outlive a transfer window, so a file and the record
  // pointing at it lapse together rather than one outliving the other.
  const { batchID } = await bee.buyStamp({
    ttlSeconds: ttlSeconds ?? Number(process.env.TRANSFER_TTL_MS ?? 259200000) / 1000,
    depth,
  })
  if (!batchID) throw new Error('the node did not return a batch id')

  c.postageBatchId = batchID
  await persist()
  return status()
}

export async function adminAddress() {
  return (await load()).adminAddress
}

/**
 * Claim the server for a wallet.
 *
 * Only possible once, and only by someone already holding the console token —
 * otherwise the first stranger to find an unclaimed server would own it.
 */
export async function claimAdmin(address) {
  const c = await load()
  if (c.adminAddress) throw new Error('this server already has an administrator')
  c.adminAddress = address.toLowerCase()
  await persist()
  return c.adminAddress
}

/**
 * Admin access: a signed-in wallet, or the console token.
 *
 * The token remains valid so an admin who loses their wallet can still get in,
 * and so a fresh server can be claimed in the first place.
 */
export async function requireSetupToken(req, res, next) {
  const c = await load()

  const session = req.get('x-admin-session')
  if (session) {
    const who = admin.sessionAddress(session)
    if (who && (!c.adminAddress || who === c.adminAddress)) {
      req.adminAddress = who
      return next()
    }
  }

  const supplied = req.get('x-setup-token') ?? req.query.token
  if (supplied === (await getSetupToken())) {
    req.viaToken = true
    return next()
  }

  return res.status(401).json({ error: 'admin sign-in required' })
}
