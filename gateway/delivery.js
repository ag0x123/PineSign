/**
 * The gateway's side of a delivery: carry signed actions, decide nothing.
 *
 * Everything that matters is settled by the contract. This module submits
 * transactions and reads state back, and it is deliberately incapable of the
 * three things that would make it an authority:
 *
 *   - It cannot accept on a recipient's behalf. An acceptance is a passkey
 *     assertion the contract verifies against a frozen credential.
 *   - It cannot release. A release needs the releaser's signature, and the
 *     sender's key half is sealed under the sender's own key — this module
 *     stores that blob and cannot open it.
 *   - It cannot report an outcome of its own. `stateOf` reads the contract.
 *
 * What it can do is refuse to relay, which is an availability problem and not
 * an authority one: another relayer, or the user's own wallet, submits the same
 * signed action and the contract reaches the same conclusion.
 */

import { createWalletClient, createPublicClient, http } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { sepolia } from 'viem/chains'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { RPC_URL } from './chain.js'
import * as setup from './setup.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

/** Where the delivery contract lives. Per deployment, so it comes from .env. */
export const ADDRESS = process.env.DELIVERY_ADDRESS ?? null

export const configured = Boolean(ADDRESS)

export const STATES = ['None', 'Sent', 'Accepted', 'Released', 'Expired', 'SenderAborted']

let abiCache = null

async function abi() {
  abiCache ??= JSON.parse(
    await readFile(path.join(__dirname, 'abi', 'pinesign-delivery.json'), 'utf8'),
  ).abi
  return abiCache
}

function requireAddress() {
  if (!ADDRESS) throw new Error('DELIVERY_ADDRESS is not set — see .env.example')
  return ADDRESS
}

const client = () => createPublicClient({ chain: sepolia, transport: http(RPC_URL) })

async function relayer() {
  const key = await setup.deployerKey()
  if (!key) throw new Error('this gateway has no key to relay with — run setup first')
  return createWalletClient({
    account: privateKeyToAccount(key),
    chain: sepolia,
    transport: http(RPC_URL),
  })
}

// ---- reads ----

/** The delivery as the contract holds it. The only account that counts. */
export async function get(id) {
  const record = await client().readContract({
    address: requireAddress(),
    abi: await abi(),
    functionName: 'get',
    args: [id],
  })
  return { ...record, state: STATES[record.state] }
}

export async function stateOf(id) {
  return STATES[
    await client().readContract({
      address: requireAddress(),
      abi: await abi(),
      functionName: 'stateOf',
      args: [id],
    })
  ]
}

export async function acceptDigest(id) {
  return client().readContract({
    address: requireAddress(),
    abi: await abi(),
    functionName: 'acceptDigest',
    args: [id],
  })
}

export async function releaseDigest(id, releasedKey) {
  return client().readContract({
    address: requireAddress(),
    abi: await abi(),
    functionName: 'releaseDigest',
    args: [id, releasedKey],
  })
}

// ---- writes, all of them relaying something somebody else authorised ----

/**
 * Simulate before sending.
 *
 * A reverted transaction still costs the gateway gas, and a caller who gets
 * "it reverted" learns nothing. Simulating first means the contract's own
 * error name comes back and nothing is spent on a request that was never
 * going to work.
 */
async function send(functionName, args) {
  const wallet = await relayer()
  const contract = { address: requireAddress(), abi: await abi() }

  try {
    await client().simulateContract({ ...contract, functionName, args, account: wallet.account })
  } catch (err) {
    throw new Error(reason(err) ?? err.shortMessage ?? err.message)
  }

  const hash = await wallet.writeContract({ ...contract, functionName, args })
  const receipt = await client().waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new Error(`${functionName} reverted on chain (${hash})`)
  return { tx: hash, gasUsed: receipt.gasUsed.toString() }
}

/** The contract's own error name, wherever viem put it. */
function reason(err) {
  for (let e = err; e; e = e.cause) {
    if (e.data?.errorName) return e.data.errorName
    if (e.errorName) return e.errorName
  }
  return null
}

export function sendDelivery(params) {
  return send('send', [params])
}

/** Carry a recipient's acceptance. The contract verifies the passkey, not us. */
export function relayAccept(id, assertion) {
  return send('accept', [id, assertion])
}

/** Carry a releaser's authorisation. We hold no half and sign nothing. */
export function relayRelease(id, releasedKey, signature) {
  return send('releaseSigned', [id, releasedKey, signature])
}

/** Put a lapse on the record. Open to anyone, including us. */
export function relayExpire(id) {
  return send('expire', [id])
}
