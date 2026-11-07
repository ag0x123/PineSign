/**
 * The delivery transaction: one EIP-8141 frame transaction, and the only thing
 * that ever hands Bob his file key.
 *
 * Two frames. The first is a VERIFY frame whose target is Bob's account: it
 * checks the RSA-2048 DKIM signature on the reply he sent and approves nothing
 * else. The second is the release, which writes the sealed key and the Swarm
 * reference. If the first frame reverts the second never runs, so there is no
 * state in which a key exists without a verified email behind it.
 *
 * Nothing here signs anything. The account's authority is the DKIM signature in
 * frame data, so the transaction carries no signatures at all — which is also
 * why it cannot be replayed into a different release: the account checks that
 * the next frame releases the accept its own signature covers.
 *
 * The whole validation prefix must fit MAX_VERIFY_GAS = 100,000. Measured in
 * the spikes: 61,330 for the DKIM check, 7,093 for the paymaster. The budgets
 * below are set from those numbers, not guessed.
 */

import * as tx from '@forshtat/hegota-support/tx'
import { getProfile } from '@forshtat/hegota-support/profiles'
import { encodeAbiParameters, encodeFunctionData, decodeFunctionResult, keccak256, toHex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

/** The devnet profile the account contracts were compiled against. */
export const profile = getProfile(process.env.FRAME_PROFILE ?? 'ethrex-eip8141-tracer')

export const RPC = process.env.FRAME_RPC ?? null
export const CHAIN_ID = process.env.FRAME_CHAIN_ID ? Number(process.env.FRAME_CHAIN_ID) : null
const MAX_FEE_WEI = BigInt(process.env.FRAME_MAX_FEE_WEI ?? 2_000_000_000n)

/** Deployed by scripts/frame-deploy.mjs; a gateway without them cannot release. */
export const RELEASE_ADDRESS = process.env.PINESIGN_RELEASE_ADDRESS ?? null
export const PAYMASTER_ADDRESS = process.env.PINESIGN_PAYMASTER_ADDRESS ?? null

// Gas for the validation prefix, which is capped at MAX_VERIFY_GAS = 100,000
// for the whole prefix — these are budgets, and it is their sum that is
// checked, so a generous number here is not caution but the thing that gets the
// transaction rejected. Measured: 55,567 for the DKIM check over short headers
// and 61,330 over real ones, 22,614 for the paymaster. 96,000 leaves room for
// longer headers without reaching the cap.
//
// Too small is just as fatal and much harder to read: a frame that runs out of
// gas reverts, and the node reports only "validation prefix frame reverted".
// The first verifying paymaster was given 15,000 and looked like a broken
// signature for a while.
const VERIFY_GAS = BigInt(process.env.FRAME_VERIFY_GAS ?? 68_000)
const PAYMASTER_GAS = BigInt(process.env.FRAME_PAYMASTER_GAS ?? 28_000)
const EXECUTION_GAS = BigInt(process.env.FRAME_EXECUTION_GAS ?? 500_000)

export function configured() {
  return Boolean(RPC && CHAIN_ID && RELEASE_ADDRESS)
}

/**
 * The key that says "Pinesign will pay for this one".
 *
 * The paymaster checks a signature rather than reading a credit balance,
 * because validation may not read another account's storage. So the free-send
 * allowance is enforced here, by declining to sign, and the signature is what
 * stops anyone else from spending the paymaster's funds.
 */
export const sponsorAccount = process.env.PINESIGN_SPONSOR_KEY
  ? privateKeyToAccount(process.env.PINESIGN_SPONSOR_KEY)
  : null

export const SPONSOR_ADDRESS = sponsorAccount?.address ?? null

async function sponsorship({ account, nonce }) {
  if (!sponsorAccount) throw new Error('PINESIGN_SPONSOR_KEY is not set')
  const digest = keccak256(
    encodeAbiParameters(
      [{ type: 'uint256' }, { type: 'address' }, { type: 'address' }, { type: 'uint256' }],
      [BigInt(CHAIN_ID), PAYMASTER_ADDRESS, account, nonce]
    )
  )
  // Signed as a raw digest, not an EIP-191 message: the contract hashes the
  // same four values and calls ecrecover on exactly this.
  return sponsorAccount.sign({ hash: digest })
}

let id = 0

export async function rpc(method, params = []) {
  if (!RPC) throw new Error('FRAME_RPC is not set')
  const response = await fetch(RPC, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }),
  })
  const body = await response.json()
  if (body.error) throw new Error(`${method}: ${body.error.message ?? JSON.stringify(body.error)}`)
  return body.result
}

const artifacts = new Map()

/** Foundry's output, read straight from contracts/out rather than copied by hand. */
export async function artifact(name) {
  if (!artifacts.has(name)) {
    const file = path.join(__dirname, '..', 'contracts', 'out', `${name}.sol`, `${name}.json`)
    artifacts.set(name, JSON.parse(await readFile(file, 'utf8')))
  }
  return artifacts.get(name)
}

export async function nonceOf(address) {
  return BigInt(await rpc('eth_getTransactionCount', [address, 'latest']))
}

/**
 * Bob's account address for a given DKIM key and release contract.
 *
 * One account per signing key, not per delivery: the account is only ever
 * authority to release the accept its own signature names, so sharing it
 * between deliveries gives nothing away and saves a deployment each time.
 */
export async function accountFor({ modulus }) {
  const { abi, bytecode } = await artifact('DkimWallet')
  return { abi, bytecode: bytecode.object, modulusHash: keccak256(toHex(modulus)) }
}

/**
 * Builds and submits the release.
 *
 * Submitted with eth_sendRawTransaction, not eth_sendFrameTransaction: the
 * spikes found the standard alt-mempool accepts frame transactions and then
 * never builds them, while the canonical mempool mines the identical bytes in
 * seconds. The DKIM check fits under MAX_VERIFY_GAS, so it does not need the
 * alt mempool's allowances in the first place.
 */
export async function release({ account, acceptHash, encryptedKey, swarmRef, dkim, sponsored = true }) {
  if (!configured()) throw new Error('the frame devnet is not configured on this server')

  const releaseAbi = (await artifact('PineSignRelease')).abi
  const data = encodeFunctionData({
    abi: releaseAbi,
    functionName: 'release',
    args: [acceptHash, encryptedKey, swarmRef],
  })

  const verifyData = encodeAbiParameters(
    [{ type: 'bytes' }, { type: 'bytes' }, { type: 'bytes' }],
    [dkim.modulus, dkim.signature, dkim.signedHeaders]
  )

  const frames = [
    tx.frame(profile, 'VERIFY', {
      scope: sponsored ? 'EXECUTION' : 'EXECUTION_AND_PAYMENT',
      target: null,
      execution: VERIFY_GAS,
      state: 0n,
      data: verifyData,
    }),
  ]
  if (sponsored) {
    if (!PAYMASTER_ADDRESS) throw new Error('PINESIGN_PAYMASTER_ADDRESS is not set')
    frames.push(
      tx.frame(profile, 'VERIFY', {
        scope: 'PAYMENT',
        target: PAYMASTER_ADDRESS,
        execution: PAYMASTER_GAS,
        state: 0n,
        data: '0x',
      })
    )
  }
  frames.push(
    tx.frame(profile, 'SENDER', {
      target: RELEASE_ADDRESS,
      execution: EXECUTION_GAS,
      state: EXECUTION_GAS,
      data,
    })
  )

  const nonce = await nonceOf(account)
  if (sponsored) {
    frames[1] = tx.frame(profile, 'VERIFY', {
      scope: 'PAYMENT',
      target: PAYMASTER_ADDRESS,
      execution: PAYMASTER_GAS,
      state: 0n,
      data: await sponsorship({ account, nonce }),
    })
  }

  const built = tx.newTx({
    chainId: CHAIN_ID,
    sender: account,
    nonceSeq: nonce,
    frames,
    signatures: [],
    fees: { maxFeePerGas: MAX_FEE_WEI },
  })

  const hash = await rpc('eth_sendRawTransaction', [tx.encodeTx(profile, built)])
  return { hash, sigHash: tx.sigHash(profile, built) }
}

export async function waitForReceipt(hash, { attempts = 60, intervalMs = 1000 } = {}) {
  for (let i = 0; i < attempts; i++) {
    const receipt = await rpc('eth_getTransactionReceipt', [hash])
    if (receipt) {
      const frames = (receipt.frameReceipts ?? []).map((f) => ({
        status: f.status,
        gasUsed: Number(f.gasUsed ?? 0),
      }))
      return {
        block: Number(receipt.blockNumber),
        status: receipt.status,
        gasUsed: Number(receipt.gasUsed ?? 0),
        frames,
        ok: receipt.status === '0x1' && frames.every((f) => f.status === '0x1'),
      }
    }
    await new Promise((r) => setTimeout(r, intervalMs))
  }
  throw new Error(`no receipt for ${hash} after ${attempts} attempts`)
}

/** What Bob reads. A row that is not there is not an error: it means not yet released. */
export async function getRelease(acceptHash) {
  const abi = (await artifact('PineSignRelease')).abi
  const result = await rpc('eth_call', [
    { to: RELEASE_ADDRESS, data: encodeFunctionData({ abi, functionName: 'get', args: [acceptHash] }) },
    'latest',
  ])
  const [encryptedKey, swarmRef, blockNumber] = decodeFunctionResult({ abi, functionName: 'get', data: result })
  return Number(blockNumber) === 0 ? null : { encryptedKey, swarmRef, blockNumber: Number(blockNumber) }
}

/** For the health endpoint and the "Devnet: up/down" badge. */
export async function status() {
  if (!RPC) return { configured: false }
  try {
    const [chainId, block] = await Promise.all([rpc('eth_chainId'), rpc('eth_blockNumber')])
    return {
      configured: configured(),
      rpc: RPC,
      chainId: Number(chainId),
      chainIdMatches: CHAIN_ID === null || Number(chainId) === CHAIN_ID,
      block: Number(block),
      release: RELEASE_ADDRESS,
      paymaster: PAYMASTER_ADDRESS,
      up: true,
    }
  } catch (error) {
    return { configured: configured(), rpc: RPC, up: false, error: error.message }
  }
}
