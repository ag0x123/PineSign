/**
 * Deploys the account for one DKIM signing key.
 *
 *   node scripts/frame-account.mjs 0x<modulus hex>
 *
 * One account per signing key, not per delivery: the account only ever
 * authorises the release whose accept hash its own signature covers, so sharing
 * it between deliveries gives nothing away. A provider that rotates its
 * selector needs a new one, which is the operational catch worth knowing.
 */

import '../gateway/env.js'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { createWalletClient, createPublicClient, http, defineChain, encodeDeployData, keccak256 } from 'viem'
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts'
import * as frame from '../gateway/frame.js'
import { storagePath } from '../gateway/paths.js'

const STATE = storagePath('frame.json')

async function state() {
  try {
    return JSON.parse(await readFile(STATE, 'utf8'))
  } catch {
    return {}
  }
}

export async function deployAccount(modulus) {
  if (!frame.RELEASE_ADDRESS) throw new Error('PINESIGN_RELEASE_ADDRESS is not set')
  const modulusHash = keccak256('0x' + Buffer.from(modulus).toString('hex'))

  const chainId = Number(await frame.rpc('eth_chainId'))
  const chain = defineChain({
    id: chainId,
    name: 'frame-devnet',
    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: [frame.RPC] } },
  })
  const read = createPublicClient({ chain, transport: http(frame.RPC) })

  const current = await state()
  const known = current.accounts?.[modulusHash]
  if (known && (await read.getCode({ address: known })) !== undefined) return known

  // The same throwaway deployer the rest of the devnet work uses, funded by the
  // devnet's own faucet so no real key is involved.
  const deployerKey = current.deployerKey ?? generatePrivateKey()
  const deployer = privateKeyToAccount(deployerKey)
  const wallet = createWalletClient({ account: deployer, chain, transport: http(frame.RPC) })

  if ((await read.getBalance({ address: deployer.address })) < 10n ** 16n) {
    await frame.rpc('skandha_explorer_faucet', [deployer.address])
    for (let i = 0; i < 30; i++) {
      if ((await read.getBalance({ address: deployer.address })) > 0n) break
      await new Promise((r) => setTimeout(r, 1000))
    }
  }

  const { abi, bytecode } = await frame.artifact('DkimWallet')
  const hash = await wallet.sendTransaction({
    to: null,
    data: encodeDeployData({ abi, bytecode: bytecode.object, args: [modulusHash, frame.RELEASE_ADDRESS] }),
    gas: BigInt(process.env.FRAME_DEPLOY_GAS ?? 15_000_000),
    type: 'legacy',
  })
  const receipt = await read.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success' || !receipt.contractAddress) {
    throw new Error(`account deployment reverted (gas used ${receipt.gasUsed})`)
  }

  await mkdir(storagePath(), { recursive: true })
  await writeFile(
    STATE,
    JSON.stringify(
      { ...current, chainId, deployerKey, accounts: { ...(current.accounts ?? {}), [modulusHash]: receipt.contractAddress } },
      null,
      2
    )
  )
  return receipt.contractAddress
}

if (process.argv[1]?.endsWith('frame-account.mjs')) {
  const arg = process.argv[2]
  if (!arg) {
    console.error('usage: node scripts/frame-account.mjs 0x<modulus hex>')
    process.exit(1)
  }
  const modulus = Uint8Array.from(Buffer.from(arg.replace(/^0x/, ''), 'hex'))
  console.log(await deployAccount(modulus))
}
