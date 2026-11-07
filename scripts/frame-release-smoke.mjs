/**
 * The delivery transaction, end to end on the frame devnet.
 *
 *   node scripts/frame-release-smoke.mjs
 *
 * Signs a message with an RSA-2048 key the way a mail provider would, deploys
 * an account pinned to that key, sends the release as one frame transaction
 * with no transaction signature at all, and reads the row back. Then tampers
 * with one byte of the DKIM signature and checks the chain refuses it — a pass
 * that only proves the happy path proves nothing about "no proof, no delivery".
 */

import '../gateway/env.js'
import crypto from 'node:crypto'
import { keccak256, toHex, encodeDeployData, createWalletClient, createPublicClient, http, defineChain } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { readFile } from 'node:fs/promises'
import * as frame from '../gateway/frame.js'
import { storagePath } from '../gateway/paths.js'

const hex = (b) => '0x' + Buffer.from(b).toString('hex')
const out = { rpc: frame.RPC }

if (!frame.RPC || !frame.RELEASE_ADDRESS) {
  console.error('set FRAME_RPC and PINESIGN_RELEASE_ADDRESS in .env (run scripts/frame-deploy.mjs first)')
  process.exit(1)
}

// --- a provider's signing key, and the headers it signs
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
const modulus = publicKey.export({ format: 'jwk' }).n
const modulusBytes = Buffer.from(modulus, 'base64url')
const signedHeaders = Buffer.from(
  'dkim-signature:v=1; a=rsa-sha256; d=gmail.com; s=20230601;\r\nfrom:bob@gmail.com\r\n'
)
const signature = crypto.sign('sha256', signedHeaders, privateKey)
out.modulusBytes = modulusBytes.length
out.signatureBytes = signature.length

// The accept hash is the hash of the headers the provider signed: the account
// checks exactly this, so the release and the email cannot drift apart.
const acceptHash = keccak256(hex(signedHeaders))
const modulusHash = keccak256(hex(modulusBytes))
out.acceptHash = acceptHash

// --- an account pinned to that key
const chainId = Number(await frame.rpc('eth_chainId'))
const chain = defineChain({
  id: chainId,
  name: 'frame-devnet',
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: { default: { http: [frame.RPC] } },
})
const read = createPublicClient({ chain, transport: http(frame.RPC) })
const { deployerKey } = JSON.parse(await readFile(storagePath('frame.json'), 'utf8'))
const payer = createWalletClient({ account: privateKeyToAccount(deployerKey), chain, transport: http(frame.RPC) })

const { abi, bytecode } = await frame.artifact('DkimWallet')
const deployHash = await payer.sendTransaction({
  to: null,
  data: encodeDeployData({ abi, bytecode: bytecode.object, args: [modulusHash, frame.RELEASE_ADDRESS] }),
  gas: BigInt(process.env.FRAME_DEPLOY_GAS ?? 15_000_000),
  type: 'legacy',
})
const account = (await read.waitForTransactionReceipt({ hash: deployHash })).contractAddress
out.account = account

// --- the release
const encryptedKey = hex(crypto.randomBytes(48))
const swarmRef = keccak256(toHex('pinesign/mumbai/swarm-ref'))

const send = async (sig) =>
  frame.release({
    account,
    acceptHash,
    encryptedKey,
    swarmRef,
    dkim: { modulus: hex(modulusBytes), signature: hex(sig), signedHeaders: hex(signedHeaders) },
  })

const { hash } = await send(signature)
const receipt = await frame.waitForReceipt(hash)
out.release = { hash, ...receipt }
out.verifyGas = receipt.frames[0]?.gasUsed ?? null
out.underVerifyCap = out.verifyGas !== null && out.verifyGas < 100_000

const row = await frame.getRelease(acceptHash)
out.readBack = row && { swarmRef: row.swarmRef, blockNumber: row.blockNumber, keyBytes: (row.encryptedKey.length - 2) / 2 }
out.keyIdentical = row?.encryptedKey === encryptedKey
out.swarmRefIdentical = row?.swarmRef === swarmRef

// --- and the negative: one bit of the signature flipped
const tampered = Buffer.from(signature)
tampered[200] ^= 1
try {
  const bad = await send(tampered)
  const badReceipt = await frame.waitForReceipt(bad.hash, { attempts: 20 })
  out.tamperedRefused = !badReceipt.ok
  out.tamperedOutcome = `mined, frames ok=${badReceipt.ok}`
} catch (error) {
  out.tamperedRefused = true
  out.tamperedOutcome = error.message.slice(0, 160)
}

out.PASS = Boolean(receipt.ok && out.keyIdentical && out.swarmRefIdentical && out.underVerifyCap && out.tamperedRefused)
console.log(JSON.stringify(out, null, 2))
process.exit(out.PASS ? 0 : 1)
