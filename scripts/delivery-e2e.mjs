/**
 * One delivery, end to end, against Sepolia.
 *
 * Two people with separate passkeys and separate derived keys: Alice sends a
 * file, Bob reads the description, accepts with his passkey, and opens the
 * file only after Alice releases her half. Every component is the real one —
 * the gateway, the contract, the P-256 precompile, Swarm, the email codes.
 *
 * What is stood in for, and only this: the authenticator tap. A script cannot
 * drive a security key or a password manager, so each person gets a software
 * P-256 key that signs exactly what an authenticator signs. From the
 * contract's side and the gateway's side there is no difference; what is NOT
 * covered is the browser, the popup boundary and whether a given passkey
 * provider returns a stable PRF output. Those need hands and are in
 * docs/TESTING.md.
 *
 *   node scripts/delivery-e2e.mjs
 */

import '../gateway/env.js'
import { createWalletClient, createPublicClient, http, toHex, keccak256 } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { sepolia } from 'viem/chains'
import { spawn } from 'node:child_process'
import { readFile, rm, mkdir } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { p256 } from '@noble/curves/p256'
import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 as nobleSha256 } from '@noble/hashes/sha256'
import * as keysplit from '../shared/keysplit.js'
import { sign as signSecp, toHex as hex, fromHex, addressFrom, signRecoverable } from '../shared/crypto.js'
import * as setup from '../gateway/setup.js'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const sha256 = (b) => createHash('sha256').update(b).digest()
const RPC = process.env.RPC_URL ?? 'https://ethereum-sepolia-rpc.publicnode.com'

const RP_ID = 'id.e2e.local'
const ORIGIN = 'https://v1.id.e2e.local'
const PORT = 8795
const BASE = `http://localhost:${PORT}`
const STORAGE = '.storage-e2e'
const LOG = `${STORAGE}/gateway.log`

let step = 0
const say = (m) => console.log(`\n${++step}. ${m}`)
const ok = (m) => console.log(`   ok   ${m}`)
let server = null

/**
 * Always take the gateway down with us.
 *
 * An earlier version only killed it on the paths it knew about, so a crash
 * left a gateway holding the port and the next run failed with "other side
 * closed" — a confusing symptom of a previous run's unrelated bug.
 */
function stopServer() {
  server?.kill()
  server = null
}
process.on('exit', stopServer)
process.on('uncaughtException', (err) => {
  stopServer()
  console.error(err)
  process.exit(1)
})
process.on('unhandledRejection', (err) => {
  stopServer()
  console.error(err)
  process.exit(1)
})
process.on('SIGINT', () => {
  stopServer()
  process.exit(130)
})

const fail = (m) => {
  console.error(`\nFAILED: ${m}`)
  stopServer()
  process.exit(1)
}

// ---- a stand-in authenticator, one per person ----

const SPKI_PREFIX = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex')
const b64url = (b) => Buffer.from(b).toString('base64url')

function authenticator() {
  const secret = p256.utils.randomPrivateKey()
  const point = Buffer.from(p256.getPublicKey(secret, false))
  let count = 0

  const authData = () => {
    const buf = Buffer.alloc(37)
    sha256(Buffer.from(RP_ID, 'utf8')).copy(buf, 0)
    buf[32] = 0x05 // user present + user verified
    buf.writeUInt32BE(++count, 33)
    return buf
  }

  return {
    credentialPublicKey: b64url(Buffer.concat([SPKI_PREFIX, point])),
    x: toHex(point.subarray(1, 33)),
    y: toHex(point.subarray(33, 65)),
    /** What the gateway's sign-in endpoint takes. */
    assertForGateway(challenge) {
      const ad = authData()
      const cd = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: ORIGIN, crossOrigin: false }))
      const sig = p256.sign(sha256(Buffer.concat([ad, sha256(cd)])), secret)
      return {
        credentialPublicKey: this.credentialPublicKey,
        clientDataJSON: b64url(cd),
        authenticatorData: b64url(ad),
        signature: b64url(sig.toDERRawBytes()),
      }
    },
    /** What the contract takes, with the offsets it needs. */
    assertForContract(digest) {
      const ad = authData()
      const challenge = Buffer.from(digest.slice(2), 'hex').toString('base64url')
      const cd = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: ORIGIN, crossOrigin: false }))
      const json = cd.toString()
      const sig = p256.sign(sha256(Buffer.concat([ad, sha256(cd)])), secret)
      const raw = Buffer.from(sig.toCompactRawBytes())
      return {
        authenticatorData: toHex(ad),
        clientDataJSON: toHex(cd),
        // Plain numbers, as the browser sends them: these cross HTTP as JSON
        // and a BigInt cannot be serialised.
        typeIndex: json.indexOf('"type":"webauthn.get"'),
        challengeIndex: json.indexOf('"challenge":"'),
        originIndex: json.indexOf('"origin":"'),
        r: toHex(raw.subarray(0, 32)),
        s: toHex(raw.subarray(32, 64)),
      }
    },
  }
}

// ---- http helpers ----

async function api(route, body) {
  const res = await fetch(BASE + route, {
    method: body ? 'POST' : 'GET',
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  })
  const json = await res.json().catch(() => ({}))
  return { status: res.status, body: json }
}

const must = async (route, body, what) => {
  const { status, body: out } = await api(route, body)
  if (status !== 200) fail(`${what}: ${out.error ?? status}`)
  return out
}

/**
 * The emailed code, read off the gateway's own output.
 *
 * With no Resend key the gateway prints the message it would have sent, which
 * is what a developer sees locally. Taken from the pipe rather than from a log
 * file: a write stream buffers, so the line was sometimes still in memory when
 * this went looking for it and the run failed for no real reason.
 */
let gatewayOutput = ''

async function codeFromLog() {
  for (let i = 0; i < 100; i++) {
    const codes = [...gatewayOutput.matchAll(/Your sign-in code is (\d{6})/g)]
    if (codes.length > seenCodes) {
      seenCodes = codes.length
      return codes.at(-1)[1]
    }
    await new Promise((r) => setTimeout(r, 100))
  }
  fail('no sign-in code reached the gateway output')
}

/** How many codes have already been consumed, so two sign-ins do not collide. */
let seenCodes = 0

/** A signed nonce, which is how the gateway knows who is asking. */
async function authAs(person) {
  const { nonce } = await must('/api/nonce', { pubKey: person.pubKey }, 'nonce')
  return {
    pubKey: person.pubKey,
    nonce,
    signature: hex(signSecp(nobleSha256(new TextEncoder().encode(nonce)), person.secret)),
  }
}

// ---- deploy ----

const key = process.env.DELIVERY_DEPLOYER_KEY ?? (await setup.deployerKey())
if (!key) fail('no deployer key: set DELIVERY_DEPLOYER_KEY or run setup')
const account = privateKeyToAccount(key)
const wallet = createWalletClient({ account, chain: sepolia, transport: http(RPC) })
const chain = createPublicClient({ chain: sepolia, transport: http(RPC) })

say(`Relayer ${account.address}`)
console.log(`   balance ${Number(await chain.getBalance({ address: account.address })) / 1e18} ETH`)

const deliveryArtifact = JSON.parse(
  await readFile(path.join(ROOT, 'contracts/out/PineSignDelivery.sol/PineSignDelivery.json'), 'utf8'),
)
const webauthnArtifact = JSON.parse(
  await readFile(path.join(ROOT, 'contracts/out/WebAuthn.sol/WebAuthn.json'), 'utf8'),
)

function link(bytecode, references, address) {
  let out = bytecode
  for (const file of Object.values(references ?? {})) {
    for (const positions of Object.values(file)) {
      for (const { start, length } of positions) {
        out = out.slice(0, 2 + start * 2) + address.slice(2).toLowerCase() + out.slice(2 + (start + length) * 2)
      }
    }
  }
  if (out.includes('__$')) fail('bytecode still has an unlinked placeholder')
  return out
}

say('Deploying')
const libHash = await wallet.deployContract({ abi: webauthnArtifact.abi, bytecode: webauthnArtifact.bytecode.object })
const lib = await chain.waitForTransactionReceipt({ hash: libHash })
if (lib.status !== 'success') fail('library deployment reverted')

const contractHash = await wallet.deployContract({
  abi: deliveryArtifact.abi,
  bytecode: link(deliveryArtifact.bytecode.object, deliveryArtifact.bytecode.linkReferences, lib.contractAddress),
  args: [toHex(sha256(Buffer.from(RP_ID, 'utf8'))), [keccak256(Buffer.from(ORIGIN, 'utf8'))]],
})
const deployed = await chain.waitForTransactionReceipt({ hash: contractHash })
if (deployed.status !== 'success') fail('contract deployment reverted')
ok(`delivery contract ${deployed.contractAddress}`)

// ---- the gateway ----

await rm(path.join(ROOT, STORAGE), { recursive: true, force: true })
await mkdir(path.join(ROOT, STORAGE), { recursive: true })

say('Starting a gateway against it')
const logStream = (await import('node:fs')).createWriteStream(path.join(ROOT, LOG))
server = spawn('node', ['gateway/server.js'], {
  cwd: ROOT,
  env: {
    ...process.env,
    PINESIGN_SKIP_ENV_FILE: '1',
    PINESIGN_STORAGE_DIR: STORAGE,
    PORT: String(PORT),
    PASSKEY_RP_ID: RP_ID,
    SIGNIN_ORIGINS: ORIGIN,
    PINESIGN_PARENT: 'e2e.eth',
    DELIVERY_ADDRESS: deployed.contractAddress,
    // The gateway relays, so it needs the funded key. In a real deployment
    // this is its own wallet with its own budget.
    RELAYER_PRIVATE_KEY: key,
    RATE_AUTH_PER_MIN: '1000',
    RATE_SEND_PER_MIN: '1000',
    RATE_CODE_PER_MIN: '1000',
  },
  stdio: ['ignore', 'pipe', 'pipe'],
})
for (const stream of [server.stdout, server.stderr]) {
  stream.pipe(logStream) // kept on disk for a failed run to be read afterwards
  stream.on('data', (chunk) => {
    gatewayOutput += chunk
  })
}

// It is not enough for the port to answer once: wait until it answers twice
// in a row, so a half-started process is not mistaken for a ready one.
let healthy = 0
for (let i = 0; i < 150; i++) {
  if (server === null || server.exitCode !== null) {
    fail(`the gateway exited (${server?.exitCode}). Its output:\n${gatewayOutput}`)
  }
  const up = await fetch(`${BASE}/api/health`).then((r) => r.ok).catch(() => false)
  if (up && ++healthy >= 2) break
  if (!up) healthy = 0
  await new Promise((r) => setTimeout(r, 200))
}
if (healthy < 2) fail(`the gateway never came up. Its output:\n${gatewayOutput}`)
ok(`gateway on ${BASE}`)

// ---- two people ----

async function signIn(label, email) {
  const auth = authenticator()
  const secret = secp256k1.utils.randomPrivateKey()
  const pubKey = hex(secp256k1.getPublicKey(secret, true))

  const { sessionId } = await must('/api/signin/code', { email }, `${label}: code`)
  const code = await codeFromLog()
  const verified = await must('/api/signin/verify', { sessionId, code }, `${label}: verify`)
  const finished = await must(
    '/api/signin/finish',
    { sessionId, pubKey, created: true, ...auth.assertForGateway(verified.challenge) },
    `${label}: finish`,
  )
  return { label, email, auth, secret, pubKey, address: finished.address, name: null }
}

say('Alice and Bob sign in, with separate passkeys')
const alice = await signIn('alice', `alice+${Date.now()}@example.com`)
const bob = await signIn('bob', `bob+${Date.now()}@example.com`)
if (alice.pubKey === bob.pubKey) fail('two sign-ins produced the same key')
if (alice.auth.x === bob.auth.x) fail('two authenticators produced the same credential')
ok(`alice ${alice.address}`)
ok(`bob   ${bob.address}`)

say('Both claim a name')
for (const person of [alice, bob]) {
  const label = `${person.label}${Date.now() % 1000000}`
  const record = await must(
    '/api/name/register',
    { ...(await authAs(person)), label },
    `${person.label}: name`,
  )
  person.name = record.name
  ok(`${person.label} is ${record.name}`)
}

// ---- Alice looks Bob up ----

say('Alice looks Bob up by email')
const found = await must('/api/recipient', { ...(await authAs(alice)), email: bob.email }, 'recipient')
if (!found.known) fail('bob was not found, though he just signed in')
if (found.pubKey !== bob.pubKey) fail('the key found is not the one bob signed in with')
if (found.passkeyX !== bob.auth.x) fail('the passkey found is not bob\'s credential')
ok(`${found.name}, with the credential a delivery will freeze`)

// ---- Alice sends ----

say('Alice builds the delivery')
const file = new TextEncoder().encode(`the quiet part, written down — ${new Date().toISOString()}`)
const now = Math.floor(Date.now() / 1000)
const prepared = keysplit.prepareDelivery({
  sender: alice.address,
  plaintext: file,
  description: 'one invoice, for the end-to-end',
  recipientPublicKey: found.pubKey,
  recipientPasskey: { x: found.passkeyX, y: found.passkeyY },
  releaser: alice.address,
  acceptBy: String(now + 3600),
  releaseBy: String(now + 7200),
  senderSecretKey: alice.secret,
})
ok(`id ${prepared.transferId}`)

// The id the contract will derive must match the one A was salted with.
const onChainId = await chain.readContract({
  address: deployed.contractAddress,
  abi: deliveryArtifact.abi,
  functionName: 'transferId',
  args: [{ ...prepared.params, swarmRef: `0x${'00'.repeat(32)}` }],
})
if (onChainId.toLowerCase() !== prepared.transferId.toLowerCase()) {
  fail(`the contract derives a different id\n   contract ${onChainId}\n   browser  ${prepared.transferId}`)
}
ok('the contract derives the same id')

say('Alice authorises her own send')
const { digest: sendDigest } = await must(
  '/api/delivery/send-digest',
  { ...(await authAs(alice)), params: prepared.params },
  'send digest',
)
const sendSignature = signRecoverable(fromHex(sendDigest), alice.secret)
ok('signed, so the gateway carries something it cannot alter')

say('Alice sends it through the gateway')
const sent = await must(
  '/api/delivery',
  {
    ...(await authAs(alice)),
    transferId: prepared.transferId,
    params: prepared.params,
    authorisation: sendSignature,
    recipientPubKey: found.pubKey,
    ciphertext: Buffer.from(prepared.ciphertext).toString('base64'),
    description: Buffer.from(prepared.description).toString('base64'),
    keptHalf: Array.from(prepared.keptHalf),
    filename: 'invoice.txt',
    recipientEmail: bob.email,
  },
  'send',
)
ok(`on chain, ${sent.gasUsed} gas, tx ${sent.tx}`)

// The relayer paid, but the record must name Alice.
const recorded = await chain.readContract({
  address: deployed.contractAddress,
  abi: deliveryArtifact.abi,
  functionName: 'get',
  args: [prepared.transferId],
})
if (recorded.sender.toLowerCase() !== alice.address.toLowerCase()) {
  fail(`the record names ${recorded.sender} as the sender, not Alice`)
}
ok('and the record names Alice, not the relayer that paid')

// ---- Bob looks ----

say('Bob reads the delivery')
const record = await must(`/api/delivery/${prepared.transferId.slice(2)}`, null, 'read')
if (record.state !== 'Sent') fail(`expected Sent, got ${record.state}`)
if (record.releasedKey !== `0x${'00'.repeat(32)}`) fail('the sender half is on chain already')
ok('state is Sent, and the sender half is not on chain')

const ciphertext = new Uint8Array(
  await (await fetch(`${BASE}/api/delivery/${prepared.transferId.slice(2)}/blob`)).arrayBuffer(),
)
const delivery = {
  transferId: record.id,
  ephemeralX: record.ephemeralX,
  ephemeralOdd: record.ephemeralOdd,
  ciphertextHash: record.ciphertextHash,
  plaintextCommitment: record.plaintextCommitment,
  description: Buffer.from(record.description, 'base64'),
}

const seen = keysplit.inspectDelivery({ secretKey: bob.secret, delivery, ciphertext })
if (seen.description !== 'one invoice, for the end-to-end') fail(`the description read back as ${seen.description}`)
ok(`he can read "${seen.description}" before deciding`)

// The point of the whole exercise.
let early = null
try {
  keysplit.openDelivery({ secretKey: bob.secret, delivery, ciphertext, releasedKey: record.releasedKey })
} catch (err) {
  early = err.message
}
if (!early) fail('BOB OPENED THE FILE BEFORE ACCEPTING')
ok(`and cannot open it: ${early}`)

// ---- Bob accepts ----

say('Bob accepts with his passkey')
const accepted = await must(
  `/api/delivery/${prepared.transferId.slice(2)}/accept`,
  { assertion: bob.auth.assertForContract(record.acceptDigest) },
  'accept',
)
if (accepted.state !== 'Accepted') fail(`expected Accepted, got ${accepted.state}`)
ok(`verified by the contract, ${accepted.gasUsed} gas, tx ${accepted.tx}`)

// Alice's passkey must not be able to accept Bob's delivery.
const wrongPerson = await api(`/api/delivery/${prepared.transferId.slice(2)}/accept`, {
  assertion: alice.auth.assertForContract(record.acceptDigest),
})
if (wrongPerson.status === 200) fail('alice accepted a delivery addressed to bob')
ok("alice's passkey cannot accept it")

const afterAccept = await must(`/api/delivery/${prepared.transferId.slice(2)}`, null, 'read after accept')
if (afterAccept.releasedKey !== `0x${'00'.repeat(32)}`) fail('accepting released the sender half')
ok('accepting did not release the sender half')

let stillClosed = null
try {
  keysplit.openDelivery({ secretKey: bob.secret, delivery, ciphertext, releasedKey: afterAccept.releasedKey })
} catch (err) {
  stillClosed = err.message
}
if (!stillClosed) fail('bob opened the file on acceptance alone')
ok('and he still cannot open it')

// ---- Alice releases ----

say('Alice releases her half')
const { keptHalf, transferId } = await must(
  `/api/delivery/${prepared.transferId.slice(2)}/kept-half`,
  await authAs(alice),
  'kept half',
)
const half = keysplit.openSenderHalf({
  secretKey: alice.secret,
  transferId,
  blob: new Uint8Array(keptHalf),
})
const releasedKey = `0x${hex(half)}`

// Bob must not be able to get Alice's sealed half.
const notBobs = await api(`/api/delivery/${prepared.transferId.slice(2)}/kept-half`, await authAs(bob))
if (notBobs.status === 200) fail("bob was handed alice's sealed half")
ok("bob cannot fetch alice's sealed half")

const { digest: releaseDigest } = await must(
  `/api/delivery/${prepared.transferId.slice(2)}/release-digest/${releasedKey.slice(2)}`,
  null,
  'release digest',
)
const released = await must(
  `/api/delivery/${prepared.transferId.slice(2)}/release`,
  { releasedKey, signature: signRecoverable(fromHex(releaseDigest), alice.secret) },
  'release',
)
if (released.state !== 'Released') fail(`expected Released, got ${released.state}`)
ok(`released, ${released.gasUsed} gas, tx ${released.tx}`)

// ---- Bob opens ----

say('Bob opens the file')
const final = await must(`/api/delivery/${prepared.transferId.slice(2)}`, null, 'read after release')
if (final.releasedKey === `0x${'00'.repeat(32)}`) fail('the sender half is still not on chain')

const opened = keysplit.openDelivery({
  secretKey: bob.secret,
  delivery,
  ciphertext,
  releasedKey: final.releasedKey,
})
if (!Buffer.from(opened.plaintext).equals(Buffer.from(file))) fail('the file that came out is not the one sent')
ok('the file is the one Alice sent, and matches what she committed to')

// And a stranger still cannot, with everything public.
const eve = secp256k1.utils.randomPrivateKey()
let eveFailed = null
try {
  keysplit.openDelivery({ secretKey: eve, delivery, ciphertext, releasedKey: final.releasedKey })
} catch (err) {
  eveFailed = err.message
}
if (!eveFailed) fail('a stranger opened the file')
ok('a stranger cannot, even with the released half')

console.log(`
Done, on Sepolia:
  contract   ${deployed.contractAddress}
  delivery   ${prepared.transferId}
  send       ${sent.gasUsed} gas
  accept     ${accepted.gasUsed} gas
  release    ${released.gasUsed} gas

  https://sepolia.etherscan.io/address/${deployed.contractAddress}

Stood in for: the authenticator tap, twice. Not covered: the browser, the
popup boundary, and whether a real passkey provider returns a stable PRF
output across devices. See docs/TESTING.md.
`)

stopServer()
