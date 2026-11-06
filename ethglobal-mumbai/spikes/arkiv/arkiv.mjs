// Spike 1 — Arkiv: schema, create with expiry, query by indexed field + owner, patch, extend.
// The payload carries a P-256 signature that is verified after reading the entity back, so the
// test proves the bytes survive the round trip exactly, not merely that a row exists.
import { createPublicClient, createWalletClient, defineSchema, str, bytes, addr, ExpirationTime } from '@arkiv-network/sdk'
import { rabdi } from '@arkiv-network/sdk/chains'
import { eq } from '@arkiv-network/sdk/query'
import { http, keccak256, toHex, stringToBytes } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { p256 } from '@noble/curves/nist.js'
import { sha256 } from '@noble/hashes/sha2.js'

const ACCESS_KEY = process.env.ARKIV_ACCESS_KEY
const PRIVATE_KEY = process.env.ARKIV_PRIVATE_KEY
if (!ACCESS_KEY || !PRIVATE_KEY) { console.error('set ARKIV_ACCESS_KEY and ARKIV_PRIVATE_KEY'); process.exit(1) }

const out = { chain: 'rabdi', chainId: 7794095 }
const t = () => Date.now()

const chain = rabdi({ accessKey: ACCESS_KEY })
const account = privateKeyToAccount(PRIVATE_KEY)
const publicClient = createPublicClient({ chain, transport: http() })
const walletClient = createWalletClient({ chain, transport: http(), account })
out.owner = account.address
out.balanceWei = (await publicClient.getBalance({ address: account.address })).toString()

// --- the schema under test
const Invite = defineSchema('pinesign.invite', {
  fingerprint: str().indexed(),
  emailHash: str().indexed(),
  payload: bytes(),
})

// --- a P-256 signature to carry in the payload
const priv = p256.utils.randomSecretKey ? p256.utils.randomSecretKey() : p256.utils.randomPrivateKey()
const pub = p256.getPublicKey(priv, false)
const signed = stringToBytes('pinesign/invite/alice@example.com')
const digest = sha256(signed)
const sig = p256.sign(digest, priv)
// @noble/curves 2.x returns the 64-byte compact r||s form directly
const payload = new Uint8Array([...pub, ...sig])
out.payloadBytes = payload.length

const emailHash = keccak256(toHex('alice@example.com'))
const fingerprint = keccak256(payload).slice(0, 18)

const gasOf = async (txHash) => {
  const r = await publicClient.getTransactionReceipt({ hash: txHash })
  return Number(r.gasUsed)
}

try {
  // --- create
  let m = t()
  const created = await walletClient.createEntity(
    Invite,
    { fingerprint, emailHash, payload },
    { expiration: ExpirationTime.fromDays(1) }
  )
  out.create = { ms: t() - m, entityKey: created.entityKey, gasUsed: await gasOf(created.txHash) }

  // --- query by indexed field + owner
  m = t()
  const found = await publicClient
    .select({ $key: true, fingerprint: true, emailHash: true, payload: true })
    .from(Invite)
    .ownedBy(account.address)
    .where(eq('emailHash', emailHash))
    .fetch()
  out.query = { ms: t() - m, rows: found.entities.length }
  const row = found.entities.find((e) => e.$key === created.entityKey)
  out.query.foundOurs = !!row

  // --- the real check: does the signature still verify from what the chain returned?
  // Values come back wrapped as { type, value }, not raw. Reading row.payload directly yields an
  // object, and new Uint8Array(object) is a silently empty array rather than an error.
  const unwrap = (v) => (v && typeof v === 'object' && 'value' in v ? v.value : v)
  if (row) {
    const back = Uint8Array.from(Buffer.from(String(unwrap(row.payload)).slice(2), 'hex'))
    out.query.payloadIdentical = Buffer.from(back).equals(Buffer.from(payload))
    const pubBack = back.slice(0, 65)
    const sigBack = back.slice(65)
    out.query.p256SignatureVerifies = p256.verify(sigBack, digest, pubBack)
  }

  // --- patch
  m = t()
  // patchEntity is positional (schema, entityKey, changes). The PatchEntityParameters type in the
  // docs is the shape executeBatch takes, not the shape this method takes.
  const patched = await walletClient.patchEntity(Invite, created.entityKey, { set: { fingerprint: '0xpatched' } })
  out.patch = { ms: t() - m, gasUsed: await gasOf(patched.txHash) }
  const after = await publicClient.select({ $key: true, fingerprint: true }).from(Invite).where(eq('emailHash', emailHash)).fetch()
  out.patch.fingerprintNow = unwrap(after.entities.find((e) => e.$key === created.entityKey)?.fingerprint)

  // --- extend expiry. The return value does not carry the new expiry under the name the types
  // suggest, so read $expiresAt from the entity on both sides instead of trusting the response.
  const expiryOf = async () => {
    const r = await publicClient.select({ $key: true, $expiresAt: true }).from(Invite).where(eq('emailHash', emailHash)).fetch()
    return Number(r.entities.find((e) => e.$key === created.entityKey)?.$expiresAt ?? 0)
  }
  const expiryBefore = await expiryOf()
  m = t()
  const extended = await walletClient.extendEntity({ entityKey: created.entityKey, expiration: ExpirationTime.fromDays(7) })
  const expiryAfter = await expiryOf()
  out.extend = { ms: t() - m, gasUsed: await gasOf(extended.txHash), expiresAtBefore: expiryBefore, expiresAtAfter: expiryAfter, grewBy: expiryAfter - expiryBefore }

  out.PASS =
    out.query.foundOurs === true &&
    out.query.payloadIdentical === true &&
    out.query.p256SignatureVerifies === true &&
    out.patch.fingerprintNow === '0xpatched' &&
    expiryAfter > expiryBefore
} catch (e) {
  out.error = e?.shortMessage || e?.message || String(e)
  out.errorName = e?.name
  out.PASS = false
}
console.log(JSON.stringify(out, null, 2))
