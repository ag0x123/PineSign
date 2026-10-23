/**
 * PineSign gateway.
 *
 * Holds the Swarm credentials, pays the postage, and sees nothing but
 * ciphertext. Every byte it stores was encrypted on the sender's machine with a
 * key it does not have and cannot derive.
 */

import './env.js' // must be first: fills process.env for every import below
import express from 'express'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import * as swarm from './swarm.js'
import * as store from './store.js'
import * as names from './names.js'
import * as setup from './setup.js'
import * as chain from './chain.js'
import * as admin from './admin.js'
import { rateLimit, requireHexParam } from './limits.js'
import * as invites from './invites.js'
import * as mail from './mail.js'
import * as ens from './ens.js'
import { keccak256, toHex as viemHex } from 'viem'
import { issueNonce, requireSignature } from './auth.js'
import { transferDigest, verify, fromHex, toHex, addressFromPublicKey } from '../shared/crypto.js'
import { randomBytes } from 'node:crypto'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const PORT = process.env.PORT ?? 8788
// Behind a reverse proxy, bind to loopback so the proxy is the only way in.
const HOST = process.env.HOST ?? '0.0.0.0'

const app = express()

/**
 * A chain error's message includes the entire request body — kilobytes of
 * bytecode nobody can act on. Keep the one line that says what went wrong.
 */
function tidy(err) {
  const short = err.shortMessage ?? err.message ?? String(err)
  const detail = err.details ?? err.cause?.details
  const line = detail ? `${short.split('\n')[0]} — ${String(detail).split('\n')[0]}` : short.split('\n')[0]
  return line.length > 300 ? line.slice(0, 300) + '…' : line
}

/** Public origin for links in emails — PUBLIC_ORIGIN, e.g. https://your.domain. */
function publicOrigin(req) {
  return process.env.PUBLIC_ORIGIN ?? `${req.protocol}://${req.get('host')}`
}

// Behind Caddy or nginx, the client address arrives in a forwarded header;
// without this every visitor looks like the proxy and rate limiting is useless.
app.set('trust proxy', 1)

app.use(express.json({ limit: '64mb' }))

app.use((req, res, next) => {
  // The sign-in page is served from its own origin and must be able to reach
  // the gateway; a request with no origin at all is a plain fetch, not a page.
  const origin = req.get('origin')
  if (origin === undefined) {
    res.set('Access-Control-Allow-Origin', '*')
  } else {
    res.set('Access-Control-Allow-Origin', origin)
    res.set('Vary', 'Origin')
  }
  res.set('Access-Control-Allow-Headers', 'Content-Type, x-setup-token, x-admin-session')
  if (req.method === 'OPTIONS') return res.sendStatus(204)

  // Nothing here should ever be framed or sniffed.
  res.set('X-Content-Type-Options', 'nosniff')
  res.set('X-Frame-Options', 'DENY')
  res.set('Referrer-Policy', 'no-referrer')
  next()
})

// Anything that spends postage, mail or gas is limited; reads are not.
const limitAuth = rateLimit({ key: 'auth', windowMs: 60_000, max: 20 })
const limitSend = rateLimit({ key: 'send', windowMs: 60_000, max: 10 })
const limitSetup = rateLimit({ key: 'setup', windowMs: 60_000, max: 60 })

// ---- admin sign-in ----

/** Who, if anyone, owns this server — asked before any sign-in is attempted. */
app.get('/api/setup/admin', async (_req, res) => {
  res.json({ adminAddress: await setup.adminAddress() })
})

app.post('/api/setup/admin/nonce', limitAuth, (req, res) => {
  const { address } = req.body ?? {}
  if (!address) return res.status(400).json({ error: 'address required' })
  const nonce = admin.issueNonce(address)
  res.json({ nonce, message: admin.challengeText(nonce, req.get('host')) })
})

/**
 * Verify a signature, and on a first run claim the server for that wallet.
 * Claiming needs the console token as well, so an unclaimed server on a public
 * address cannot simply be taken by whoever finds it.
 */
app.post('/api/setup/admin/verify', limitAuth, async (req, res) => {
  try {
    const { address, nonce, signature, token } = req.body ?? {}
    const result = await admin.verify({ address, nonce, signature, host: req.get('host') })
    if (!result.ok) return res.status(401).json({ error: result.error })

    const existing = await setup.adminAddress()
    if (!existing) {
      if (token !== (await setup.getSetupToken())) {
        return res.status(403).json({ error: 'the console token is required to claim this server' })
      }
      await setup.claimAdmin(result.address)
    } else if (existing !== result.address) {
      return res.status(403).json({ error: 'that wallet is not the administrator of this server' })
    }

    res.json({ session: result.session, address: result.address })
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

app.post('/api/setup/admin/signout', (req, res) => {
  const session = req.get('x-admin-session')
  if (session) admin.endSession(session)
  res.json({ ok: true })
})

// ---- setup ----

app.get('/api/setup/status', limitSetup, setup.requireSetupToken, async (_req, res) => {
  try {
    res.json(await setup.status())
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

/** Is this name free? Asked while the admin types, so it stays a plain lookup. */
app.get('/api/setup/name/:name', setup.requireSetupToken, async (req, res) => {
  try {
    res.json(await chain.nameStatus(req.params.name.toLowerCase()))
  } catch (err) {
    res.status(502).json({ error: `could not reach the chain: ${err.message}` })
  }
})

app.post('/api/setup/name', setup.requireSetupToken, async (req, res) => {
  try {
    const state = await setup.chooseName(req.body?.name)
    names.setParent(state.parentName)
    res.json(state)
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

app.post('/api/setup/keys', setup.requireSetupToken, async (_req, res) => {
  try {
    res.json(await setup.generateDeployer())
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

/** Buying the name takes two transactions and a mandated wait between them. */
app.post('/api/setup/register-name', setup.requireSetupToken, async (req, res) => {
  // Two transactions plus the registrar's enforced wait; well past any default.
  req.setTimeout(300000)
  res.setTimeout(300000)
  try {
    res.json(await setup.registerName())
  } catch (err) {
    res.status(400).json({ error: tidy(err) })
  }
})

app.post('/api/setup/resolver', setup.requireSetupToken, async (_req, res) => {
  try {
    res.json(await setup.attachResolver())
  } catch (err) {
    res.status(400).json({ error: tidy(err) })
  }
})

app.post('/api/setup/deploy', setup.requireSetupToken, async (_req, res) => {
  try {
    res.json(await setup.deploy())
  } catch (err) {
    res.status(400).json({ error: tidy(err) })
  }
})

/** Buying postage can take a while; the node waits on Gnosis. */
app.post('/api/setup/postage', setup.requireSetupToken, async (req, res) => {
  req.setTimeout(180000)
  res.setTimeout(180000)
  try {
    res.json(await setup.buyPostage(req.body ?? {}))
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

app.get('/api/health', async (_req, res) => {
  const state = await setup.status()
  res.json({
    ok: true,
    configured: state.step === 'ready',
    parentName: state.parentName,
    receiptsAddress: state.receiptsAddress,
    swarm: await swarm.stampInfo().catch((e) => ({ error: e.message })),
  })
})

app.post('/api/nonce', limitAuth, (req, res) => {
  const { pubKey } = req.body ?? {}
  if (!pubKey) return res.status(400).json({ error: 'pubKey required' })
  res.json({ nonce: issueNonce(pubKey) })
})

// ---- invitations ----

/**
 * Alice invites Bob by email. Requires a name: an invitation is an offer to
 * send, and only a named sender may send.
 */
app.post('/api/invite', limitSend, requireSignature, async (req, res) => {
  try {
    const sender = await names.reverse(req.pubKey)
    if (!sender) return res.status(403).json({ error: 'claim a name before inviting anyone' })

    const { toEmail, fromEmail } = req.body
    const invite = await invites.create({
      fromPubKey: req.pubKey, fromName: sender.name, fromEmail, toEmail,
    })

    const link = `${publicOrigin(req)}/?invite=${invite.id}#get-started`
    await mail.invitation({ to: toEmail, fromName: sender.name, link })

    res.json({ id: invite.id, link, status: invite.status })
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

/** What the recipient sees when they open the link: who, and whether it still stands. */
app.get('/api/invite/:id', requireHexParam('id', { length: 24 }), async (req, res) => {
  const inv = await invites.get(req.params.id)
  if (!inv) return res.status(404).json({ error: 'no such invitation' })
  res.json({ id: inv.id, fromName: inv.fromName, status: inv.status, acceptedBy: inv.acceptedBy?.name ?? null })
})

/** Sender's list, so the page can show who has accepted. */
app.post('/api/invites', requireSignature, async (req, res) => {
  res.json(await invites.bySender(req.pubKey))
})

// ---- names ----

/** Is this label free? Asked while the user types. */
app.get('/api/name/available/:label', async (req, res) => {
  const label = req.params.label.toLowerCase()
  if (!names.validLabel(label)) {
    return res.json({ label, available: false, reason: 'A name is 3-32 characters: letters, digits and hyphens.' })
  }
  const taken = await names.resolve(label)
  res.json({ label, name: names.fullName(label), available: !taken })
})

/**
 * Claim a name and publish an encryption key under it.
 *
 * One proof is enough: the signature over the nonce shows the key is theirs,
 * and the address is derived from that same key rather than accepted from the
 * browser — a page could claim any address, but not a key it cannot sign for.
 */
app.post('/api/name/register', limitSend, requireSignature, async (req, res) => {
  try {
    const { label } = req.body

    const record = await names.register(String(label ?? '').toLowerCase(), {
      pubKey: req.pubKey,
      address: addressFromPublicKey(req.pubKey),
    })

    // Arrived via an invitation: close the loop and tell the sender to proceed.
    const { inviteId } = req.body
    if (inviteId) {
      try {
        const inv = await invites.accept(inviteId, { pubKey: req.pubKey, name: record.name })
        if (inv.fromEmail) {
          await mail.accepted({
            to: inv.fromEmail,
            recipientName: record.name,
            link: `${publicOrigin(req)}/#get-started`,
          })
        }
      } catch (err) {
        // A stale invitation must not stop the name from being claimed.
        console.log(`  invitation ${inviteId} not accepted: ${err.message}`)
      }
    }

    res.json(record)
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

app.get('/api/name/resolve/:name', async (req, res) => {
  const record = await names.resolve(req.params.name.toLowerCase())
  if (!record) return res.status(404).json({ error: 'no such name' })
  res.json(record)
})

app.get('/api/name/by-address/:address', async (req, res) => {
  const record = await names.byAddress(req.params.address)
  if (!record) return res.status(404).json({ error: 'this wallet has no name' })
  res.json(record)
})

app.get('/api/name/reverse/:pubKey', async (req, res) => {
  const record = await names.reverse(req.params.pubKey.toLowerCase())
  if (!record) return res.status(404).json({ error: 'this key has no name' })
  res.json(record)
})

// Resolution is public by necessity; enumeration of every user is not.
app.get('/api/names', setup.requireSetupToken, async (_req, res) => res.json(await names.list()))

/**
 * Alice sends. She supplies ciphertext, the hash of the plaintext, and her
 * signature over the transfer digest — the sender half of the proof, committed
 * before Bob ever sees the file.
 */
app.post('/api/send', limitSend, requireSignature, async (req, res) => {
  try {
    const { recipientPubKey, plaintextHash, senderSignature, filename, ciphertext } = req.body
    if (!recipientPubKey || !plaintextHash || !senderSignature || !ciphertext) {
      return res.status(400).json({ error: 'recipientPubKey, plaintextHash, senderSignature and ciphertext required' })
    }

    // The gate: only a named sender may spend the gateway's postage. The name
    // is also what published the sender's key, so this is the same check as
    // "is this someone the system can vouch for".
    const senderName = await names.reverse(req.pubKey)
    if (!senderName) {
      return res.status(403).json({ error: 'claim a name before sending' })
    }

    const digest = transferDigest({
      senderPubKey: req.pubKey,
      recipientPubKey,
      plaintextHash,
    })
    if (!verify(fromHex(senderSignature), digest, fromHex(req.pubKey))) {
      return res.status(400).json({ error: 'sender signature does not match the transfer' })
    }

    const recipientName = await names.reverse(recipientPubKey)

    const blob = Buffer.from(ciphertext, 'base64')
    const reference = await swarm.upload(new Uint8Array(blob))

    const id = randomBytes(16).toString('hex')
    const transfer = await store.create({
      id,
      reference,
      senderPubKey: req.pubKey,
      senderName: senderName.name,
      recipientPubKey,
      recipientName: recipientName?.name ?? null,
      plaintextHash,
      senderSignature,
      filename: filename ?? 'file',
      size: blob.length,
      digest: toHex(digest),
    })

    const claimUrl = `${publicOrigin(req)}/claim.html?id=${id}`

    // The sender's half of the attestation, on chain, under a name that will
    // resolve for as long as the parent does. The plaintext hash is committed
    // to, not published — the recipient reveals it when they claim, which is
    // what proves they decrypted rather than merely downloaded.
    attest(id, {
      'sender': senderName.name,
      'sender.key': req.pubKey,
      'sender.sig': senderSignature,
      'recipient': recipientName?.name ?? '',
      'recipient.key': recipientPubKey,
      'file.name': filename ?? 'file',
      'file.commitment': keccak256(fromHex(plaintextHash)),
      'swarm': reference,
      'sent': new Date().toISOString(),
    }).catch((err) => console.log(`  attestation failed: ${err.message}`))

    const recipientEmail = await invites.emailFor(recipientPubKey)
    if (recipientEmail) {
      mail.fileReady({
        to: recipientEmail,
        fromName: senderName.name,
        filename: filename ?? 'a file',
        link: claimUrl,
        expires: new Date(transfer.expiresAt).toUTCString(),
      }).catch((err) => console.log(`  mail failed: ${err.message}`))
    }

    res.json({ id, reference, expiresAt: transfer.expiresAt, claimUrl })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

/** Public record. Enough to verify the transfer; not enough to read the file. */
app.get('/api/transfer/:id', requireHexParam('id', { length: 32 }), async (req, res) => {
  const t = await store.get(req.params.id)
  if (!t) return res.status(404).json({ error: 'no such transfer' })
  res.json({
    id: t.id,
    senderPubKey: t.senderPubKey,
    senderName: t.senderName ?? null,
    recipientPubKey: t.recipientPubKey,
    recipientName: t.recipientName ?? null,
    // The hash is what the recipient must produce to claim. Publishing it up
    // front would let anyone sign a receipt without ever opening the file, so
    // before the claim only its commitment is visible.
    fileCommitment: keccak256(fromHex(t.plaintextHash)),
    plaintextHash: t.claim ? t.plaintextHash : null,
    senderSignature: t.senderSignature,
    filename: t.filename,
    size: t.size,
    reference: t.reference,
    createdAt: t.createdAt,
    expiresAt: t.expiresAt,
    expired: Boolean(t.expired),
    claim: t.claim,
    attestation: `${t.id}.tx.${names.getParent()}`,
  })
})

/** The ciphertext itself. Useless without Bob's private key. */
app.get('/api/blob/:id', requireHexParam('id', { length: 32 }), async (req, res) => {
  const t = await store.get(req.params.id)
  if (!t) return res.status(404).json({ error: 'no such transfer' })
  if (t.expired) return res.status(410).json({ error: 'transfer expired' })
  try {
    const bytes = await swarm.download(t.reference)
    res.set('Content-Type', 'application/octet-stream').send(Buffer.from(bytes))
  } catch (err) {
    res.status(502).json({ error: `swarm fetch failed: ${err.message}` })
  }
})

/**
 * Bob claims. His signature is over the same digest Alice signed, which he can
 * only produce after decrypting — so the pair of signatures is the receipt.
 */
app.post('/api/claim', requireSignature, async (req, res) => {
  try {
    const { id, claimSignature, plaintextHash } = req.body
    const t = await store.get(id)
    if (!t) return res.status(404).json({ error: 'no such transfer' })
    if (req.pubKey !== t.recipientPubKey) {
      return res.status(403).json({ error: 'only the named recipient can claim' })
    }

    // Proof of decryption. The hash was never published — only its commitment —
    // so the recipient can have it only by decrypting the file. Presenting it
    // is what turns "downloaded" into "received".
    if (!plaintextHash || plaintextHash.toLowerCase() !== t.plaintextHash.toLowerCase()) {
      return res.status(400).json({ error: 'the file hash does not match — decrypt the file to claim it' })
    }
    if (!verify(fromHex(claimSignature), fromHex(t.digest), fromHex(req.pubKey))) {
      return res.status(400).json({ error: 'claim signature does not match the transfer' })
    }
    const updated = await store.recordClaim(id, { recipientSignature: claimSignature })

    // The recipient's half, and the freeze: from here the record is final.
    finalizeAttestation(id, {
      'file.hash': t.plaintextHash,
      'recipient.sig': claimSignature,
      'delivered': new Date().toISOString(),
    }).catch((err) => console.log(`  attestation finalize failed: ${err.message}`))

    const senderEmail = await invites.senderEmailFor(t.senderPubKey)
    if (senderEmail) {
      mail.delivered({
        to: senderEmail,
        recipientName: t.recipientName ?? 'the recipient',
        filename: t.filename,
        receiptLink: `${publicOrigin(req)}/claim.html?id=${id}`,
      }).catch((err) => console.log(`  mail failed: ${err.message}`))
    }

    res.json({ ok: true, claim: updated.claim })
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

// The whole transfer log, admin only — it names every sender and recipient.
/** The on-chain name a transfer's attestation lives under. */
async function attestationName(id) {
  const parent = names.getParent()
  return `${id}.tx.${parent}`
}

/**
 * On-chain writes for one transfer happen strictly in order. A claim can arrive
 * seconds after a send, and the freeze must not overtake the record it seals —
 * nor may two transactions from one wallet contend for a nonce.
 */
const chainQueue = new Map()
function enqueue(id, work) {
  const prev = chainQueue.get(id) ?? Promise.resolve()
  const next = prev.then(work, work).finally(() => {
    if (chainQueue.get(id) === next) chainQueue.delete(id)
  })
  chainQueue.set(id, next)
  return next
}

// One wallet, one nonce sequence: all attestations share a single lane.
let chainLane = Promise.resolve()
function serialize(work) {
  const run = chainLane.then(work, work)
  chainLane = run.catch(() => {})
  return run
}

function attest(id, records) {
  return enqueue(id, () => serialize(async () => {
    const resolver = await setup.resolverAddress()
    const key = await setup.deployerKey()
    if (!resolver || !key) return
    const name = await attestationName(id)
    const { tx } = await ens.writeRecords(key, { resolver, name, records })
    console.log(`  attested ${name} ${tx}`)
  }))
}

function finalizeAttestation(id, records) {
  return enqueue(id, () => serialize(async () => {
    const resolver = await setup.resolverAddress()
    const key = await setup.deployerKey()
    if (!resolver || !key) return
    const name = await attestationName(id)
    const { tx } = await ens.finalizeRecords(key, { resolver, name, records })
    console.log(`  finalized ${name} ${tx}`)
  }))
}

/** Read an attestation back from chain — what anyone can verify independently. */
app.get('/api/attestation/:id', requireHexParam('id', { length: 32 }), async (req, res) => {
  const resolver = await setup.resolverAddress()
  if (!resolver) return res.status(404).json({ error: 'no resolver attached' })
  const name = await attestationName(req.params.id)
  const keys = ['sender', 'sender.key', 'sender.sig', 'recipient', 'recipient.key', 'file.name', 'file.commitment', 'file.hash', 'swarm', 'sent', 'recipient.sig', 'delivered']
  const out = {}
  for (const k of keys) out[k] = await ens.readRecord(resolver, name, k).catch(() => '')
  res.json({ name, resolver, records: out })
})

app.get('/api/transfers', setup.requireSetupToken, async (_req, res) => res.json(await store.list()))

// Bundles change on every deploy. Served with no-cache, the browser revalidates
// each load (cheap, ETag) instead of running last week's code from its cache.
app.use(express.static(path.join(__dirname, '..', 'web'), {
  etag: true,
  setHeaders(res, filePath) {
    if (filePath.endsWith('.bundle.js') || filePath.endsWith('.html')) {
      res.set('Cache-Control', 'no-cache')
    }
  },
}))

app.listen(PORT, HOST, async () => {
  const state = await setup.status()
  names.setParent(state.parentName)

  console.log(`pinesign gateway on http://localhost:${PORT}  [swarm: ${await swarm.mode()}]`)
  if (state.step === 'ready') {
    console.log(`  ${state.parentName} · receipts at ${state.receiptsAddress}`)
  } else {
    console.log('  not configured yet')
  }

  // Always printed: this link is the only way into the admin panel, and an
  // operator who has lost it has lost access to their own server.
  const token = await setup.getSetupToken()
  console.log(`  admin: http://localhost:${PORT}/setup.html?token=${token}`)
})
