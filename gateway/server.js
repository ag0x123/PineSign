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
import * as names from './names.js'
import * as setup from './setup.js'
import * as chain from './chain.js'
import * as admin from './admin.js'
import { rateLimit, requireHexParam, isHex } from './limits.js'
import * as invites from './invites.js'
import * as mail from './mail.js'
import * as ens from './ens.js'
import * as otp from './otp.js'
import * as passkey from './passkey.js'
import * as users from './users.js'
import { emailHash, normaliseEmail } from './secrets.js'
import * as pages from './pages.js'
import { BEE_URL } from './bee.js'
import * as delivery from './delivery.js'
import * as deliveries from './deliveries.js'
import { issueNonce, requireSignature } from './auth.js'
import { fromHex, addressFromPublicKey } from '../shared/crypto.js'
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

/**
 * The sign-in domain, served from the allow-list.
 *
 * A request to `v1.<signin domain>` is answered with the bytes of whichever
 * Swarm reference v1 was published at, fetched through the local Bee node. A
 * request to a version this gateway has not published is a 404 — not the
 * current version, not a redirect. The whole point of pinning a version is
 * that asking for it gets that version or nothing.
 *
 * Runs before the app's own routes, because these hostnames serve one thing
 * and must never fall through to the gateway's API or its lander.
 */
app.use(async (req, res, next) => {
  const route = pages.routeFor(req.get('host'))
  if (!route) return next()

  // The apex of the sign-in domain is a signpost, not a page: it points at
  // whichever version is current so a bare link still lands somewhere real.
  if (route.apex) {
    const now = await pages.current()
    if (!now) return res.status(404).type('text/plain').send('no sign-in page has been published yet')
    return res.redirect(302, `https://${now.version}.${pages.SIGNIN_DOMAIN}${req.originalUrl}`)
  }

  const reference = await pages.referenceFor(route.version)
  if (!reference) {
    return res.status(404).type('text/plain').send('no such sign-in page version')
  }

  try {
    const upstream = await fetch(`${BEE_URL}/bzz/${reference}${req.path}`, {
      headers: { accept: req.get('accept') ?? '*/*' },
      signal: AbortSignal.timeout(15_000),
    })
    if (!upstream.ok) return res.status(upstream.status).type('text/plain').send('not found in that version')

    const type = upstream.headers.get('content-type')
    if (type) res.set('Content-Type', type)
    // Immutable by construction: a version is a hash, so it can be cached hard.
    res.set('Cache-Control', 'public, max-age=31536000, immutable')
    res.set('X-Content-Type-Options', 'nosniff')
    res.set('Referrer-Policy', 'no-referrer')
    res.send(Buffer.from(await upstream.arrayBuffer()))
  } catch (err) {
    res.status(502).type('text/plain').send(`could not fetch that version from Swarm: ${err.message}`)
  }
})

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

// Anything that spends postage, mail or gas is limited; reads are not. The
// numbers are per minute and per client, and overridable because what is
// generous for one deployment is a wall for another.
const perMinute = (name, fallback) => Number(process.env[name] ?? fallback)

const limitAuth = rateLimit({ key: 'auth', windowMs: 60_000, max: perMinute('RATE_AUTH_PER_MIN', 20) })
const limitSend = rateLimit({ key: 'send', windowMs: 60_000, max: perMinute('RATE_SEND_PER_MIN', 10) })
const limitSetup = rateLimit({ key: 'setup', windowMs: 60_000, max: perMinute('RATE_SETUP_PER_MIN', 60) })
const limitCode = rateLimit({ key: 'code', windowMs: 60_000, max: perMinute('RATE_CODE_PER_MIN', 10) })

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
    const result = await setup.attachResolver()
    names.setResolver(await setup.resolverAddress())
    res.json(result)
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
    // The parent actually in use, which is not always the one setup recorded:
    // PINESIGN_PARENT can supply it, and reporting the stored value then says
    // "none" about a server that is happily issuing subnames.
    parentName: names.getParent(),
    receiptsAddress: state.receiptsAddress,
    swarm: await swarm.stampInfo().catch((e) => ({ error: e.message })),
    signInPage: await pages.current(),
  })
})

// ---- sign-in: an email code, then a passkey ----

/**
 * Step one. A six-digit code to the address, and a session id to carry.
 *
 * The response says nothing about whether the address is already known. A
 * sign-in page that could be used to ask "does this person have an account"
 * is a different product from the one we are building.
 */
app.post('/api/signin/code', limitCode, async (req, res) => {
  try {
    const { sessionId, code, expiresInMs } = otp.issue(req.body?.email, req.ip)
    await mail.signInCode({
      to: normaliseEmail(req.body.email),
      code,
      minutes: Math.round(expiresInMs / 60_000),
    })
    res.json({ sessionId, expiresInMs })
  } catch (err) {
    if (err.status === 429) res.set('Retry-After', String(err.retryAfter))
    res.status(err.status ?? 400).json({ error: err.message })
  }
})

/**
 * Step two. A good code earns the passkey challenge — and `known` tells the
 * page whether to create a passkey or ask for the one already there.
 */
app.post('/api/signin/verify', limitAuth, async (req, res) => {
  try {
    const { sessionId, code } = req.body ?? {}
    const result = otp.verify(sessionId, code)
    if (!result.ok) return res.status(401).json({ error: result.error })

    if (!passkey.configured) {
      return res.status(503).json({ error: 'this server has no passkey configuration yet' })
    }

    const user = await users.byEmailHash(await emailHash(result.email))
    res.json({
      known: Boolean(user),
      email: result.email,
      rpId: passkey.RP_ID,
      rpName: passkey.RP_NAME,
      challenge: await passkey.challengeFor(result.email, sessionId),
      // The browser derives its key with this, and we never see the result.
      prfSalt: 'pinesign/v1',
    })
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

/**
 * Step three. The page has derived its key and says so.
 *
 * What is checked is the ceremony, not the key: that the challenge signed was
 * the one this session was issued, and that the page driving it was one of the
 * published sign-in pages. The key itself arrives as a public key, because the
 * private half never leaves the page that derived it.
 */
app.post('/api/signin/finish', limitAuth, async (req, res) => {
  try {
    const {
      sessionId, pubKey, clientDataJSON, authenticatorData, signature,
      credentialPublicKey, created,
    } = req.body ?? {}

    const email = otp.verifiedEmail(sessionId)
    if (!email) return res.status(401).json({ error: 'that sign-in has expired — start again' })
    if (!isHex(pubKey, 66)) return res.status(400).json({ error: 'pubKey must be a 33-byte compressed key' })

    const hash = await emailHash(email)
    const existing = await users.byEmailHash(hash)

    // A returning user is verified against the credential already on file, so
    // the page cannot nominate a different one. A new user registers theirs.
    const onFile = existing?.credential?.spki ?? null
    if (onFile && credentialPublicKey && credentialPublicKey !== onFile) {
      return res.status(401).json({ error: 'that is not the passkey this address is registered to' })
    }

    let credential
    try {
      credential = passkey.credentialKey(onFile ?? credentialPublicKey)
    } catch (err) {
      return res.status(400).json({ error: err.message })
    }

    const ceremony = await passkey.checkCeremony({
      email,
      sessionId,
      clientDataJSON,
      authenticatorData,
      signature,
      credentialPublicKey: credential.spki,
      // Sign-up creates the passkey and then immediately asserts it; the
      // assertion is what is verified, because that is what carries a
      // signature we can check against the key being registered.
      expectedType: 'webauthn.get',
      previousSignCount: existing?.signCount ?? 0,
    })
    if (!ceremony.ok) return res.status(401).json({ error: ceremony.error })

    const user = await users.bind({
      emailHash: hash,
      pubKey,
      address: addressFromPublicKey(pubKey),
      credential,
      signCount: ceremony.signCount,
    })
    otp.close(sessionId)

    const named = await names.reverse(pubKey)
    res.json({
      pubKey: user.pubKey,
      address: user.address,
      name: named?.name ?? null,
      // The page shows this so a user can tell which credential they are on.
      credential: { x: credential.x, y: credential.y },
      registered: !onFile,
    })
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

app.post('/api/nonce', limitAuth, (req, res) => {
  const { pubKey } = req.body ?? {}
  if (!pubKey) return res.status(400).json({ error: 'pubKey required' })
  res.json({ nonce: issueNonce(pubKey) })
})

// ---- invitations ----

/**
 * Who is this email address?
 *
 * One question with two answers, because from the sender's side it is one
 * question. Either the address already has a key — in which case they get the
 * name and the key to encrypt to, read from the chain — or it does not, and an
 * invitation goes out instead. The sender does not have to know which case
 * they are in, and is not told anything about an address that has no account
 * beyond the fact that an invitation was sent.
 *
 * Requires a name: addressing someone is an offer to send, and only a named
 * sender may send.
 */
app.post('/api/recipient', limitSend, requireSignature, async (req, res) => {
  try {
    const sender = await names.reverse(req.pubKey)
    if (!sender) return res.status(403).json({ error: 'claim a name before sending to anyone' })

    const { email, fromEmail } = req.body ?? {}
    if (!invites.validEmail(email)) return res.status(400).json({ error: 'that is not an email address' })

    const user = await users.byEmailHash(await emailHash(email))
    if (user?.name) {
      // The chain is the authority on where to encrypt. Asking it here means a
      // key rotated on chain is picked up without this server being involved.
      const record = await names.resolve(user.name)
      if (record?.pubKey) {
        return res.json({
          known: true,
          name: record.name,
          pubKey: record.pubKey,
          // The passkey a delivery freezes as the only credential that may
          // accept it. Absent for anyone who last signed in before deliveries
          // existed, and a sender needs to know that rather than discover it
          // when the contract refuses their transaction.
          passkeyX: user.credential?.x ?? null,
          passkeyY: user.credential?.y ?? null,
        })
      }
    }

    const invite = await invites.create({
      fromPubKey: req.pubKey, fromName: sender.name, fromEmail, toEmail: email,
    })
    const link = `${publicOrigin(req)}/?invite=${invite.id}#get-started`
    await mail.invitation({ to: email, fromName: sender.name, link })

    res.json({ known: false, invited: true, id: invite.id, status: invite.status })
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
      // Set at sign-in, under a key only this server holds. It is what lets an
      // invitation addressed to an email find the key that answers to it,
      // without the address itself being published.
      emailHash: await users.emailHashFor(req.pubKey),
    })
    await users.setName(req.pubKey, record.name)

    // The records themselves, on chain, where anyone can read them and this
    // server cannot quietly change what it told someone yesterday.
    publishUser(record).catch((err) => console.log(`  user records failed: ${err.message}`))

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

// ---- deliveries: the gateway carries, the contract decides ----

/**
 * Record a delivery the sender has already built.
 *
 * The ciphertext and the encrypted description go to Swarm, the parameters go
 * to the contract, and the sender's sealed key half is kept here unopened. The
 * gateway cannot read that half, so it cannot release — which is the only
 * reason it is allowed to hold it.
 */
app.post('/api/delivery', limitSend, requireSignature, async (req, res) => {
  if (!delivery.configured) {
    return res.status(503).json({ error: 'this gateway has no delivery contract configured' })
  }
  try {
    const sender = await names.reverse(req.pubKey)
    if (!sender) return res.status(403).json({ error: 'claim a name before sending' })

    // Called `authorisation` rather than `signature` on purpose: every signed
    // route already carries a `signature` over the nonce, and a second field
    // by that name silently overwrote it — the request then failed as "bad
    // signature" with nothing pointing at the collision.
    const {
      transferId, params, authorisation, ciphertext, description, keptHalf, filename, recipientEmail,
    } = req.body
    if (!transferId || !params || !authorisation || !ciphertext || !keptHalf) {
      return res.status(400).json({
        error: 'transferId, params, authorisation, ciphertext and keptHalf required',
      })
    }
    // The sender signs their own send, so this gateway is carrying something
    // it cannot alter. It also cannot send as anyone else.
    if (params.sender?.toLowerCase() !== addressFromPublicKey(req.pubKey).toLowerCase()) {
      return res.status(403).json({ error: 'the delivery names a different sender than the one signing' })
    }

    // Stored first: a contract record pointing at a ciphertext that is not
    // there yet would be a delivery nobody can inspect.
    const swarmRef = await swarm.upload(new Uint8Array(Buffer.from(ciphertext, 'base64')))
    const descriptionRef = description
      ? await swarm.upload(new Uint8Array(Buffer.from(description, 'base64')))
      : null

    // A Swarm reference is 32 bytes in both modes — a real one, and the
    // content hash the local fallback addresses blobs by — so it goes on chain
    // as-is rather than being squeezed into shape.
    if (!isHex(swarmRef, 64)) {
      throw new Error(`a swarm reference should be 32 hex bytes, got ${swarmRef.length} characters`)
    }

    const sent = await delivery.sendDelivery({ ...params, swarmRef: `0x${swarmRef}` }, authorisation)

    const recipientName = req.body.recipientPubKey
      ? await names.reverse(req.body.recipientPubKey)
      : null
    const record = await deliveries.create({
      id: transferId,
      senderPubKey: req.pubKey,
      senderName: sender.name,
      recipientPubKey: req.body.recipientPubKey ?? null,
      recipientName: recipientName?.name ?? null,
      recipientEmail,
      filename: filename ?? 'file',
      size: Buffer.from(ciphertext, 'base64').length,
      swarmRef,
      descriptionRef,
      keptHalf,
      sentTx: sent.tx,
    })

    if (recipientEmail) {
      mail.fileReady({
        to: recipientEmail,
        fromName: sender.name,
        filename: record.filename,
        link: `${publicOrigin(req)}/claim.html?id=${transferId}`,
        expires: new Date(Number(params.acceptBy) * 1000).toUTCString(),
      }).catch((err) => console.log(`  mail failed: ${err.message}`))
    }

    res.json({ id: transferId, tx: sent.tx, gasUsed: sent.gasUsed, swarmRef })
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

/**
 * Everything needed to inspect a delivery, from the chain and from Swarm.
 *
 * The state here is read from the contract, not from this gateway's own
 * records — so a gateway that wanted to lie about whether something was
 * accepted would be contradicted by anyone who looked.
 */
app.get('/api/delivery/:id', requireHexParam('id', { length: 64 }), async (req, res) => {
  if (!delivery.configured) {
    return res.status(503).json({ error: 'this gateway has no delivery contract configured' })
  }
  try {
    const id = `0x${req.params.id}`
    const onChain = await delivery.get(id)
    if (onChain.state === 'None') return res.status(404).json({ error: 'no such delivery' })

    const local = await deliveries.get(id)
    const description = local?.descriptionRef
      ? Buffer.from(await swarm.download(local.descriptionRef)).toString('base64')
      : null

    res.json({
      id,
      contract: delivery.ADDRESS,
      state: onChain.state,
      // The relying party the acceptance must be signed under. Supplied
      // because the contract stores only its hash, and a page guessing it from
      // its own hostname would guess wrong the moment either name changed.
      rpId: passkey.RP_ID,
      // The fields a recipient needs to derive their half and check the file.
      ephemeralX: onChain.ephemeralX,
      ephemeralOdd: onChain.ephemeralOdd,
      ciphertextHash: onChain.ciphertextHash,
      plaintextCommitment: onChain.plaintextCommitment,
      releaseCommitment: onChain.releaseCommitment,
      descriptionHash: onChain.descriptionHash,
      passkeyX: onChain.passkeyX,
      passkeyY: onChain.passkeyY,
      releaser: onChain.releaser,
      acceptBy: onChain.acceptBy.toString(),
      releaseBy: onChain.releaseBy.toString(),
      acceptedAt: onChain.acceptedAt.toString(),
      releasedAt: onChain.releasedAt.toString(),
      // Zero until the acceptance is recorded. This is the whole mechanism.
      releasedKey: onChain.releasedKey,
      senderName: local?.senderName ?? null,
      filename: local?.filename ?? null,
      size: local?.size ?? null,
      swarmRef: local?.swarmRef ?? null,
      description,
      acceptDigest: onChain.state === 'Sent' ? await delivery.acceptDigest(id) : null,
    })
  } catch (err) {
    res.status(502).json({ error: err.message })
  }
})

/** The ciphertext. Useless without both halves of the key. */
app.get('/api/delivery/:id/blob', requireHexParam('id', { length: 64 }), async (req, res) => {
  const local = await deliveries.get(`0x${req.params.id}`)
  if (!local) return res.status(404).json({ error: 'no such delivery' })
  try {
    const bytes = await swarm.download(local.swarmRef)
    res.set('Content-Type', 'application/octet-stream').send(Buffer.from(bytes))
  } catch (err) {
    res.status(502).json({ error: `swarm fetch failed: ${err.message}` })
  }
})

/**
 * Carry an acceptance to the contract.
 *
 * Unauthenticated on purpose: the assertion is the authentication, and it is
 * the contract that checks it. Requiring a signed-in caller as well would mean
 * a recipient who cannot reach this gateway cannot accept, when in fact anyone
 * could carry the same assertion.
 */
app.post('/api/delivery/:id/accept', limitSend, requireHexParam('id', { length: 64 }), async (req, res) => {
  if (!delivery.configured) {
    return res.status(503).json({ error: 'this gateway has no delivery contract configured' })
  }
  try {
    const id = `0x${req.params.id}`
    const { assertion } = req.body ?? {}
    if (!assertion) return res.status(400).json({ error: 'assertion required' })

    const relayed = await delivery.relayAccept(id, assertion)

    const local = await deliveries.get(id)
    if (local?.senderPubKey) {
      const senderEmail = await invites.senderEmailFor(local.senderPubKey)
      if (senderEmail) {
        mail.accepted({
          to: senderEmail,
          recipientName: local.recipientName ?? 'the recipient',
          link: `${publicOrigin(req)}/send.html?release=${id}`,
        }).catch((err) => console.log(`  mail failed: ${err.message}`))
      }
    }

    res.json({ ok: true, ...relayed, state: await delivery.stateOf(id) })
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

/** The sealed half back to the sender, who is the only one who can open it. */
app.post('/api/delivery/:id/kept-half', requireHexParam('id', { length: 64 }), requireSignature, async (req, res) => {
  const local = await deliveries.get(`0x${req.params.id}`)
  if (!local) return res.status(404).json({ error: 'no such delivery' })
  if (local.senderPubKey !== req.pubKey) {
    return res.status(403).json({ error: 'only the sender holds this' })
  }
  res.json({ keptHalf: local.keptHalf, transferId: local.id })
})

/**
 * The digest the sender signs to authorise their own send.
 *
 * Asked for before anything is stored, because the sender has to sign it and
 * the swarm reference — the one field they do not sign over — does not exist
 * until the ciphertext is uploaded.
 */
app.post('/api/delivery/send-digest', limitSend, requireSignature, async (req, res) => {
  if (!delivery.configured) {
    return res.status(503).json({ error: 'this gateway has no delivery contract configured' })
  }
  try {
    const { params } = req.body ?? {}
    if (!params) return res.status(400).json({ error: 'params required' })
    const id = await delivery.transferId({ ...params, swarmRef: `0x${'00'.repeat(32)}` })
    const releaser = params.releaser && !/^0x0+$/.test(params.releaser) ? params.releaser : params.sender
    res.json({
      transferId: id,
      digest: await delivery.sendDigest(id, params.releaseCommitment, params.descriptionHash, releaser),
    })
  } catch (err) {
    res.status(502).json({ error: err.message })
  }
})

/** The digest the releaser signs, computed by the contract. */
app.get('/api/delivery/:id/release-digest/:key', requireHexParam('id', { length: 64 }), async (req, res) => {
  if (!isHex(req.params.key, 64)) return res.status(400).json({ error: 'key must be 32 hex bytes' })
  try {
    res.json({ digest: await delivery.releaseDigest(`0x${req.params.id}`, `0x${req.params.key}`) })
  } catch (err) {
    res.status(502).json({ error: err.message })
  }
})

/** Carry a release. The signature is the releaser's; we hold no half. */
app.post('/api/delivery/:id/release', limitSend, requireHexParam('id', { length: 64 }), async (req, res) => {
  if (!delivery.configured) {
    return res.status(503).json({ error: 'this gateway has no delivery contract configured' })
  }
  try {
    const id = `0x${req.params.id}`
    const { releasedKey, signature } = req.body ?? {}
    if (!isHex(releasedKey?.replace(/^0x/, ''), 64)) {
      return res.status(400).json({ error: 'releasedKey must be 32 hex bytes' })
    }
    if (!signature) return res.status(400).json({ error: 'signature required' })

    const relayed = await delivery.relayRelease(id, releasedKey, signature)

    const local = await deliveries.get(id)
    if (local?.recipientEmail) {
      mail.fileReady({
        to: local.recipientEmail,
        fromName: local.senderName ?? 'the sender',
        filename: local.filename ?? 'a file',
        link: `${publicOrigin(req)}/claim.html?id=${id}`,
        expires: 'once released, it stays released',
      }).catch((err) => console.log(`  mail failed: ${err.message}`))
    }

    res.json({ ok: true, ...relayed, state: await delivery.stateOf(id) })
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

/** Put a lapse on the record, from either side. */
app.post('/api/delivery/:id/expire', limitSend, requireHexParam('id', { length: 64 }), async (req, res) => {
  try {
    const id = `0x${req.params.id}`
    const relayed = await delivery.relayExpire(id)
    res.json({ ok: true, ...relayed, state: await delivery.stateOf(id) })
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

/** A sender's deliveries, so they can see what is waiting to be released. */
app.post('/api/deliveries', requireSignature, async (req, res) => {
  const mine = await deliveries.bySender(req.pubKey)
  if (!delivery.configured) return res.json(mine.map((d) => ({ ...d, keptHalf: undefined })))
  res.json(
    await Promise.all(
      mine.map(async (d) => ({
        id: d.id,
        filename: d.filename,
        recipientName: d.recipientName,
        createdAt: d.createdAt,
        // From the contract, so this list cannot say "accepted" on its own.
        state: await delivery.stateOf(d.id).catch(() => 'unknown'),
      })),
    ),
  )
})

/**
 * On-chain writes share one wallet, so they go in order.
 *
 * Two transactions from one account contending for a nonce is a way to lose
 * both of them. The queue is per subject and the lane is global: writes about
 * one name cannot overtake each other, and no two writes from this wallet are
 * ever in flight at once.
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

// One wallet, one nonce sequence: every write shares a single lane.
let chainLane = Promise.resolve()
function serialize(work) {
  const run = chainLane.then(work, work)
  chainLane = run.catch(() => {})
  return run
}

/**
 * A user's own records: their key and their keyed email hash, under their name.
 *
 * Deliberately not frozen. A receipt is final the moment it is claimed, but a
 * user's records are the live answer to "where do I encrypt to for this
 * person", and that has to stay writable.
 */
function publishUser(record) {
  return enqueue(record.name, () => serialize(async () => {
    const resolver = await setup.resolverAddress()
    const key = await setup.deployerKey()
    if (!resolver || !key) return
    const { tx } = await ens.writeRecords(key, {
      resolver,
      name: record.name,
      records: names.recordsFor(record),
    })
    console.log(`  published ${record.name} ${tx}`)
  }))
}

app.get('/api/deliveries/all', setup.requireSetupToken, async (_req, res) => res.json(await deliveries.list()))

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
  names.setResolver(await setup.resolverAddress())

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
