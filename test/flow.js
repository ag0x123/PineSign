/**
 * End-to-end: Alice encrypts and sends, Bob decrypts and claims, and the
 * things that must not be possible are not possible.
 */

import {
  generatePrivateKey, publicKeyFrom, deriveSharedKey, encrypt, decrypt,
  hashPlaintext, transferDigest, sign, toHex, fromHex,
} from '../shared/crypto.js'
import { sha256 } from '@noble/hashes/sha256'
import { readFile } from 'node:fs/promises'
import http from 'node:http'
import { keyFromPrfOutput, PRF_SALT } from '../shared/prf.js'
import * as pages from '../gateway/pages.js'
import { authenticator } from './authenticator.js'

const BASE = process.env.BASE ?? 'http://localhost:8799'
const SERVER_LOG = process.env.SERVER_LOG ?? '.storage-test/server.log'
const SIGNIN_ORIGIN = process.env.SIGNIN_ORIGIN ?? 'https://v1.id.test.local'
let pass = 0, fail = 0

function check(label, condition) {
  console.log(`${condition ? '  ok  ' : ' FAIL '} ${label}`)
  condition ? pass++ : fail++
}

async function post(path, body) {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  return { status: res.status, body: await res.json().catch(() => ({})) }
}

async function auth(priv, pub) {
  const { status, body } = await post('/api/nonce', { pubKey: pub })
  // A missing nonce here used to surface as "pubKey required" three calls
  // later, which is a long way from the thing that actually went wrong.
  if (!body.nonce) throw new Error(`no nonce issued (${status}): ${body.error ?? 'unknown'}`)
  const signature = toHex(sign(sha256(new TextEncoder().encode(body.nonce)), priv))
  return { pubKey: pub, nonce: body.nonce, signature }
}

const alicePriv = generatePrivateKey(), alicePub = toHex(publicKeyFrom(alicePriv))
const bobPriv = generatePrivateKey(), bobPub = toHex(publicKeyFrom(bobPriv))
const evePriv = generatePrivateKey(), evePub = toHex(publicKeyFrom(evePriv))

const plaintext = new TextEncoder().encode('The quiet part, written down. ' + Date.now())
const plaintextHash = toHex(hashPlaintext(plaintext))

/**
 * The emailed code, read back from the server's own log.
 *
 * With no Resend key the gateway prints the message it would have sent, which
 * is exactly what a developer sees locally. Nothing is stubbed to get it.
 */
async function codeFromLog() {
  for (let attempt = 0; attempt < 40; attempt++) {
    const log = await readFile(SERVER_LOG, 'utf8').catch(() => '')
    const codes = [...log.matchAll(/Your sign-in code is (\d{6})/g)]
    if (codes.length) return codes.at(-1)[1]
    await new Promise((r) => setTimeout(r, 50))
  }
  throw new Error('no sign-in code reached the log')
}

// The only thing stood in for is the tap itself. See test/authenticator.js.
const RP_ID = process.env.PASSKEY_RP_ID ?? 'id.test.local'
const alicePasskey = authenticator({ rpId: RP_ID, origin: SIGNIN_ORIGIN })

/**
 * Host-based routing has to be driven with a real Host header, which fetch is
 * not allowed to set — so these go out over plain http.
 */
function asHost(host, path = '/') {
  const url = new URL(BASE)
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: url.hostname, port: url.port, path, method: 'GET', headers: { host } },
      (res) => {
        let body = ''
        res.on('data', (c) => (body += c))
        res.on('end', () => resolve({ status: res.statusCode, location: res.headers.location, body }))
      },
    )
    req.on('error', reject)
    req.end()
  })
}

console.log('\nsign-in page allow-list')
// The sign-in domain serves published versions and nothing else. An
// unpublished version is a 404, not a quiet fall-through to the lander.
const unpublished = await asHost('v9.id.test.local')
check('an unpublished version is refused', unpublished.status === 404)
const notAVersion = await asHost('admin.id.test.local')
check('a subdomain that is not a version is refused', notAVersion.status === 404)
const apex = await asHost('id.test.local')
check('the sign-in apex has nothing to point at yet', apex.status === 404)
const onApi = await asHost('id.test.local', '/api/health')
check('the API is not reachable under the sign-in domain', onApi.status === 404)
const lander = await fetch(`${BASE}/api/health`)
check('the gateway itself still answers on its own host', lander.status === 200)

// The list itself: versions are named, fixed, and the apex follows the newest.
check('a host under the sign-in domain names a version', pages.routeFor('v3.id.test.local')?.version === 'v3')
check('the sign-in domain itself is the apex', pages.routeFor('id.test.local')?.apex === true)
check('an unrelated host is not our business', pages.routeFor('example.com') === null)
check('a lookalike suffix is not our business', pages.routeFor('evil-id.test.local') === null)

const ref1 = 'a'.repeat(64)
await pages.publish({ version: 'v1', reference: ref1, files: 3, bytes: 1234 })
check('a published version is served', (await pages.referenceFor('v1')) === ref1)
check('and becomes the one the apex points at', (await pages.current())?.version === 'v1')
check('an unpublished version has no reference', (await pages.referenceFor('v2')) === null)
check('a non-version is never a reference', (await pages.referenceFor('../../etc')) === null)

let repointed = null
try {
  await pages.publish({ version: 'v1', reference: 'b'.repeat(64), files: 3, bytes: 1234 })
} catch (err) {
  repointed = err.message
}
check('a published version cannot be repointed', /already published/.test(repointed ?? ''))
check('and the error says to publish the next one', /v2/.test(repointed ?? ''))

console.log('\nkey derivation')
// The passkey's own output is the one thing a test cannot produce, so it is
// supplied here. Everything downstream of it is the real derivation.
const prfOutput = new Uint8Array(32).fill(7)
const derived = keyFromPrfOutput(prfOutput)
check('the salt is the one the gateway advertises', PRF_SALT === 'pinesign/v1')
check('a PRF output derives a usable key', derived.length === 32)
check('the same output always derives the same key', toHex(keyFromPrfOutput(prfOutput)) === toHex(derived))
const otherOutput = new Uint8Array(32).fill(8)
check('a different output derives a different key', toHex(keyFromPrfOutput(otherOutput)) !== toHex(derived))
check('the derived key has a public half', toHex(publicKeyFrom(derived)).length === 66)

console.log('\nsign-in')
const signInEmail = `alice+${Date.now()}@example.com`
const codeReq = await post('/api/signin/code', { email: signInEmail })
check('a code is issued for an address', codeReq.status === 200 && typeof codeReq.body.sessionId === 'string')
check('the response carries a session and nothing else', Object.keys(codeReq.body).sort().join() === 'expiresInMs,sessionId')

const badEmail = await post('/api/signin/code', { email: 'not-an-address' })
check('a malformed address is refused', badEmail.status === 400)

const sessionId = codeReq.body.sessionId
const code = await codeFromLog()

const wrongCode = await post('/api/signin/verify', { sessionId, code: '000000' === code ? '111111' : '000000' })
check('a wrong code is refused', wrongCode.status === 401)

const verified = await post('/api/signin/verify', { sessionId, code })
check('the right code earns a challenge', verified.status === 200 && typeof verified.body.challenge === 'string')
check('the challenge carries the session id', Buffer.from(verified.body.challenge, 'base64url').subarray(32).toString() === sessionId)
check('the page is told which salt to derive with', verified.body.prfSalt === 'pinesign/v1')
check('a first-time address is not known', verified.body.known === false)

const reused = await post('/api/signin/verify', { sessionId, code })
check('a code cannot be used twice', reused.status === 401)

const wrongOrigin = await post('/api/signin/finish', {
  sessionId,
  pubKey: alicePub,
  created: true,
  ...alicePasskey.assert({ challenge: verified.body.challenge, as: 'https://evil.example' }),
})
check('a ceremony from another origin is refused', wrongOrigin.status === 401)

const wrongChallenge = await post('/api/signin/finish', {
  sessionId,
  pubKey: alicePub,
  created: true,
  ...alicePasskey.assert({ challenge: Buffer.from('nope'.repeat(11)).toString('base64url') }),
})
check('a challenge this session was not issued is refused', wrongChallenge.status === 401)

// The check that was missing before this existed: clientDataJSON comes from
// the browser, so saying the right things inside it must not be enough.
const tampered = Buffer.from(JSON.stringify({
  type: 'webauthn.get', challenge: verified.body.challenge, origin: SIGNIN_ORIGIN, crossOrigin: false, extra: 'x',
})).toString('base64url')
const forgedCeremony = await post('/api/signin/finish', {
  sessionId,
  pubKey: alicePub,
  created: true,
  ...alicePasskey.assert({ challenge: verified.body.challenge }),
  clientDataJSON: tampered,
})
check('a forged clientDataJSON is refused', forgedCeremony.status === 401)

const strangerPasskey = authenticator({ rpId: RP_ID, origin: SIGNIN_ORIGIN })
const wrongKey = await post('/api/signin/finish', {
  sessionId,
  pubKey: alicePub,
  created: true,
  ...strangerPasskey.assert({ challenge: verified.body.challenge }),
  credentialPublicKey: alicePasskey.credentialPublicKey,
})
check('a signature from another credential is refused', wrongKey.status === 401)

const noUv = await post('/api/signin/finish', {
  sessionId,
  pubKey: alicePub,
  created: true,
  ...alicePasskey.assert({ challenge: verified.body.challenge, ad: alicePasskey.authData({ flags: 0x01 }) }),
})
check('an authenticator that did not verify the user is refused', noUv.status === 401)

const wrongRp = await post('/api/signin/finish', {
  sessionId,
  pubKey: alicePub,
  created: true,
  ...alicePasskey.assert({ challenge: verified.body.challenge, ad: alicePasskey.authData({ rp: 'id.evil.example' }) }),
})
check('an assertion for another relying party is refused', wrongRp.status === 401)

const finished = await post('/api/signin/finish', {
  sessionId,
  pubKey: alicePub,
  created: true,
  ...alicePasskey.assert({ challenge: verified.body.challenge }),
})
check('the key is bound to the address', finished.status === 200 && finished.body.pubKey === alicePub)
check('no name yet', finished.body.name === null)
check('the credential is recorded for on-chain use', /^0x[0-9a-f]{64}$/.test(finished.body.credential?.x ?? ''))
check('and this counts as a registration', finished.body.registered === true)

const spent = await post('/api/signin/finish', {
  sessionId,
  pubKey: alicePub,
  created: true,
  ...alicePasskey.assert({ challenge: verified.body.challenge }),
})
check('a finished session cannot be finished again', spent.status === 401)

// Signing in again with a different derived key would orphan everything
// already encrypted to the first one, so it is refused.
const second = await post('/api/signin/code', { email: signInEmail })
const secondVerified = await post('/api/signin/verify', { sessionId: second.body.sessionId, code: await codeFromLog() })
check('a returning address is known', secondVerified.body.known === true)
const otherKey = await post('/api/signin/finish', {
  sessionId: second.body.sessionId,
  pubKey: evePub,
  ...alicePasskey.assert({ challenge: secondVerified.body.challenge }),
})

check('a second, different key for one address is refused', otherKey.status === 400)

// Another passkey cannot sign in as a known address: the credential on file is
// the one the delivery contract will verify against, so it is fixed too.
const third = await post('/api/signin/code', { email: signInEmail })
const thirdVerified = await post('/api/signin/verify', { sessionId: third.body.sessionId, code: await codeFromLog() })
const wrongCredential = await post('/api/signin/finish', {
  sessionId: third.body.sessionId,
  pubKey: alicePub,
  ...strangerPasskey.assert({ challenge: thirdVerified.body.challenge }),
})
check('another passkey cannot sign in as a known address', wrongCredential.status === 401)

// And the registered one still works, which is the half that is easy to break.
const fourth = await post('/api/signin/code', { email: signInEmail })
const fourthVerified = await post('/api/signin/verify', { sessionId: fourth.body.sessionId, code: await codeFromLog() })
const returning = await post('/api/signin/finish', {
  sessionId: fourth.body.sessionId,
  pubKey: alicePub,
  ...alicePasskey.assert({ challenge: fourthVerified.body.challenge }),
})
check('the registered passkey signs in again', returning.status === 200 && returning.body.pubKey === alicePub)
check('and is not a fresh registration', returning.body.registered === false)

console.log('\nnames')
const aliceName = await post('/api/name/register', { ...(await auth(alicePriv, alicePub)), label: 'alice' + Date.now() % 100000 })
check('a name can be claimed', aliceName.status === 200 && aliceName.body.name.endsWith('.test.eth'))
check('the name carries the keyed email hash', typeof aliceName.body.emailHash === 'string' && aliceName.body.emailHash.length === 64)
const bobName = await post('/api/name/register', { ...(await auth(bobPriv, bobPub)), label: 'bob' + Date.now() % 100000 })
check('a second name can be claimed', bobName.status === 200)

const taken = await post('/api/name/register', { ...(await auth(evePriv, evePub)), label: aliceName.body.label })
check('a taken name is refused', taken.status === 400)

const resolved = await (await fetch(`${BASE}/api/name/resolve/${aliceName.body.name}`)).json()
check('a name resolves to the key', resolved.pubKey === alicePub)

console.log('\ngating')
const unnamed = await post('/api/send', {
  ...(await auth(evePriv, evePub)),
  recipientPubKey: bobPub, plaintextHash: '00'.repeat(32),
  senderSignature: '00'.repeat(64), ciphertext: 'AAAA',
})
check('an unnamed sender cannot send', unnamed.status === 403)

console.log('\nrecipients')
// Alice signed in with signInEmail earlier, so that address resolves to her
// key — read back through the same path a sender would use.
const knownTo = await post('/api/recipient', { ...(await auth(bobPriv, bobPub)), email: signInEmail })
check('a known address resolves to a key', knownTo.status === 200 && knownTo.body.known === true)
check('and to the key that address signed in with', knownTo.body.pubKey === alicePub)

const strangerTo = await post('/api/recipient', {
  ...(await auth(bobPriv, bobPub)),
  email: `stranger+${Date.now()}@example.com`,
  fromEmail: 'bob@example.com',
})
check('an unknown address is invited instead', strangerTo.status === 200 && strangerTo.body.known === false)
check('the invitation is what the sender is told about', typeof strangerTo.body.id === 'string')

const unnamedAsk = await post('/api/recipient', { ...(await auth(evePriv, evePub)), email: signInEmail })
check('an unnamed sender cannot look anyone up', unnamedAsk.status === 403)

// The whole loop: Bob invites an address, that person signs in and claims a
// name quoting the invitation, and Bob is emailed that he can go ahead.
const carolEmail = `carol+${Date.now()}@example.com`
const carolInvite = await post('/api/recipient', {
  ...(await auth(bobPriv, bobPub)),
  email: carolEmail,
  fromEmail: 'bob-receipts@example.com',
})

const carolPriv = generatePrivateKey(), carolPub = toHex(publicKeyFrom(carolPriv))
const carolPasskey = authenticator({ rpId: RP_ID, origin: SIGNIN_ORIGIN })
const carolCode = await post('/api/signin/code', { email: carolEmail })
const carolVerified = await post('/api/signin/verify', { sessionId: carolCode.body.sessionId, code: await codeFromLog() })
await post('/api/signin/finish', {
  sessionId: carolCode.body.sessionId,
  pubKey: carolPub,
  created: true,
  ...carolPasskey.assert({ challenge: carolVerified.body.challenge }),
})
const carolName = await post('/api/name/register', {
  ...(await auth(carolPriv, carolPub)),
  label: 'carol' + Date.now() % 100000,
  inviteId: carolInvite.body.id,
})
check('the invited party can claim a name', carolName.status === 200)

const inviteNow = await (await fetch(`${BASE}/api/invite/${carolInvite.body.id}`)).json()
check('the invitation is marked accepted', inviteNow.status === 'accepted')
check('and names who accepted it', inviteNow.acceptedBy === carolName.body.name)

const senderTold = await readFile(SERVER_LOG, 'utf8')
check('the sender is emailed that they can send', senderTold.includes('bob-receipts@example.com'))

// And now that address resolves, which is the point of the whole exchange.
const carolNow = await post('/api/recipient', { ...(await auth(bobPriv, bobPub)), email: carolEmail })
check('the invited address now resolves to their key', carolNow.body.known === true && carolNow.body.pubKey === carolPub)

console.log('\nsend')
const sharedAlice = deriveSharedKey(alicePriv, fromHex(bobPub))
const ciphertext = encrypt(plaintext, sharedAlice)
const digest = transferDigest({ senderPubKey: alicePub, recipientPubKey: bobPub, plaintextHash })

const sent = await post('/api/send', {
  ...(await auth(alicePriv, alicePub)),
  recipientPubKey: bobPub,
  plaintextHash,
  senderSignature: toHex(sign(digest, alicePriv)),
  filename: 'note.txt',
  ciphertext: Buffer.from(ciphertext).toString('base64'),
})
check('gateway accepts the transfer', sent.status === 200 && sent.body.id)
check('gateway returns a swarm reference', Boolean(sent.body.reference))
const id = sent.body.id

console.log('\nauth')
const stale = await post('/api/send', {
  pubKey: alicePub, nonce: 'never-issued', signature: '00'.repeat(64),
  recipientPubKey: bobPub, plaintextHash, senderSignature: '00'.repeat(64),
  ciphertext: 'AAAA',
})
check('unknown nonce is rejected', stale.status === 401)

const a = await auth(alicePriv, alicePub)
await post('/api/send', { ...a, recipientPubKey: bobPub, plaintextHash, senderSignature: toHex(sign(digest, alicePriv)), ciphertext: Buffer.from(ciphertext).toString('base64') })
const replay = await post('/api/send', { ...a, recipientPubKey: bobPub, plaintextHash, senderSignature: toHex(sign(digest, alicePriv)), ciphertext: Buffer.from(ciphertext).toString('base64') })
check('a nonce cannot be replayed', replay.status === 401)

console.log('\nreceive')
const record = await (await fetch(`${BASE}/api/transfer/${id}`)).json()
check('record names the recipient', record.recipientPubKey === bobPub)
check('record carries both names', record.senderName === aliceName.body.name && record.recipientName === bobName.body.name)
check('record carries no plaintext', !JSON.stringify(record).includes('quiet part'))
check('record does not publish the signable digest', record.digest === undefined)
check('hash is hidden before the claim', record.plaintextHash === null && Boolean(record.fileCommitment))

const blob = new Uint8Array(await (await fetch(`${BASE}/api/blob/${id}`)).arrayBuffer())
check('stored blob is not the plaintext', !Buffer.from(blob).toString().includes('quiet part'))

const sharedBob = deriveSharedKey(bobPriv, fromHex(record.senderPubKey))
const recovered = decrypt(blob, sharedBob)
check('bob decrypts to the original', Buffer.from(recovered).equals(Buffer.from(plaintext)))
check('decrypted hash matches the published commitment', '0x' + toHex(hashPlaintext(fromHex(toHex(hashPlaintext(recovered))))) === record.fileCommitment)

console.log('\neve')
let eveFailed = false
try {
  const eveKey = deriveSharedKey(evePriv, fromHex(record.senderPubKey))
  decrypt(blob, eveKey)
} catch {
  eveFailed = true
}
check('a third party cannot decrypt', eveFailed)

const eveClaim = await post('/api/claim', {
  ...(await auth(evePriv, evePub)),
  id,
  claimSignature: toHex(sign(sha256(new TextEncoder().encode('guess')), evePriv)),
  plaintextHash,
})
check('a third party cannot claim', eveClaim.status === 403)

console.log('\nclaim')
const claimSig = toHex(sign(transferDigest({
  senderPubKey: record.senderPubKey, recipientPubKey: bobPub, plaintextHash: toHex(hashPlaintext(recovered)),
}), bobPriv))
// Signing alone is not enough: the hash must be presented, and only decrypting yields it.
const lazy = await post('/api/claim', { ...(await auth(bobPriv, bobPub)), id, claimSignature: claimSig })
check('a claim without the file hash is refused', lazy.status === 400)

const claimed = await post('/api/claim', { ...(await auth(bobPriv, bobPub)), id, claimSignature: claimSig, plaintextHash })
check('bob claims by presenting the decrypted hash', claimed.status === 200 && claimed.body.claim)

const again = await post('/api/claim', { ...(await auth(bobPriv, bobPub)), id, claimSignature: claimSig, plaintextHash })
check('a claim is write-once', again.status === 400 && /already claimed/.test(again.body.error))

const final = await (await fetch(`${BASE}/api/transfer/${id}`)).json()
check('receipt is on the record', Boolean(final.claim?.recipientSignature))

console.log('\ndeliveries, unconfigured')
// With no DELIVERY_ADDRESS the gateway must say so rather than half-work.
// This is the state a fresh deployment is in, and it is worth knowing that
// every delivery route refuses cleanly in it.
const noContract = await post('/api/delivery', {
  ...(await auth(alicePriv, alicePub)),
  transferId: '0x' + '11'.repeat(32),
  params: {},
  ciphertext: 'AAAA',
  keptHalf: [1, 2, 3],
})
check('sending a delivery is refused without a contract', noContract.status === 503)

const noRead = await (await fetch(`${BASE}/api/delivery/${'11'.repeat(32)}`)).json()
check('and reading one says the same', /no delivery contract/.test(noRead.error ?? ''))

const noAccept = await post(`/api/delivery/${'11'.repeat(32)}/accept`, { assertion: {} })
check('and so does relaying an acceptance', noAccept.status === 503)

const noRelease = await post(`/api/delivery/${'11'.repeat(32)}/release`, {
  releasedKey: '0x' + 'ab'.repeat(32),
  signature: '0x' + '00'.repeat(65),
})
check('and relaying a release', noRelease.status === 503)

// The id is a 32-byte hash, and anything else must not reach a lookup.
const badId = await (await fetch(`${BASE}/api/delivery/nothex`)).json()
check('a malformed id is refused', /hex string/.test(badId.error ?? ''))

// The sealed half is the sender's alone, and the route is signature-gated.
const notMine = await post(`/api/delivery/${'11'.repeat(32)}/kept-half`, await auth(evePriv, evePub))
check('the kept half is not handed to a stranger', notMine.status === 404 || notMine.status === 403)

console.log(`\n${pass} passed, ${fail} failed\n`)
process.exit(fail === 0 ? 0 : 1)
