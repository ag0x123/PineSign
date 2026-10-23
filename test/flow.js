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
import { keyFromPrfOutput, PRF_SALT } from '../shared/prf.js'

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

/**
 * The one thing stood in for: the authenticator tap. Everything the browser
 * would send after it — the challenge it signed over and the origin it was on
 * — is built here exactly as the real ceremony builds it.
 */
function clientData({ type, challenge, origin = SIGNIN_ORIGIN }) {
  return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false })).toString('base64')
}

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
  clientDataJSON: clientData({ type: 'webauthn.create', challenge: verified.body.challenge, origin: 'https://evil.example' }),
})
check('a ceremony from another origin is refused', wrongOrigin.status === 401)

const wrongChallenge = await post('/api/signin/finish', {
  sessionId,
  pubKey: alicePub,
  created: true,
  clientDataJSON: clientData({ type: 'webauthn.create', challenge: Buffer.from('nope'.repeat(11)).toString('base64url') }),
})
check('a challenge this session was not issued is refused', wrongChallenge.status === 401)

const finished = await post('/api/signin/finish', {
  sessionId,
  pubKey: alicePub,
  created: true,
  clientDataJSON: clientData({ type: 'webauthn.create', challenge: verified.body.challenge }),
})
check('the key is bound to the address', finished.status === 200 && finished.body.pubKey === alicePub)
check('no name yet', finished.body.name === null)

const spent = await post('/api/signin/finish', {
  sessionId,
  pubKey: alicePub,
  created: true,
  clientDataJSON: clientData({ type: 'webauthn.create', challenge: verified.body.challenge }),
})
check('a finished session cannot be finished again', spent.status === 401)

// Signing in again with a different key would orphan everything already
// encrypted to the first one, so it is refused rather than silently allowed.
const second = await post('/api/signin/code', { email: signInEmail })
const secondVerified = await post('/api/signin/verify', { sessionId: second.body.sessionId, code: await codeFromLog() })
check('a returning address is known', secondVerified.body.known === true)
const otherKey = await post('/api/signin/finish', {
  sessionId: second.body.sessionId,
  pubKey: evePub,
  clientDataJSON: clientData({ type: 'webauthn.get', challenge: secondVerified.body.challenge }),
})
check('a second, different key for one address is refused', otherKey.status === 400)

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
const carolCode = await post('/api/signin/code', { email: carolEmail })
const carolVerified = await post('/api/signin/verify', { sessionId: carolCode.body.sessionId, code: await codeFromLog() })
await post('/api/signin/finish', {
  sessionId: carolCode.body.sessionId,
  pubKey: carolPub,
  created: true,
  clientDataJSON: clientData({ type: 'webauthn.create', challenge: carolVerified.body.challenge }),
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

console.log(`\n${pass} passed, ${fail} failed\n`)
process.exit(fail === 0 ? 0 : 1)
