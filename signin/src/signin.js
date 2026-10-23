/**
 * The sign-in page.
 *
 * This page is static, published to Swarm, and served from its own origin. It
 * is the only place the user's private key ever exists.
 *
 * Why its own origin: a passkey scoped to `id.example.com` can be asserted by
 * that host and anything beneath it, and by nothing above it. So this page can
 * derive the key, and the lander on the apex — which the gateway serves, and
 * could in principle serve something else — cannot.
 *
 * The app therefore never receives the key. It opens this page in a popup and
 * asks it to do things: sign a digest, encrypt a file for a recipient, open a
 * transfer. Plaintext and ciphertext cross the boundary; the key does not.
 */

import {
  deriveSharedKey, encrypt, decrypt, hashPlaintext, transferDigest, sign,
  toHex, fromHex, keccak256,
} from '../../shared/crypto.js'
import { createAndDerive, derive, bytesToBase64url, NoPrfError } from '../../shared/prf.js'
import { sha256 } from '@noble/hashes/sha256'

const GATEWAY = __PINESIGN_GATEWAY__
const APP_ORIGINS = __PINESIGN_APP_ORIGINS__

const el = (id) => document.getElementById(id)

/** The key, for as long as this page is open. Never stored, never sent. */
let identity = null
let session = null
let email = null

/** Who opened us, once we have checked they are allowed to have. */
let appOrigin = null

function say(message, kind = '') {
  el('status').textContent = message
  el('status').className = `status ${kind}`.trim()
}

function show(step) {
  for (const id of ['step-email', 'step-code', 'step-passkey', 'step-done']) {
    el(id).hidden = id !== step
  }
}

async function api(path, body) {
  const res = await fetch(GATEWAY + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const json = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(json.error ?? `${res.status} ${res.statusText}`)
  return json
}

// ---- the flow ----

el('email-form').addEventListener('submit', async (event) => {
  event.preventDefault()
  el('email-send').disabled = true
  say('Sending a code…')
  try {
    email = el('email').value.trim()
    const result = await api('/api/signin/code', { email })
    session = { id: result.sessionId }
    el('code-sent-to').textContent = email
    show('step-code')
    say('')
    el('code').focus()
  } catch (err) {
    say(err.message, 'error')
    el('email-send').disabled = false
  }
})

el('code-form').addEventListener('submit', async (event) => {
  event.preventDefault()
  el('code-send').disabled = true
  say('Checking…')
  try {
    const result = await api('/api/signin/verify', { sessionId: session.id, code: el('code').value.trim() })
    session = { ...session, ...result }
    show('step-passkey')
    el('passkey-what').textContent = result.known
      ? 'Use the passkey you signed up with. It is what derives your key.'
      : 'Create a passkey. It will derive your encryption key — here, in this page, every time you sign in.'
    say('')
  } catch (err) {
    say(err.message, 'error')
    el('code-send').disabled = false
  }
})

el('passkey-go').addEventListener('click', async () => {
  el('passkey-go').disabled = true
  say('Waiting for your passkey…')
  try {
    const ceremony = session.known
      ? await derive({ challenge: session.challenge, rpId: session.rpId })
      : await createAndDerive({
          challenge: session.challenge,
          rpId: session.rpId,
          rpName: session.rpName,
          email,
          // The handle is derived from the session, not from the address: the
          // authenticator stores it, and an email address stored in a password
          // manager is one more copy of it than needs to exist.
          userHandle: bytesToBase64url(sha256(new TextEncoder().encode(session.id))),
        })

    say('Registering your key…')
    const registered = await api('/api/signin/finish', {
      sessionId: session.id,
      pubKey: ceremony.publicKeyHex,
      // The gateway verifies this signature against the credential's public
      // key, so none of it is taken on trust.
      clientDataJSON: ceremony.clientDataJSON,
      authenticatorData: ceremony.authenticatorData,
      signature: ceremony.signature,
      credentialPublicKey: ceremony.credentialPublicKey,
      created: ceremony.created,
    })

    identity = ceremony
    el('who').textContent = registered.name ?? registered.address
    show('step-done')
    say('')
    handOff(registered)
  } catch (err) {
    say(err instanceof NoPrfError ? err.message : err.message, 'error')
    el('passkey-go').disabled = false
  }
})

// ---- handing control back ----

/**
 * The app gets the public half and nothing else: a key, an address, a name.
 * Everything that needs the private half is asked for over postMessage and
 * answered here.
 */
function handOff(registered) {
  const summary = {
    publicKey: identity.publicKeyHex,
    address: identity.address,
    name: registered.name ?? null,
  }

  if (appOrigin && window.opener) {
    post({ pinesign: 'signedin', identity: summary })
    el('close-note').hidden = false
    return
  }

  // Redirect fallback. The key cannot travel, so it does not: the app learns
  // who signed in and opens this page again in a popup when it needs work done.
  const back = new URLSearchParams(location.search).get('return')
  if (back && APP_ORIGINS.some((o) => back.startsWith(o + '/') || back === o)) {
    const url = new URL(back)
    url.hash = new URLSearchParams(summary).toString()
    location.replace(url.toString())
  }
}

function post(message) {
  window.opener?.postMessage(message, appOrigin)
}

// ---- what the app may ask for ----

const methods = {
  identity() {
    return { publicKey: identity.publicKeyHex, address: identity.address }
  },

  /** Prove to the gateway who is asking. The nonce is the gateway's, not ours. */
  signNonce({ nonce }) {
    return { signature: toHex(sign(sha256(new TextEncoder().encode(nonce)), identity.privateKey)) }
  },

  /**
   * Encrypt a file for a recipient and sign for having sent it, in one call.
   *
   * The sender's half of the receipt is produced here, over the same digest the
   * recipient will later sign — so the app cannot encrypt a file and then
   * commit to a different one.
   */
  encryptFor({ plaintext, recipientPubKey }) {
    const bytes = new Uint8Array(plaintext)
    const sharedKey = deriveSharedKey(identity.privateKey, fromHex(recipientPubKey))
    const ciphertext = encrypt(bytes, sharedKey)
    const plaintextHash = toHex(hashPlaintext(bytes))

    const digest = transferDigest({
      senderPubKey: identity.publicKeyHex,
      recipientPubKey,
      plaintextHash,
    })

    return {
      ciphertext: Array.from(ciphertext),
      plaintextHash,
      senderSignature: toHex(sign(digest, identity.privateKey)),
    }
  },

  /**
   * Decrypt a transfer and sign its receipt, in one call.
   *
   * One call on purpose: a page that could decrypt and then decline to sign
   * would be able to read a file without leaving a receipt, which is the one
   * thing this whole design exists to prevent.
   */
  openTransfer({ ciphertext, senderPubKey, expectedCommitment }) {
    const sharedKey = deriveSharedKey(identity.privateKey, fromHex(senderPubKey))
    const plaintext = decrypt(Uint8Array.from(ciphertext), sharedKey)

    const plaintextHash = toHex(hashPlaintext(plaintext))
    // The sender committed to keccak(hash), not to the hash itself — so the
    // check is against the commitment, and the hash stays ours to reveal.
    if (expectedCommitment && keccak256(fromHex(plaintextHash)) !== expectedCommitment.toLowerCase()) {
      throw new Error('the decrypted file does not match what the sender committed to')
    }

    const digest = transferDigest({
      senderPubKey,
      recipientPubKey: identity.publicKeyHex,
      plaintextHash,
    })

    return {
      plaintext: Array.from(plaintext),
      plaintextHash,
      signature: toHex(sign(digest, identity.privateKey)),
    }
  },
}

addEventListener('message', (event) => {
  if (event.origin !== appOrigin) return
  const { pinesign, id, method, params } = event.data ?? {}
  if (pinesign !== 'rpc') return

  try {
    if (!identity) throw new Error('nobody is signed in on this page')
    if (!methods[method]) throw new Error(`no such method: ${method}`)
    post({ pinesign: 'result', id, ok: true, value: methods[method](params ?? {}) })
  } catch (err) {
    post({ pinesign: 'result', id, ok: false, error: err.message })
  }
})

// ---- boot ----

/**
 * Who opened this page, checked against the list compiled into it. An app
 * origin that is not on the list gets no messages at all — not an error, which
 * would itself be a signal; simply nothing.
 */
function openerOrigin() {
  const claimed = new URLSearchParams(location.hash.slice(1)).get('origin')
    ?? new URLSearchParams(location.search).get('origin')
  if (!claimed) return null
  return APP_ORIGINS.includes(claimed) ? claimed : null
}

appOrigin = openerOrigin()
if (window.opener && appOrigin) post({ pinesign: 'ready' })
show('step-email')
el('email').focus()
