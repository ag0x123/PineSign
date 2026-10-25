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

import { sign, signRecoverable, toHex, fromHex } from '../../shared/crypto.js'
import { createAndDerive, derive, bytesToBase64url, NoPrfError } from '../../shared/prf.js'
import { assertOverDigest } from '../../shared/passkey-sign.js'
import {
  inspectDelivery, openDelivery, prepareDelivery, openSenderHalf,
} from '../../shared/keysplit.js'
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
  for (const id of ['step-email', 'step-code', 'step-passkey', 'step-confirm', 'step-done']) {
    el(id).hidden = id !== step
  }
}

const short = (hex) => `${hex.slice(0, 10)}…${hex.slice(-8)}`

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} bytes`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

/**
 * Put the delivery in front of the user and wait for them to decide.
 *
 * Resolves on accept and rejects on decline, so the caller's `await` reads as
 * the user's answer. Nothing touches the passkey until this resolves.
 */
function confirmAccept({ description, ciphertextHash, ciphertextBytes, transferId, digest }) {
  el('c-description').textContent = description ?? 'the sender left no description'
  el('c-size').textContent = formatSize(ciphertextBytes)
  el('c-ciphertext').textContent = short(ciphertextHash)
  el('c-transfer').textContent = short(transferId)
  el('c-digest').textContent = short(digest)
  show('step-confirm')
  say('')

  return new Promise((resolve, reject) => {
    const accept = () => {
      cleanup()
      resolve(true)
    }
    const decline = () => {
      cleanup()
      show('step-done')
      reject(new Error('the recipient declined'))
    }
    function cleanup() {
      el('confirm-accept').removeEventListener('click', accept)
      el('decline-accept').removeEventListener('click', decline)
    }
    el('confirm-accept').addEventListener('click', accept)
    el('decline-accept').addEventListener('click', decline)
  })
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
   * Look at a delivery before agreeing to anything.
   *
   * Three things happen here and the order is the point. The recipient's key
   * half is derived, which needs the passkey-derived key and nothing from the
   * sender. The description is decrypted with it, so the recipient can read
   * what they are being offered. And the ciphertext is fetched and hashed
   * against the record — because accepting is a signature, and signing for an
   * envelope whose contents do not match what was promised is exactly what
   * this is meant to stop.
   *
   * No passkey tap, no signature, nothing on chain. Just a look.
   */
  inspect({ delivery, ciphertext }) {
    return inspectDelivery({ secretKey: identity.privateKey, delivery, ciphertext: new Uint8Array(ciphertext) })
  },

  /**
   * Build a delivery: encrypt the file, split the key, keep one half.
   *
   * Everything that touches a key happens here. The app gets back ciphertext,
   * an encrypted description, the parameters for the contract, and the
   * sender's half sealed under the sender's own key — which the gateway can
   * store and cannot read. It never gets the half itself, so it can neither
   * release early nor hand the file to somebody who never accepted.
   */
  prepareSend({
    sender, plaintext, description, recipientPublicKey, recipientPasskey,
    releaser, releaserPublicKey, acceptBy, releaseBy,
  }) {
    const prepared = prepareDelivery({
      sender,
      plaintext: new Uint8Array(plaintext),
      description,
      recipientPublicKey,
      recipientPasskey,
      releaser,
      // Given, the half is sealed so the releaser can read it and release
      // without the sender. Omitted, only the sender can ever open it.
      releaserPublicKey,
      acceptBy,
      releaseBy,
      senderSecretKey: identity.privateKey,
    })
    return {
      transferId: prepared.transferId,
      params: prepared.params,
      ciphertext: Array.from(prepared.ciphertext),
      description: Array.from(prepared.description),
      keptHalf: Array.from(prepared.keptHalf),
      releaseMode: prepared.releaseMode,
    }
  },

  /**
   * Open the sealed half, then authorise its release.
   *
   * Two steps because the contract's release digest is a function of the half
   * itself, so it cannot be asked for until the half is in hand. The signature
   * is over that digest, so a relayer can carry the authorisation and can
   * change nothing about it — and the sender needs no ether, which is the only
   * reason they can be the default releaser at all.
   */
  /** The sender's authorisation for their own send, relayed by the gateway. */
  signSend({ digest }) {
    return { signature: signRecoverable(fromHex(digest), identity.privateKey) }
  },

  openKeptHalf({ transferId, keptHalf }) {
    const half = openSenderHalf({
      secretKey: identity.privateKey,
      transferId,
      blob: new Uint8Array(keptHalf),
    })
    // Handed back to the sender's own page, which then needs it to ask the
    // contract for the matching release digest and to submit the release. The
    // sender is the party releasing it, so this is not a leak — it is the
    // point.
    return { releasedKey: '0x' + toHex(half) }
  },

  signRelease({ digest }) {
    return { signature: signRecoverable(fromHex(digest), identity.privateKey) }
  },

  /**
   * Sign the acceptance.
   *
   * The digest comes from the contract, not from here — it is read from the
   * chain by the caller and the contract recomputes it from its own record, so
   * a signature over anything else is refused on chain rather than trusted
   * here. What this returns is relayable by anyone and decides nothing: the
   * contract is what turns it into an acceptance.
   */
  async signAccept({ digest, rpId, summary }) {
    // The summary is rendered here and the passkey is not touched until the
    // user presses the button. An app that wanted a signature quietly would
    // have to get past a panel it does not control.
    await confirmAccept({ ...summary, digest })
    say('Waiting for your passkey…')
    const assertion = await assertOverDigest({ digest, rpId })
    show('step-done')
    say('Accepted. Waiting for the sender to release the key.')
    return assertion
  },

  /**
   * Open a delivery, once both halves exist.
   *
   * `B` comes from the chain, where it only appears after the acceptance. So
   * this cannot succeed early: without `B` there is no `K`, and the call fails
   * on a missing argument rather than on a decryption that half-works.
   */
  open({ delivery, ciphertext, releasedKey }) {
    const opened = openDelivery({
      secretKey: identity.privateKey,
      delivery,
      ciphertext: new Uint8Array(ciphertext),
      releasedKey,
    })
    return { plaintext: Array.from(opened.plaintext), plaintextHash: opened.plaintextHash }
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
