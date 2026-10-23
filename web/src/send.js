/**
 * Send page.
 *
 * The file is read here and encrypted in the sign-in window, which is the only
 * place a key exists. What leaves this page is ciphertext and a signature over
 * what was sent — produced before the gateway sees anything, so the sender's
 * half of the receipt is committed before the recipient has the file at all.
 */

import { Gateway, toBase64 } from '../../shared/client.js'
import { signIn, signedIn, current, encryptFor, signer } from '../../shared/keysource.js'

const el = (id) => document.getElementById(id)
const gateway = new Gateway(location.origin)

let identity = null
let me = null
let recipient = null
let file = null

function say(message, kind = '') {
  el('status').textContent = message
  el('status').className = `status ${kind}`.trim()
}

function validEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} bytes`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function checkReady() {
  el('send').disabled = !(recipient && file)
}

// ---- sign in ----

el('signin').addEventListener('click', async () => {
  el('signin').disabled = true
  say('Waiting for the sign-in window…')
  try {
    identity = await signIn()
    await afterSignIn()
  } catch (err) {
    say(err.message, 'error')
    if (err.code === 'popup-blocked') {
      el('signin').textContent = 'Open the sign-in page'
      el('signin').onclick = () => location.assign(err.url)
    }
    el('signin').disabled = false
  }
})

async function afterSignIn() {
  me = await gateway.reverseName(identity.publicKey)
  if (!me) {
    say('')
    el('signin-panel').hidden = true
    el('noname-panel').hidden = false
    return
  }
  el('signin-panel').hidden = true
  el('me').textContent = me.name
  el('compose').hidden = false
  say('')
}

// ---- the recipient ----

el('to').addEventListener('input', () => {
  recipient = null
  el('to-result').textContent = ''
  el('to-result').className = 'resolved'
  el('to-check').disabled = !validEmail(el('to').value.trim())
  checkReady()
})

el('to-check').addEventListener('click', async () => {
  el('to-check').disabled = true
  el('to-result').textContent = 'Looking them up…'
  el('to-result').className = 'resolved'
  try {
    const result = await gateway.recipient(await signer(), {
      email: el('to').value.trim(),
      fromEmail: el('from').value.trim() || undefined,
    })

    if (result.known) {
      recipient = result
      el('to-result').textContent = `${result.name} — encrypting to their published key.`
      el('to-result').className = 'resolved ok'
    } else {
      // Nothing can be encrypted to someone with no key, so the file waits.
      // They sign up, and the sender gets an email saying to come back.
      recipient = null
      el('to-result').textContent =
        'They have no key yet, so we have invited them. You will get an email when they are ready.'
      el('to-result').className = 'resolved'
    }
  } catch (err) {
    el('to-result').textContent = err.message
    el('to-result').className = 'resolved error'
  }
  el('to-check').disabled = false
  checkReady()
})

// ---- the file ----

el('file').addEventListener('change', () => {
  file = el('file').files?.[0] ?? null
  el('file-name').textContent = file ? `${file.name} · ${formatSize(file.size)}` : ''
  checkReady()
})

// ---- send ----

el('send').addEventListener('click', async () => {
  el('send').disabled = true
  try {
    say('Reading the file…')
    const plaintext = new Uint8Array(await file.arrayBuffer())

    // Encryption and the sender's signature happen in the sign-in window, over
    // the same digest the recipient will sign on opening it. This page cannot
    // encrypt one file and commit to another.
    say('Encrypting in the sign-in window…')
    const sealed = await encryptFor({ plaintext, recipientPubKey: recipient.pubKey })

    say('Uploading…')
    const sent = await gateway.send(await signer(), {
      recipientPubKey: recipient.pubKey,
      plaintextHash: sealed.plaintextHash,
      senderSignature: sealed.senderSignature,
      filename: file.name,
      ciphertext: toBase64(Uint8Array.from(sealed.ciphertext)),
    })

    el('sent-link').textContent = sent.claimUrl
    el('sent-link').href = sent.claimUrl
    el('sent').hidden = false
    el('compose').hidden = true
    say('Sent. You have already signed for it.', 'done')
  } catch (err) {
    say(err.message, 'error')
    el('send').disabled = false
  }
})

// ---- boot ----

if (signedIn()) {
  identity = current()
  afterSignIn()
} else {
  el('signin-panel').hidden = false
}
