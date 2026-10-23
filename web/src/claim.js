/**
 * Claim page.
 *
 * Fetches the ciphertext and hands it to the sign-in window, which decrypts it
 * and signs the receipt in one operation. This page never holds the key, so it
 * cannot read the file without leaving a receipt behind.
 */

import { Gateway } from '../../shared/client.js'
import { signIn, signedIn, current, openTransfer, signer } from '../../shared/keysource.js'

const el = (id) => document.getElementById(id)
const gateway = new Gateway(location.origin)
const id = new URLSearchParams(location.search).get('id')

let identity = null
let transfer = null

function say(message, kind = '') {
  el('status').textContent = message
  el('status').className = `status ${kind}`.trim()
}

function subtitle(text, colour) {
  el('subtitle').textContent = text
  if (colour) el('subtitle').style.color = colour
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} bytes`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

const short = (hex) => `${hex.slice(0, 10)}…${hex.slice(-6)}`

function showReceipt(claim) {
  el('r-time').textContent = new Date(claim.claimedAt).toLocaleString()
  el('r-hash').textContent = short(transfer.plaintextHash)
  el('r-sig').textContent = short(claim.recipientSignature)
  el('receipt').hidden = false
  el('accept').disabled = true
}

async function load() {
  if (!id) return subtitle('No transfer in this link.', '#ff9c7a')

  try {
    transfer = await gateway.transfer(id)
  } catch (err) {
    return subtitle(err.message, '#ff9c7a')
  }

  el('f-name').textContent = transfer.filename
  el('f-size').textContent = formatSize(transfer.size)
  el('f-sender').textContent = transfer.senderName ?? short(transfer.senderPubKey)
  el('f-ref').textContent = short(transfer.reference)
  el('f-expires').textContent = new Date(transfer.expiresAt).toLocaleString()
  el('details').hidden = false

  if (transfer.expired) {
    return subtitle('This transfer expired. The file is gone.', '#ff9c7a')
  }

  if (transfer.claim) {
    subtitle('Already delivered.', 'var(--glow)')
    el('identity-panel').hidden = true
    return showReceipt(transfer.claim)
  }

  subtitle('Sign in to open it.')
  el('signin-panel').hidden = false
}

/**
 * Signing in is what produces the key, so it has to happen before the file can
 * be checked as addressed to anyone at all.
 */
el('signin').addEventListener('click', async () => {
  el('signin').disabled = true
  say('Waiting for the sign-in window…')
  try {
    identity = await signIn()
    el('signin-panel').hidden = true
    say('')

    const named = await gateway.reverseName(identity.publicKey)
    el('pubkey').textContent = named?.name ?? identity.publicKey
    el('key-mode').textContent =
      'Derived in the sign-in window from your passkey. It is never stored and never sent.'
    el('identity-panel').hidden = false

    // The recipient is named in the transfer itself, so a link alone opens nothing.
    if (transfer.recipientPubKey !== identity.publicKey) {
      el('identity-hint').textContent =
        'This file was sent to a different key. Give the sender the name above and ask them to send it again.'
      return subtitle('Not addressed to you.', '#ff9c7a')
    }

    el('action-panel').hidden = false
    subtitle('Waiting for you to accept.')
  } catch (err) {
    say(err.message, 'error')
    el('signin').disabled = false
  }
})

el('accept').addEventListener('click', async () => {
  el('accept').disabled = true
  try {
    say('Fetching the encrypted file…')
    const blob = await gateway.blob(id)

    // Decryption and the receipt are one step, and both happen in the sign-in
    // window: this page cannot take the file and then decline to sign for it,
    // because it never has the key to decrypt with on its own.
    say('Decrypting in the sign-in window…')
    const opened = await openTransfer({
      ciphertext: blob,
      senderPubKey: transfer.senderPubKey,
      expectedCommitment: transfer.fileCommitment,
    })

    // The hash we just derived is the proof: nobody had it before this moment
    // except the sender. Presenting it is what makes the receipt mean "opened".
    say('Recording the receipt…')
    const { claim } = await gateway.claim(await signer(), id, opened.signature, opened.plaintextHash)

    const bytes = Uint8Array.from(opened.plaintext)
    const url = URL.createObjectURL(new Blob([bytes]))
    const a = document.createElement('a')
    a.href = url
    a.download = transfer.filename
    a.click()
    URL.revokeObjectURL(url)

    say('Decrypted, verified, and receipted.', 'done')
    subtitle('Delivered.', 'var(--glow)')
    showReceipt(claim)
  } catch (err) {
    say(err.message, 'error')
    el('accept').disabled = false
  }
})

load()
