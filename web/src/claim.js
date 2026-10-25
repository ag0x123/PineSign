/**
 * Claim page: inspect, accept, open.
 *
 * The order is the whole mechanism and this page cannot shortcut it. It holds
 * no key, so it cannot decrypt; the sign-in window holds the key but needs the
 * sender's half, which does not exist on chain until the acceptance is
 * recorded. Reading the file without accepting is not refused here — it is
 * arithmetically unavailable.
 */

import { Gateway } from '../../shared/client.js'
import {
  signIn, signedIn, current, inspectDelivery, signAccept, openDelivery, signer,
} from '../../shared/keysource.js'

const el = (id) => document.getElementById(id)
const gateway = new Gateway(location.origin)
const id = new URLSearchParams(location.search).get('id')

let identity = null
let record = null
let ciphertext = null

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

async function load() {
  if (!id) return subtitle('No delivery in this link.', '#ff9c7a')

  try {
    record = await gateway.delivery(id)
  } catch (err) {
    return subtitle(err.message, '#ff9c7a')
  }

  el('f-name').textContent = record.filename ?? '—'
  el('f-size').textContent = record.size ? formatSize(record.size) : '—'
  el('f-sender').textContent = record.senderName ?? '—'
  el('f-state').textContent = record.state
  el('f-contract').textContent = short(record.contract)
  el('details').hidden = false

  if (record.state === 'Expired' || record.state === 'SenderAborted') {
    return subtitle(
      record.state === 'Expired' ? 'This delivery lapsed.' : 'The sender withdrew this.',
      '#ff9c7a',
    )
  }

  subtitle('Sign in to look at it.')
  el('signin-panel').hidden = false
}

// ---- sign in ----

el('signin').addEventListener('click', async () => {
  el('signin').disabled = true
  say('Waiting for the sign-in window…')
  try {
    identity = await signIn()
    el('signin-panel').hidden = true
    say('')

    const named = await gateway.reverseName(identity.publicKey)
    el('pubkey').textContent = named?.name ?? identity.publicKey
    el('identity-panel').hidden = false

    await inspect()
  } catch (err) {
    say(err.message, 'error')
    el('signin').disabled = false
  }
})

/**
 * Look, before agreeing to anything.
 *
 * The ciphertext is fetched and checked against the record inside the sign-in
 * window, which refuses if it does not match — so the description shown beside
 * it is never a description of some other file.
 */
async function inspect() {
  say('Fetching the file and checking it…')
  ciphertext = await gateway.deliveryBlob(id)

  let seen
  try {
    seen = await inspectDelivery({ delivery: record, ciphertext })
  } catch (err) {
    // Either it is not addressed to this key, or the stored file is not the
    // one committed to. Both are reasons not to accept.
    el('identity-hint').textContent = err.message
    return subtitle('Do not accept this.', '#ff9c7a')
  }

  el('d-description').textContent = seen.description ?? 'the sender left no description'
  el('d-stored').textContent = short(seen.ciphertextHash)
  el('inspected').hidden = false

  if (record.state === 'Released') {
    subtitle('Accepted and released.')
    el('open-panel').hidden = false
    return
  }
  if (record.state === 'Accepted') {
    subtitle('Accepted. Waiting for the sender to release the key.')
    el('waiting-panel').hidden = false
    return
  }

  subtitle('Waiting for you to accept.')
  el('accept-panel').hidden = false
}

// ---- accept ----

el('accept').addEventListener('click', async () => {
  el('accept').disabled = true
  try {
    // The summary and the passkey tap both happen in the sign-in window. This
    // page cannot obtain an acceptance without the recipient reading it there.
    say('Confirm in the sign-in window…')
    const assertion = await signAccept({
      digest: record.acceptDigest,
      // From the gateway, not guessed: the contract stores only the hash of
      // it, and deriving it from this page's hostname would be wrong as soon
      // as either name changed.
      rpId: record.rpId,
      summary: {
        description: el('d-description').textContent,
        ciphertextHash: record.ciphertextHash,
        ciphertextBytes: ciphertext.length,
        transferId: record.id,
      },
    })

    say('Recording your acceptance on chain…')
    const accepted = await gateway.acceptDelivery(id, assertion)

    record = await gateway.delivery(id)
    el('f-state').textContent = record.state
    el('accept-panel').hidden = true
    el('waiting-panel').hidden = false
    el('accept-tx').textContent = accepted.tx
    subtitle('Accepted. Waiting for the sender to release the key.')
    say('', 'done')
  } catch (err) {
    say(err.message, 'error')
    el('accept').disabled = false
  }
})

// ---- open ----

el('open').addEventListener('click', async () => {
  el('open').disabled = true
  try {
    record = await gateway.delivery(id)
    if (record.state !== 'Released') {
      el('open').disabled = false
      return say('The sender has not released the key yet.', 'error')
    }

    // Both halves exist now. The decryption happens in the sign-in window,
    // which is the only place either half can be combined.
    say('Opening it in the sign-in window…')
    const opened = await openDelivery({
      delivery: record,
      ciphertext,
      releasedKey: record.releasedKey,
    })

    const bytes = Uint8Array.from(opened.plaintext)
    const url = URL.createObjectURL(new Blob([bytes]))
    const a = document.createElement('a')
    a.href = url
    a.download = record.filename ?? 'file'
    a.click()
    URL.revokeObjectURL(url)

    el('r-hash').textContent = short(opened.plaintextHash)
    el('receipt').hidden = false
    say('Decrypted, and it matches what the sender committed to.', 'done')
  } catch (err) {
    say(err.message, 'error')
    el('open').disabled = false
  }
})

// ---- waiting ----

el('refresh').addEventListener('click', async () => {
  try {
    record = await gateway.delivery(id)
    el('f-state').textContent = record.state
    if (record.state === 'Released') {
      el('waiting-panel').hidden = true
      el('open-panel').hidden = false
      subtitle('Released. You can open it now.')
    } else {
      say(`Still ${record.state.toLowerCase()}.`)
    }
  } catch (err) {
    say(err.message, 'error')
  }
})

if (signedIn()) identity = current()
load()
