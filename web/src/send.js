/**
 * Send page.
 *
 * The file is read here and everything else happens in the sign-in window:
 * encryption, the key split, and holding back one half. What leaves this page
 * is ciphertext, a set of commitments for the contract, and that half sealed
 * under the sender's own key — which the gateway stores and cannot read.
 *
 * Releasing is a second visit. The recipient has to accept on chain first, and
 * until they do there is nothing to release and no way to release it.
 */

import { Gateway, toBase64 } from '../../shared/client.js'
import {
  signIn, signedIn, current, prepareSend, openKeptHalf, signRelease, signer,
} from '../../shared/keysource.js'

const el = (id) => document.getElementById(id)
const gateway = new Gateway(location.origin)

/** How long the recipient has to accept, and the sender to release after. */
const ACCEPT_WINDOW_S = 7 * 24 * 60 * 60
const RELEASE_WINDOW_S = 14 * 24 * 60 * 60

let identity = null
let me = null
let recipient = null
let file = null

function say(message, kind = '') {
  el('status').textContent = message
  el('status').className = `status ${kind}`.trim()
}

const validEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)

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
  await refreshOutbox()

  // Arrived from the "they accepted" email.
  const toRelease = new URLSearchParams(location.search).get('release')
  if (toRelease) await offerRelease(toRelease)
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

    if (result.known && result.passkeyX) {
      recipient = result
      el('to-result').textContent = `${result.name} — encrypting to their published key.`
      el('to-result').className = 'resolved ok'
    } else if (result.known) {
      // A name without a registered credential cannot accept on chain, so
      // there is nothing to send to yet even though they exist.
      recipient = null
      el('to-result').textContent =
        `${result.name} has not signed in since deliveries were introduced, so they cannot accept yet.`
      el('to-result').className = 'resolved error'
    } else {
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
    const now = Math.floor(Date.now() / 1000)

    // Everything that touches a key happens in the sign-in window. This page
    // never sees the file's key or either half of it.
    say('Encrypting and splitting the key in the sign-in window…')
    const prepared = await prepareSend({
      sender: identity.address,
      plaintext,
      description: el('description').value.trim() || `${file.name}, ${formatSize(file.size)}`,
      recipientPublicKey: recipient.pubKey,
      recipientPasskey: { x: recipient.passkeyX, y: recipient.passkeyY },
      // The sender releases, by default and without needing any ether: the
      // release is signed here and carried by whoever will carry it.
      releaser: identity.address,
      acceptBy: String(now + ACCEPT_WINDOW_S),
      releaseBy: String(now + RELEASE_WINDOW_S),
    })

    say('Storing the file and recording the delivery…')
    const sent = await gateway.sendDelivery(await signer(), {
      transferId: prepared.transferId,
      params: prepared.params,
      recipientPubKey: recipient.pubKey,
      ciphertext: toBase64(Uint8Array.from(prepared.ciphertext)),
      description: toBase64(Uint8Array.from(prepared.description)),
      keptHalf: prepared.keptHalf,
      filename: file.name,
      recipientEmail: el('to').value.trim(),
    })

    el('sent-link').textContent = `${location.origin}/claim.html?id=${sent.id}`
    el('sent-link').href = `/claim.html?id=${sent.id}`
    el('sent-tx').textContent = sent.tx
    el('sent').hidden = false
    el('compose').hidden = true
    say('Sent. They cannot open it until they accept on chain, and you release.', 'done')
    await refreshOutbox()
  } catch (err) {
    say(err.message, 'error')
    el('send').disabled = false
  }
})

// ---- release ----

/**
 * Release the held-back half.
 *
 * Only reachable once the contract says `Accepted`. The sealed half comes back
 * from the gateway, is opened in the sign-in window, and the signature
 * authorising this one release is made there too — so the sender needs no
 * ether and the gateway never holds anything it could release on its own.
 */
async function offerRelease(id) {
  try {
    const d = await gateway.delivery(id)
    el('release-file').textContent = d.filename ?? id
    el('release-state').textContent = d.state
    el('release-panel').hidden = false
    el('release-go').disabled = d.state !== 'Accepted'
    el('release-go').dataset.id = id
    if (d.state !== 'Accepted') {
      el('release-note').textContent =
        d.state === 'Sent'
          ? 'They have not accepted yet. There is nothing to release until they do.'
          : `This delivery is ${d.state.toLowerCase()}.`
    } else {
      el('release-note').textContent = 'They accepted. Releasing lets them open the file.'
    }
  } catch (err) {
    say(err.message, 'error')
  }
}

el('release-go').addEventListener('click', async () => {
  const id = el('release-go').dataset.id
  el('release-go').disabled = true
  say('Fetching your sealed half…')
  try {
    const { keptHalf, transferId } = await gateway.keptHalf(await signer(), id)

    // The half opens in the sign-in window; the digest is then the contract's
    // to compute from it, and the signature over that digest is made in the
    // window too.
    say('Opening it in the sign-in window…')
    const { releasedKey } = await openKeptHalf({ transferId, keptHalf })
    const { digest } = await gateway.releaseDigest(id, releasedKey)
    const { signature } = await signRelease({ digest })

    say('Releasing…')
    const released = await gateway.releaseDelivery(id, { releasedKey, signature })
    el('release-state').textContent = released.state
    el('release-note').textContent = 'Released. They can open it now.'
    say('Released.', 'done')
    await refreshOutbox()
  } catch (err) {
    say(err.message, 'error')
    el('release-go').disabled = false
  }
})

// ---- the outbox ----

async function refreshOutbox() {
  try {
    const mine = await gateway.myDeliveries(await signer())
    el('outbox').hidden = mine.length === 0
    el('outbox-items').innerHTML = mine
      .map(
        (d) =>
          `<li><span class="who">${d.filename ?? d.id.slice(0, 10)}</span>` +
          `<span class="st ${d.state?.toLowerCase() ?? ''}">${d.state ?? '—'}</span>` +
          (d.state === 'Accepted' ? ` <a href="?release=${d.id}">release</a>` : '') +
          `</li>`,
      )
      .join('')
  } catch {
    // Not fatal; sending still works.
  }
}

// ---- boot ----

if (signedIn()) {
  identity = current()
  afterSignIn()
} else {
  el('signin-panel').hidden = false
}
