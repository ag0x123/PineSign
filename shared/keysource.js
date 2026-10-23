/**
 * The app's handle on a key it is not allowed to have.
 *
 * The private key lives in the sign-in page, which is served from its own
 * origin so that this code — and anything else the gateway serves — cannot
 * assert the passkey or read what it derives. What the app gets is a window it
 * can ask questions of.
 *
 * So every operation here is a round trip: the app sends bytes in and gets a
 * result out. Plaintext, ciphertext and signatures cross that boundary. The key
 * never does.
 */

const SIGNIN_URL = __PINESIGN_SIGNIN_URL__

const ORIGIN = new URL(SIGNIN_URL).origin

let popup = null
let ready = null
let session = null
let nextId = 1
const pending = new Map()

addEventListener('message', (event) => {
  if (event.origin !== ORIGIN) return
  const { pinesign, id, ok, value, error, identity } = event.data ?? {}

  if (pinesign === 'signedin') {
    session = identity
    ready?.resolve(identity)
    return
  }

  if (pinesign === 'result') {
    const waiting = pending.get(id)
    if (!waiting) return
    pending.delete(id)
    ok ? waiting.resolve(value) : waiting.reject(new Error(error))
  }
})

/** Whoever is signed in, if the sign-in window has told us. */
export function current() {
  return session
}

export function signedIn() {
  return Boolean(session) && Boolean(popup) && !popup.closed
}

/**
 * Open the sign-in page and wait for it to report back.
 *
 * A popup, so the page keeps its own origin and the key stays in it. If the
 * browser refuses to open one, the caller is told — the fallback is a full
 * redirect, which the app has to drive because it loses this page.
 */
export function signIn() {
  if (signedIn()) return Promise.resolve(session)

  const url = `${SIGNIN_URL}#origin=${encodeURIComponent(location.origin)}`
  popup = window.open(url, 'pinesign-signin', 'width=440,height=620,noopener=no')
  if (!popup) {
    return Promise.reject(Object.assign(
      new Error('Your browser blocked the sign-in window. Allow pop-ups for this site, or use the link to sign in.'),
      { code: 'popup-blocked', url: `${SIGNIN_URL}?return=${encodeURIComponent(location.href)}` },
    ))
  }

  return new Promise((resolve, reject) => {
    ready = { resolve, reject }
    // A window the user simply closed is not an error worth a stack trace, but
    // the promise still has to settle or the caller waits for ever.
    const watch = setInterval(() => {
      if (!popup || popup.closed) {
        clearInterval(watch)
        if (!session) reject(new Error('the sign-in window was closed'))
      }
      if (session) clearInterval(watch)
    }, 400)
  })
}

export function signOut() {
  popup?.close()
  popup = null
  session = null
}

function call(method, params) {
  if (!signedIn()) {
    return Promise.reject(new Error('sign in first — the key lives in the sign-in window'))
  }
  const id = nextId++
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject })
    popup.postMessage({ pinesign: 'rpc', id, method, params }, ORIGIN)
  })
}

export async function identity() {
  return session ?? call('identity')
}

/**
 * A signer in the shape the gateway client expects. Signing happens in the
 * sign-in window; this is only the message that asks for it.
 */
export async function signer() {
  const id = await identity()
  return {
    publicKeyHex: id.publicKey,
    address: id.address,
    async signNonce(nonce) {
      const { signature } = await call('signNonce', { nonce })
      return signature
    },
  }
}

/** Encrypt a file for a recipient and sign for having sent it. */
export function encryptFor({ plaintext, recipientPubKey }) {
  return call('encryptFor', { plaintext: Array.from(plaintext), recipientPubKey })
}

/** Decrypt a transfer and sign its receipt — one step, so neither can be skipped. */
export function openTransfer({ ciphertext, senderPubKey, expectedCommitment }) {
  return call('openTransfer', { ciphertext: Array.from(ciphertext), senderPubKey, expectedCommitment })
}
