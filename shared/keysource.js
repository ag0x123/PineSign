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

// ---- deliveries ----
//
// The app reads the delivery from the chain and the ciphertext from Swarm, and
// passes both in. It gets back a description and a verdict on the ciphertext —
// never the recipient's key half, which is what would let it decrypt early.

/**
 * Look at a delivery without agreeing to anything.
 *
 * The sign-in window checks the ciphertext against the record before it
 * returns, so a mismatch arrives as an error rather than as a description the
 * user might act on.
 */
export function inspectDelivery({ delivery, ciphertext }) {
  return call('inspect', { delivery, ciphertext: Array.from(ciphertext) })
}

/**
 * Ask for an acceptance.
 *
 * The digest must be the one read from the contract. The sign-in window shows
 * the user what it means and waits for them before touching the passkey, so
 * this call can sit unanswered for as long as they take — and can come back
 * refused, which is not an error in the app so much as an answer.
 */
export function signAccept({ digest, rpId, summary }) {
  return call('signAccept', { digest, rpId, summary })
}

/**
 * Build a delivery.
 *
 * The app supplies the file and who it is for, and gets back ciphertext, the
 * contract's parameters, and the sender's key half sealed under the sender's
 * own key. Never the half itself — so nothing downstream of here can release
 * early or hand the file to someone who never accepted.
 */
export function prepareSend(args) {
  return call('prepareSend', { ...args, plaintext: Array.from(args.plaintext) })
}

/**
 * Authorise a release.
 *
 * Two steps: the sealed blob opens to the half, and the half is what the
 * contract's release digest is computed from — so the digest cannot be asked
 * for until the half is in hand. The signature over it may be carried by
 * anyone, so the sender needs no ether, which is what lets them be the
 * releaser rather than some funded service holding everyone's halves.
 */
/** Authorise a send. The digest is the contract's, read through the gateway. */
export function signSend({ digest }) {
  return call('signSend', { digest })
}

export function openKeptHalf({ transferId, keptHalf }) {
  return call('openKeptHalf', { transferId, keptHalf: Array.from(keptHalf) })
}

export function signRelease({ digest }) {
  return call('signRelease', { digest })
}

/**
 * Open a released delivery.
 *
 * `releasedKey` is `B`, read from the chain, where it does not exist until the
 * acceptance has been recorded. So this cannot be made to work early by
 * calling it differently.
 */
export function openDelivery({ delivery, ciphertext, releasedKey }) {
  return call('open', { delivery, ciphertext: Array.from(ciphertext), releasedKey })
}
