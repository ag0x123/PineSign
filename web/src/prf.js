/**
 * The passkey test page.
 *
 * One question: does the same passkey, used on two different devices, derive
 * the same keys? If it does not, a recipient who accepts on his phone cannot
 * decrypt on his laptop, and Pinesign needs a backup key it currently has no
 * design for. So this page exists to be opened twice and compared, and it
 * prints the derived public keys in full rather than a verdict.
 *
 * Nothing is sent anywhere. The PRF output never leaves the page, and the
 * private keys are derived, printed as public halves, and dropped.
 */

import { x25519 } from '@noble/curves/ed25519'
import { secp256k1 } from '@noble/curves/secp256k1'
import { p256 } from '@noble/curves/p256'

const SALT = 'pinesign/v1'
const encoder = new TextEncoder()

const el = (id) => document.getElementById(id)
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')

function show(id, value) {
  el(id).textContent = value
}

function status(message, kind = '') {
  const node = el('status')
  node.textContent = message
  node.className = kind
}

/**
 * HKDF-SHA256 over the PRF output, one info string per curve.
 *
 * WebCrypto rather than a bundled HKDF so the derivation is the platform's own,
 * and so this page would give the same answer in any browser that implements
 * the standard.
 */
async function derive(prf, info) {
  const key = await crypto.subtle.importKey('raw', prf, 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: encoder.encode(SALT), info: encoder.encode(info) },
    key,
    256
  )
  return new Uint8Array(bits)
}

/**
 * secp256k1 rejects a few scalars, and a curve that silently fixed one up would
 * derive a different key on a different implementation. The counter goes into
 * the info string and the first in-range candidate wins, which is deterministic
 * and the same answer everywhere.
 */
async function deriveValid(prf, info, isValid) {
  for (let counter = 0; counter < 256; counter++) {
    const candidate = await derive(prf, `${info}/${counter}`)
    if (isValid(candidate)) return candidate
  }
  throw new Error(`could not derive a ${info} key from this passkey`)
}

function prfOutput(credential) {
  const results = credential?.getClientExtensionResults?.()?.prf?.results
  if (!results?.first) {
    throw new Error(
      'This authenticator did not return a PRF result. iCloud Keychain, Google Password Manager, ' +
        '1Password, Bitwarden and Chrome profile passkeys do; most hardware keys do not.'
    )
  }
  return new Uint8Array(results.first)
}

const challenge = () => crypto.getRandomValues(new Uint8Array(32))

/** The same salt on every device and every visit, or the keys would never match. */
const prfInput = { eval: { first: encoder.encode('pinesign/prf/v1') } }

async function create() {
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: challenge(),
      rp: { id: location.hostname, name: 'Pinesign' },
      user: {
        // A fixed user handle, so creating on a second device joins the same
        // credential in the password manager instead of making a new one.
        id: encoder.encode('pinesign-prf-test'),
        name: 'prf-test@pinesign.xyz',
        displayName: 'Pinesign PRF test',
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      extensions: { prf: prfInput },
    },
  })
  // An authenticator is allowed to return no PRF result on creation, and
  // several do, so the key always comes from an assertion.
  return credential
}

async function assert() {
  return navigator.credentials.get({
    publicKey: {
      challenge: challenge(),
      rpId: location.hostname,
      userVerification: 'required',
      extensions: { prf: prfInput },
    },
  })
}

async function report(credential) {
  const prf = prfOutput(credential)
  show('prf-bytes', `${prf.length} bytes`)
  // A fingerprint of the PRF output itself, so two devices can be compared at a
  // glance without either of them showing the secret.
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', prf))
  show('prf-fingerprint', hex(digest).slice(0, 32))

  const xPriv = await derive(prf, 'x25519')
  show('x25519', hex(x25519.getPublicKey(xPriv)))

  const kPriv = await deriveValid(prf, `${SALT}/key`, (c) => secp256k1.utils.isValidPrivateKey(c))
  show('secp256k1', hex(secp256k1.getPublicKey(kPriv, true)))

  const pPriv = await deriveValid(prf, `${SALT}/p256`, (c) => {
    try {
      p256.getPublicKey(c, false)
      return true
    } catch {
      return false
    }
  })
  show('p256', hex(p256.getPublicKey(pPriv, false)))

  show('credential-id', credential.id)
  el('results').hidden = false
}

async function run(which) {
  el('results').hidden = true
  try {
    status(which === 'create' ? 'Creating a passkey…' : 'Asking for your passkey…')
    if (which === 'create') await create()
    status('Deriving…')
    await report(await assert())
    status('Done. Compare the keys below with the other device.', 'ok')
  } catch (error) {
    status(error.message || String(error), 'bad')
  }
}

function environment() {
  const ua = navigator.userAgent
  const lines = [
    ['Origin', location.origin],
    ['Relying party', location.hostname],
    ['Platform', navigator.platform ?? 'unknown'],
    ['Browser', ua],
    ['Screen', `${screen.width}×${screen.height} @${devicePixelRatio}×`],
    ['Touch points', navigator.maxTouchPoints ?? 0],
  ]
  el('environment').innerHTML = lines
    .map(([k, v]) => `<div class="row"><span>${k}</span><code>${v}</code></div>`)
    .join('')
}

async function support() {
  if (!window.PublicKeyCredential) return status('This browser has no WebAuthn at all.', 'bad')
  const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?.()
  show('platform-authenticator', available ? 'yes' : 'no')
  if (location.protocol !== 'https:' && location.hostname !== 'localhost') {
    status('Passkeys need HTTPS. This page will not work over plain HTTP.', 'bad')
  }
}

environment()
support()
el('create').addEventListener('click', () => run('create'))
el('signin').addEventListener('click', () => run('signin'))
