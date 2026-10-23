/**
 * Gateway client, shared by every page.
 *
 * It never handles a private key. Anything that needs signing goes through a
 * `signer`, which in the app is a message to the sign-in window — so the
 * gateway learns who is asking without the key ever leaving the page that
 * derived it.
 */

export class Gateway {
  constructor(baseUrl) {
    this.baseUrl = baseUrl.replace(/\/$/, '')
  }

  async #json(path, options) {
    const res = await fetch(this.baseUrl + path, options)
    const body = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(body.error ?? `${res.status} ${res.statusText}`)
    return body
  }

  #post(path, body) {
    return this.#json(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
  }

  /**
   * A fresh nonce, signed — the gateway's proof of who is asking.
   *
   * The signer is handed the nonce rather than a digest. It builds the digest
   * itself, so whatever holds the key only ever signs things it recognises,
   * never an opaque 32 bytes this code chose.
   */
  async #auth(signer) {
    const pubKey = signer.publicKeyHex
    const { nonce } = await this.#post('/api/nonce', { pubKey })
    return { pubKey, nonce, signature: await signer.signNonce(nonce) }
  }

  health() {
    return this.#json('/api/health')
  }

  async send(signer, payload) {
    return this.#post('/api/send', { ...(await this.#auth(signer)), ...payload })
  }

  transfer(id) {
    return this.#json(`/api/transfer/${id}`)
  }

  async blob(id) {
    const res = await fetch(`${this.baseUrl}/api/blob/${id}`)
    if (!res.ok) throw new Error(`blob fetch failed: ${res.status}`)
    return new Uint8Array(await res.arrayBuffer())
  }

  async claim(signer, id, claimSignature, plaintextHash) {
    return this.#post('/api/claim', { ...(await this.#auth(signer)), id, claimSignature, plaintextHash })
  }

  // ---- names ----

  /** Claim a name and publish an encryption key under it. */
  async registerName(signer, label, inviteId = null) {
    return this.#post('/api/name/register', {
      ...(await this.#auth(signer)),
      label,
      inviteId,
    })
  }

  // ---- recipients ----

  /**
   * Resolve an email address to a key, or invite it. One call, because from
   * the sender's side "who is this person" is one question.
   */
  async recipient(signer, { email, fromEmail }) {
    return this.#post('/api/recipient', { ...(await this.#auth(signer)), email, fromEmail })
  }

  inviteStatus(id) {
    return this.#json(`/api/invite/${encodeURIComponent(id)}`)
  }

  async myInvites(signer) {
    return this.#post('/api/invites', await this.#auth(signer))
  }

  nameAvailable(label) {
    return this.#json(`/api/name/available/${encodeURIComponent(label)}`)
  }

  /** Name to key — how a sender finds out where to encrypt. */
  resolveName(name) {
    return this.#json(`/api/name/resolve/${encodeURIComponent(name)}`)
  }

  /** Key to name, for showing a person rather than a hex string. */
  async reverseName(pubKey) {
    try {
      return await this.#json(`/api/name/reverse/${pubKey}`)
    } catch {
      return null
    }
  }
}

export function toBase64(bytes) {
  let binary = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk))
  }
  return btoa(binary)
}
