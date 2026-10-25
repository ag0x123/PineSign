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
   * The field is `signature`, so no payload may use that name: spreading a
   * payload over this would replace the nonce signature with something else
   * and the request would fail as "bad signature" with nothing to suggest why.
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

  // ---- deliveries ----

  /** Who this gateway is, if a sender wants it to release on their behalf. */
  releaser() {
    return this.#json('/api/delivery/releaser')
  }

  /** The digest the sender signs, computed by the contract. */
  async sendDigest(signer, params) {
    return this.#post('/api/delivery/send-digest', { ...(await this.#auth(signer)), params })
  }

  /** Record a delivery the signing window has already built. */
  async sendDelivery(signer, payload) {
    return this.#post('/api/delivery', { ...(await this.#auth(signer)), ...payload })
  }

  delivery(id) {
    return this.#json(`/api/delivery/${strip(id)}`)
  }

  async deliveryBlob(id) {
    const res = await fetch(`${this.baseUrl}/api/delivery/${strip(id)}/blob`)
    if (!res.ok) throw new Error(`blob fetch failed: ${res.status}`)
    return new Uint8Array(await res.arrayBuffer())
  }

  /**
   * Carry an acceptance. Unauthenticated by design: the assertion is the
   * authentication and the contract is what checks it, so a recipient is not
   * made to hold a session with this particular gateway.
   */
  acceptDelivery(id, assertion) {
    return this.#post(`/api/delivery/${strip(id)}/accept`, { assertion })
  }

  /** The sender's sealed key half, back to the only party who can open it. */
  async keptHalf(signer, id) {
    return this.#post(`/api/delivery/${strip(id)}/kept-half`, await this.#auth(signer))
  }

  releaseDigest(id, releasedKey) {
    return this.#json(`/api/delivery/${strip(id)}/release-digest/${strip(releasedKey)}`)
  }

  releaseDelivery(id, { releasedKey, signature }) {
    return this.#post(`/api/delivery/${strip(id)}/release`, { releasedKey, signature })
  }

  expireDelivery(id) {
    return this.#post(`/api/delivery/${strip(id)}/expire`, {})
  }

  async myDeliveries(signer) {
    return this.#post('/api/deliveries', await this.#auth(signer))
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

/** Ids and keys travel with or without 0x; the routes want them without. */
function strip(value) {
  return String(value).replace(/^0x/, '')
}

export function toBase64(bytes) {
  let binary = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk))
  }
  return btoa(binary)
}
