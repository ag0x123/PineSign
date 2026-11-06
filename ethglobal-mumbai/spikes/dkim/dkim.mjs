// Spike 3 — DKIM verified locally, and a P-256 public key lifted out of the email body.
//
// If spikes/dkim/sample.eml exists it is verified against real DNS. Otherwise the spike builds and
// signs its own message and verifies it through an injected resolver: that exercises the same code
// path but does NOT prove a real provider's signature, so the report says which mode ran.
import fs from 'node:fs'
import crypto from 'node:crypto'
import { dkimSign, dkimVerify } from 'mailauth'
import { p256 } from '@noble/curves/nist.js'
import { sha256 } from '@noble/hashes/sha2.js'

const SAMPLE = new URL('./sample.eml', import.meta.url)
const out = {}

// --- a P-256 keypair whose public half travels in the email body, as an invite would carry it
const priv = p256.utils.randomSecretKey()
const pub = p256.getPublicKey(priv, false)
const pubHex = '0x' + Buffer.from(pub).toString('hex')
const challenge = sha256(new TextEncoder().encode('pinesign/invite/accept'))
const sigOverChallenge = p256.sign(challenge, priv)

let eml
let resolver
if (fs.existsSync(SAMPLE)) {
  eml = fs.readFileSync(SAMPLE)
  out.mode = 'real .eml, real DNS'
  out.emlBytes = eml.length
} else {
  out.mode = 'self-signed .eml, injected resolver (no sample.eml present)'
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' })
  const spki = publicKey.export({ type: 'spki', format: 'der' })
  const dnsValue = 'v=DKIM1; k=rsa; p=' + Buffer.from(spki).toString('base64')

  const raw = Buffer.from(
    'From: PineSign <no-reply@pinesign.xyz>\r\n' +
      'To: alice@example.com\r\n' +
      'Subject: Your PineSign invite\r\n' +
      'Date: Thu, 06 Nov 2026 09:00:00 +0000\r\n' +
      'Message-ID: <invite-1@pinesign.xyz>\r\n' +
      'MIME-Version: 1.0\r\n' +
      'Content-Type: text/plain; charset=utf-8\r\n' +
      '\r\n' +
      'Accept your delivery.\r\n' +
      '\r\n' +
      'pinesign-key: ' + pubHex + '\r\n'
  )
  const headers = await dkimSign(raw, {
    canonicalization: 'relaxed/relaxed',
    signatureData: [{ signingDomain: 'pinesign.xyz', selector: 'mumbai', privateKey: pem }],
  })
  eml = Buffer.concat([Buffer.from(headers.signatures), raw])
  out.emlBytes = eml.length
  resolver = async (name, type) => {
    if (type === 'TXT' && name === 'mumbai._domainkey.pinesign.xyz') return [[dnsValue]]
    const dns = await import('node:dns/promises')
    return dns.resolve(name, type)
  }
}

// --- verify
const t = Date.now()
const res = await dkimVerify(eml, resolver ? { resolver } : {})
out.verifyMs = Date.now() - t
out.results = (res.results ?? []).map((r) => ({
  signingDomain: r.signingDomain,
  selector: r.selector,
  algo: r.algo,
  status: r.status?.result,
  comment: r.status?.comment,
  spkiBytes: r.publicKey ? Buffer.from(r.publicKey, "base64").length : undefined,
  bodyHashMatches: r.bodyHash ? r.status?.result === 'pass' : undefined,
}))
out.dkimPass = out.results.some((r) => r.status === 'pass')

// --- lift the P-256 key out of the body and check a signature made with it
const body = eml.toString('utf8')
const found = body.match(/pinesign-key:\s*(0x[0-9a-fA-F]{130})/)
out.publicKeyInBody = !!found
if (found) {
  const extracted = Uint8Array.from(Buffer.from(found[1].slice(2), 'hex'))
  out.extractedKeyBytes = extracted.length
  out.extractedKeyMatches = Buffer.from(extracted).equals(Buffer.from(pub))
  out.p256SignatureVerifiesWithExtractedKey = p256.verify(sigOverChallenge, challenge, extracted)
}

out.PASS = out.dkimPass === true && out.publicKeyInBody === true && out.p256SignatureVerifiesWithExtractedKey === true
out.CAVEAT = fs.existsSync(SAMPLE) ? null : 'Ran against a self-signed message, so it proves the verifier and the key extraction, not a real provider signature. Drop a real .eml at spikes/dkim/sample.eml and rerun for that.'
console.log(JSON.stringify(out, null, 2))
