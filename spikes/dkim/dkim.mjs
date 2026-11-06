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
//
// A real provider does not hand us the body as we typed it: Gmail sends it quoted-printable with
// soft line breaks every 76 columns, or base64 for the HTML alternative, either of which cuts a
// 130-character hex string in half. So search the raw bytes, the same bytes with soft breaks
// removed, and every base64 part decoded, and take the first candidate that yields a key.
const candidates = [eml.toString('utf8')]
candidates.push(candidates[0].replace(/=\r?\n/g, ''))
for (const blob of candidates[0].match(/(?:[A-Za-z0-9+/]{60,}\r?\n)+[A-Za-z0-9+/]*={0,2}/g) || []) {
  try { candidates.push(Buffer.from(blob.replace(/\s/g, ''), 'base64').toString('utf8')) } catch {}
}
const hunt = (re) => { for (const c of candidates) { const m = c.match(re); if (m) return m[1] } return null }

const foundKey = hunt(/pinesign-key:\s*(0x[0-9a-fA-F]{130})/)
out.publicKeyInBody = !!foundKey
if (foundKey) {
  const extracted = Uint8Array.from(Buffer.from(foundKey.slice(2), 'hex'))
  out.extractedKeyBytes = extracted.length
  // In real mode the keypair in this file is not the one in the email, so the signature has to
  // travel with the key. Fall back to the locally made one only for the self-signed path.
  const foundSig = hunt(/pinesign-sig:\s*(0x[0-9a-fA-F]{128})/)
  out.signatureInBody = !!foundSig
  out.extractedKeyMatches = foundSig ? undefined : Buffer.from(extracted).equals(Buffer.from(pub))
  const sig = foundSig ? Uint8Array.from(Buffer.from(foundSig.slice(2), 'hex')) : sigOverChallenge
  out.p256SignatureVerifiesWithExtractedKey = p256.verify(sig, challenge, extracted)
}

out.PASS = out.dkimPass === true && out.publicKeyInBody === true && out.p256SignatureVerifiesWithExtractedKey === true
out.CAVEAT = fs.existsSync(SAMPLE) ? null : 'Ran against a self-signed message, so it proves the verifier and the key extraction, not a real provider signature. Drop a real .eml at spikes/dkim/sample.eml and rerun for that.'
console.log(JSON.stringify(out, null, 2))
