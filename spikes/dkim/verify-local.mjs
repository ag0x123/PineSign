// A local DKIM check you can run on a real email without handing the email to anyone.
//
//   node verify-local.mjs /path/to/message.eml
//
// Everything happens in this process. The only thing that leaves the machine is a DNS TXT lookup
// for <selector>._domainkey.<signing domain> — that asks "what is gmail.com's public key", and
// carries neither the local part of any address nor a byte of the message.
//
// What it prints is deliberately redacted: signing domain, selector, pass/fail, and whether the
// Pinesign key and signature in the body check out. No addresses, no subject, no body.
import fs from 'node:fs'
import { dkimVerify } from 'mailauth'
import { p256 } from '@noble/curves/nist.js'
import { sha256 } from '@noble/hashes/sha2.js'

const path = process.argv[2]
if (!path) {
  console.error('usage: node verify-local.mjs /path/to/message.eml')
  process.exit(2)
}

const eml = fs.readFileSync(path)
const out = { file: path.replace(/^.*\//, ''), emlBytes: eml.length }

// --- the signature itself
const r = await dkimVerify(eml)
out.signatures = (r.results || []).map((s) => ({
  signingDomain: s.signingDomain,
  selector: s.selector,
  algo: s.algo,
  result: s.status?.result,
  comment: s.status?.comment || undefined,
  bodyHashMatches: s.bodyHash ? s.status?.result === 'pass' : undefined,
  keyBits: s.publicKey ? Buffer.from(s.publicKey, 'base64').length * 8 : undefined,
}))
out.dkimPass = out.signatures.some((s) => s.result === 'pass')

// --- the Pinesign payload, dug out of whatever encoding the provider chose
//
// Gmail sends the body quoted-printable with a soft line break every 76 columns, or base64 for
// the HTML alternative. Either one cuts a 130-character hex string in half, so search the raw
// bytes, the same bytes with soft breaks removed, and every base64 part decoded.
const candidates = [eml.toString('utf8')]
candidates.push(candidates[0].replace(/=\r?\n/g, ''))
for (const blob of candidates[0].match(/(?:[A-Za-z0-9+/]{60,}\r?\n)+[A-Za-z0-9+/]*={0,2}/g) || []) {
  try { candidates.push(Buffer.from(blob.replace(/\s/g, ''), 'base64').toString('utf8')) } catch {}
}
const hunt = (re) => { for (const c of candidates) { const m = c.match(re); if (m) return m[1] } return null }

const keyHex = hunt(/pinesign-key:\s*(0x[0-9a-fA-F]{130})/)
const sigHex = hunt(/pinesign-sig:\s*(0x[0-9a-fA-F]{128})/)
out.keyInBody = !!keyHex
out.sigInBody = !!sigHex
if (keyHex && sigHex) {
  const challenge = sha256(new TextEncoder().encode('pinesign/invite/accept'))
  const key = Uint8Array.from(Buffer.from(keyHex.slice(2), 'hex'))
  const sig = Uint8Array.from(Buffer.from(sigHex.slice(2), 'hex'))
  // The accept is only meaningful if the same message both carries the key and is DKIM-signed by
  // the provider: the signature proves the key, DKIM proves the sender.
  out.p256Verifies = p256.verify(sig, challenge, key)
  out.keyFingerprint = '0x' + Buffer.from(sha256(key)).toString('hex').slice(0, 16)
}

out.PASS = out.dkimPass === true && out.keyInBody === true && out.sigInBody === true && out.p256Verifies === true
console.log(JSON.stringify(out, null, 2))
