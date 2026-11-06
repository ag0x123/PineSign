// Spike 4 — passkey PRF in a real browser, via Chrome's CDP virtual authenticator.
// Creates a credential, asks for the PRF extension, derives X25519 and secp256k1 keys from the
// PRF output, and takes a real P-256 assertion which is then verified against the credential's
// own public key.
import http from 'node:http'
import { chromium } from 'playwright'
import { p256 } from '@noble/curves/nist.js'

const PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>prf</title></head><body><script>
const b64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'')
const bytes = (b) => Array.from(new Uint8Array(b))

async function hkdf(secret, info) {
  const key = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits'])
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode('pinesign/v1'), info: new TextEncoder().encode(info) },
    key, 256))
}

window.run = async () => {
  const out = {}
  const challenge = crypto.getRandomValues(new Uint8Array(32))
  const cred = await navigator.credentials.create({ publicKey: {
    challenge,
    rp: { id: 'localhost', name: 'PineSign spike' },
    user: { id: new Uint8Array([1,2,3,4]), name: 'alice@example.com', displayName: 'Alice' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    extensions: { prf: {} },
  }})
  out.created = !!cred
  out.credentialId = b64u(cred.rawId)
  const createExt = cred.getClientExtensionResults()
  out.prfSupportedAtCreate = !!createExt.prf
  out.createExtensions = Object.keys(createExt)

  // the credential's own P-256 public key, for verifying the assertion later
  const spki = cred.response.getPublicKey()
  out.publicKeySpki = bytes(spki)
  out.publicKeyAlg = cred.response.getPublicKeyAlgorithm()

  // --- PRF evaluation on an assertion
  const challenge2 = crypto.getRandomValues(new Uint8Array(32))
  const assertion = await navigator.credentials.get({ publicKey: {
    challenge: challenge2,
    rpId: 'localhost',
    allowCredentials: [{ type: 'public-key', id: cred.rawId }],
    userVerification: 'required',
    extensions: { prf: { eval: { first: new TextEncoder().encode('pinesign/v1') } } },
  }})
  const getExt = assertion.getClientExtensionResults()
  out.getExtensions = Object.keys(getExt)
  out.prfResultsPresent = !!(getExt.prf && getExt.prf.results && getExt.prf.results.first)

  if (out.prfResultsPresent) {
    const prf = new Uint8Array(getExt.prf.results.first)
    out.prfBytes = prf.length
    out.x25519 = bytes(await hkdf(prf, 'x25519'))
    out.secp256k1 = bytes(await hkdf(prf, 'secp256k1'))

    // stability: the same salt must give the same bytes on a second assertion
    const a2 = await navigator.credentials.get({ publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: 'localhost',
      allowCredentials: [{ type: 'public-key', id: cred.rawId }], userVerification: 'required',
      extensions: { prf: { eval: { first: new TextEncoder().encode('pinesign/v1') } } },
    }})
    const prf2 = new Uint8Array(a2.getClientExtensionResults().prf.results.first)
    out.prfStableAcrossAssertions = prf.length === prf2.length && prf.every((v, i) => v === prf2[i])
  }

  // --- the real P-256 signature the chain would check
  out.assertion = {
    authenticatorData: bytes(assertion.response.authenticatorData),
    clientDataJSON: bytes(assertion.response.clientDataJSON),
    signature: bytes(assertion.response.signature),
  }
  return out
}
</script></body></html>`

const server = http.createServer((_, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(PAGE) })
await new Promise((r) => server.listen(0, '127.0.0.1', r))
const port = server.address().port

const out = { browser: null }
let browser
try {
  browser = await chromium.launch({ channel: 'chrome', headless: true })
  out.browser = browser.version()
  const ctx = await browser.newContext()
  const page = await ctx.newPage()
  const cdp = await ctx.newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true },
  })
  out.authenticatorId = authenticatorId
  await page.goto(`http://localhost:${port}/`)
  Object.assign(out, await page.evaluate(() => window.run()))
} catch (e) {
  out.error = (e?.message ?? String(e)).split('\n').slice(0, 4).join(' | ').slice(0, 400)
} finally {
  await browser?.close()
  server.close()
}

// --- verify the assertion's P-256 signature off-browser
if (out.assertion && out.publicKeySpki) {
  const { sha256 } = await import('@noble/hashes/sha2.js')
  const spki = Uint8Array.from(out.publicKeySpki)
  const pub = spki.slice(spki.length - 65)
  const authData = Uint8Array.from(out.assertion.authenticatorData)
  const clientHash = sha256(Uint8Array.from(out.assertion.clientDataJSON))
  const signed = sha256(new Uint8Array([...authData, ...clientHash]))
  const der = Uint8Array.from(out.assertion.signature)
  // noble's verify defaults to lowS: true and rejects a high-s signature. Authenticators emit
  // high-s freely and nothing in WebAuthn normalises it, so a verifier must accept both. The
  // EIP-7951 precompile accepts both too, which is why the chain side does not care.
  const sigObj = p256.Signature.fromBytes(der, 'der')
  out.signatureHighS = sigObj.hasHighS()
  const raw = new Uint8Array([...authData, ...clientHash])
  const tryVerify = (msg, opts) => { try { return p256.verify(der, msg, pub, { format: 'der', ...opts }) } catch (e) { return 'ERR ' + e.message.slice(0, 60) } }
  out.verifyMatrix = {
    hashedMsg_lowS: tryVerify(signed, {}),
    hashedMsg_anyS: tryVerify(signed, { lowS: false }),
    rawMsg_anyS: tryVerify(raw, { lowS: false }),
    rawMsg_prehashTrue: tryVerify(raw, { lowS: false, prehash: true }),
  }
  out.p256AssertionVerifies = Object.values(out.verifyMatrix).some((v) => v === true)
  out.signatureBytesDer = der.length
  delete out.assertion
  delete out.publicKeySpki
}
out.derivedX25519Bytes = out.x25519?.length
out.derivedSecp256k1Bytes = out.secp256k1?.length
delete out.x25519; delete out.secp256k1
out.PASS = out.prfResultsPresent === true && out.prfStableAcrossAssertions === true && out.p256AssertionVerifies === true
console.log(JSON.stringify(out, null, 2))
