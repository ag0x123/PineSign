# Testing

Two suites run without a browser, a chain, or a Bee node:

```
npm test              # gateway and sign-in flow, 70 checks
npm run test:contracts # resolver and receipts, 14 checks
```

`npm test` starts a throwaway gateway with its own storage directory and no
credentials, so it exercises the unconfigured path and cannot touch a real
wallet. Real passkey settings are used — the ceremony checks are part of what is
being tested — and the only thing stood in for is the authenticator tap itself:
the test builds the `clientDataJSON` a browser would send, with the challenge it
was actually issued and an origin from the allow-list. Everything downstream of
the tap is the real code, including the HKDF derivation from a PRF output.

The emailed code is read back from the gateway's own log. With no Resend key
set, the gateway prints the message it would have sent, which is what a
developer sees locally. Nothing is faked to obtain it.

## What the automated suite cannot reach

Three things need a real browser and a real authenticator:

1. **The PRF extension.** Whether a given passkey provider returns a PRF result
   at all, and whether it returns the same one on another device.
2. **The popup boundary.** That the app really cannot read the key, and that
   `postMessage` origin checks hold in both directions.
3. **rpId scoping.** That a page on the parent domain cannot assert a credential
   scoped to the sign-in subdomain — the property the whole design rests on.

The checklist below covers them. Run it against a deployment, not localhost:
passkeys are origin-bound, and localhost does not have the subdomain structure
the scoping depends on.

---

# Manual end-to-end checklist

Needs: the gateway deployed, `SIGNIN_DOMAIN` set, a version published with
`npm run publish-page`, Resend configured, and a passkey provider that supports
PRF (1Password, Bitwarden, Proton Pass, Dashlane, or a Chrome profile passkey).

## 1. Sign up

- [ ] Open the app. Click **Sign in**. A window opens on
      `v1.<signin domain>` — check the address bar says that, not the app's host.
- [ ] Enter an email. A six-digit code arrives within a few seconds.
- [ ] Enter a wrong code. It is refused and you can try again.
- [ ] Enter the right code. You are asked for a passkey, and the text says
      *create*, not *use the one you signed up with*.
- [ ] Create the passkey. Your authenticator prompts twice — once to create,
      once to assert. This is expected: the assertion is how the PRF output is
      obtained, and doing it immediately means a new passkey yields its key in
      the same sitting.
- [ ] The window shows an address. The app's nav updates to match.

**If PRF is unsupported** you get a named error listing providers that work, and
no account is created. Worth testing deliberately with a hardware-only key.

## 2. Take a name

- [ ] In the app, claim a name. It reports the full name.
- [ ] `https://<gateway>/api/name/resolve/<name>` returns your public key.
- [ ] Once the chain write lands, the records are readable on chain:
      `node scripts/verify.mjs` reads receipts; for a user record, read the
      resolver's `text(namehash(<name>), "pinesign.key")` directly.
- [ ] The published key equals the one the sign-in window showed.

## 3. The key is the same key, somewhere else

This is the property that matters most, and the easiest one to get wrong.

- [ ] On a second device with the same passkey synced, sign in again.
- [ ] The address shown is **identical** to the first device's.
- [ ] The app finds your existing name rather than offering to claim one.

If the address differs, the PRF output is not stable across that provider's
devices and files sent to the first address will not open on the second.

## 4. Send to someone who has no account

- [ ] On the send page, enter an address nobody has signed up with.
- [ ] You are told they have been invited. The file is not sent.
- [ ] That address receives the invitation email.
- [ ] Open the invitation link, sign up, and claim a name.
- [ ] The sender receives an **accepted** email naming the new name.
- [ ] Back on the send page, look the address up again. It now resolves to a
      name and a key.

## 5. Send and receive

- [ ] Pick a file and send it. The sign-in window is used to encrypt; watch the
      status text say so.
- [ ] The recipient gets an email with a claim link.
- [ ] Open the link **signed out**. You are asked to sign in before anything
      about the file's contents is reachable.
- [ ] Sign in as someone else. You are told it is addressed to a different key,
      and `/api/claim` refuses you.
- [ ] Sign in as the recipient. Accept. The file downloads and decrypts.
- [ ] The receipt shows both signatures.
- [ ] The sender gets a **delivered** email.
- [ ] Try to claim again. It is refused: the receipt is write-once.

## 6. The boundary holds

- [ ] With the sign-in window open, run in the app's console:
      `localStorage` and `indexedDB` hold no private key, and no 64-character
      hex string appears anywhere in them.
- [ ] In the app's console, `window.open('https://<signin domain>')` then try to
      read anything from the returned window. The browser refuses: different
      origin.
- [ ] On the **app's** origin, run `navigator.credentials.get({publicKey:
      {challenge: new Uint8Array(32), rpId: '<signin domain>'}})`. It must fail.
      A parent domain may not assert a credential scoped to its subdomain, and
      this is the check that proves the lander cannot reach the key.
- [ ] From any other origin, open the sign-in page with
      `#origin=https://evil.example` and try to drive it over `postMessage`. It
      answers nothing at all.

## 7. The allow-list

- [ ] `https://v1.<signin domain>/` serves the page.
- [ ] `https://v99.<signin domain>/` is a 404.
- [ ] `https://anything.<signin domain>/` is a 404.
- [ ] `https://<signin domain>/` redirects to the current version.
- [ ] `https://v1.<signin domain>/api/health` is a 404 — the API is not reachable
      under the sign-in domain.
- [ ] Publish again with `npm run publish-page`. It becomes v2; v1 still serves
      its original bytes.
