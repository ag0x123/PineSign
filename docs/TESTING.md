# Testing

Two suites run without a browser, a chain, or a Bee node:

```
npm test                # gateway, sign-in, key split, assertion parsing
npm run test:contracts   # delivery, WebAuthn, resolver, receipts
```

Three more need a chain, and are worth running before a deployment is believed:

```
npm run check:p256      # is the P-256 precompile live on the target chain
npm run check:accept    # deploy, and verify one passkey assertion on chain
npm run e2e             # a whole delivery: send, inspect, accept, release, open
npm run e2e:gateway     # the same, with the gateway releasing once it is final
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

`npm run e2e` proves the protocol against a real chain, but it stands in for the
authenticator tap — a script cannot drive a security key or a password manager.
Four things therefore need a real browser and real hands:

1. **The PRF extension.** Whether a given passkey provider returns a PRF result
   at all, and whether it returns the **same** one on another device. If it does
   not, files sent to the first device cannot be opened on the second, and no
   amount of testing elsewhere would reveal it.
2. **The popup boundary.** That the app really cannot read the key, and that the
   `postMessage` origin checks hold in both directions.
3. **rpId scoping.** That a page on the parent domain cannot assert a credential
   scoped to the sign-in subdomain — the property the whole design rests on.
4. **The confirmation summary.** That an acceptance cannot be obtained without
   the user seeing, in the signing page, what they are agreeing to.

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

## 5. Send and receive, the whole way through

This is the sequence the automated end-to-end already proves against Sepolia. What
it cannot prove is that a real authenticator does its part, so it is walked again
by hand.

- [ ] On the send page, pick a file, write a description, and send.
- [ ] Watch the status text: the encryption and the key split happen in the
      sign-in window, not in the app.
- [ ] The recipient gets an email with a link.
- [ ] Open the link **signed out**. Nothing about the file's contents is
      reachable, and the description is not shown.
- [ ] Sign in as **someone else**. You are told it is not addressed to you, and
      accepting is not offered.
- [ ] Sign in as the recipient. The description appears. The file does not.
- [ ] Click accept. **The sign-in window shows a summary** — the description, the
      size, the stored file's hash, the delivery id and the digest being signed —
      and does nothing until you press the button. This is step 4 above.
- [ ] Decline once, with "Not now". Nothing is signed and nothing reaches the chain.
- [ ] Accept. Your authenticator prompts; the acceptance is relayed and the state
      becomes `Accepted`.
- [ ] **Try to open it now.** It must refuse: the sender has not released.
      `releasedKey` on chain is still thirty-two zero bytes.
- [ ] The sender gets an email saying they can release.
- [ ] As the sender, release. Your authenticator is not needed — the release is
      signed with the key already derived in the sign-in window.

### Both ways of holding the sender's half

Run section 5 twice, once with each option on the send page.

- [ ] **This server (default).** After the recipient accepts, nobody touches the
      send page: the gateway releases on its own once the acceptance is final.
      Watch the gateway log — it should say what it is waiting for, then
      `released <id> <tx>`.
- [ ] While it is waiting, confirm `releasedKey` on chain is still thirty-two
      zero bytes. A release before finality would be a leak, not a race.
- [ ] **You.** The send page offers a Release button and the gateway never acts.
      Confirm the gateway log says nothing about this delivery at all.
- [ ] In that mode, ask the gateway for the sealed half as the sender and
      confirm it is returned; ask as anyone else and confirm it is not.
- [ ] As the recipient, open it. The file downloads and the receipt shows a hash
      matching what the sender committed to before you accepted.
- [ ] Read the state back from the contract directly, with `cast` — not from the
      gateway. It should say `Released`.

### And the things that must fail

- [ ] Accept the same delivery twice. The second attempt is refused.
- [ ] Release twice. Refused.
- [ ] Let an `acceptBy` deadline pass without accepting, then call
      `expire`. The state becomes `Expired` and `senderDefaulted` is false.
- [ ] Accept, then let `releaseBy` pass without releasing, then `expire`.
      `senderDefaulted` is **true** — the sender took an acceptance and gave
      nothing, and that is on the record.

## 6. The boundary holds

- [ ] With the sign-in window open, run in the app's console:
      `localStorage` and `indexedDB` hold no private key, and no 64-character
      hex string appears anywhere in them.
- [ ] In the app's console, confirm there is no way to ask the sign-in window for
      the key itself: the only methods it answers are `identity`, `signNonce`,
      `inspect`, `signAccept`, `prepareSend`, `openKeptHalf`, `signRelease` and
      `open`. Ask it for anything else and it replies "no such method".
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
