# PineSign

Verifiable file transfer: if someone opens a file you sent, you get proof on Ethereum — unforgeable by either side.

> Hackathon version (ETHRome 2026) and its full README: branch `ethrome-2026`.

## Now (main, in progress)
- Sign-in: email code + passkey. No vendor wallet, no extension.
- Key: derived in the browser from the passkey (WebAuthn PRF → HKDF → secp256k1). Never stored, never sent.
- Sign-in page: static, on Swarm, served at `v1.id.pinesign.xyz` from an allow-list. Its own
  origin on purpose: a passkey scoped to `id.` cannot be asserted by the apex, so the lander
  cannot reach the key.
- All crypto — encrypt, decrypt, sign, receipt — runs in that page. The app passes bytes in
  and gets results out.
- Gateway: self-hostable, swappable. Uploads ciphertext to Swarm, sends emails, writes receipts to ENS.
- Proof: unchanged — recipient must decrypt to claim; receipt frozen on chain.

## Before (ethrome-2026)
- Social sign-in creating a vendor wallet.
- Desktop extension holding the key to encrypt and sign locally.
- One server doing everything else.
- Same proof, but through several permissioned gates.

## Still trusted
Our gateway, DNS, registrar, VPS, and the allow-list owner.

## Run it
```bash
cp .env.example .env     # every deployment value lives here
npm install
npm test                 # gateway and sign-in flow
npm run test:contracts   # resolver and receipts
npm run build && npm run gateway
```
Deploying: [docs/SETUP.md](docs/SETUP.md). The passkey checks no suite can do:
[docs/TESTING.md](docs/TESTING.md).

## Verify a transfer yourself

No PineSign server involved — read the resolver on Sepolia directly. A real transfer
from the demo, `966e872faac33223ef0ab629cdd31b85.tx.pinesign.eth`:

```bash
RESOLVER=0xa7bdce7d8499a299d84406b0a29a33e4d515201c        # pinesign.eth's resolver
NODE=$(cast namehash 966e872faac33223ef0ab629cdd31b85.tx.pinesign.eth)
RPC=https://ethereum-sepolia-rpc.publicnode.com

cast call $RESOLVER "text(bytes32,string)(string)" $NODE "sender"        --rpc-url $RPC
cast call $RESOLVER "text(bytes32,string)(string)" $NODE "recipient"     --rpc-url $RPC
cast call $RESOLVER "text(bytes32,string)(string)" $NODE "file.hash"     --rpc-url $RPC
cast call $RESOLVER "text(bytes32,string)(string)" $NODE "recipient.sig" --rpc-url $RPC
cast call $RESOLVER "frozen(bytes32)(bool)"        $NODE                 --rpc-url $RPC
```

Keys: `sender`, `sender.key`, `sender.sig`, `recipient`, `recipient.key`, `file.name`,
`file.commitment`, `file.hash`, `swarm`, `sent`, `recipient.sig`, `delivered`.

To *verify* rather than just read: rebuild the digest — `keccak("pinesign/v1" ‖ sender.key
‖ recipient.key ‖ file.hash)` — and check `recipient.sig` against `recipient.key` with
secp256k1 (see `transferDigest` and `verify` in `shared/crypto.js`). A valid signature
over a digest containing `file.hash` proves the recipient possessed the hash, which they
could only get by decrypting.

The resolver is what the ENSv2 registry returns for `pinesign.eth`
(`getResolver("pinesign")` on `0xBDC85dD5b15D7ecb354cd7cb6f2c50b4f2c4F0E2`), so the
chain of trust starts at ENS, not at us. The same data is served for convenience at
`/api/attestation/<id>`.

## Contracts (Sepolia)

Ours — addresses in the admin panel after setup. Integrated: ENSv2 registrar
`0xa88553f454b77203b0d036a05c894d555eaaa2cc`, ENSv2 registry
`0xBDC85dD5b15D7ecb354cd7cb6f2c50b4f2c4F0E2`, ENSv2 fee token
`0x768f42455a2d082e23ceef7d51e5787c82d67a39`.
