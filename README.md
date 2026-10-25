# PineSign

Send a file to one person. They cannot read it until their acceptance is recorded on
Ethereum, and that acceptance is signed by their passkey and verified by a contract —
not by us.

> Hackathon version (ETHRome 2026) and its full README: branch `ethrome-2026`.

## How it cannot be cheated

The file's key is split, and one half does not exist publicly until the recipient has
accepted:

```
C = AEAD(K, salt ‖ F)              the ciphertext, public on Swarm the whole time
K = A XOR B                        the key, which nobody ever holds whole
A = HKDF(ECDH(e_A, pk_B), id)      only the recipient can derive this
B                                  the sender's half, held back
```

The sender publishes `C` and `keccak(B)`. The recipient can compute `A` the moment the
delivery exists, and `A` alone decrypts nothing. `B` reaches the chain only through
`release`, which the contract permits only after `accept`, and `accept` is a WebAuthn
assertion the contract verifies itself through the P-256 precompile.

So the ordering is not a policy anyone enforces. No acceptance, no `B`; no `B`, no `K`;
no `K`, no plaintext. The gateway cannot shortcut it, and neither can the page the
recipient is looking at.

## Who holds the sender's half

One choice, made per delivery, and it is the only trust decision a sender makes.

**This server (default).** The sender's half is encrypted to the gateway, which releases
it once the recipient's acceptance is final. The sender never has to be reachable again.
The cost: the gateway can read that half, so a dishonest one could hand it to a recipient
who never accepted. It cannot forge the acceptance — that is on chain, signed by a
passkey — but it can let someone read a file without one.

**The sender.** Her half is sealed to her own key and nobody else can open it, the
gateway included. Nobody can leak it and nobody can release early. The cost: the
recipient waits until she comes back and releases.

Releasing is deliberately not prompt. `release` puts the half into transaction calldata,
and calldata is public from the moment a transaction is broadcast — whether or not it
succeeds. A release submitted against an acceptance that is later reorganised away
therefore publishes the half for a delivery nobody accepted, and the revert does not take
it back. So nothing is released until the block holding the acceptance is final.

## What is proven

- **A passkey was tapped for this exact delivery.** The contract checks the signature
  against the credential frozen at send, that the signed challenge is the digest it
  computed itself, the relying party, the origin against a list fixed at deployment,
  and the user-presence and user-verification flags.
- **The recipient agreed to specific terms.** The Accept digest covers the transfer id,
  the ciphertext hash, the plaintext commitment, the description hash, `keccak(B)`, the
  swarm reference and who may release. None of it can change afterwards — the contract
  has no setter for any of it.
- **The file is the one committed to.** After release the recipient recovers
  `keccak(salt ‖ F)` and checks it against the commitment made before they accepted.
- **A sender who took an acceptance and gave nothing is on record.** An accepted,
  unreleased, lapsed delivery reports `senderDefaulted`.
- **The sender is who the record says.** A send is relayed, so the sender signs it; the
  relayer pays the gas and can alter nothing.

## What is not proven, and who is still trusted

These are limits of the design, not things left to do.

- **Acceptance is not reading.** The recipient signs before `B` exists, so an acceptance
  means "I accept delivery", not "I have read the file". This is registered post: you
  sign for the envelope. Nothing on chain can show what someone did with the bytes
  afterwards.
- **The sender's half can be leaked by whoever holds it.** In the default mode that is
  this gateway, which is trusted not to hand it to a recipient who never accepted. A
  sender who will not extend that trust releases herself, and then the only party who
  can leak it is the one who has the file anyway. See *Who holds the sender's half*.
- **A junk file is only provably junk off chain.** The commitment lets the recipient
  *detect* that what arrived is not what was described — but only after accepting. Their
  remedy is to show an arbitrator that the delivered bytes do not match, which this
  contract does not adjudicate.
- **The signing page is trusted.** It is the one place the user's key exists. It is
  static, published to Swarm by hash, and served from its own origin so that nothing the
  gateway serves can assert the passkey — but a user who loads it is trusting those
  bytes. Checking the published reference against what the gateway serves is the only
  defence, and it is a manual one.
- **Also trusted:** DNS, the registrar, the VPS, and whoever owns the allow-list of
  published sign-in pages. A gateway can refuse to relay, which is an availability
  problem rather than an authority one — any relayer can carry the same signed action.

## Verify a delivery yourself

The contract already checked the passkey, so verification is reading its state rather
than re-doing its work.

```bash
DELIVERY=0x…                 # the contract, from /api/health
ID=0x…                       # the delivery id
RPC=https://ethereum-sepolia-rpc.publicnode.com

cast call $DELIVERY "get(bytes32)" $ID --rpc-url $RPC
cast call $DELIVERY "stateOf(bytes32)(uint8)" $ID --rpc-url $RPC
cast call $DELIVERY "senderDefaulted(bytes32)(bool)" $ID --rpc-url $RPC
```

States are `None, Sent, Accepted, Released, Expired, SenderAborted`. `Released` means the
contract verified a passkey assertion from the credential frozen at send, and then the
releaser produced a half matching the commitment.

Two things worth checking yourself rather than taking from the state:

```bash
# The released half really is the one committed to at send.
cast keccak $(cast abi-encode "f(bytes32)" <releasedKey>)   # == releaseCommitment

# The id really is derived from the delivery, so no field was swapped.
cast call $DELIVERY "transferId((address,address,bytes32,bytes32,bytes32,bool,bytes32,bool,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,uint64))(bytes32)" \
  "(<sender>,<releaser>,…)" --rpc-url $RPC
```

And the `Accepted` event carries the credential that accepted, so a third party can see
*which* passkey signed without trusting anyone's account of it.

## Run it

```bash
cp .env.example .env     # every deployment value lives here, nothing is compiled in
npm install
npm test                 # gateway, sign-in, key split, assertion parsing
npm run test:contracts   # delivery, WebAuthn, resolver, receipts
npm run build && npm run gateway
```

Against a real chain:

```bash
npm run check:p256       # is the P-256 precompile live where you are deploying
npm run check:accept     # deploy, and verify a passkey assertion on chain
npm run e2e              # one whole delivery, two passkeys, sender releases
npm run e2e:gateway      # the same, with the gateway releasing on finality
```

Deploying: [docs/SETUP.md](docs/SETUP.md). The checks no suite can do — a real browser,
a real authenticator, and whether your passkey provider derives the same key on a second
device: [docs/TESTING.md](docs/TESTING.md).

## Contracts

`PineSignDelivery` and the `WebAuthn` library it links against; addresses come from your
own deployment. `PineSignResolver` holds users' published keys as ENS text records.
`PineSignReceipts` is the earlier write-once receipt contract, kept untouched for
transfers made under it.

On-chain P-256 verification is the EIP-7951 precompile at `0x100`, which is live on
Sepolia and mainnet and costs 6,900 gas. There is deliberately no Solidity fallback: a
chain without it would verify at roughly fifty times that, which should be a conscious
redeployment and not a silent one. `npm run check:p256` says whether a chain has it.

ENS, per network — Sepolia values are in `.env.example`, and nothing is compiled in.
