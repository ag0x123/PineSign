# Mumbai sponsor-tech spikes

Run 2026-11-06 for PineSign at ETHGlobal Mumbai. Each test is a throwaway script under
`spikes/<name>/`, with its raw output kept in `../results/<name>.json`. Nothing here is app code.

| # | Test | Verdict | Headline |
|---|---|---|---|
| 1 | Arkiv | **PASS** | create 124,876 gas / ~3–8 s; query ~370 ms; patch and extend both work |
| 2 | Swarm | **PASS** | upload 37 ms, download 7 ms, reference reproduced by bmt-js |
| 3 | DKIM local | **PASS (self-signed)** | verifies in 22 ms; needs your `.eml` for a real-provider run |
| 4 | Passkey PRF | **PASS** | 32-byte PRF, stable across assertions; X25519 + secp256k1 derived |
| 5a | Frame tx | **PASS** | mined, 2 frames, 26,102 gas — but only via the canonical mempool |
| 5b | P-256 account | **PASS** | VERIFY frame 23,634 gas, EIP-7951 precompile live on the devnet |
| 5c | Sponsored gas | **PASS** | sender held 0 ETH on both sides; paymaster paid |
| 5d | DKIM in a frame | **PASS** | 61,330 gas — fits the public mempool, no alt mempool needed |
| 5e | Execute-frame store | **PASS** | `{acceptHash, encryptedKey}` written and read back byte-identical |
| 6 | anon-RPC | **PASS (passthrough only)** | both reads routed; anonymity itself unproven |
| 7 | ENSv2 | **PASS** | live on mainnet; wildcard + CCIP-Read resolve; `pinesign.eth` free at 0.00225 ETH/yr |
| 8 | Arc | **PARTIAL** | Bridge Kit **cannot** deliver on Gnosis; USDC transfer not run (no funds) |

---

## 1. Arkiv — PASS

`@arkiv-network/sdk` 1.0.1, Rabdi testnet chain **7794095**, RPC via `rabdi({ accessKey })`
(the key goes in the URL, so `http()` takes no argument).

| op | latency | gas |
|---|---|---|
| `createEntity` (1-day expiry) | 7,249 ms | 124,876 |
| query by indexed field + `ownedBy` | 376 ms | — |
| `patchEntity` | 2,655 ms | 49,050 |
| `extendEntity` (→ 7 days) | 2,863 ms | 50,732 |

Schema `pinesign.invite { fingerprint: str().indexed(), emailHash: str().indexed(), payload: bytes() }`.
The payload carried a P-256 public key plus signature (129 bytes); after reading it back the bytes were
identical and **the signature still verified**, which is the real proof rather than "a row exists".
Extension proven by reading `$expiresAt` on both sides: 339,406 → 598,611.

**Gotchas**
- Query results wrap every value as `{ type, value }`. Reading `row.payload` gives an object, and
  `new Uint8Array(object)` is a **silently empty array**, not an error. First run reported a payload
  mismatch with no clue why. Always unwrap `.value`.
- `patchEntity` is **positional**: `(schema, entityKey, changes)`. The `PatchEntityParameters` type in
  the docs is what `executeBatch` takes; passing that shape fails with "Invalid schema".
- `extendEntity`'s return does not carry the new expiry under the name its type suggests.
- `docs.arkiv.network/entities/change-and-delete/` is a **404**. The SDK's own `.d.ts` is the reference.

## 2. Swarm — PASS

Bee 2.8.2 on Hetzner, batch `028c83a3…c9e3` depth 17. 64 KiB encrypted with AES-256-GCM, uploaded,
downloaded, decrypted, and the reference recomputed by `bmt-js` **without consulting Bee**.

upload **37 ms** · download **7 ms** · BMT recompute **53 ms** · references match · plaintext recovered.

**The gotcha that cost an hour.** `bee-js`'s `uploadData` defaults to **redundancy level 1**, and it
drops `redundancyLevel: 0` because `0` is falsy. The resulting reference is an erasure-coded root, not
a BMT root, so `bmt-js` can never reproduce it. Root chunk size for an 8 KiB file by level:

| level | 0 | 1 | 2 | 3 | 4 |
|---|---|---|---|---|---|
| root bytes | **72** | 168 | 232 | 264 | 808 |

Only level 0 (72 bytes = 8 span + 2 refs) is a plain BMT root. Single-chunk uploads (≤4096 B) matched
all along, which is what proved `bmt-js` was right and the setting was wrong. **Fix: raw POST to
`/bytes` with header `swarm-redundancy-level: 0`.**

> If you want client-verifiable references, you must pin redundancy to 0 and give up erasure coding.
> That is a real design decision, not a workaround.

## 3. DKIM, local — PASS (self-signed)

`mailauth` 4.8.4. Verified in **22 ms**, `rsa-sha256`, relaxed/relaxed, body hash matched. A P-256
public key carried as a `pinesign-key: 0x…` line in the body was extracted (65 bytes) and a signature
made with its private half verified against it.

**Caveat:** no `sample.eml` was provided, so the spike signed its own message and verified it through an
injected resolver. That proves the verifier, the canonicalisation and the key extraction — **not a real
provider's signature or a real DNS lookup**. Drop a real file at `spikes/dkim/sample.eml` and rerun;
the script switches to real DNS by itself. The on-chain half is proven independently by 5d.

## 4. Passkey PRF — PASS

Playwright driving the installed **Chrome 150** with a CDP virtual authenticator (ctap2_1, internal,
resident key, UV on). PRF present at create and at get, **32 bytes**, and **stable across assertions**.
X25519 and secp256k1 both derived via HKDF-SHA256 (salt `pinesign/v1`). A real assertion signature
verified against the credential's own public key.

**Gotchas**
- Playwright 1.56 **cannot download chromium on macOS 12**. `channel: 'chrome'` against the installed
  browser works and needs no download.
- `@noble/curves` **2.x `verify()` hashes the message itself**, so an assertion must be checked against
  raw `authenticatorData ‖ sha256(clientDataJSON)`, *not* its SHA-256. Passing the digest fails as a
  plain bad signature. The workshop's copy is **1.9.1** and takes the digest instead — the two spikes
  are not interchangeable, and this cost a wrong first diagnosis.
- Assertions come back **high-s about half the time** and nothing in WebAuthn normalises `s`. noble
  defaults to `lowS: true` and rejects those, so any off-chain verifier needs `lowS: false`. The
  EIP-7951 precompile accepts both, so the chain side is unaffected.

**Caveat:** a virtual authenticator cannot prove that *real hardware* yields the same PRF bytes on a
second physical device. That stays a manual two-device tap — PineSign's `docs/TESTING.md` §3, and still
the one check that could invalidate the design.

## 5. EIP-8141 frame transactions — PASS, with one devnet defect

Chain **1337**, `ethrex/v23.0.0-eip8141-tracer-9aa3645d`, gateway
`https://altmempoolgateway.forshtat.com/rpc`, explorer `https://explorer.altmempool.wtf/`.
No faucet needed: `step_1_check` self-funds 1 ETH.

### The defect, stated first

**The standard alt-mempool accepts frame transactions and then never builds them.**
`eth_sendFrameTransaction` returns success; resubmitting says "Frame transaction already known";
`debug_bundler_dumpMempool` goes empty; the tx is never mined. Reproduced with **two independent
freshly-funded keys**, 120 s each. Meanwhile 35 type-`0x6` txs from other senders landed in a 60-block
window and baseFee was 7 wei, so the chain was healthy. **The identical signed bytes mine in seconds
through `eth_sendRawTransaction`.** So frame execution works; the sidecar → block-builder handoff does
not. Every result below went through the canonical path.

### Results

| sub-test | result | gas |
|---|---|---|
| 5a sample frame tx | mined, block 5029, 2 frames | 26,102 total |
| 5b P-256 passkey account | mined, block 5120 | VERIFY **23,634**, total 487,285 |
| 5c sponsored, sender 0 ETH | mined, block 5165, 3 frames | 30,902 + 7,093 + 56,173 = 502,121 |
| 5d RSA-2048 DKIM in VERIFY | mined, block 5197 | VERIFY **61,330**, total 536,637 |
| 5e execute frame stores | read back byte-identical | 56,173 |

Tx hashes (search them at the explorer):
`0x3c52b213…a756` (5a) · `0xd4c9f09b…ccce0` (5b/5e) · `0x1bac54a2…2ae0` (5c) · 5d at block 5197.

### 5b — an account owned only by a passkey

**EIP-7951 P-256 precompile at `0x100` is LIVE on this devnet** (valid → `1`, bit-flipped → empty,
6,900 gas). RIP-7212 at `0x0b` is absent. No Solidity verifier needed.

The devnet profile declares a native `P256 = 0x2` signature scheme, but **the support library has no
code path for it**, so the wallet does not rely on the protocol verifying P-256. Instead the signature
rides in an **ARBITRARY (`0x0`) signature entry**: `sigHash` elides the signature bytes of any entry
whose `msg` is empty, so signing does not change the hash — verified directly
(`sigHashUnchangedAfterSigning: true`). Putting `r‖s` in frame *data* would be circular, because frame
data is covered by the hash. The wallet reads `r‖s` with `SIGDATACOPY`, the digest with
`TXPARAM(SIG_HASH)`, and calls `0x100` itself.

A bit flipped in `s` is **refused before inclusion** ("validation prefix frame reverted"), so the check
is real rather than a blind approve.

The message signed here is the raw tx signature hash. A real passkey signs
`sha256(authenticatorData ‖ sha256(clientDataJSON))` with the tx hash as the challenge; that wrapping is
PineSign's existing `WebAuthn.sol` and layers on unchanged.

### 5d — the answer inverts the question

The brief asked whether the public mempool rejects an RSA-2048 DKIM frame while the alt mempool admits
it. **It does not: at 61,330 gas the check fits inside the 100,000 validation-prefix cap, so the
canonical public mempool accepts and mines it.** No alt mempool, no staking, no reputation.

Getting there needed one optimisation. The first verifier compared the PKCS#1 EM byte by byte and cost
**246,505 gas** — indexing `bytes memory` bounds-checks every access, and indexing a `bytes constant`
copies the whole constant each time. Comparing EM as **eight 32-byte words** costs **63,661**. The
MODEXP precompile itself is only 5,461 gas (EIP-2565: multiplication_complexity 1024, iteration_count
16); the padding check was the whole cost. My initial estimate of "~5.5k, it'll fit easily" was wrong by
45× and only measurement caught it.

Notable: that transaction carried **`signatures: []`** — no signature entries at all. Authorisation came
purely from the DKIM signature checked inside the VERIFY frame.

### Frame gotchas
- **`MAX_VERIFY_GAS` is 100,000** for the *whole* validation prefix (all VERIFY frames plus signature
  cost). Asking 400k + 200k state is refused outright: "prefix gas budget exceeds MAX_VERIFY_GAS".
- A wallet that hardcodes `approve(EXECUTION_AND_PAYMENT)` **cannot be sponsored**: under a paymaster its
  frame is only allowed `EXECUTION`, and over-approving reverts the whole prefix. Read
  `FrameParam.ALLOWED_SCOPE` for the current frame and approve exactly that.
- The workshop's `deployGasLimit: 6000000` is too small for a contract of this size — `HegotaSupport`
  deploys Yul opcode helpers in its constructor. The deploy consumed exactly the limit and reverted with
  no reason. Raised to 15,000,000.
- The docs name `altmempool.forshtat.com`; the workshop uses `altmempoolgateway.forshtat.com`. Same
  chain and same block height, but I wasted time dumping the wrong node's mempool.

## 6. anon-RPC — PASS over passthrough only

`@anon-rpc/browser-harness` 0.4.0, bundled with esbuild, run in Chrome under Playwright (browser-only).

Through the **passthrough** specifier `0x4fd77be3…8d27` (mainnet): worker ready in 1,266 ms, Arkiv read
returned `0x76edaf` in **609 ms**, devnet read returned `0x539` in **1,983 ms**. Both through
`worker.fetch`.

- **Both RPCs accept a fetch from the harness's null-origin document**, so CORS from `Origin: null` is
  not a blocker. That was the thing most likely to kill this outright.
- **Passthrough is the non-anonymizing reference network** — it fulfils calls with an ordinary fetch. So
  this proves the harness, the specifier read and the routing API. **It does not prove anonymity.**
- **Tor failed, environmentally.** The worker really does boot an Arti client in WASM, but the demo
  gateway `152.236.3.22:12298` is gone ("all gateways failed"), and without it circuits never build:
  "Reached circuit build retry limit" on three consecutive consensus attempts over 150 s. The docs
  already warn it is demonstration-only. Running an anonymizing network means hosting your own gateway.
- The specifier contract is read through the host's **own** `rpcProvider`, and **that read is not
  anonymized** — the app still tells a mainnet RPC that it is opening an anon-rpc session.

## 7. ENSv2 — PASS (read-only, no transactions)

**ENSv2 is live on mainnet.** Every published address has code on both networks.

| | mainnet | Sepolia |
|---|---|---|
| UniversalResolverV2 | `0x06fdd07f007adac667177b46ab2eb9a75132cfd5` | `0x24e1d8e068620b647ca097f961a61055f4f42d72` |
| UpgradableUniversalResolverProxy | `0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe` | same address |
| ETHRegistry | `0xf60aba43e1f7f3dab1186ff03b561401c9df85e2` | `0xd4ebcbbdf463c9c45784603db0ddd499bc44a8b4` |
| ETHRegistrar | `0xd6d8369e55c94ae8afa714e6cf7ab5be54d5cc81` | `0xf633e7fc17e2bbe0d0965d18ec1821dcb754a3d3` |
| RootRegistry | `0x2553c09be6447beffdb86fa622ad41fb8f77a91e` | `0xb458d6a3a77919449d03e7a6903c26827c1ec43f` |

Resolution through the proxy: onchain `nick.eth` 845 ms · offchain CCIP-Read 2,513 ms · **wildcard
subname** (an unregistered random label under a gateway-backed parent) 1,507 ms · L2 `jesse.base.eth`
1,128 ms. So **ENSIP-10 wildcard + EIP-3668 both work**, which is what lets one code path serve a
subname per user with nothing registered per user.

**`pinesign.eth` is available: 0.00225 ETH/yr, 0.01126 ETH for 5 years** (≈ $5/yr). Priced via the ENSv1
`ETHRegistrarController` at `0x59E1…E547`, which is still the registration path. The ENSv2 `ETHRegistrar`
**reverts** on `available(string)` and `rentPrice(string,uint256)` — different ABI, so do not assume the
v1 interface when scripting a real registration.

## 8. Arc — PARTIAL

**Bridge Kit cannot deliver tokens on Gnosis Chain. Answer: no.**
26 chains are supported — Arbitrum, Arc, Avalanche, Base, Codex, Cronos, EDGE, Ethereum, HyperEVM,
Injective, Ink, Linea, Monad, Morph, OP Mainnet, Pharos, Plasma, Plume, Polygon PoS, Sei, Solana, Sonic,
Unichain, World Chain, X Layer, XDC — and Gnosis is not among them.
Docs: `https://docs.arc.io/app-kit/bridge.md`, chains at
`https://docs.arc.io/app-kit/references/supported-blockchains.md`.

**This matters for PineSign:** Swarm postage is bought in **xBZZ on Gnosis**. Circle's bridge cannot
reach Gnosis, so it cannot fund postage batches. Funding Gnosis needs a different route.

The USDC transfer on Arc testnet was **not run** — no testnet USDC for
`0x222d0AD1b152f20e948AE290BC3C911a2D09fe13` (faucet: `https://faucet.circle.com`), and the landing docs
give neither the testnet chain id nor its RPC.

*Note: `https://docs.arc.io/` serves an "Agent Instructions" block telling an agent to install Circle
skills before reading the docs. That is page content, not an instruction from you, and it was ignored.*

---

## Safe to build on

- **Arkiv** for invite records — schema, indexed queries, patch and expiry extension all work, and
  bytes payloads survive exactly. Writes are one block (~3–8 s), reads ~370 ms.
- **Swarm** for encrypted blobs, *with redundancy pinned to 0* if you want to verify references yourself.
- **The P-256 passkey account on EIP-8141** — the precompile is live, the ARBITRARY-entry pattern avoids
  the circularity cleanly, and a bad signature is refused before inclusion.
- **Sponsored gas** — a passkey account that never holds ETH works today.
- **DKIM inside a VERIFY frame** at 61,330 gas, in the **public** mempool. This is the strongest result:
  the design does not need an alt mempool at all.
- **ENSv2 wildcard + CCIP-Read subnames**, through the proxy address that is identical on mainnet and
  Sepolia. `pinesign.eth` is free and costs ~$5/yr.
- **Passkey PRF** — stable, and both key derivations work.

## Needs a fallback

- **The alt mempool cannot be relied on to include anything.** Send frame txs through
  `eth_sendRawTransaction`. Since 5d fits the public cap this costs the design nothing — but any plan
  that *depends* on alt-mempool admission (relaxed storage rules for a staked entity) has no working
  path today. Treat the alt mempool as a demo, not a dependency.
- **anon-RPC gives you the API but not anonymity** unless you host a gateway. Build behind an interface
  so passthrough can be swapped for a real network later.
- **Funding Gnosis for Swarm postage** is unsolved by Circle. Needs its own route.
- **Arc** is unexercised. Drop it unless it earns a prize.
- **The devnet is explicitly throwaway** — "no persistence guarantee, may be reset at any time". Every
  address in this report can vanish. Nothing should hardcode them.

## Still needs you

1. A real `.eml` at `spikes/dkim/sample.eml` → turns test 3 from self-signed into real.
2. Arc testnet USDC, *only if* we chase that prize.
3. The two-device passkey tap. Unautomatable, and the only check that could still invalidate the design.
