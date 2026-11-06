# Pinesign
Send a file. Prove it arrived. No company in the middle.

## Versions
- **v0.1 Rome** — prototype. Google sign-in, Circle, our server relayed everything.
- **v0.2 Road to Devcon** — no Google/Circle. Passkey + email code. Page hash in ENS.
- **v0.3 Mumbai** (new) — messages on Arkiv, files on Swarm, DKIM proves email, delivery proof in one frame tx, Anon-RPC. Self-run mode.

## Sponsors
**Arkiv** — replaces our server's database and email relay. Invites and accepts are short-lived: cheap, signed, public, queryable, expire by themselves. Only the final proof goes on chain.
**Swarm** — encrypted files. Page served by hash, verifiable with bmt-js.
**EF · Frame tx** — passkey account, Pinesign pays gas. One tx checks Bob's DKIM and releases the file key: his email reply alone authorises it, no wallet signature. No proof, no delivery.
**EF · Anon-RPC** — nobody learns who checks or sends what.

## CROPS
- C: gateway can't block delivery; self-run possible.
- O: open source; page verifiable against its hash.
- P: no Google; gateway can't link email to address; Anon-RPC.
- S: keys on device; delivery proof enforced in one tx.

## Arkiv
Writer wallet: 0xab1A75cd8fd8aAeD39ac39f44Eb47A688078c810 · Query: `pinesign.invite where emailHash = H(recipient), ownedBy(writer)` · Docs: /arkiv
