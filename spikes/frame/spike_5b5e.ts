// Spikes 5b + 5e in one transaction:
//   5b  the account's only owner is a P-256 (passkey) key
//   5e  the execute frame stores {acceptHash, encryptedKey} so a reader can fetch it
import { p256 } from "@noble/curves/nist";
import { encodeFunctionData, decodeFunctionResult, keccak256, toHex, hexToBytes, type Address, type Hex } from "viem";
import * as lib from "@forshtat/hegota-support/tx";
import { profile } from "../lib/frameTx/profile.js";
import { loadConfig } from "../lib/config.js";
import { deployContract, loadArtifact } from "../lib/contracts.js";
import { rpc } from "../lib/rpc.js";
import { accountNonce, sendRawFrameTx } from "../lib/frameTx/send.js";
import { computeSigHash } from "../lib/frameTx/codec.js";

const cfg = loadConfig();
const hex = (u: Uint8Array) => ("0x" + Buffer.from(u).toString("hex")) as Hex;
const out: Record<string, unknown> = {};

// --- the passkey. A real one lives in the authenticator; this is the same curve and the same
// --- signature format, which is what the chain sees.
const priv = p256.utils.randomSecretKey ? p256.utils.randomSecretKey() : (p256.utils as any).randomPrivateKey();
const pub = p256.getPublicKey(priv, false).slice(1);
const qx = hex(pub.slice(0, 32));
const qy = hex(pub.slice(32, 64));
out.passkeyPublicKey = { qx, qy };

const wallet = (await deployContract("P256Wallet" as any, [qx, qy], cfg.walletFundingWei)) as Address;
const store = (await deployContract("DeliveryStore" as any, [])) as Address;
out.wallet = wallet;
out.store = store;

// --- what the execute frame will write
const acceptHash = keccak256(toHex("pinesign/mumbai/accept/1"));
const encryptedKey = hex(crypto.getRandomValues(new Uint8Array(48)));
const storeAbi = loadArtifact("DeliveryStore" as any).abi;
const data = encodeFunctionData({ abi: storeAbi, functionName: "store", args: [acceptHash, encryptedKey] });
out.acceptHash = acceptHash;
out.encryptedKeyBytes = 48;

// --- the frame transaction. The signature sits in an ARBITRARY entry with an empty `msg`, which
// --- sigHash elides, so signing it does not change it.
const nonce = await accountNonce(wallet);
const frames = [
  lib.frame(profile, "VERIFY", { scope: "EXECUTION_AND_PAYMENT", target: null, execution: 80_000n, state: 0n }),
  lib.frame(profile, "SENDER", { target: store, execution: 500_000n, state: 500_000n, data }),
];
let tx = lib.newTx({
  chainId: cfg.chainId,
  sender: wallet,
  nonceSeq: nonce,
  frames,
  signatures: [{ scheme: lib.sigScheme(profile, "ARBITRARY"), signer: "0x", msg: "0x", signature: "0x" }],
  fees: { maxFeePerGas: cfg.maxFeePerGasWei },
});

const digest = computeSigHash(tx);
const sig = p256.sign(hexToBytes(digest), priv);
const rs = (("0x" + sig.r.toString(16).padStart(64, "0") + sig.s.toString(16).padStart(64, "0")) as Hex);
tx = { ...tx, signatures: [{ ...tx.signatures[0], signature: rs }] };
out.sigHash = digest;
out.signatureBytes = 64;
out.sigHashUnchangedAfterSigning = computeSigHash(tx) === digest;

// --- send
try {
  const hash = await sendRawFrameTx(tx);
  out.txHash = hash;
  let r: any = null;
  for (let i = 0; i < 90 && !r; i++) {
    r = await rpc(cfg.gatewayUrl, "eth_getTransactionReceipt", [hash]);
    if (!r) await new Promise((res) => setTimeout(res, 1000));
  }
  out.mined = !!r;
  if (r) {
    out.block = Number(r.blockNumber);
    out.status = r.status;
    out.frames = r.frameReceipts?.length ?? 0;
    out.framesAllSucceeded = (r.frameReceipts ?? []).every((f: any) => f.status === "0x1");
    out.gasUsed = Number(r.gasUsed ?? 0);
    out.frameGas = (r.frameReceipts ?? []).map((f: any) => Number(f.gasUsed ?? 0));
  }
} catch (e: any) {
  out.sendError = e?.message ?? String(e);
}

// --- 5e: can a reader fetch it back?
const readData = encodeFunctionData({ abi: storeAbi, functionName: "get", args: [acceptHash] });
const raw = await rpc(cfg.gatewayUrl, "eth_call", [{ to: store, data: readData }, "latest"]);
const [readKey, readBlock] = decodeFunctionResult({ abi: storeAbi, functionName: "get", data: raw }) as [Hex, bigint];
out.readBack = { encryptedKey: readKey, blockNumber: Number(readBlock) };
out.readBackMatches = readKey.toLowerCase() === encryptedKey.toLowerCase();

// --- the negative test: the same wallet, a signature with one bit flipped. If this is
// --- admitted the wallet is not really checking anything.
const nonce2 = await accountNonce(wallet);
let bad = lib.newTx({
  chainId: cfg.chainId,
  sender: wallet,
  nonceSeq: nonce2,
  frames: [
    lib.frame(profile, "VERIFY", { scope: "EXECUTION_AND_PAYMENT", target: null, execution: 80_000n, state: 0n }),
    lib.frame(profile, "SENDER", { target: store, execution: 500_000n, state: 500_000n, data }),
  ],
  signatures: [{ scheme: lib.sigScheme(profile, "ARBITRARY"), signer: "0x", msg: "0x", signature: "0x" }],
  fees: { maxFeePerGas: cfg.maxFeePerGasWei },
});
const d2 = computeSigHash(bad);
const s2 = p256.sign(hexToBytes(d2), priv);
const flipped = ("0x" + s2.r.toString(16).padStart(64, "0") + (s2.s ^ 1n).toString(16).padStart(64, "0")) as Hex;
bad = { ...bad, signatures: [{ ...bad.signatures[0], signature: flipped }] };
const neg: Record<string, unknown> = {};
try {
  const h2 = await sendRawFrameTx(bad);
  let r2: any = null;
  for (let i = 0; i < 30 && !r2; i++) {
    r2 = await rpc(cfg.gatewayUrl, "eth_getTransactionReceipt", [h2]);
    if (!r2) await new Promise((res) => setTimeout(res, 1000));
  }
  neg.accepted = true;
  neg.mined = !!r2;
  neg.status = r2?.status;
} catch (e: any) {
  neg.accepted = false;
  neg.rejection = (e?.message ?? String(e)).slice(0, 160);
}
neg.rejectedAsExpected = neg.accepted === false || neg.status === "0x0";
out.badSignature = neg;

out.PASS = out.mined === true && out.framesAllSucceeded === true && out.readBackMatches === true && neg.rejectedAsExpected === true;
console.log(JSON.stringify(out, null, 2));
