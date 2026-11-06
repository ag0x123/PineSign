// Spike 5d — a VERIFY frame that checks an RSA-2048 DKIM signature.
// Reports: does it verify, what does it cost, and what each mempool says about it.
import crypto from "node:crypto";
import { encodeAbiParameters, encodeFunctionData, keccak256, type Address, type Hex } from "viem";
import * as lib from "@forshtat/hegota-support/tx";
import { profile } from "../lib/frameTx/profile.js";
import { loadConfig } from "../lib/config.js";
import { deployContract, loadArtifact } from "../lib/contracts.js";
import { rpc } from "../lib/rpc.js";
import { accountNonce, sendFrameTx, sendRawFrameTx } from "../lib/frameTx/send.js";

const cfg = loadConfig();
const hex = (b: Buffer | Uint8Array) => ("0x" + Buffer.from(b).toString("hex")) as Hex;
const out: Record<string, unknown> = {};

// --- an RSA-2048 DKIM key and a signature over DKIM-shaped signed headers
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = publicKey.export({ format: "jwk" }) as { n: string; e: string };
const modulus = Buffer.from(jwk.n, "base64url");
out.modulusBits = modulus.length * 8;
out.exponent = Buffer.from(jwk.e, "base64url").readUIntBE(0, Buffer.from(jwk.e, "base64url").length);

const signedHeaders = Buffer.from(
  "from:PineSign <no-reply@pinesign.xyz>\r\n" +
    "to:alice@example.com\r\n" +
    "subject:Your delivery receipt\r\n" +
    "dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=pinesign.xyz; s=mumbai;\r\n" +
    " bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; h=from:to:subject; b="
);
const signature = crypto.sign("sha256", signedHeaders, privateKey);
out.signatureBytes = signature.length;
out.signedHeaderBytes = signedHeaders.length;

const modulusHash = keccak256(hex(modulus));
const dkimAbi = loadArtifact("DkimWallet" as any).abi;
const wallet = (await deployContract("DkimWallet" as any, [modulusHash], cfg.walletFundingWei)) as Address;
const store = (await deployContract("DeliveryStore" as any, [])) as Address;
out.wallet = wallet;

// --- 1. does the verifier agree off-frame, and what does the RSA check alone cost?
const verifyCall = (sig: Buffer) =>
  encodeFunctionData({ abi: dkimAbi, functionName: "verify", args: [hex(modulus), hex(sig), hex(crypto.createHash("sha256").update(signedHeaders).digest())] });
const good = await rpc(cfg.gatewayUrl, "eth_call", [{ to: wallet, data: verifyCall(signature) }, "latest"]);
const tampered = Buffer.from(signature);
tampered[200] ^= 1;
const bad = await rpc(cfg.gatewayUrl, "eth_call", [{ to: wallet, data: verifyCall(tampered) }, "latest"]);
out.verifyStandalone = { validSignature: BigInt(good) === 1n, tamperedSignature: BigInt(bad) === 1n };
const est = await rpc(cfg.gatewayUrl, "eth_estimateGas", [{ to: wallet, data: verifyCall(signature) }]);
out.gasRsaVerifyStandalone = parseInt(est, 16);

// --- 2. the same check inside a VERIFY frame
const frameData = encodeAbiParameters(
  [{ type: "bytes" }, { type: "bytes" }, { type: "bytes" }],
  [hex(modulus), hex(signature), hex(signedHeaders)]
);
const storeAbi = loadArtifact("DeliveryStore" as any).abi;
const senderData = encodeFunctionData({
  abi: storeAbi,
  functionName: "store",
  args: [keccak256(hex(signedHeaders)), hex(crypto.randomBytes(48))],
});

const build = async (data: Hex, verifyGas: bigint) =>
  lib.newTx({
    chainId: cfg.chainId,
    sender: wallet,
    nonceSeq: await accountNonce(wallet),
    frames: [
      lib.frame(profile, "VERIFY", { scope: "EXECUTION_AND_PAYMENT", target: null, execution: verifyGas, state: 0n, data }),
      lib.frame(profile, "SENDER", { target: store, execution: 500_000n, state: 500_000n, data: senderData }),
    ],
    signatures: [],
    fees: { maxFeePerGas: cfg.maxFeePerGasWei },
  });

const submit = async (tx: any, how: "alt" | "canonical") => {
  const r: Record<string, unknown> = {};
  try {
    const hash = how === "alt" ? await sendFrameTx(tx) : await sendRawFrameTx(tx);
    r.accepted = true;
    let rec: any = null;
    for (let i = 0; i < 60 && !rec; i++) {
      rec = await rpc(cfg.gatewayUrl, "eth_getTransactionReceipt", [hash]);
      if (!rec) await new Promise((res) => setTimeout(res, 1000));
    }
    r.mined = !!rec;
    if (rec) {
      r.block = Number(rec.blockNumber);
      r.status = rec.status;
      r.gasUsed = Number(rec.gasUsed ?? 0);
      r.frameGas = (rec.frameReceipts ?? []).map((f: any) => Number(f.gasUsed ?? 0));
      r.framesAllSucceeded = (rec.frameReceipts ?? []).every((f: any) => f.status === "0x1");
    }
  } catch (e: any) {
    r.accepted = false;
    r.rejection = (e?.message ?? String(e)).slice(0, 200);
  }
  return r;
};

// 90k asked, inside MAX_VERIFY_GAS of 100k
out.canonical = await submit(await build(frameData, 90_000n), "canonical");
out.alt = await submit(await build(frameData, 90_000n), "alt");

// --- 3. a tampered signature must not be admitted
const tamperedFrameData = encodeAbiParameters(
  [{ type: "bytes" }, { type: "bytes" }, { type: "bytes" }],
  [hex(modulus), hex(tampered), hex(signedHeaders)]
);
out.tamperedInFrame = await submit(await build(tamperedFrameData, 90_000n), "canonical");

out.PASS =
  (out.verifyStandalone as any).validSignature === true &&
  (out.verifyStandalone as any).tamperedSignature === false &&
  (out.canonical as any).framesAllSucceeded === true &&
  (out.tamperedInFrame as any).accepted === false;
console.log(JSON.stringify(out, null, 2));
