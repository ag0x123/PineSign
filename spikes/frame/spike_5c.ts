// Spike 5c — sponsored gas: a P-256 (passkey) account that has never held ETH, paid for by a paymaster.
import { p256 } from "@noble/curves/nist";
import { encodeFunctionData, keccak256, toHex, hexToBytes, type Address, type Hex } from "viem";
import * as lib from "@forshtat/hegota-support/tx";
import { profile } from "../lib/frameTx/profile.js";
import { loadConfig } from "../lib/config.js";
import { getBalance } from "../lib/chain.js";
import { deployContract, loadArtifact } from "../lib/contracts.js";
import { rpc } from "../lib/rpc.js";
import { accountNonce, sendRawFrameTx } from "../lib/frameTx/send.js";
import { computeSigHash } from "../lib/frameTx/codec.js";

const cfg = loadConfig();
const hex = (u: Uint8Array) => ("0x" + Buffer.from(u).toString("hex")) as Hex;
const out: Record<string, unknown> = {};

const priv = (p256.utils as any).randomSecretKey?.() ?? (p256.utils as any).randomPrivateKey();
const pub = p256.getPublicKey(priv, false).slice(1);
const qx = hex(pub.slice(0, 32));
const qy = hex(pub.slice(32, 64));

// value 0: the wallet is created with no ETH and never receives any
const wallet = (await deployContract("P256Wallet" as any, [qx, qy], 0n)) as Address;
const paymaster = (await deployContract("SponsorPaymaster" as any, [], cfg.paymasterFundingWei)) as Address;
const store = (await deployContract("DeliveryStore" as any, [])) as Address;
out.wallet = wallet;
out.paymaster = paymaster;
out.walletBalanceBefore = (await getBalance(wallet)).toString();
const payBefore = await getBalance(paymaster);

const acceptHash = keccak256(toHex("pinesign/mumbai/sponsored/1"));
const encryptedKey = hex(crypto.getRandomValues(new Uint8Array(48)));
const storeAbi = loadArtifact("DeliveryStore" as any).abi;
const data = encodeFunctionData({ abi: storeAbi, functionName: "store", args: [acceptHash, encryptedKey] });

// prefix budget: 60k (wallet's P-256 check) + 30k (paymaster) = 90k, inside MAX_VERIFY_GAS of 100k
let tx = lib.newTx({
  chainId: cfg.chainId,
  sender: wallet,
  nonceSeq: await accountNonce(wallet),
  frames: [
    lib.frame(profile, "VERIFY", { scope: "EXECUTION", target: null, execution: 60_000n, state: 0n }),
    lib.frame(profile, "VERIFY", { scope: "PAYMENT", target: paymaster, execution: 30_000n, state: 0n }),
    lib.frame(profile, "SENDER", { target: store, execution: 500_000n, state: 500_000n, data }),
  ],
  signatures: [{ scheme: lib.sigScheme(profile, "ARBITRARY"), signer: "0x", msg: "0x", signature: "0x" }],
  fees: { maxFeePerGas: cfg.maxFeePerGasWei },
});
const digest = computeSigHash(tx);
const sig = p256.sign(hexToBytes(digest), priv);
tx = { ...tx, signatures: [{ ...tx.signatures[0], signature: ("0x" + sig.r.toString(16).padStart(64, "0") + sig.s.toString(16).padStart(64, "0")) as Hex }] };

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
  out.sendError = (e?.message ?? String(e)).slice(0, 200);
}

const payAfter = await getBalance(paymaster);
out.walletBalanceAfter = (await getBalance(wallet)).toString();
out.paymasterPaidWei = (payBefore - payAfter).toString();
out.senderNeverHeldEth = out.walletBalanceBefore === "0" && out.walletBalanceAfter === "0";
out.PASS = out.mined === true && out.framesAllSucceeded === true && out.senderNeverHeldEth === true && payAfter < payBefore;
console.log(JSON.stringify(out, null, 2));
