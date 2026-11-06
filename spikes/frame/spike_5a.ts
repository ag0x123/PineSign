// Spike 5a — send a sample frame tx. Tries the alt-mempool, then the canonical
// mempool, and reports which path actually gets mined.
import { privateKeyToAccount } from "viem/accounts";
import { loadConfig } from "../lib/config.js";
import { ensureParticipantKey } from "../lib/state.js";
import { buildSelfRelayTx, signFrameTx, txHash } from "../lib/frameTx/build.js";
import { accountNonce, sendFrameTx, sendRawFrameTx } from "../lib/frameTx/send.js";
import { rpc } from "../lib/rpc.js";

const cfg = loadConfig();
const key = ensureParticipantKey();
const from = privateKeyToAccount(key).address;
const out: Record<string, unknown> = { sender: from };

const poll = async (hash: string, secs: number) => {
  for (let i = 0; i < secs; i++) {
    const r = await rpc(cfg.gatewayUrl, "eth_getTransactionReceipt", [hash]);
    if (r) return r;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return null;
};

for (const path of ["alt", "canonical"] as const) {
  const nonce = await accountNonce(from);
  const tx = await signFrameTx(
    buildSelfRelayTx({ from, to: cfg.recipient, value: cfg.transferWei, nonce, chainId: cfg.chainId, maxFeePerGas: cfg.maxFeePerGasWei }),
    key
  );
  const hash = txHash(tx);
  const res: Record<string, unknown> = { nonce: Number(nonce), hash };
  try {
    const sent = path === "alt" ? await sendFrameTx(tx) : await sendRawFrameTx(tx);
    res.accepted = true;
    const r: any = await poll(sent, 90);
    res.mined = !!r;
    if (r) {
      res.block = Number(r.blockNumber);
      res.status = r.status;
      res.frames = r.frameReceipts?.length ?? 0;
      res.framesOk = (r.frameReceipts ?? []).every((f: any) => f.status === "0x1");
      res.gasUsed = Number(r.gasUsed ?? 0);
    }
  } catch (e: any) {
    res.accepted = false;
    res.error = e?.message ?? String(e);
  }
  out[path] = res;
  if ((res as any).mined) break;
}
console.log(JSON.stringify(out, null, 2));
