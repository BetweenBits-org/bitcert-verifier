// Cross-check that the SHIPPED browser JS in index.html produces identical
// results to verify.py. Extracts the pure functions from the single-file HTML,
// evaluates them under Node's Web Crypto, and runs them on the fixtures.
// Run: node fixtures/browser-js-check.mjs
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const html = readFileSync(path.join(here, "..", "index.html"), "utf8");

// pull the <script> body, keep only the pure functions (drop the UI wiring)
const script = html.split("<script>")[1].split("</script>")[0];
const cut = script.indexOf("/* ---------- UI plumbing");
const pure = script.slice(0, cut);

const factory = new Function(
  pure + "\nreturn {hexToBytes,bytesToHex,verifyMerkle,decodeOpReturn,txidFromRaw," +
         "payloadHash,verifyChainLinks,verifyPreimage,eqHex};"
);
const F = factory();

function load(name) {
  return JSON.parse(readFileSync(path.join(here, name), "utf8"));
}

let failures = 0;
function expect(cond, msg) { if (!cond) { console.log("  ✗ " + msg); failures++; } else { console.log("  ✓ " + msg); } }

const valid = load("sample-bundle.valid.json");
const tampered = load("sample-bundle.tampered.json");
const tamperedChain = load("sample-bundle.tampered-chain.json");

console.log("browser-js vs fixtures:");
{
  const m = await F.verifyMerkle(valid.record, valid.merkle);
  expect(m.ok, "valid: merkle inclusion holds");
  const d = F.decodeOpReturn(valid.anchor.op_return_payload_hex);
  expect(F.eqHex(d.merkle_root, valid.merkle.root), "valid: OP_RETURN root == merkle root");
  const t = await F.txidFromRaw(valid.anchor.reveal_tx_hex);
  expect(F.eqHex(t.txid, valid.anchor.reveal_txid), "valid: computed txid == reveal_txid (" + t.txid + ")");
  expect(F.eqHex(t.opReturnHex, valid.anchor.op_return_payload_hex), "valid: raw-tx OP_RETURN == payload");
  const ph = await F.payloadHash(valid.chain.entry);
  expect(F.eqHex(ph, valid.chain.entry.payload_hash), "valid: chain payload_hash recomputes");
}
{
  const m = await F.verifyMerkle(tampered.record, tampered.merkle);
  expect(!m.ok, "tampered: merkle inclusion correctly FAILS");
}
// §5 chain (link D) — browser JS must gate just like Python
{
  const ph = await F.payloadHash(tamperedChain.chain.entry);
  expect(!F.eqHex(ph, tamperedChain.chain.entry.payload_hash), "tampered-chain: payload_hash correctly does NOT recompute");
  // walk-back continuity: a forged linked entry must break the linkage
  const head = valid.chain.entry;
  const goodPrior = { exchange_id: "demoex", seq: 0, kind: "daily",
    prev_entry_hash: "00".repeat(32), body_hash: "be".repeat(32), business_date: "2026-05-27" };
  goodPrior.payload_hash = await F.payloadHash(goodPrior);
  const linkedHead = { ...head, seq: 1, prev_entry_hash: goodPrior.payload_hash };
  expect((await F.verifyChainLinks([goodPrior], linkedHead)).ok, "chain links: clean walk-back hash-linkage holds");
  const forgedPrior = { ...goodPrior, payload_hash: "ff".repeat(32) };
  expect(!(await F.verifyChainLinks([forgedPrior], linkedHead)).ok, "chain links: forged prior entry correctly breaks continuity");
}
// pinned RFC-6962 test vector must match merkle-batching
{
  const cur = await F.verifyMerkle({ leaf_bytes: "00".repeat(32) },
    { root: "7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9", siblings: [], directions: [] });
  expect(cur.ok, "pinned vector: H_leaf(0x00*32) matches ann-core merkle-batching");
}

// §2.1 preimage (link A) — browser JS must match Python + examples
{
  // daily jcs: self-consistency (no secret), then identity binding (account+salt)
  const self = await F.verifyPreimage(valid.record, null, null, null);
  expect(self.self_ok, "valid(daily): leaf_bytes == hash(declared fields)");
  const ident = await F.verifyPreimage(valid.record, null, "alice@demoex", "5e".repeat(32));
  expect(ident.identity_ok === true, "valid(daily): account+salt -> user_commitment matches");
  const wrong = await F.verifyPreimage(valid.record, null, "mallory", "5e".repeat(32));
  expect(wrong.identity_ok === false, "daily: wrong account -> identity MISMATCH");

  // file scheme: hash the example's original artifact
  const fileBundle = JSON.parse(readFileSync(path.join(here, "..", "examples",
    "01-attestation-file", "bundle.json"), "utf8"));
  const art = new Uint8Array(readFileSync(path.join(here, "..", "examples",
    "01-attestation-file", "original-report.txt")));
  const fp = await F.verifyPreimage(fileBundle.record, art, null, null);
  expect(fp.self_ok, "file scheme: SHA-256(original artifact) == leaf_bytes");
  const tampered2 = await F.verifyPreimage(fileBundle.record, new Uint8Array([1, 2, 3]), null, null);
  expect(tampered2.self_ok === false, "file scheme: altered bytes -> binding FAILS");
}

console.log(failures ? "\nFAIL (" + failures + ")" : "\nOK — browser JS matches Python + core test vector");
process.exit(failures ? 1 : 0);
