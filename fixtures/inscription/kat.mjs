/* =============================================================================
 * kat.mjs - tier 3 (③ inscription) known answers for zk-core.js.
 *
 * Pins the `inscription` section of fixtures/bc30-v2-vectors.json (the
 * byte-identical copy of ann-core/crates/bc30-leaf/tests/vectors/
 * bc30-v2-kat.json, frozen by docs/inscription-tier-spec-2026-09-02.md)
 * against the browser primitives:
 *
 *   envelopes    - strict parse (MUST 19), re-serialisation identity (MUST 20),
 *                  body = R(143) ‖ s, canonical chunking, envelope_root (spec 2.3)
 *   witness      - MUST 18: indexed item only, control block, no annex
 *   anchor       - MUST 15/16: the three-way equivalence, flags 0b11
 *   batch        - MUST 25: one leaf, empty path
 *   negative     - all 29 cases refused at their declared stage with their
 *                  declared error identifier (a vector must not pass by failing
 *                  for the wrong reason)
 *
 * verify.py --selftest runs the same section through the Python primitives, and
 * fixtures/v5-grade-check.mjs proves index.html's pipeline reproduces the
 * Python oracle over the complete ③ bundles in fixtures/v5/.
 *
 *   node fixtures/inscription/kat.mjs
 * ========================================================================== */
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..");
const Z = createRequire(import.meta.url)(join(repo, "zk-core.js"));

let failures = 0;
const ok = (l) => console.log("  ok    " + l);
const bad = (l, why) => { console.log("  FAIL  " + l + (why ? ": " + why : "")); failures++; };
const expect = (c, l, why) => (c ? ok(l) : bad(l, why));
const hex = (h) => Uint8Array.from(Buffer.from(h, "hex"));
const toHex = (b) => Buffer.from(b).toString("hex");
const utf8 = (s) => new TextEncoder().encode(s);

const vec = JSON.parse(readFileSync(join(repo, "fixtures", "bc30-v2-vectors.json"), "utf8"));
const ins = vec.inscription;
if (!ins) { console.log("FAIL  section `inscription` missing - stale fixtures/bc30-v2-vectors.json"); process.exit(1); }
const oracle = JSON.parse(readFileSync(join(repo, "fixtures", "v5-expected.json"), "utf8"));
const noneRoot = await Z.envelopeRootNoneHex();

console.log("③ inscription tier known answers (zk-core.js)\n");

/* ---- frozen constants (spec 2.1 / 2.3 / 3) ---- */
expect(ins.protocol_tag === Z.INSC_PROTOCOL_TAG && ins.protocol_tag_hex === toHex(utf8(Z.INSC_PROTOCOL_TAG)),
  'constants - protocol_tag "bcrt"');
expect(ins.content_type === Z.INSC_CONTENT_TYPE && ins.content_type_hex === toHex(utf8(Z.INSC_CONTENT_TYPE)),
  "constants - content_type (enforced by equality, never displayed)");
expect(ins.envelope_tag_utf8 === Z.ENVELOPE_TAG_V1, "constants - envelope_root domain tag");
expect(ins.max_push === Z.INSC_MAX_PUSH && ins.body_max === Z.INSC_BODY_MAX, "constants - 520 B chunks, " + Z.INSC_BODY_MAX + " B body cap");
expect(ins.flags === 0b11, "constants - flags 0b11 is the sole ③ discriminator");
expect(noneRoot === vec.envelope_root, "constants - the ①② envelope_root constant");
try { expect(!!Z.secpLiftX(hex(ins.nums_internal_key)), "constants - BIP-341 NUMS internal key is a point (no key path)"); }
catch (e) { bad("constants - NUMS internal key", e.message); }

/* ---- positives: both envelopes ---- */
for (const name of Object.keys(ins.envelopes).sort()) {
  const e = ins.envelopes[name];
  let env = null;
  try { env = Z.parseInscriptionEnvelope(hex(e.script)); }
  catch (ex) { bad(`envelope ${name} - strict parse`, ex.code || ex.message); continue; }
  const sSrc = e.s_source === "multisig.s" ? vec.multisig.s : vec[e.s_source];
  expect(toHex(env.protocolTag) === ins.protocol_tag_hex && toHex(env.contentType) === ins.content_type_hex
    && toHex(env.scriptKey) === ins.script_key_x_only, `envelope ${name} - script_key + tag + content_type recovered`);
  expect(toHex(env.body) === vec.R + sSrc && toHex(env.body) === e.body && env.body.length === e.body_len,
    `envelope ${name} - body is R(143) ‖ s (${e.s_source})`);
  expect(JSON.stringify(env.chunkLens) === JSON.stringify(e.chunk_lens), `envelope ${name} - canonical chunking ${JSON.stringify(e.chunk_lens)}`);
  expect(toHex(Z.buildInscriptionScript(env.scriptKey, env.protocolTag, env.contentType, env.body)) === e.script,
    `envelope ${name} - re-serialises to the SAME script (MUST 20)`);
  expect(toHex(await Z.envelopeRootV1(env.protocolTag, env.contentType, env.body)) === e.envelope_root,
    `envelope ${name} - envelope_root preimage (spec 2.3)`);
}

/* ---- the reveal witness: only the indexed item is read (MUST 18) ---- */
try {
  const items = ins.reveal.witness.map(hex);
  const script = Z.inscriptionWitnessScript(items, ins.reveal.witness_item_index);
  expect(toHex(script) === ins.envelopes.single.script, `reveal - witness item ${ins.reveal.witness_item_index} IS the envelope script`);
} catch (e) { bad("reveal - witness item", e.code || e.message); }

/* ---- the anchor and the batch (MUST 15/16/25) ---- */
expect(JSON.stringify(Z.inscriptionEquivalenceError(ins.anchor.flags, ins.anchor.aux_inputs.envelope_root, noneRoot, true)) === "[null,null]",
  "anchor - the three-way equivalence holds for the positive");
expect(await Z.inscriptionBatchError(ins.bundle.merkle, hex(ins.bundle.record.leaf_bytes)) === null,
  "batch - the ③ bundle carries a one-leaf merkle section");

/* ---- negatives: each refused at its stage with its own identifier ---- */
expect(ins.negative.length === 29, "negatives - 29 cases present");
for (const nc of ins.negative) {
  let got = null;
  if (nc.stage === "envelope" || nc.stage === "binding") {
    try {
      const env = Z.parseInscriptionEnvelope(hex(nc.script));
      if (toHex(env.protocolTag) !== ins.protocol_tag_hex) got = "protocol_tag_mismatch";
      else if (toHex(env.contentType) !== ins.content_type_hex) got = "content_type_mismatch";
      else if (toHex(env.body.subarray(0, 143)) !== vec.R) got = "record_mismatch";
      else if (toHex(env.body.subarray(143)) !== vec.s_webauthn) got = "signature_mismatch";
    } catch (e) { got = e.code || e.message; }
  } else if (nc.stage === "witness") {
    try { Z.parseInscriptionEnvelope(Z.inscriptionWitnessScript(nc.witness.map(hex), nc.witness_item_index)); }
    catch (e) { got = e.code || e.message; }
  } else if (nc.stage === "anchor") {
    got = Z.inscriptionEquivalenceError(nc.flags, nc.envelope_root, noneRoot, nc.has_inscription)[0];
  } else if (nc.stage === "batch") {
    got = await Z.inscriptionBatchError(nc.merkle, hex(nc.leaf_input));
  } else {
    // stage `bundle` is the verifier's schema whitelist, not a primitive. Do not
    // pretend to check it here: assert instead that the COMPLETE v5 fixture built
    // from this vector is rejected (v5-grade-check.mjs then proves index.html
    // reaches the same verdict as verify.py on that same file).
    const rel = "v5/ins-neg-" + nc.name.replace(/_/g, "-") + ".json";
    const row = oracle.rows.find((r) => r.file === rel);
    expect(!!row && row.grade === "rejected" && row.steps.some((s) => s.key === "schema" && s.state === "bad"),
      `negative - ${nc.name} (bundle schema) is refused by the complete fixture ${rel}`,
      row ? "grade " + row.grade : "no oracle row");
    continue;
  }
  expect(got === nc.error, `negative - ${nc.name} refused at ${nc.stage} with "${nc.error}"`, "got " + JSON.stringify(got));
}

/* ---- undetermined: MUST 26 cannot run without the reveal transaction ---- */
for (const uc of ins.undetermined)
  expect(uc.expect === "undetermined" && uc.error === "reveal_tx_missing", `undetermined - ${uc.name} stays undetermined`);

console.log(failures ? `\nFAIL (${failures})`
  : "\nOK - zk-core.js matches the engine KAT's ③ section (2 envelopes, witness, anchor, batch, 29 negatives)");
process.exit(failures ? 1 : 0);
