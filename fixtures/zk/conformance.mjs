/* =============================================================================
 * conformance.mjs - cross-implementation gate for the zk verifier.
 *
 * The engine (Go) and this verifier (JS) implement the same frozen contract
 * twice. Nothing but a shared fixture stops them drifting: a changed DST, a
 * reordered transcript binding, a different point encoding all produce "does
 * not verify" with no hint of where. So this runner checks the JS against the
 * Go-generated golden fixtures, and - critically - compares the CHALLENGE
 * STREAM step by step, so a divergence names the exact challenge it started at.
 *
 * Run: node fixtures/zk/conformance.mjs
 * Exits non-zero on any mismatch; wire it into CI as-is.
 * ========================================================================== */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { webcrypto } from "node:crypto";
import { createRequire } from "node:module";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
if (!globalThis.atob) globalThis.atob = (s) => Buffer.from(s, "base64").toString("binary");

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..");
const require = createRequire(import.meta.url);
const zk = require(join(repo, "zk-core.js"));

/* The Go fixture's context and public inputs (golden_test.go). A verifier must
 * supply these from its own records - here the fixture definition IS the
 * record. */
const GOLDEN_CTX = { org_id: "00000000-0000-0000-0000-00000000abcd", run_ref: "golden:v1" };
const GOLDEN_VALUES = [3n, 250n, 1000000n];
const GOLDEN_TOTAL = GOLDEN_VALUES.reduce((a, b) => a + b, 0n).toString();

function parseVectors(text) {
  const out = { generators: {}, commitments: [], challenges: {} };
  for (const line of text.split("\n")) {
    // Challenge ids contain colons (bp-ipa:3), so they need their own pattern -
    // a first-colon split silently produces the key "chal bp-ipa".
    const c = /^chal (\S+):\s*([0-9a-f]+)$/.exec(line.trim());
    if (c) { out.challenges[c[1]] = c[2]; continue; }
    const m = /^([^:]+):\s*(.+)$/.exec(line.trim());
    if (!m) continue;
    const [, k, v] = m;
    if (k === "spec") out.spec = v;
    else if (k === "padded_m") out.paddedM = Number(v);
    else if (/^C\d+$/.test(k)) out.commitments.push(v);
    else out.generators[k] = v;
  }
  return out;
}

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const scalarHex = (s) => s.toString(16).padStart(64, "0");

let failures = 0;
const bad = (l, why) => { console.log(`  FAIL  ${l}: ${why}`); failures++; };
function check(label, got, want) {
  if (got === want) { console.log(`  ok    ${label}`); return true; }
  console.log(`  FAIL  ${label}\n        got  ${got}\n        want ${want}`);
  failures++;
  return false;
}

const vectors = parseVectors(readFileSync(join(here, "vectors.txt"), "utf8"));
const proof = readFileSync(join(here, "bulletproofs.proof"));

console.log(`zk conformance - ${vectors.spec}\n`);

/* ---- 1. generators: derived independently, must equal Go's ---- */
console.log("generators (try-and-increment, spec §14.4)");
check("g", hex(zk.zkSec1Encode(zk.ZK_G)), vectors.generators.g);
check("h", hex(zk.zkSec1Encode(await zk.zkDeriveNUMS(zk.ZK_DST.h, "h"))), vectors.generators.h);
check("u", hex(zk.zkSec1Encode(await zk.zkDeriveNUMS(zk.ZK_DST.u, "u"))), vectors.generators.u);
for (let i = 0; i < 4; i++) {
  check(`G${i}`, hex(zk.zkSec1Encode(await zk.zkDeriveNUMS(zk.ZK_DST.gvec, `G:${i}`))), vectors.generators[`G${i}`]);
  check(`H${i}`, hex(zk.zkSec1Encode(await zk.zkDeriveNUMS(zk.ZK_DST.hvec, `H:${i}`))), vectors.generators[`H${i}`]);
}

/* ---- 2. cs_digest over the fixture's commitments ---- */
console.log("\ncs_digest (spec §14.2)");
const commitments = vectors.commitments.map((h) => zk.zkSec1Decode(Buffer.from(h, "hex")));
check("cs_digest", scalarHex(await zk.zkCsDigest(commitments)), vectors.generators.cs_digest);

/* ---- 3. full verification + challenge stream ---- */
console.log("\nverification (committed-sum-range, bulletproofs)");
let result;
try {
  result = await zk.verifyZk(
    {
      spec: "zk-transparent-statements-spec/v2.1.0",
      variant: "bulletproofs",
      statement: "committed-sum-range",
      context: GOLDEN_CTX,
      public_inputs: { n: GOLDEN_VALUES.length, total: GOLDEN_TOTAL },
      envelope_b64: proof.toString("base64"),
    },
    { context: GOLDEN_CTX, public_inputs: { n: GOLDEN_VALUES.length, total: GOLDEN_TOTAL } },
  );
  console.log("  ok    proof verifies");
} catch (err) {
  console.log(`  FAIL  proof did not verify: ${err.message}`);
  failures++;
  if (err.challenges) result = { challenges: err.challenges };
}

if (result) {
  console.log("\nchallenge stream (this is what localises a divergence)");
  check("padded_m", String(vectors.paddedM), String(4));
  for (const [id, want] of Object.entries(vectors.challenges)) {
    if (result.challenges[id] === undefined) { console.log(`  FAIL  ${id} not produced by the JS verifier`); failures++; continue; }
    check(id, scalarHex(result.challenges[id]), want);
  }
}

/* ---- 3b. committed-sum-cmp: the Mint statement, sum hidden ---- */
console.log("\nverification (committed-sum-cmp, bulletproofs)");
{
  const cmpProof = readFileSync(join(here, "cmp-ge.proof"));
  const CMP_PI = { n: 5, threshold: "12400000000", direction: "ge" };
  try {
    const r = await zk.verifyZk(
      { spec: "zk-transparent-statements-spec/v2.1.0", variant: "bulletproofs", statement: "committed-sum-cmp",
        context: GOLDEN_CTX, public_inputs: CMP_PI, envelope_b64: cmpProof.toString("base64") },
      { context: GOLDEN_CTX, public_inputs: CMP_PI },
    );
    console.log("  ok    proof verifies (Σ reserves ≥ 12,400,000,000)");
    if (r.total !== null) { console.log("  FAIL  a sum-hiding statement reported a total"); failures++; }
    else console.log("  ok    the sum is not revealed");
  } catch (err) { console.log(`  FAIL  ${err.message}`); failures++; }

  // The direction is transcript-bound AND changes the derived commitment D.
  try {
    await zk.verifyZk(
      { spec: "zk-transparent-statements-spec/v2.1.0", variant: "bulletproofs", statement: "committed-sum-cmp",
        context: GOLDEN_CTX, public_inputs: { ...CMP_PI, direction: "le" }, envelope_b64: cmpProof.toString("base64") },
      { context: GOLDEN_CTX, public_inputs: { ...CMP_PI, direction: "le" } },
    );
    console.log("  FAIL  a `ge` proof verified as `le`");
    failures++;
  } catch { console.log("  ok    direction flip rejected"); }
}

/* ---- 3c. sigma-fs carrier: same statements, other machinery ----
 * Two carriers proving one statement is defence in depth - a flaw in one is
 * caught by the other. It also inverts the cost: ~50x the bytes, ~half the
 * verification time, because there is no generator folding. */
console.log("\nverification (sigma-fs carrier)");
for (const [file, statement, pi] of [
  ["sigma-fs.proof", "committed-sum-range", { n: 3, total: "1000253" }],
  ["cmp-ge-sigmafs.proof", "committed-sum-cmp", { n: 5, threshold: "12400000000", direction: "ge" }],
]) {
  const env = readFileSync(join(here, file)).toString("base64");
  const t0 = Date.now();
  try {
    const r = await zk.verifyZk(
      { spec: "zk-transparent-statements-spec/v2.1.0", variant: "sigma-fs", statement,
        context: GOLDEN_CTX, public_inputs: pi, envelope_b64: env },
      { context: GOLDEN_CTX, public_inputs: pi });
    if (!r.ok) { bad(statement, "not ok"); }
    else console.log(`  ok    ${statement} (${Date.now() - t0} ms, ${Math.round(env.length * 3 / 4 / 1024)} KB)`);
    if (statement === "committed-sum-cmp" && r.total !== null) {
      console.log("  FAIL  cmp reported a total"); failures++;
    }
  } catch (err) { console.log(`  FAIL  ${statement}: ${err.message}`); failures++; }
}
{
  // A carrier swap must be refused - the variant code point separates them.
  const env = readFileSync(join(here, "cmp-ge-sigmafs.proof"));
  const pi = { n: 5, threshold: "12400000000", direction: "ge" };
  try {
    await zk.verifyZk(
      { spec: "zk-transparent-statements-spec/v2.1.0", variant: "bulletproofs", statement: "committed-sum-cmp",
        context: GOLDEN_CTX, public_inputs: pi, envelope_b64: env.toString("base64") },
      { context: GOLDEN_CTX, public_inputs: pi });
    console.log("  FAIL  a sigma-fs envelope verified as bulletproofs"); failures++;
  } catch { console.log("  ok    carrier swap rejected"); }
}

/* ---- 4. the verifier must REFUSE a tampered envelope ---- */
console.log("\nnegative: a flipped byte must be rejected");
{
  const bad = Buffer.from(proof);
  bad[bad.length - 1] ^= 0x01;
  try {
    await zk.verifyZk(
      { spec: "zk-transparent-statements-spec/v2.1.0", variant: "bulletproofs", statement: "committed-sum-range",
        context: GOLDEN_CTX, public_inputs: { n: 3, total: GOLDEN_TOTAL }, envelope_b64: bad.toString("base64") },
      { context: GOLDEN_CTX, public_inputs: { n: 3, total: GOLDEN_TOTAL } },
    );
    console.log("  FAIL  a tampered envelope verified");
    failures++;
  } catch { console.log("  ok    tampered envelope rejected"); }
}

/* ---- 5. a wrong expectation must be refused, not adopted (bundle §8.2) ---- */
console.log("\nnegative: the caller's expectation wins over the bundle");
{
  try {
    await zk.verifyZk(
      { spec: "zk-transparent-statements-spec/v2.1.0", variant: "bulletproofs", statement: "committed-sum-range",
        context: GOLDEN_CTX, public_inputs: { n: 3, total: GOLDEN_TOTAL }, envelope_b64: proof.toString("base64") },
      { context: GOLDEN_CTX, public_inputs: { n: 3, total: "999" } },
    );
    console.log("  FAIL  a total the caller did not expect was accepted");
    failures++;
  } catch { console.log("  ok    mismatched total refused"); }
}

/* ---- 6. a bundle cannot misstate what it proved ----
 * The parameters are transcript-bound, so relabelling them in the JSON must
 * fail. This is what lets the UI present the displayed values as genuine
 * rather than as an unverified claim. */
console.log("\nnegative: the bundle cannot relabel its own claim");
{
  const cmpProof = readFileSync(join(here, "cmp-ge.proof"));
  for (const [field, value] of [["threshold", "1"], ["direction", "le"], ["n", 4]]) {
    const pi = { n: 5, threshold: "12400000000", direction: "ge", [field]: value };
    try {
      await zk.verifyZk(
        { spec: "zk-transparent-statements-spec/v2.1.0", variant: "bulletproofs", statement: "committed-sum-cmp",
          context: GOLDEN_CTX, public_inputs: pi, envelope_b64: cmpProof.toString("base64") },
        { context: GOLDEN_CTX, public_inputs: pi });
      console.log(`  FAIL  a bundle claiming ${field}=${value} verified`);
      failures++;
    } catch { console.log(`  ok    relabelled ${field} rejected`); }
  }
}

console.log(failures === 0 ? "\nPASS - JS matches the Go contract" : `\nFAIL - ${failures} mismatch(es)`);
process.exit(failures === 0 ? 1 * 0 : 1);
