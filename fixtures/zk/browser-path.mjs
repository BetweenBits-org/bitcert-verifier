/* =============================================================================
 * browser-path.mjs — exercise the code that actually ships.
 *
 * conformance.mjs tests zk-core.js. This tests the copy INSIDE index.html, by
 * extracting its <script> and running it against a real bundle. Without this
 * the tested artefact and the shipped artefact are different files, and the
 * inline check only proves they are byte-identical — not that the inlined
 * version still runs (a browser-only global, a stray DOM reference, and the
 * page breaks while CI stays green).
 * ========================================================================== */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
if (!globalThis.atob) globalThis.atob = (s) => Buffer.from(s, "base64").toString("binary");

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..");

const html = readFileSync(join(repo, "index.html"), "utf8");
const m = html.match(/\/\* ===== BEGIN inlined zk-core\.js[^\n]*\n([\s\S]*?)\n\/\* ===== END inlined zk-core\.js ===== \*\//);
if (!m) { console.error("no inlined zk block in index.html"); process.exit(1); }

// Run the inlined source and hand back its entry point. Nothing else from the
// page is loaded, so a DOM dependency inside the zk block would fail here.
const verifyZk = new Function(`${m[1]}\nreturn verifyZk;`)();

const CTX = { org_id: "00000000-0000-0000-0000-00000000abcd", run_ref: "golden:v1" };
let failures = 0;
const ok = (label) => console.log(`  ok    ${label}`);
const bad = (label, why) => { console.log(`  FAIL  ${label}: ${why}`); failures++; };

console.log("browser path — the inlined verifier inside index.html\n");

/* committed-sum-range */
{
  const env = readFileSync(join(here, "bulletproofs.proof")).toString("base64");
  const pi = { n: 3, total: "1000253" };
  try {
    const r = await verifyZk(
      { spec: "zk-transparent-statements-spec/v2.1.0", variant: "bulletproofs",
        statement: "committed-sum-range", context: CTX, public_inputs: pi, envelope_b64: env },
      { context: CTX, public_inputs: pi });
    r.ok ? ok("committed-sum-range verifies") : bad("committed-sum-range", "not ok");
  } catch (e) { bad("committed-sum-range", e.message); }
}

/* committed-sum-cmp */
{
  const env = readFileSync(join(here, "cmp-ge.proof")).toString("base64");
  const pi = { n: 5, threshold: "12400000000", direction: "ge" };
  try {
    const r = await verifyZk(
      { spec: "zk-transparent-statements-spec/v2.1.0", variant: "bulletproofs",
        statement: "committed-sum-cmp", context: CTX, public_inputs: pi, envelope_b64: env },
      { context: CTX, public_inputs: pi });
    if (!r.ok) bad("committed-sum-cmp", "not ok");
    else if (r.total !== null) bad("committed-sum-cmp", "reported a total for a sum-hiding statement");
    else ok("committed-sum-cmp verifies, sum stays hidden");
  } catch (e) { bad("committed-sum-cmp", e.message); }
}

/* a wrong run_ref must not verify — context binding is the point */
{
  const env = readFileSync(join(here, "bulletproofs.proof")).toString("base64");
  const other = { org_id: CTX.org_id, run_ref: "golden:v2" };
  const pi = { n: 3, total: "1000253" };
  try {
    await verifyZk(
      { spec: "zk-transparent-statements-spec/v2.1.0", variant: "bulletproofs",
        statement: "committed-sum-range", context: other, public_inputs: pi, envelope_b64: env },
      { context: other, public_inputs: pi });
    bad("context binding", "a proof verified under a different run_ref");
  } catch { ok("a different run_ref is rejected"); }
}

console.log(failures === 0 ? "\nPASS — the shipped inline verifier works" : `\nFAIL — ${failures}`);
process.exit(failures === 0 ? 0 : 1);
