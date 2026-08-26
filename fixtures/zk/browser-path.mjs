/* =============================================================================
 * browser-path.mjs - exercise the code that actually ships.
 *
 * conformance.mjs tests zk-core.js. This tests the copy INSIDE index.html, by
 * extracting its <script> and running it against a real bundle. Without this
 * the tested artefact and the shipped artefact are different files, and the
 * inline check only proves they are byte-identical - not that the inlined
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
const inlined = new Function(`${m[1]}\nreturn { verifyZk, p256Verify, p256Mul, p256Compress, P256_G, webauthnVerifyAssertion, b64uToBytes };`)();
const verifyZk = inlined.verifyZk;

const CTX = { org_id: "00000000-0000-0000-0000-00000000abcd", run_ref: "golden:v1" };
let failures = 0;
const ok = (label) => console.log(`  ok    ${label}`);
const bad = (label, why) => { console.log(`  FAIL  ${label}: ${why}`); failures++; };

console.log("browser path - the inlined verifier inside index.html\n");

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

/* a wrong run_ref must not verify - context binding is the point */
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

/* P-256 / WebAuthn (bundle §9–§10) - the inlined copy must run too, on the
 * RFC 6979 §A.2.5 vector and on the shared bc30-v2 KAT assertion. */
{
  const hex = (h) => Uint8Array.from(Buffer.from(h, "hex"));
  const x = BigInt("0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
  const pub = inlined.p256Compress(inlined.p256Mul(inlined.P256_G, x));
  // DER of RFC 6979 A.2.5 "sample" (r = EFD4…, s = F7CB… - both MSB-set, so each INTEGER carries one leading 0x00)
  const der = hex("3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");
  try {
    (await inlined.p256Verify(pub, new TextEncoder().encode("sample"), der)) ? ok("inline P-256: RFC 6979 A.2.5 'sample' verifies (crypto.subtle)") : bad("inline P-256", "RFC vector did not verify");
    (await inlined.p256Verify(pub, new TextEncoder().encode("sample"), der, { pure: true })) ? ok("inline P-256: RFC 6979 A.2.5 'sample' verifies (pure BigInt)") : bad("inline P-256 pure", "RFC vector did not verify");
    (await inlined.p256Verify(pub, new TextEncoder().encode("sampl3"), der)) ? bad("inline P-256", "altered message verified") : ok("inline P-256: altered message rejected");
  } catch (e) { bad("inline P-256", e.message); }
  const vec = JSON.parse(readFileSync(join(repo, "fixtures", "bc30-v2-vectors.json"), "utf8"));
  try {
    const r = await inlined.webauthnVerifyAssertion({ pub33: hex(vec.issuer_pub33), authData: hex(vec.authenticator_data),
      cdj: hex(vec.client_data_json), sigDer: hex(vec.signature_der), challenge: hex(vec.m), rpId: vec.rp_id, origins: [vec.origin] });
    r.ok ? ok("inline WebAuthn: engine KAT issuer assertion verifies") : bad("inline WebAuthn", r.reasons.join("; "));
  } catch (e) { bad("inline WebAuthn", e.message); }
}

console.log(failures === 0 ? "\nPASS - the shipped inline verifier works" : `\nFAIL - ${failures}`);
process.exit(failures === 0 ? 0 : 1);
