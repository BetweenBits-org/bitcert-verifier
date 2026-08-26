/* =============================================================================
 * v4-grade-check.mjs - the browser's runV4 must reproduce Python's oracle.
 *
 * fixtures/v4-expected.json is written by fixtures/generate.py from
 * verify.py::verify_v4 - grade, exit code, both axes and the state of every
 * numbered step, per fixture and per option set. This runs the SHIPPED JS
 * (the pure section of index.html, above the "UI plumbing" marker) on the
 * same inputs and diffs. A drift names the fixture, the step and both states.
 *
 *   node fixtures/v4-grade-check.mjs
 * ========================================================================== */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
if (!globalThis.atob) globalThis.atob = (s) => Buffer.from(s, "base64").toString("binary");
if (!globalThis.btoa) globalThis.btoa = (s) => Buffer.from(s, "binary").toString("base64");

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(join(here, "..", "index.html"), "utf8");
const script = html.split("<script>")[1].split("</script>")[0];
const pure = script.slice(0, script.indexOf("/* ---------- UI plumbing"));
const F = new Function(pure + "\nreturn {runV4, parsePresentationBlob, decodeAnchorPayload, legacyPayloadProblem};")();

const oracle = JSON.parse(readFileSync(join(here, "v4-expected.json"), "utf8"));
let failures = 0, rows = 0;
const bad = (l) => { console.log("  FAIL  " + l); failures++; };

for (const row of oracle.rows) {
  rows++;
  const bundle = JSON.parse(readFileSync(join(here, row.file), "utf8"));
  const label = row.file + (row.identifier ? " --identifier " + row.identifier : "") + (row.presentation ? " --present" : "") + (row.nonce ? " --nonce" : "");
  if (row.legacy) {
    // Legacy bundles go through the UI-coupled verify(); the pure part that
    // decides the §4.1 compatibility rule is checked here.
    const problem = await F.legacyPayloadProblem(F.decodeAnchorPayload(bundle.anchor.op_return_payload_hex));
    const want = row.exit_code === 0 ? null : "problem";
    if ((problem === null) !== (want === null)) bad(label + ": legacyPayloadProblem=" + JSON.stringify(problem) + " but oracle exit " + row.exit_code);
    else console.log("  ok    " + label + " → " + row.grade + (problem ? " (" + problem + ")" : ""));
    continue;
  }
  const opts = { now: row.now };
  if (row.identifier !== undefined) opts.identifier = row.identifier;
  if (row.nonce !== undefined) opts.nonceHex = row.nonce;
  if (row.presentation) opts.presentation = F.parsePresentationBlob(readFileSync(join(here, row.presentation), "utf8"));
  const r = await F.runV4(bundle, opts);
  const diffs = [];
  if (r.grade !== row.grade) diffs.push("grade js=" + r.grade + " py=" + row.grade);
  if (r.exitCode !== row.exit_code) diffs.push("exit js=" + r.exitCode + " py=" + row.exit_code);
  for (const ax of ["attribution", "presenter"]) if (r.axes[ax] !== row.axes[ax]) diffs.push(ax + " js=" + JSON.stringify(r.axes[ax]) + " py=" + JSON.stringify(row.axes[ax]));
  if (r.steps.length !== row.steps.length) diffs.push("step count js=" + r.steps.length + " py=" + row.steps.length);
  const n = Math.min(r.steps.length, row.steps.length);
  for (let i = 0; i < n; i++) {
    const a = r.steps[i], b = row.steps[i];
    if (a.num !== b.num || a.key !== b.key || a.state !== b.state)
      diffs.push("step " + b.num + "/" + b.key + " js=" + a.num + "/" + a.key + "/" + a.state + " py=" + b.state);
  }
  if (diffs.length) bad(label + "\n        " + diffs.join("\n        "));
  else console.log("  ok    " + label + " → " + r.grade + " · " + r.axes.attribution + " · " + r.axes.presenter);
}

console.log(failures ? "\nFAIL (" + failures + " of " + rows + " rows)" : "\nOK - runV4 (index.html) reproduces verify.py's oracle on all " + rows + " rows");
process.exit(failures ? 1 : 0);
