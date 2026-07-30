/* =============================================================================
 * inline-zk.mjs — keep index.html's copy of zk-core.js honest.
 *
 * index.html must stay a single self-contained file (save it, run it offline,
 * forever). zk-core.js exists so the same code can be unit-tested and read on
 * its own. Two copies of crypto is exactly the drift this repository warns
 * about everywhere else, so the copy is MECHANICAL and this tool is the only
 * thing allowed to make it.
 *
 *   node tools/inline-zk.mjs           # re-inline (writes index.html)
 *   node tools/inline-zk.mjs --check   # fail if the inline copy has drifted
 *
 * CI runs --check, so a hand-edit inside index.html's zk block is caught
 * instead of quietly shipping a verifier that differs from the tested one.
 * ========================================================================== */
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const BEGIN = "/* ===== BEGIN inlined zk-core.js — edit zk-core.js, then run tools/inline-zk.mjs ===== */";
const END = "/* ===== END inlined zk-core.js ===== */";

/** The browser copy drops the CommonJS export tail and the duplicate directive. */
function browserCopy() {
  return readFileSync(join(repo, "zk-core.js"), "utf8")
    .split('if (typeof module !== "undefined"')[0]
    .replace(/^"use strict";\n/, "")
    .trimEnd();
}

const html = readFileSync(join(repo, "index.html"), "utf8");
const block = `${BEGIN}\n${browserCopy()}\n${END}`;
const re = new RegExp(
  escapeRe(BEGIN) + "[\\s\\S]*?" + escapeRe(END),
);
function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

if (!re.test(html)) {
  console.error("index.html has no inlined zk-core block (expected the BEGIN/END markers)");
  process.exit(1);
}

const updated = html.replace(re, block);
if (process.argv.includes("--check")) {
  if (updated !== html) {
    console.error("FAIL  index.html's inlined zk-core has drifted from zk-core.js.\n" +
                  "      Run: node tools/inline-zk.mjs");
    process.exit(1);
  }
  console.log("ok    index.html inline copy matches zk-core.js");
} else {
  writeFileSync(join(repo, "index.html"), updated);
  console.log("ok    re-inlined zk-core.js into index.html");
}
