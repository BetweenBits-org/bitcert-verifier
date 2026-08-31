/* =============================================================================
 * kat.mjs - party-model v2 known answers for zk-core.js (bundle §12, N0).
 *
 * Pins the NEW engine-KAT sections of fixtures/bc30-v2-vectors.json (the
 * byte-identical copy of ann-core/crates/bc30-leaf/tests/vectors/
 * bc30-v2-kat.json) against zk-core.js:
 *
 *   cosign                   - m_i = SHA256("BC30/cosign/v1" ‖ m ‖ role_len ‖ role), role_ord table
 *   wallet                   - Bitcoin message digest (double SHA-256), secp256k1
 *                              ECDSA on the DIGEST directly, low-s, key_id,
 *                              registration recovery (header 27..=34 → 33 B compressed)
 *   multisig                 - strict 0x10 parse / reassembly round-trip, per-entry
 *                              verification against the role-recomputed m_i
 *   es256_plain_alternate_s  - (r, n−s) ACCEPTED for 0x02 (low-s not enforced there)
 *   policy_open + negatives  - appendix-B grammar gate (script-local, the console
 *                              (TS) mirrors it) + JCS bytes + policy_hash
 *   negative_v2              - all 27 cases fail at their declared stage with
 *                              their declared error identifier
 *
 * verify.py --selftest runs the same sections through the Python primitives.
 *
 *   node fixtures/multisig/kat.mjs
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
const sha256 = (b) => Z.zkSha256(b);

const vec = JSON.parse(readFileSync(join(repo, "fixtures", "bc30-v2-vectors.json"), "utf8"));
for (const k of ["cosign", "wallet", "multisig", "policy_open", "es256_plain_alternate_s", "negative_v2"]) {
  if (!(k in vec)) { console.log("FAIL  section " + k + " missing - stale fixtures/bc30-v2-vectors.json"); process.exit(1); }
}
const m = hex(vec.m);

console.log("party-model v2 known answers (zk-core.js)\n");

/* ---- cosign: m_i per role + the frozen role_ord table ---- */
expect(vec.cosign.tag_utf8 === Z.COSIGN_TAG && vec.cosign.m === vec.m, "cosign - tag + m pinned");
for (const cv of vec.cosign.vectors) {
  const mi = await Z.cosignMessage(m, cv.role);
  expect(toHex(mi) === cv.m_i && Z.bytesToB64u(mi) === cv.m_i_b64u && Z.COSIGN_ROLE_ORD[cv.role] === cv.role_ord,
    `cosign - m_i(${cv.role}) + b64u + role_ord ${cv.role_ord}`);
}

/* ---- wallet: digest, direct-digest ECDSA, low-s, key_id, recovery ---- */
const wa = vec.wallet;
const wpub = hex(wa.public_key);
expect(wa.curve_id === 2, "wallet - curve_id 2 (secp256k1)");
const wmsg = utf8("BC30 issuance " + vec.m);
expect(new TextDecoder().decode(wmsg) === wa.issuance_message_utf8 && wmsg.length === wa.issuance_message_len,
  "wallet - issuance message (\"BC30 issuance \" + hex(m))");
const wdg = await Z.bitcoinMessageDigest(wmsg);
expect(toHex(wdg) === wa.issuance_digest, "wallet - digest = double-SHA256(0x18 + magic + varint + msg)");
const rs = hex(wa.signature_rs);
const wr = BigInt("0x" + wa.signature_rs.slice(0, 64)), ws = BigInt("0x" + wa.signature_rs.slice(64));
expect(Z.secpIsLowS(ws), "wallet - engine signature is low-s");
expect(Z.secp256k1VerifyDigest(wpub, wdg, wr, ws), "wallet - secp256k1 ECDSA verifies the DIGEST directly");
expect(!Z.secp256k1VerifyDigest(wpub, await sha256(wdg), wr, ws), "wallet - a re-hashed digest correctly fails (no re-hash)");
expect(wa.s_wallet === "04" + wa.signature_rs && rs.length === 64, "wallet - s (0x04) = 0x04 + r + s, exactly 65 B");
expect(toHex(await sha256(Z.zkCat(Uint8Array.of(2, wa.curve_id), wpub))) === wa.key_id,
  "wallet - key_id = SHA256(0x02 + curve_id + pubkey33)");
const rdg = await Z.bitcoinMessageDigest(utf8(wa.registration_message_utf8));
expect(toHex(rdg) === wa.registration_digest, "wallet - registration digest");
const sig65 = hex(wa.registration_sig65);
const header = sig65[0], rr = BigInt("0x" + toHex(sig65.subarray(1, 33))), sr = BigInt("0x" + toHex(sig65.subarray(33)));
expect(header === wa.registration_recovery_header, "wallet - recovery header " + header);
const rec = Z.secp256k1RecoverPubkey(rdg, header, rr, sr);
expect(toHex(rec) === wa.recovered_public_key && wa.recovered_public_key === wa.public_key,
  "wallet - registration recovery returns the 33 B compressed key");
const twin = header >= 31 ? header - 4 : header + 4;   // same recid, opposite compression hint
expect(toHex(Z.secp256k1RecoverPubkey(rdg, twin, rr, sr)) === toHex(rec),
  `wallet - headers ${header}/${twin} recover the same key (27..=34 is one range)`);
for (const badH of [26, 35]) {
  try { Z.secp256k1RecoverPubkey(rdg, badH, rr, sr); bad(`wallet - recovery header ${badH} rejected`); }
  catch { ok(`wallet - recovery header ${badH} rejected`); }
}

/* ---- multisig: parse, reassemble, leaf binding, per-entry verify ---- */
const ms = vec.multisig;
const pubmap = new Map();
for (const t of ms.entries) pubmap.set(t.key_id, { curve: t.curve_id, pub: hex(t.public_key) });
const entries = Z.parseMultisigS(hex(ms.s));
expect(entries.length === ms.count, "multisig - count " + ms.count);
expect(toHex(Z.assembleMultisigS(entries.map((e) => ({ role: e.role, keyId: e.keyId, inner: e.inner })))) === ms.s,
  "multisig - parse -> reassemble round-trips byte-for-byte");
expect(toHex(Z.assembleMultisigS(ms.entries.map((t) => ({ role: t.role, keyId: hex(t.key_id), inner: hex(t.inner_sig) })))) === ms.s,
  "multisig - s rebuilt from the entry list (the v5 signers[] direction)");
const leafInput = await sha256(Z.zkCat(utf8("BC30/leaf/v2"), Uint8Array.of(0x01), hex(vec.R), hex(ms.s)));
expect(toHex(leafInput) === ms.leaf_input, "multisig - leaf_input = SHA256(leaf-v2 tag + 0x01 + R + s)");
expect(toHex(await sha256(Z.zkCat(Uint8Array.of(0x00), leafInput))) === ms.leaf_hash, "multisig - leaf_hash = H_leaf(leaf_input)");

/** Verify ONE parsed entry against the m_i recomputed from its PARSED role.
 * Returns null on success or the engine error identifier. */
async function verifyEntry(e, pure) {
  const info = pubmap.get(toHex(e.keyId));
  if (!info) return "unknown_key";
  const mi = await Z.cosignMessage(m, e.role);
  if (e.alg === 0x01) {
    const r = await Z.webauthnVerifyAssertion({ pub33: info.pub, authData: e.authData, cdj: e.cdj,
      sigDer: e.sigDer, challenge: mi, rpId: vec.rp_id, origins: [vec.origin], pure });
    if (r.ok) return null;
    return r.reasons.some((x) => x.includes("challenge")) ? "challenge_mismatch" : "bad_signature";
  }
  if (e.alg === 0x02) return (await Z.p256Verify(info.pub, mi, e.sigDer, { pure })) ? null : "bad_signature";
  if (e.alg === 0x04) {
    if (!Z.secpIsLowS(e.s)) return "non_low_s";
    const dg = await Z.bitcoinMessageDigest(utf8("BC30 cosign " + toHex(mi)));
    return Z.secp256k1VerifyDigest(info.pub, dg, e.r, e.s) ? null : "bad_signature";
  }
  return "unknown_inner_alg";
}
for (const [i, e] of entries.entries()) {
  const t = ms.entries[i];
  expect(toHex(await Z.cosignMessage(m, e.role)) === t.m_i, `multisig - ${e.role} m_i recomputes from the parsed role`);
  expect((e.alg === 0x04 ? 2 : 1) === t.curve_id, `multisig - ${e.role} alg 0x0${e.alg.toString(16)} <-> curve_id ${t.curve_id}`);
  for (const pure of [false, true]) {
    const err = await verifyEntry(e, pure);
    expect(err === null, `multisig - ${e.role} entry verifies (alg 0x0${e.alg.toString(16)}, ${pure ? "pure" : "subtle"})`, err);
  }
}
{ const t = ms.entries.find((x) => x.inner_alg === 4);
  const dg = await Z.bitcoinMessageDigest(utf8(t.wallet_message_utf8));
  expect(toHex(dg) === t.wallet_digest && t.wallet_message_utf8 === "BC30 cosign " + t.m_i,
    "multisig - endorser wallet message + digest"); }

/* ---- es256_plain_alternate_s: low-s NOT enforced for 0x02 ---- */
for (const pure of [false, true]) {
  expect(vec.es256_plain_alternate_s.expect === "valid"
    && await Z.p256Verify(hex(vec.issuer_pub33), m, hex(vec.es256_plain_alternate_s.signature_der), { pure }),
    `es256-plain - (r, n-s) re-encoding ACCEPTED (${pure ? "pure" : "subtle"})`);
}

/* ---- policy grammar gate (appendix B; script-local - the console mirrors it) ---- */
const POLICY_KEY_RE = /^[a-z][a-z0-9_]{0,31}$/;
function policyCharForbidden(cp) {
  return cp < 0x20 || cp === 0x7f || (cp >= 0x80 && cp <= 0x9f) || (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069);
}
function policyValidate(pairs) {   // -> {policy} or throws {code}
  if (pairs.length > 16) throw msE("too_many_pairs");
  const seen = new Set();
  for (const [k, v] of pairs) {
    if (typeof k !== "string" || !POLICY_KEY_RE.test(k)) throw msE("invalid_key");
    if (seen.has(k)) throw msE("duplicate_key");
    seen.add(k);
    if (typeof v !== "string") throw msE("invalid_value");
    for (const ch of v) if (policyCharForbidden(ch.codePointAt(0))) throw msE("forbidden_char");
    if (utf8(v).length > 256) throw msE("value_too_long");
  }
  for (const k of ["document_type", "jurisdiction"]) if (!seen.has(k)) throw msE("missing_required_key");
  const policy = {};
  for (const k of [...seen].sort()) policy[k] = pairs.find((p) => p[0] === k)[1];
  if (utf8(JSON.stringify(policy)).length > 2048) throw msE("jcs_too_long");
  return policy;
}
function msE(code) { const e = new Error(code); e.code = code; return e; }
for (const pv of vec.policy_open.vectors) {
  try {
    const policy = policyValidate(pv.pairs);
    const jcs = JSON.stringify(policy);            // keys ASCII-closed: code-unit order == byte order
    expect(jcs === pv.jcs_utf8 && toHex(utf8(jcs)) === pv.jcs_hex && toHex(await sha256(utf8(jcs))) === pv.policy_hash,
      `policy - ${pv.name}: grammar ok, JCS bytes + policy_hash`);
  } catch (e) { bad(`policy - ${pv.name} unexpectedly refused`, e.message); }
}

/* ---- negative_v2: all 27 fail at their stage with their identifier ---- */
expect(vec.negative_v2.length === 27, "negatives - 27 cases present");
for (const nc of vec.negative_v2) {
  let got = null;
  if (nc.stage === "parse") {
    try { Z.parseMultisigS(hex(nc.s)); } catch (e) { got = e.code || e.message; }
  } else if (nc.stage === "policy") {
    try { policyValidate(nc.pairs); } catch (e) { got = e.code || e.message; }
  } else if (nc.stage === "verify") {
    const sb = hex(nc.s);
    if (sb[0] === 0x10) {
      let parsed = null;
      try { parsed = Z.parseMultisigS(sb); } catch (e) { got = "parse:" + (e.code || e.message); }
      if (parsed) for (const e of parsed) { const err = await verifyEntry(e, false); if (err) { got = err; break; } }
    } else if (sb[0] === 0x04 && sb.length === 65) {
      const r = BigInt("0x" + toHex(sb.subarray(1, 33))), s = BigInt("0x" + toHex(sb.subarray(33)));
      if (!Z.secpIsLowS(s)) {
        // prove it is the POLICY that rejects: the mirrored scalar verifies
        got = Z.secp256k1VerifyDigest(wpub, wdg, r, Z.ZK_N - s) ? "non_low_s" : "bad_signature";
      } else got = Z.secp256k1VerifyDigest(wpub, wdg, r, s) ? null : "bad_signature";
    } else got = "unknown_alg";
  }
  expect(got === nc.error, `negative - ${nc.name} fails at ${nc.stage} with "${nc.error}"`, "got " + JSON.stringify(got));
}

console.log(failures ? `\nFAIL (${failures})` : "\nOK - zk-core.js matches the engine KAT's party-model v2 sections (cosign / wallet / multisig / policy / 27 negatives)");
process.exit(failures ? 1 : 0);
