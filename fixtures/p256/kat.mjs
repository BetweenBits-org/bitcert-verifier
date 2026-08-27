/* =============================================================================
 * kat.mjs - P-256 / ES256 / WebAuthn known answers for zk-core.js.
 *
 * Pins the JS routines (both the Web Crypto path and the pure BigInt fallback)
 * against RFC 6979 §A.2.5 "ECDSA, 256 Bits (Prime Field)" - copied from the
 * RFC text (https://www.rfc-editor.org/rfc/rfc6979.txt) and cross-checked with
 * the vendored p256-0.13.2 crate (src/ecdsa.rs, test `rfc6979`); the same
 * vector verify.py --selftest pins - and against fixtures/bc30-v2-vectors.json,
 * the KAT file ann-core and the console pin too.
 *
 *   node fixtures/p256/kat.mjs
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
const big = (h) => BigInt("0x" + h);
const utf8 = (s) => new TextEncoder().encode(s);
function rsToDer(r, s) {
  const int = (v) => { let b = Buffer.from(v.toString(16).padStart(64, "0"), "hex"); if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return Buffer.concat([Buffer.from([2, b.length]), b]); };
  const body = Buffer.concat([int(r), int(s)]);
  return Uint8Array.from(Buffer.concat([Buffer.from([0x30, body.length]), body]));
}

const RFC = {
  x: "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
  Ux: "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
  Uy: "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
  sample: { r: "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", s: "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8" },
  test:   { r: "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367", s: "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083" },
};

console.log("P-256 known answers (zk-core.js)\n");

/* curve arithmetic + key encoding */
const U = Z.p256Mul(Z.P256_G, big(RFC.x));
expect(U.x === big(RFC.Ux) && U.y === big(RFC.Uy), "RFC 6979 A.2.5 - x·G == (Ux, Uy)");
const pub = Z.p256Compress(U);
expect(Z.p256Decompress(pub).y === U.y, "decompress - 02/03 prefix recovers Uy");
const flipped = new Uint8Array(pub); flipped[0] = 5 - pub[0];
expect(Z.p256Decompress(flipped).y === Z.P256_P - U.y, "decompress - opposite parity yields −y");
try { Z.p256Decompress(new Uint8Array(33).fill(0xff, 1).fill(2, 0, 1)); bad("decompress - x ≥ p rejected"); } catch { ok("decompress - x ≥ p rejected"); }
try { Z.p256Decompress(new Uint8Array(65)); bad("decompress - 65-byte key rejected"); } catch { ok("decompress - non-33-byte key rejected"); }

/* signatures, both execution paths */
for (const pure of [false, true]) {
  const path = pure ? "pure BigInt" : "crypto.subtle";
  for (const m of ["sample", "test"]) {
    const der = rsToDer(big(RFC[m].r), big(RFC[m].s));
    expect(await Z.p256Verify(pub, utf8(m), der, { pure }), `${path} - SHA-256(${JSON.stringify(m)}) verifies`);
    expect(!(await Z.p256Verify(pub, utf8(m + "!"), der, { pure })), `${path} - altered message rejected`);
    expect(await Z.p256Verify(pub, utf8(m), rsToDer(big(RFC[m].r), Z.P256_N - big(RFC[m].s)), { pure }), `${path} - (r, n−s) also verifies (low-s not enforced)`);
  }
  const wrongKey = Z.p256Compress(Z.p256Mul(Z.P256_G, 2n));
  expect(!(await Z.p256Verify(wrongKey, utf8("sample"), rsToDer(big(RFC.sample.r), big(RFC.sample.s)), { pure })), `${path} - wrong key rejected`);
}

/* DER strictness */
const good = rsToDer(big(RFC.sample.r), big(RFC.sample.s));
const rejects = (sig, label) => { try { Z.derToRawSig(sig); bad("DER strict - " + label + " rejected"); } catch { ok("DER strict - " + label + " rejected"); } };
rejects(Uint8Array.from([...good, 0]), "trailing byte");
rejects(good.subarray(0, good.length - 1), "truncated");
{ // r has its MSB set: one 0x00 is minimal, two are not
  const sint = good.subarray(2 + 2 + good[3]);
  const nonmin = Uint8Array.from([2, 0x22, 0, 0, ...Buffer.from(RFC.sample.r, "hex")]);
  rejects(Uint8Array.from([0x30, nonmin.length + sint.length, ...nonmin, ...sint]), "non-minimal leading 0x00 (MSB-set value)");
}
rejects(Uint8Array.from([0x30, 7, 2, 2, 0, 1, 2, 1, 1]), "non-minimal leading 0x00 (small value)");
rejects(rsToDer(big(RFC.sample.r), 0n), "s = 0");
rejects(rsToDer(Z.P256_N, big(RFC.sample.s)), "r = n");
rejects(Uint8Array.from([0x30, 0x81, good.length - 2, ...good.subarray(2)]), "long-form length");
{ const d = Z.derToRawSig(good); expect(d.r === big(RFC.sample.r) && d.s === big(RFC.sample.s) && d.raw.length === 64, "DER strict - canonical encoding round-trips to raw r‖s"); }

/* base64url */
{ const all = Uint8Array.from({ length: 256 }, (_, i) => i);
  expect(Buffer.from(Z.b64uToBytes(Z.bytesToB64u(all))).equals(Buffer.from(all)), "base64url - 256-byte round-trip");
  try { Z.b64uToBytes("ab+/"); bad("base64url - standard alphabet rejected"); } catch { ok("base64url - standard alphabet rejected"); }
  try { Z.b64uToBytes("abc=="); bad("base64url - padding rejected"); } catch { ok("base64url - padding rejected"); } }

/* engine KAT - fixtures/bc30-v2-vectors.json is a byte-identical copy of
 * ann-core/crates/bc30-leaf/tests/vectors/bc30-v2-kat.json (the canonical file) */
const vec = JSON.parse(readFileSync(join(repo, "fixtures", "bc30-v2-vectors.json"), "utf8"));
for (const pure of [false, true]) {
  const path = pure ? "pure" : "subtle";
  const r = await Z.webauthnVerifyAssertion({ pub33: hex(vec.issuer_pub33), authData: hex(vec.authenticator_data), cdj: hex(vec.client_data_json),
    sigDer: hex(vec.signature_der), challenge: hex(vec.m), rpId: vec.rp_id, origins: [vec.origin], pure });
  expect(r.ok, `engine KAT (${path}) - issuer WebAuthn assertion verifies`, r.reasons.join("; "));
  expect(r.facts.uv === true && r.facts.signCount === vec.sign_count && r.facts.origin === vec.origin, `engine KAT (${path}) - parsed facts (UV, signCount, origin)`);
  const wrongRp = await Z.webauthnVerifyAssertion({ pub33: hex(vec.issuer_pub33), authData: hex(vec.authenticator_data), cdj: hex(vec.client_data_json),
    sigDer: hex(vec.signature_der), challenge: hex(vec.m), rpId: "evil.example.com", origins: [vec.origin], pure });
  expect(!wrongRp.ok && wrongRp.reasons.some(x => x.startsWith("rpIdHash")), `engine KAT (${path}) - wrong rpId is named in the reasons`);
  const wrongChal = await Z.webauthnVerifyAssertion({ pub33: hex(vec.issuer_pub33), authData: hex(vec.authenticator_data), cdj: hex(vec.client_data_json),
    sigDer: hex(vec.signature_der), challenge: hex(vec.leaf_input), rpId: vec.rp_id, origins: [vec.origin], pure });
  expect(!wrongChal.ok && wrongChal.reasons.some(x => x.includes("challenge")), `engine KAT (${path}) - wrong challenge is named in the reasons`);
  expect(await Z.p256Verify(hex(vec.issuer_pub33), hex(vec.m), hex(vec.signature_der_plain), { pure }), `engine KAT (${path}) - es256-plain signature over m verifies`);
  const pr = await Z.webauthnVerifyAssertion({ pub33: hex(vec.subject_pub33), authData: hex(vec.present_authenticator_data), cdj: hex(vec.present_client_data_json),
    sigDer: hex(vec.present_signature_der), challenge: hex(vec.present_challenge), rpId: vec.rp_id, origins: [vec.origin], pure });
  expect(pr.ok && pr.facts.signCount === vec.present_sign_count, `engine KAT (${path}) - presentation assertion verifies under the subject key`, pr.reasons.join("; "));
}
{ const ad = Z.parseAuthenticatorData(hex(vec.authenticator_data));
  expect(Buffer.from(ad.rpIdHash).toString("hex") === vec.rp_id_hash && ad.flags === 0x05 && ad.signCount === vec.sign_count, "engine KAT - authenticatorData rpIdHash/flags/signCount"); }
{ const U = Z.p256Mul(Z.P256_G, big(vec.issuer_priv)), S = Z.p256Mul(Z.P256_G, big(vec.subject_priv));
  expect(Buffer.from(Z.p256Compress(U)).toString("hex") === vec.issuer_pub33 && Buffer.from(Z.p256Compress(S)).toString("hex") === vec.subject_pub33, "engine KAT - issuer/subject pub33 = compress(priv·G)"); }

console.log(failures ? `\nFAIL (${failures})` : "\nOK - zk-core.js P-256/WebAuthn matches RFC 6979 A.2.5 + the engine KAT on both paths");
process.exit(failures ? 1 : 0);
