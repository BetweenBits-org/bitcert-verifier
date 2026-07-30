/* =============================================================================
 * zk-core.js — zero-knowledge statement verification (bundle §8)
 *
 * Verifies `committed-sum-range` and `committed-sum-cmp` bulletproofs envelopes
 * per the frozen wire contract `zk-transparent-statements-spec.md v2.1.0`.
 *
 * NO DEPENDENCIES. Plain BigInt over secp256k1 — the same rule the rest of this
 * verifier follows, so you can read every line that decides the answer. It is
 * not fast (a few seconds for a 100-value proof); it is auditable, which is the
 * property this repository sells.
 *
 * This file is inlined verbatim into index.html and also loaded directly by the
 * conformance runner, so it must stay free of both DOM and Node built-ins.
 * SHA-256 comes from Web Crypto, which both environments provide.
 * ========================================================================== */
"use strict";

/* ---------- secp256k1 field ---------- */
const ZK_P = 2n ** 256n - 2n ** 32n - 977n;              // field modulus
const ZK_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n; // group order

const zkMod = (a, m) => ((a % m) + m) % m;
function zkPow(b, e, m) { let r = 1n; b = zkMod(b, m); while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; }
const zkInvP = (a) => zkPow(a, ZK_P - 2n, ZK_P);
const zkInvN = (a) => zkPow(a, ZK_N - 2n, ZK_N);
/** p ≡ 3 (mod 4) ⇒ sqrt(a) = a^((p+1)/4). Returns null when a is not a QR. */
function zkSqrtP(a) { const r = zkPow(a, (ZK_P + 1n) / 4n, ZK_P); return r * r % ZK_P === zkMod(a, ZK_P) ? r : null; }

/* ---------- points ----------
 * Affine {x,y} (null = infinity) is the external form; the arithmetic runs in
 * JACOBIAN coordinates internally. That is not premature optimisation: an
 * affine addition needs a modular inverse, and a verification performs on the
 * order of a million point operations — with inverses it does not finish.
 * Jacobian defers every inverse to a single conversion at the end. */
const ZK_G = { x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
               y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n };

const M = (a) => { const r = a % ZK_P; return r < 0n ? r + ZK_P : r; };
/** Jacobian: (X, Y, Z) represents affine (X/Z², Y/Z³); Z = 0 is infinity. */
const zkJinf = () => ({ X: 1n, Y: 1n, Z: 0n });
function zkToJ(p) { return p === null ? zkJinf() : { X: p.x, Y: p.y, Z: 1n }; }
function zkToAffine(j) {
  if (j.Z === 0n) return null;
  const zi = zkInvP(j.Z), zi2 = zi * zi % ZK_P, zi3 = zi2 * zi % ZK_P;
  return { x: j.X * zi2 % ZK_P, y: j.Y * zi3 % ZK_P };
}
function zkJdouble(j) {
  if (j.Z === 0n || j.Y === 0n) return zkJinf();
  const A = j.X * j.X % ZK_P, B = j.Y * j.Y % ZK_P, C = B * B % ZK_P;
  const D = M(2n * ((j.X + B) * (j.X + B) % ZK_P - A - C));
  const E = 3n * A % ZK_P, F = E * E % ZK_P;
  const X = M(F - 2n * D);
  return { X, Y: M(E * M(D - X) - 8n * C), Z: 2n * j.Y % ZK_P * j.Z % ZK_P };
}
function zkJadd(a, b) {
  if (a.Z === 0n) return b;
  if (b.Z === 0n) return a;
  const z1z1 = a.Z * a.Z % ZK_P, z2z2 = b.Z * b.Z % ZK_P;
  const u1 = a.X * z2z2 % ZK_P, u2 = b.X * z1z1 % ZK_P;
  const s1 = a.Y * b.Z % ZK_P * z2z2 % ZK_P, s2 = b.Y * a.Z % ZK_P * z1z1 % ZK_P;
  if (u1 === u2) return s1 === s2 ? zkJdouble(a) : zkJinf();
  const h = M(u2 - u1), i = 4n * h % ZK_P * h % ZK_P, jj = h * i % ZK_P;
  const r = M(2n * (s2 - s1)), v = u1 * i % ZK_P;
  const X = M(r * r - jj - 2n * v);
  return { X, Y: M(r * M(v - X) - 2n * s1 % ZK_P * jj), Z: M(((a.Z + b.Z) * (a.Z + b.Z) % ZK_P - z1z1 - z2z2) * h) };
}
function zkJmul(j, k) {
  k = zkMod(k, ZK_N);
  if (k === 0n || j.Z === 0n) return zkJinf();
  let acc = zkJinf(), base = j;
  while (k > 0n) { if (k & 1n) acc = zkJadd(acc, base); base = zkJdouble(base); k >>= 1n; }
  return acc;
}

function zkPtEq(a, b) { if (a === null || b === null) return a === b; return a.x === b.x && a.y === b.y; }
function zkNeg(p) { return p === null ? null : { x: p.x, y: zkMod(-p.y, ZK_P) }; }
function zkAdd(p, q) { return zkToAffine(zkJadd(zkToJ(p), zkToJ(q))); }
function zkMul(p, k) { return zkToAffine(zkJmul(zkToJ(p), k)); }
/** Σ scalars[i]·points[i], accumulated in Jacobian (one inverse total). */
function zkMsm(points, scalars) {
  let acc = zkJinf();
  for (let i = 0; i < points.length; i++) {
    if (points[i] === null) continue;
    acc = zkJadd(acc, zkJmul(zkToJ(points[i]), scalars[i]));
  }
  return zkToAffine(acc);
}
/** Σ points[i] — every scalar equal, so multiply the sum once, not each term. */
function zkSumPoints(points) { let acc = zkJinf(); for (const p of points) if (p !== null) acc = zkJadd(acc, zkToJ(p)); return zkToAffine(acc); }

/* ---------- SEC1 (spec §14.1) ---------- */
const ZK_POINT_LEN = 33;
function zkSec1Encode(p) {
  const out = new Uint8Array(ZK_POINT_LEN);
  if (p === null) return out;                                  // infinity = 33 zero bytes
  out[0] = (p.y & 1n) === 1n ? 0x03 : 0x02;
  let x = p.x;
  for (let i = 32; i >= 1; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
}
function zkSec1Decode(b) {
  if (b.length !== ZK_POINT_LEN) throw new Error("SEC1: length " + b.length + ", want 33");
  const prefix = b[0];
  let x = 0n;
  for (let i = 1; i < ZK_POINT_LEN; i++) x = (x << 8n) | BigInt(b[i]);
  if (prefix === 0x00) {
    if (x !== 0n) throw new Error("SEC1: infinity encoding carries a non-zero X");
    return null;
  }
  if (prefix !== 0x02 && prefix !== 0x03) throw new Error("SEC1: prefix 0x" + prefix.toString(16));
  if (x >= ZK_P) throw new Error("SEC1: non-canonical X");     // aliasing guard
  const y2 = zkMod(x * x % ZK_P * x + 7n, ZK_P);
  const y = zkSqrtP(y2);
  if (y === null) throw new Error("SEC1: X is not on the curve");
  const wantOdd = prefix === 0x03;
  return { x, y: ((y & 1n) === 1n) === wantOdd ? y : zkMod(-y, ZK_P) };
}

/* ---------- byte helpers ---------- */
function zkU32be(v) { return Uint8Array.of((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255); }
function zkU64be(v) { const o = new Uint8Array(8); let x = BigInt(v); for (let i = 7; i >= 0; i--) { o[i] = Number(x & 0xffn); x >>= 8n; } return o; }
function zkLenPrefixed(str) {
  const b = new TextEncoder().encode(str);
  const o = new Uint8Array(4 + b.length);
  o.set(zkU32be(b.length), 0); o.set(b, 4);
  return o;
}
function zkScalarBytes(s) { const o = new Uint8Array(32); let x = zkMod(s, ZK_N); for (let i = 31; i >= 0; i--) { o[i] = Number(x & 0xffn); x >>= 8n; } return o; }
function zkBytesToBig(b) { let x = 0n; for (const v of b) x = (x << 8n) | BigInt(v); return x; }
function zkCat(...arrs) { let n = 0; for (const a of arrs) n += a.length; const o = new Uint8Array(n); let k = 0; for (const a of arrs) { o.set(a, k); k += a.length; } return o; }
async function zkSha256(bytes) { return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)); }

/* ---------- NUMS generators (spec §14.4) ----------
 * try-and-increment. Deliberately NOT hash-to-curve: RFC 9380 defines several
 * maps and libraries disagree on which to use for secp256k1 (gnark picks SVDW,
 * the registered suite is SSWU), so a hash-to-curve generator would only be
 * reproducible by whoever picked the same map. This is 15 lines and anyone can
 * redo it. Public generators only — not constant time, and it does not need
 * to be. */
const ZK_DST = {
  h:    "BITCERT-ZKTS:SECP256K1:PEDERSEN:H:v1",
  gvec: "BITCERT-ZKTS:SECP256K1:BP:GVEC:v1",
  hvec: "BITCERT-ZKTS:SECP256K1:BP:HVEC:v1",
  u:    "BITCERT-ZKTS:SECP256K1:BP:U:v1",
  csd:  "BITCERT-ZKTS:SECP256K1:CSDIGEST:v1",
};
async function zkDeriveNUMS(dst, msg) {
  for (let ctr = 0; ctr < 256; ctr++) {
    const x = zkBytesToBig(await zkSha256(zkCat(zkLenPrefixed(dst), zkLenPrefixed(msg), Uint8Array.of(ctr))));
    if (x >= ZK_P) continue;                                    // non-canonical: skip, never reduce
    const y = zkSqrtP(zkMod(x * x % ZK_P * x + 7n, ZK_P));
    if (y === null) continue;
    return { x, y: (y & 1n) === 0n ? y : zkMod(-y, ZK_P) };     // always the even root
  }
  throw new Error("NUMS derivation exhausted");
}
const zkGenCache = { h: null, u: null, g: [], hv: [] };
async function zkGenerators(size) {
  if (!zkGenCache.h) zkGenCache.h = await zkDeriveNUMS(ZK_DST.h, "h");
  if (!zkGenCache.u) zkGenCache.u = await zkDeriveNUMS(ZK_DST.u, "u");
  while (zkGenCache.g.length < size) {
    const i = zkGenCache.g.length;
    zkGenCache.g.push(await zkDeriveNUMS(ZK_DST.gvec, "G:" + i));
    zkGenCache.hv.push(await zkDeriveNUMS(ZK_DST.hvec, "H:" + i));
  }
  return { g: zkGenCache.g.slice(0, size), h: zkGenCache.hv.slice(0, size), u: zkGenCache.u, baseH: zkGenCache.h };
}

/* ---------- cs_digest (spec §14.2) ---------- */
async function zkCsDigest(commitments) {
  const parts = [zkLenPrefixed(ZK_DST.csd), zkU64be(commitments.length)];
  for (const c of commitments) parts.push(zkSec1Encode(c));
  return zkMod(zkBytesToBig(await zkSha256(zkCat(...parts))), ZK_N);
}

/* ---------- Fiat–Shamir transcript ----------
 * Mirrors gnark-crypto's fiatshamir.Transcript exactly:
 *   challenge_i = SHA256( name_i ‖ (i>0 ? challenge_{i-1} : ε) ‖ bindings… )
 * Challenges MUST be computed in registration order; the previous digest is the
 * chaining link, so computing out of order silently changes every value after. */
class ZkTranscript {
  constructor(ids) { this.ids = ids; this.bind = new Map(); this.done = new Map(); this.prev = null; this.pos = 0; }
  add(id, bytes) {
    if (this.done.has(id)) throw new Error("transcript: " + id + " already computed");
    if (!this.bind.has(id)) this.bind.set(id, []);
    this.bind.get(id).push(bytes);
  }
  async challenge(id) {
    if (this.done.has(id)) return this.done.get(id);
    if (this.ids[this.pos] !== id) throw new Error("transcript: out of order, want " + this.ids[this.pos] + " got " + id);
    const parts = [new TextEncoder().encode(id)];
    if (this.pos > 0) parts.push(this.prev);
    for (const b of this.bind.get(id) || []) parts.push(b);
    const digest = await zkSha256(zkCat(...parts));
    this.prev = digest; this.pos++;
    const scalar = zkMod(zkBytesToBig(digest), ZK_N);
    this.done.set(id, scalar);
    return scalar;
  }
}

const zkNextPow2 = (n) => { if (n <= 1) return 1; let p = 1; while (p < n) p <<= 1; return p; };
function zkBpChallengeIds(rounds) {
  const ids = ["bp-m", "bp-y", "bp-z", "bp-x", "bp-w"];
  for (let k = 0; k < rounds; k++) ids.push("bp-ipa:" + k);
  ids.push("sum-pok");
  return ids;
}

/** Seed the §2.1 preamble onto the first challenge. */
async function zkSeedTranscript(t, first, statementId, variantId, publicInputParts, ctx) {
  const gen = await zkGenerators(1);
  const items = [
    zkLenPrefixed("BITCERT-ZKTS:v1"),
    zkLenPrefixed(variantId),
    zkLenPrefixed(statementId),
    zkLenPrefixed("SECP256K1"),
    zkCat(zkSec1Encode(ZK_G), zkSec1Encode(gen.baseH)),
    zkLenPrefixed(ZK_DST.gvec), zkLenPrefixed(ZK_DST.hvec), zkLenPrefixed(ZK_DST.u),
    ...publicInputParts,
    zkLenPrefixed(ctx.org_id), zkLenPrefixed(ctx.run_ref),
  ];
  for (const it of items) t.add(first, it);
}

/* ---------- envelope parsing (spec §11) ---------- */
const ZK_STATEMENT_CODE = { 0x01: "committed-sum-range", 0x02: "committed-sum-cmp" };
const ZK_VARIANT_CODE = { 0x01: "sigma-fs", 0x02: "bulletproofs" };

class ZkReader {
  constructor(buf) { this.b = buf; this.o = 0; }
  take(n) { if (this.b.length - this.o < n) throw new Error("envelope truncated"); const s = this.b.subarray(this.o, this.o + n); this.o += n; return s; }
  u8() { return this.take(1)[0]; }
  u32() { const b = this.take(4); return ((b[0] << 24) >>> 0) + (b[1] << 16) + (b[2] << 8) + b[3]; }
  u64() { return zkBytesToBig(this.take(8)); }
  scalar() { const s = zkBytesToBig(this.take(32)); if (s >= ZK_N) throw new Error("non-canonical scalar"); return s; }
  point() { return zkSec1Decode(this.take(ZK_POINT_LEN)); }
  end() { if (this.o !== this.b.length) throw new Error("trailing bytes in envelope: " + (this.b.length - this.o)); }
}

const ZK_BIT_WIDTH = 64;
const ZK_MAX_N = 4096;

/**
 * verifyZk — the entry point. `bundleZk` is the bundle's §8 `zk` object and
 * `expected` is what the CALLER independently knows (bundle §8.2). Returns a
 * structured result; throws only on malformed input.
 */
async function verifyZk(bundleZk, expected) {
  const notes = [];
  if (typeof bundleZk.spec !== "string" || !bundleZk.spec.startsWith("zk-transparent-statements-spec/v2."))
    throw new Error("unsupported zk spec version: " + bundleZk.spec);

  const raw = zkB64ToBytes(bundleZk.envelope_b64);
  if (raw.length < 7 || String.fromCharCode(raw[0], raw[1], raw[2], raw[3]) !== "ZKTS")
    throw new Error("not a ZKTS envelope");
  if (raw[4] !== 0x01) throw new Error("envelope version 0x" + raw[4].toString(16));
  const variant = ZK_VARIANT_CODE[raw[5]], statement = ZK_STATEMENT_CODE[raw[6]];
  if (!variant) throw new Error("unknown variant code 0x" + raw[5].toString(16));
  if (!statement) throw new Error("unknown statement code 0x" + raw[6].toString(16));
  // The JSON is a claim about the bytes; disagreement means one of them lies.
  if (bundleZk.variant !== variant) throw new Error("bundle says variant " + bundleZk.variant + ", envelope says " + variant);
  if (bundleZk.statement !== statement) throw new Error("bundle says statement " + bundleZk.statement + ", envelope says " + statement);
  if (variant !== "bulletproofs") throw new Error("this verifier implements bulletproofs only; envelope is " + variant);

  // §8.2 — the caller's own values win. Comparing rather than adopting is what
  // stops the prover from choosing which statement it proved.
  const ctx = expected.context;
  if (!ctx || typeof ctx.org_id !== "string" || typeof ctx.run_ref !== "string")
    throw new Error("expected.context {org_id, run_ref} is required");
  for (const k of ["org_id", "run_ref"]) {
    if (bundleZk.context?.[k] !== undefined && bundleZk.context[k] !== ctx[k])
      notes.push(`bundle context.${k} differs from yours — yours was used`);
  }

  const rd = new ZkReader(raw.subarray(7));
  const n = rd.u32();
  if (n < 1 || n > ZK_MAX_N) throw new Error("N=" + n + " out of [1, " + ZK_MAX_N + "]");
  if (n * ZK_POINT_LEN > raw.length) throw new Error("N=" + n + " exceeds the bytes present");

  let total = null, threshold = null, direction = null;
  if (statement === "committed-sum-range") {
    total = rd.u64();
  } else {
    threshold = rd.u64();
    const d = rd.u8();
    if (d !== 0x00 && d !== 0x01) throw new Error("direction byte 0x" + d.toString(16));
    direction = d === 0x00 ? "ge" : "le";
  }
  const claimedDigest = rd.scalar();
  const commitments = [];
  for (let i = 0; i < n; i++) commitments.push(rd.point());

  // Compare public inputs against the caller's expectation (§8.2).
  const pi = expected.public_inputs || {};
  const want = (k, got) => {
    if (pi[k] === undefined) { notes.push(`public_inputs.${k} not supplied — the envelope's value was accepted unchecked`); return; }
    if (String(pi[k]) !== String(got)) throw new Error(`public_inputs.${k}: you expected ${pi[k]}, the proof states ${got}`);
  };
  want("n", n);
  if (statement === "committed-sum-range") want("total", total.toString());
  else { want("threshold", threshold.toString()); want("direction", direction); }

  const digest = await zkCsDigest(commitments);
  if (digest !== claimedDigest) throw new Error("commitment-set digest mismatch");

  // Aggregate width: cmp appends the derived surplus commitment (spec §12.3).
  const aggCount = statement === "committed-sum-cmp" ? n + 1 : n;
  const m = zkNextPow2(aggCount);
  const nm = m * ZK_BIT_WIDTH;
  const rounds = Math.log2(nm) | 0;
  if (2 ** rounds !== nm) throw new Error("padded width is not a power of two");

  const A = rd.point(), S = rd.point(), T1 = rd.point(), T2 = rd.point();
  const tauX = rd.scalar(), mu = rd.scalar(), tHat = rd.scalar();
  // Per-round PAIRS (spec §8.3). Reading all L then all R parses without
  // error and yields a plausible-looking but wrong challenge stream.
  const L = [], R = [];
  for (let i = 0; i < rounds; i++) { L.push(rd.point()); R.push(rd.point()); }
  const a = rd.scalar(), b = rd.scalar();
  let sumPok = null;
  if (statement === "committed-sum-range") sumPok = { R: rd.point(), Z: rd.scalar() };
  rd.end();

  const gens = await zkGenerators(nm);
  const baseH = gens.baseH;

  // Padded commitment vector. Padding is IDENTITY and derived here, never
  // transmitted (spec §8.1) — deriving it IS the padding check.
  const padded = new Array(m).fill(null);
  for (let i = 0; i < n; i++) padded[i] = commitments[i];
  if (statement === "committed-sum-cmp") {
    const sum = zkSumPoints(commitments);
    const sg = zkMul(ZK_G, threshold);
    // §12.3: ge ⇒ ΣC − S·g ; le ⇒ S·g − ΣC. Derived, never read.
    padded[n] = direction === "ge" ? zkAdd(sum, zkNeg(sg)) : zkAdd(sg, zkNeg(sum));
  }

  const ids = zkBpChallengeIds(rounds);
  const chals = {};
  // Attach the challenge stream to any failure. "Does not verify" is one bit;
  // "diverges at bp-ipa:3" is a location. This is the whole reason the golden
  // fixture publishes intermediate challenges.
  const bail = (msg) => { const e = new Error(msg); e.challenges = chals; throw e; };
  const t = new ZkTranscript(ids);
  const piParts = statement === "committed-sum-range"
    ? [zkU32be(n), zkU64be(total), zkScalarBytes(digest)]
    : [zkU32be(n), zkU64be(threshold), Uint8Array.of(direction === "ge" ? 0 : 1), zkScalarBytes(digest)];
  const statementId = statement === "committed-sum-range" ? "committed-sum-range:v1" : "committed-sum-cmp:v1";
  await zkSeedTranscript(t, ids[0], statementId, "bulletproofs:v1", piParts, ctx);

  t.add("bp-m", zkU32be(m));
  chals["bp-m"] = await t.challenge("bp-m");
  t.add("bp-y", zkSec1Encode(A)); t.add("bp-y", zkSec1Encode(S));
  const y = chals["bp-y"] = await t.challenge("bp-y");
  const z = chals["bp-z"] = await t.challenge("bp-z");
  if (y === 0n || z === 0n) bail("degenerate challenge");
  t.add("bp-x", zkSec1Encode(T1)); t.add("bp-x", zkSec1Encode(T2));
  const x = chals["bp-x"] = await t.challenge("bp-x");
  t.add("bp-w", zkScalarBytes(tauX)); t.add("bp-w", zkScalarBytes(mu)); t.add("bp-w", zkScalarBytes(tHat));
  const w = chals["bp-w"] = await t.challenge("bp-w");
  const Q = zkMul(gens.u, w);

  // Powers and the aggregation weights d_i = z^{2+j}·2^l.
  const yPow = new Array(nm); { let acc = 1n; for (let i = 0; i < nm; i++) { yPow[i] = acc; acc = acc * y % ZK_N; } }
  const dVec = new Array(nm);
  { let zj = z * z % ZK_N;
    for (let j = 0; j < m; j++) { let p2 = 1n; for (let l = 0; l < ZK_BIT_WIDTH; l++) { dVec[j * ZK_BIT_WIDTH + l] = zj * p2 % ZK_N; p2 = p2 * 2n % ZK_N; } zj = zj * z % ZK_N; } }

  // δ(y,z) = (z − z²)·Σyⁱ − Σ_j z^{3+j}·(2⁶⁴−1)
  let delta;
  { let sumY = 0n; for (const v of yPow) sumY = (sumY + v) % ZK_N;
    const z2 = z * z % ZK_N;
    delta = zkMod((z - z2) * sumY, ZK_N);
    const full64 = (1n << 64n) - 1n;
    let zj = z2 * z % ZK_N;
    for (let j = 0; j < m; j++) { delta = zkMod(delta - zj * full64, ZK_N); zj = zj * z % ZK_N; } }

  // Check (65): t̂·g + τx·h == δ·g + Σ_j z^{2+j}·V_j + x·T1 + x²·T2
  { const lhs = zkAdd(zkMul(ZK_G, tHat), zkMul(baseH, tauX));
    let rhs = zkMul(ZK_G, delta);
    let zj = z * z % ZK_N;
    for (let j = 0; j < m; j++) { rhs = zkAdd(rhs, zkMul(padded[j], zj)); zj = zj * z % ZK_N; }
    rhs = zkAdd(rhs, zkMul(T1, x));
    rhs = zkAdd(rhs, zkMul(T2, x * x % ZK_N));
    if (!zkPtEq(lhs, rhs)) bail("bulletproofs main equation failed"); }

  // P_ipa = A + x·S − μ·h − z·ΣG_i + Σ(z·yⁱ + d_i)·H'_i , with H'_i = y^{-i}·H_i
  const yInv = zkInvN(y);
  const hPrime = new Array(nm);
  { let acc = 1n; for (let i = 0; i < nm; i++) { hPrime[i] = zkMul(gens.h[i], acc); acc = acc * yInv % ZK_N; } }
  let P = zkAdd(A, zkMul(S, x));
  P = zkAdd(P, zkMul(baseH, zkMod(-mu, ZK_N)));
  { // every G_i carries the same weight −z, so sum first and multiply once
    const negZ = zkMod(-z, ZK_N);
    P = zkAdd(P, zkMul(zkSumPoints(gens.g), negZ));
    const coeff = new Array(nm);
    for (let i = 0; i < nm; i++) coeff[i] = (z * yPow[i] + dVec[i]) % ZK_N;
    P = zkAdd(P, zkMsm(hPrime, coeff)); }

  // Fold: P* = P + t̂·Q + Σ(u_k²·L_k + u_k^{-2}·R_k), bases folded in step.
  let Pstar = zkAdd(P, zkMul(Q, tHat));
  let gCur = gens.g.slice(), hCur = hPrime.slice();
  for (let k = 0; k < rounds; k++) {
    const label = "bp-ipa:" + k;
    t.add(label, zkSec1Encode(L[k])); t.add(label, zkSec1Encode(R[k]));
    const uk = chals[label] = await t.challenge(label);
    if (uk === 0n) bail("zero IPA challenge");
    const ukInv = zkInvN(uk);
    Pstar = zkAdd(Pstar, zkMul(L[k], uk * uk % ZK_N));
    Pstar = zkAdd(Pstar, zkMul(R[k], ukInv * ukInv % ZK_N));
    const half = gCur.length / 2, ng = new Array(half), nh = new Array(half);
    for (let i = 0; i < half; i++) {
      ng[i] = zkAdd(zkMul(gCur[i], ukInv), zkMul(gCur[half + i], uk));
      nh[i] = zkAdd(zkMul(hCur[i], uk), zkMul(hCur[half + i], ukInv));
    }
    gCur = ng; hCur = nh;
  }
  { const rhs = zkAdd(zkAdd(zkMul(gCur[0], a), zkMul(hCur[0], b)), zkMul(Q, a * b % ZK_N));
    if (!zkPtEq(Pstar, rhs)) bail("inner-product argument failed"); }

  // committed-sum-range additionally proves ΣC − T·g opens to 0 on h.
  if (statement === "committed-sum-range") {
    const Y = zkAdd(zkSumPoints(commitments), zkNeg(zkMul(ZK_G, total)));
    t.add("sum-pok", zkSec1Encode(sumPok.R));
    const c = chals["sum-pok"] = await t.challenge("sum-pok");
    // z·h == R + c·Y
    if (!zkPtEq(zkMul(baseH, sumPok.Z), zkAdd(sumPok.R, zkMul(Y, c))))
      bail("sum proof failed");
  }

  return {
    ok: true, variant, statement, n,
    total: total === null ? null : total.toString(),
    threshold: threshold === null ? null : threshold.toString(),
    direction, notes, challenges: chals,
  };
}

function zkB64ToBytes(s) {
  if (typeof s !== "string") throw new Error("envelope_b64 must be a string");
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { verifyZk, zkDeriveNUMS, zkSec1Encode, zkSec1Decode, zkCsDigest, ZK_DST, ZK_G };
}
