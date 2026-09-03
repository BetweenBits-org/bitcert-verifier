/* =============================================================================
 * zk-core.js - zero-knowledge statement verification (bundle §8)
 *              + P-256 / WebAuthn (bundle §9–§10, appended at the end of the file)
 *
 * Verifies `committed-sum-range` and `committed-sum-cmp` bulletproofs envelopes
 * per the frozen wire contract `zk-transparent-statements-spec.md v2.1.0`.
 *
 * NO DEPENDENCIES. Plain BigInt over secp256k1 - the same rule the rest of this
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
 * order of a million point operations - with inverses it does not finish.
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
/**
 * k1·P + k2·Q in ONE double-and-add pass (Shamir's trick). The IPA fold does
 * exactly this shape for every basis element in every round - computing the
 * two products separately doubles the work for no reason.
 */
function zkJmul2(P, k1, Q, k2) {
  k1 = zkMod(k1, ZK_N); k2 = zkMod(k2, ZK_N);
  if (k1 === 0n) return zkJmul(Q, k2);
  if (k2 === 0n) return zkJmul(P, k1);
  const PQ = zkJadd(P, Q);
  const bits = Math.max(k1.toString(2).length, k2.toString(2).length);
  let acc = zkJinf();
  for (let i = bits - 1; i >= 0; i--) {
    acc = zkJdouble(acc);
    const b = (((k1 >> BigInt(i)) & 1n) << 1n) | ((k2 >> BigInt(i)) & 1n);
    if (b === 3n) acc = zkJadd(acc, PQ);
    else if (b === 2n) acc = zkJadd(acc, P);
    else if (b === 1n) acc = zkJadd(acc, Q);
  }
  return acc;
}

/** Σ scalars[i]·pointsJ[i] with everything staying Jacobian. */
function zkMsmJ(pointsJ, scalars) {
  let acc = zkJinf();
  for (let i = 0; i < pointsJ.length; i++) acc = zkJadd(acc, zkJmul(pointsJ[i], scalars[i]));
  return acc;
}
/** Σ points[i] - every scalar equal, so multiply the sum once, not each term. */
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
 * redo it. Public generators only - not constant time, and it does not need
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
async function zkSeedTranscript(t, first, statementId, variantId, publicInputParts, ctx, skipBpDst) {
  const gen = await zkGenerators(skipBpDst ? 0 : 1);
  const items = [
    zkLenPrefixed("BITCERT-ZKTS:v1"),
    zkLenPrefixed(variantId),
    zkLenPrefixed(statementId),
    zkLenPrefixed("SECP256K1"),
    zkCat(zkSec1Encode(ZK_G), zkSec1Encode(gen.baseH)),
    // §2.1 item 5: only bulletproofs binds its vector-generator DSTs.
    ...(skipBpDst ? [] : [zkLenPrefixed(ZK_DST.gvec), zkLenPrefixed(ZK_DST.hvec), zkLenPrefixed(ZK_DST.u)]),
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

/** §12.3: ge ⇒ ΣC − S·g ; le ⇒ S·g − ΣC. Derived by the verifier, never read. */
function zkDeriveSurplus(commitments, threshold, direction) {
  const sum = zkSumPoints(commitments);
  const sg = zkMul(ZK_G, threshold);
  return direction === "ge" ? zkAdd(sum, zkNeg(sg)) : zkAdd(sg, zkNeg(sum));
}

/* ---------- sigma-fs carrier (spec §7, §12.9) ----------
 * Bit decomposition with a CDS OR-proof per bit, plus a recomposition link
 * tying those bits to each commitment. Larger on the wire than bulletproofs by
 * ~50x, but roughly twice as fast to verify - there is no generator folding,
 * just a flat pass per bit. */

/** Challenge ids in §7.2 order; cmp drops the trailing sum PoK. */
function zkSigmaFSChallengeIds(n, withSumPok) {
  const ids = [];
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < ZK_BIT_WIDTH; j++) ids.push("bit:" + i + ":" + j);
    ids.push("recompose:" + i);
  }
  if (withSumPok) ids.push("sum-pok");
  return ids;
}

/**
 * Verify the per-value obligations against `commitments`. For cmp the last
 * entry is the DERIVED surplus commitment, not something read off the wire.
 */
async function zkSigmaFSVerifyCore(commitments, blocks, t, step) {
  const gens = await zkGenerators(0);
  const h = gens.baseH;
  const negG = zkNeg(ZK_G);
  for (let i = 0; i < commitments.length; i++) {
    if (step && i % 4 === 0) await step("value " + (i + 1) + "/" + commitments.length, 0.1 + 0.85 * (i / commitments.length));
    const { bits, ors, recompose } = blocks[i];
    let weighted = zkJinf();
    let pow2 = 1n;
    for (let j = 0; j < ZK_BIT_WIDTH; j++) {
      const B = bits[j], o = ors[j];
      const label = "bit:" + i + ":" + j;
      for (const p of [B, o.R0, o.R1]) t.add(label, zkSec1Encode(p));
      const c = await t.challenge(label);
      const c1 = zkMod(c - o.C0, ZK_N);
      // z0·h == R0 + c0·B          (branch b=0, Y0 = B)
      if (!zkPtEq(zkMul(h, o.Z0), zkAdd(o.R0, zkMul(B, o.C0))))
        throw new Error("sigma-fs: bit OR branch0 (i=" + i + " j=" + j + ")");
      // z1·h == R1 + c1·(B − g)    (branch b=1, Y1 = B − g)
      if (!zkPtEq(zkMul(h, o.Z1), zkAdd(o.R1, zkMul(zkAdd(B, negG), c1))))
        throw new Error("sigma-fs: bit OR branch1 (i=" + i + " j=" + j + ")");
      weighted = zkJadd(weighted, zkJmul(zkToJ(B), pow2));
      pow2 = pow2 * 2n % ZK_N;
    }
    // Recomposition: C_i − Σ 2^j·B_j must be a known multiple of h.
    const Y = zkAdd(commitments[i], zkNeg(zkToAffine(weighted)));
    t.add("recompose:" + i, zkSec1Encode(recompose.R));
    const c = await t.challenge("recompose:" + i);
    if (!zkPtEq(zkMul(h, recompose.Z), zkAdd(recompose.R, zkMul(Y, c))))
      throw new Error("sigma-fs: recomposition (i=" + i + ")");
  }
}

/** Read m per-value proof blocks in §7.4 order. */
function zkReadSigmaFSBlocks(rd, m) {
  const blocks = [];
  for (let i = 0; i < m; i++) {
    const bits = [], ors = [];
    for (let j = 0; j < ZK_BIT_WIDTH; j++) bits.push(rd.point());
    for (let j = 0; j < ZK_BIT_WIDTH; j++) {
      ors.push({ R0: rd.point(), R1: rd.point(), C0: rd.scalar(), Z0: rd.scalar(), Z1: rd.scalar() });
    }
    blocks.push({ bits, ors, recompose: { R: rd.point(), Z: rd.scalar() } });
  }
  return blocks;
}

/**
 * verifyZk - the entry point. `bundleZk` is the bundle's §8 `zk` object and
 * `expected` is what the CALLER independently knows (bundle §8.2). Returns a
 * structured result; throws only on malformed input.
 */
async function verifyZk(bundleZk, expected, onProgress) {
  const notes = [];
  // Verification is seconds of straight-line BigInt work. Without yielding the
  // browser cannot repaint and the page looks hung, so every phase reports and
  // then hands the event loop back. The yield costs a millisecond; the
  // alternative is a user who thinks the tool is broken.
  const step = async (label, frac) => {
    if (!onProgress) return;
    onProgress(label, frac);
    await new Promise((r) => setTimeout(r, 0));
  };
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

  // §8.2 - the caller's own values win. Comparing rather than adopting is what
  // stops the prover from choosing which statement it proved.
  const ctx = expected.context;
  if (!ctx || typeof ctx.org_id !== "string" || typeof ctx.run_ref !== "string")
    throw new Error("expected.context {org_id, run_ref} is required");
  for (const k of ["org_id", "run_ref"]) {
    if (bundleZk.context?.[k] !== undefined && bundleZk.context[k] !== ctx[k])
      notes.push(`bundle context.${k} differs from yours - yours was used`);
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
    if (pi[k] === undefined) { notes.push(`public_inputs.${k} not supplied - the envelope's value was accepted unchecked`); return; }
    if (String(pi[k]) !== String(got)) throw new Error(`public_inputs.${k}: you expected ${pi[k]}, the proof states ${got}`);
  };
  want("n", n);
  if (statement === "committed-sum-range") want("total", total.toString());
  else { want("threshold", threshold.toString()); want("direction", direction); }

  const digest = await zkCsDigest(commitments);
  if (digest !== claimedDigest) throw new Error("commitment-set digest mismatch");

  if (variant === "sigma-fs") {
    // §7 carrier. Same statement, same public inputs, different machinery:
    // one proof block per value, and for cmp one extra block for the surplus
    // whose commitment we derive rather than read.
    const m = statement === "committed-sum-cmp" ? n + 1 : n;
    const blocks = zkReadSigmaFSBlocks(rd, m);
    const sumPokSF = statement === "committed-sum-range"
      ? { R: rd.point(), Z: rd.scalar() } : null;
    rd.end();

    const withD = commitments.slice();
    if (statement === "committed-sum-cmp") withD.push(zkDeriveSurplus(commitments, threshold, direction));

    await step("generators", 0.05);
    const gensSF = await zkGenerators(0);
    const idsSF = zkSigmaFSChallengeIds(m, statement === "committed-sum-range");
    const tSF = new ZkTranscript(idsSF);
    const piSF = statement === "committed-sum-range"
      ? [zkU32be(n), zkU64be(total), zkScalarBytes(digest)]
      : [zkU32be(n), zkU64be(threshold), Uint8Array.of(direction === "ge" ? 0 : 1), zkScalarBytes(digest)];
    const stmtIdSF = statement === "committed-sum-range" ? "committed-sum-range:v1" : "committed-sum-cmp:v1";
    await zkSeedTranscript(tSF, idsSF[0], stmtIdSF, "sigma-fs:v1", piSF, ctx, true);
    await zkSigmaFSVerifyCore(withD, blocks, tSF, step);

    if (statement === "committed-sum-range") {
      const Y = zkAdd(zkSumPoints(commitments), zkNeg(zkMul(ZK_G, total)));
      tSF.add("sum-pok", zkSec1Encode(sumPokSF.R));
      const c = await tSF.challenge("sum-pok");
      if (!zkPtEq(zkMul(gensSF.baseH, sumPokSF.Z), zkAdd(sumPokSF.R, zkMul(Y, c))))
        throw new Error("sigma-fs: sum proof failed");
    }
    await step("done", 1);
    return { ok: true, variant, statement, n,
      total: total === null ? null : total.toString(),
      threshold: threshold === null ? null : threshold.toString(),
      direction, notes, challenges: {} };
  }

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

  await step("generators (" + nm + " points)", 0.05);
  const gens = await zkGenerators(nm);
  const baseH = gens.baseH;

  // Padded commitment vector. Padding is IDENTITY and derived here, never
  // transmitted (spec §8.1) - deriving it IS the padding check.
  const padded = new Array(m).fill(null);
  for (let i = 0; i < n; i++) padded[i] = commitments[i];
  if (statement === "committed-sum-cmp") padded[n] = zkDeriveSurplus(commitments, threshold, direction);

  await step("transcript", 0.2);
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

  await step("main equation", 0.25);
  // Check (65): t̂·g + τx·h == δ·g + Σ_j z^{2+j}·V_j + x·T1 + x²·T2
  { const lhs = zkAdd(zkMul(ZK_G, tHat), zkMul(baseH, tauX));
    let rhs = zkMul(ZK_G, delta);
    let zj = z * z % ZK_N;
    for (let j = 0; j < m; j++) { rhs = zkAdd(rhs, zkMul(padded[j], zj)); zj = zj * z % ZK_N; }
    rhs = zkAdd(rhs, zkMul(T1, x));
    rhs = zkAdd(rhs, zkMul(T2, x * x % ZK_N));
    if (!zkPtEq(lhs, rhs)) bail("bulletproofs main equation failed"); }

  // P_ipa = A + x·S − μ·h − z·ΣG_i + Σ(z·yⁱ + d_i)·H'_i , with H'_i = y^{-i}·H_i
  await step("H' basis", 0.3);
  const yInv = zkInvN(y);
  // Jacobian from here to the end: an affine round trip costs a modular
  // inverse, and this section performs thousands of operations.
  const hPrimeJ = new Array(nm);
  { let acc = 1n; for (let i = 0; i < nm; i++) { hPrimeJ[i] = zkJmul(zkToJ(gens.h[i]), acc); acc = acc * yInv % ZK_N; } }

  await step("P commitment", 0.45);
  let PJ = zkJadd(zkToJ(A), zkJmul(zkToJ(S), x));
  PJ = zkJadd(PJ, zkJmul(zkToJ(baseH), zkMod(-mu, ZK_N)));
  { // every G_i carries the same weight −z, so sum first and multiply once
    const negZ = zkMod(-z, ZK_N);
    PJ = zkJadd(PJ, zkJmul(zkToJ(zkSumPoints(gens.g)), negZ));
    const coeff = new Array(nm);
    for (let i = 0; i < nm; i++) coeff[i] = (z * yPow[i] + dVec[i]) % ZK_N;
    PJ = zkJadd(PJ, zkMsmJ(hPrimeJ, coeff)); }

  // Fold: P* = P + t̂·Q + Σ(u_k²·L_k + u_k^{-2}·R_k), bases folded in step.
  let Pstar = zkJadd(PJ, zkJmul(zkToJ(Q), tHat));
  let gCur = gens.g.map(zkToJ), hCur = hPrimeJ;
  for (let k = 0; k < rounds; k++) {
    await step("inner-product round " + (k + 1) + "/" + rounds, 0.5 + 0.45 * (k / rounds));
    const label = "bp-ipa:" + k;
    t.add(label, zkSec1Encode(L[k])); t.add(label, zkSec1Encode(R[k]));
    const uk = chals[label] = await t.challenge(label);
    if (uk === 0n) bail("zero IPA challenge");
    const ukInv = zkInvN(uk);
    Pstar = zkJadd(Pstar, zkJmul(zkToJ(L[k]), uk * uk % ZK_N));
    Pstar = zkJadd(Pstar, zkJmul(zkToJ(R[k]), ukInv * ukInv % ZK_N));
    const half = gCur.length / 2, ng = new Array(half), nh = new Array(half);
    for (let i = 0; i < half; i++) {
      ng[i] = zkJmul2(gCur[i], ukInv, gCur[half + i], uk);
      nh[i] = zkJmul2(hCur[i], uk, hCur[half + i], ukInv);
    }
    gCur = ng; hCur = nh;
  }
  await step("final check", 0.95);
  { const rhs = zkJadd(zkJadd(zkJmul(gCur[0], a), zkJmul(hCur[0], b)), zkJmul(zkToJ(Q), a * b % ZK_N));
    if (!zkPtEq(zkToAffine(Pstar), zkToAffine(rhs))) bail("inner-product argument failed"); }

  // committed-sum-range additionally proves ΣC − T·g opens to 0 on h.
  if (statement === "committed-sum-range") {
    const Y = zkAdd(zkSumPoints(commitments), zkNeg(zkMul(ZK_G, total)));
    t.add("sum-pok", zkSec1Encode(sumPok.R));
    const c = chals["sum-pok"] = await t.challenge("sum-pok");
    // z·h == R + c·Y
    if (!zkPtEq(zkMul(baseH, sumPok.Z), zkAdd(sumPok.R, zkMul(Y, c))))
      bail("sum proof failed");
  }

  await step("done", 1);
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


/* =============================================================================
 * P-256 / WebAuthn (bundle §9–§10) - ES256 for the issuer signature (passkey or
 * customer KMS) and for the presenter check. verify-cli/verify.py mirrors every
 * function here; fixtures/p256/kat.mjs pins both against RFC 6979 §A.2.5.
 *
 * Verification prefers Web Crypto (crypto.subtle) and falls back to plain
 * BigInt affine arithmetic where subtle is absent (some file:// contexts).
 * The fallback is not a lesser path: kat.mjs runs the same vectors through it.
 * ========================================================================== */
const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const P256_A = P256_P - 3n;
const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_G = { x: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
                 y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n };

const p256Mod = (a, m) => ((a % m) + m) % m;
function p256Pow(b, e, m) { let r = 1n; b = p256Mod(b, m); while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; }
const p256InvP = (a) => p256Pow(a, P256_P - 2n, P256_P);
const p256InvN = (a) => p256Pow(a, P256_N - 2n, P256_N);
/** p ≡ 3 (mod 4) ⇒ sqrt(a) = a^((p+1)/4). Returns null when a is not a square. */
function p256SqrtP(a) { const r = p256Pow(a, (P256_P + 1n) / 4n, P256_P); return r * r % P256_P === p256Mod(a, P256_P) ? r : null; }

/* affine points {x,y}; null = infinity. Two scalar multiplications per verify -
 * inverses are affordable here, unlike the bulletproofs loop above. */
function p256Double(P) {
  if (P === null || P.y === 0n) return null;
  const lam = p256Mod((3n * P.x * P.x + P256_A) * p256InvP(2n * P.y), P256_P);
  const x = p256Mod(lam * lam - 2n * P.x, P256_P);
  return { x, y: p256Mod(lam * (P.x - x) - P.y, P256_P) };
}
function p256AddPt(P, Q) {
  if (P === null) return Q;
  if (Q === null) return P;
  if (P.x === Q.x) return p256Mod(P.y + Q.y, P256_P) === 0n ? null : p256Double(P);
  const lam = p256Mod((Q.y - P.y) * p256InvP(p256Mod(Q.x - P.x, P256_P)), P256_P);
  const x = p256Mod(lam * lam - P.x - Q.x, P256_P);
  return { x, y: p256Mod(lam * (P.x - x) - P.y, P256_P) };
}
function p256Mul(P, k) { let R = null, Q = P; while (k > 0n) { if (k & 1n) R = p256AddPt(R, Q); Q = p256Double(Q); k >>= 1n; } return R; }
function p256OnCurve(P) { return P !== null && p256Mod(P.y * P.y - (P.x * P.x * P.x + P256_A * P.x + P256_B), P256_P) === 0n; }

function p256BytesToBig(b) { let x = 0n; for (const v of b) x = (x << 8n) | BigInt(v); return x; }
function p256BigToBytes(x, n) { const o = new Uint8Array(n); for (let i = n - 1; i >= 0; i--) { o[i] = Number(x & 0xffn); x >>= 8n; } return o; }

/** SEC1 compressed (02/03 ‖ x) → {x, y}. Rejects wrong length/prefix, x ≥ p, x off-curve. */
function p256Decompress(pk33) {
  if (!(pk33 instanceof Uint8Array) || pk33.length !== 33 || (pk33[0] !== 2 && pk33[0] !== 3))
    throw new Error("public key must be 33-byte SEC1 compressed (02/03 ‖ x)");
  const x = p256BytesToBig(pk33.subarray(1));
  if (x >= P256_P) throw new Error("public key x is not a canonical field element");
  let y = p256SqrtP(p256Mod(x * x * x + P256_A * x + P256_B, P256_P));
  if (y === null) throw new Error("public key x is not on P-256");
  if ((y & 1n) !== BigInt(pk33[0] & 1)) y = P256_P - y;
  return { x, y };
}
function p256Compress(P) { const o = new Uint8Array(33); o[0] = 2 + Number(P.y & 1n); o.set(p256BigToBytes(P.x, 32), 1); return o; }
/** 0x04 ‖ x ‖ y - the "raw" form Web Crypto imports. */
function p256Uncompressed(P) { const o = new Uint8Array(65); o[0] = 4; o.set(p256BigToBytes(P.x, 32), 1); o.set(p256BigToBytes(P.y, 32), 33); return o; }

/** Strict DER ECDSA-Sig-Value → {r, s, raw(64)}. Short-form lengths only, no
 * trailing bytes, minimal INTEGERs, r,s ∈ [1, n−1]. low-s NOT enforced. */
function derToRawSig(sig) {
  const bad = (m) => { throw new Error("DER: " + m); };
  if (!(sig instanceof Uint8Array) || sig.length < 8 || sig[0] !== 0x30) bad("expected SEQUENCE");
  if (sig[1] >= 0x80 || 2 + sig[1] !== sig.length) bad("SEQUENCE length does not match (trailing/short)");
  let o = 2;
  const readInt = () => {
    if (o + 2 > sig.length || sig[o] !== 0x02) bad("expected INTEGER");
    const ln = sig[o + 1];
    if (ln === 0 || ln >= 0x80 || o + 2 + ln > sig.length) bad("bad INTEGER length");
    const body = sig.subarray(o + 2, o + 2 + ln);
    if (body[0] & 0x80) bad("negative INTEGER");
    if (ln > 1 && body[0] === 0x00 && !(body[1] & 0x80)) bad("non-minimal INTEGER (leading 0x00)");
    o += 2 + ln;
    return p256BytesToBig(body);
  };
  const r = readInt(), s = readInt();
  if (o !== sig.length) bad("trailing bytes inside SEQUENCE");
  if (!(r >= 1n && r < P256_N && s >= 1n && s < P256_N)) bad("r/s out of range [1, n-1]");
  const raw = new Uint8Array(64); raw.set(p256BigToBytes(r, 32), 0); raw.set(p256BigToBytes(s, 32), 32);
  return { r, s, raw };
}

async function p256VerifyPure(Q, r, s, msg) {
  const e = p256Mod(p256BytesToBig(await zkSha256(msg)), P256_N);
  const w = p256InvN(s);
  const X = p256AddPt(p256Mul(P256_G, e * w % P256_N), p256Mul(Q, r * w % P256_N));
  return X !== null && p256Mod(X.x, P256_N) === r;
}
/** ECDSA P-256 / SHA-256 (ES256). `msg` is hashed here - pass the raw message
 * (WebAuthn: authenticatorData ‖ SHA256(clientDataJSON); es256-plain: m).
 * opts.pure forces the BigInt path (tests). Throws on malformed key/signature. */
async function p256Verify(pub33, msg, sigDer, opts) {
  const Q = p256Decompress(pub33);
  const sig = derToRawSig(sigDer);
  const subtle = (typeof crypto !== "undefined" && crypto.subtle && crypto.subtle.importKey) ? crypto.subtle : null;
  if (subtle && !(opts && opts.pure)) {
    try {
      const key = await subtle.importKey("raw", p256Uncompressed(Q), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      return await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig.raw, msg);
    } catch (e) {
      // Web Crypto refused (no P-256 in this context, insecure origin quirks…). The key
      // and signature were already validated above, so the pure path answers the same
      // question on the same math - it is not a weaker check (kat.mjs pins both paths).
    }
  }
  return p256VerifyPure(Q, sig.r, sig.s, msg);
}

/* ---------- base64url (RFC 4648 §5, unpadded - what WebAuthn speaks) ---------- */
function bytesToB64u(b) { let s = ""; for (const v of b) s += String.fromCharCode(v); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function b64uToBytes(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("not base64url");
  if (s.length % 4 === 1) throw new Error("not base64url (length)");
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - s.length % 4) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/* ---------- WebAuthn assertion pieces ---------- */
/** rpIdHash(32) ‖ flags(1) ‖ signCount(4 BE) ‖ [extensions…]. Extension bytes are
 * ignored here but the SIGNATURE covers the whole buffer. */
function parseAuthenticatorData(b) {
  if (!(b instanceof Uint8Array) || b.length < 37) throw new Error("authenticatorData shorter than 37 bytes");
  return { rpIdHash: b.subarray(0, 32), flags: b[32], up: !!(b[32] & 0x01), uv: !!(b[32] & 0x04),
           signCount: ((b[33] << 24) >>> 0) + (b[34] << 16) + (b[35] << 8) + b[36], extensions: b.subarray(37) };
}
function parseClientDataJson(b) {
  let cd;
  try { cd = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(b)); }
  catch (e) { throw new Error("clientDataJSON is not UTF-8 JSON: " + e.message); }
  if (!cd || typeof cd !== "object" || Array.isArray(cd)) throw new Error("clientDataJSON is not an object");
  return { type: cd.type, challenge: cd.challenge, origin: cd.origin, crossOrigin: cd.crossOrigin };
}
function p256BytesEq(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }

/** All checks of bundle-schema §9.1, collected (not short-circuited) so a
 * report can show every reason. {pub33, authData, cdj, sigDer, challenge,
 * rpId, origins, requireUv=true, pure} → {ok, reasons[], facts{}}. */
async function webauthnVerifyAssertion(a) {
  const rpId = a.rpId, origins = a.origins || [], requireUv = a.requireUv !== false;
  const reasons = [], facts = { rpId };
  try {
    const ad = parseAuthenticatorData(a.authData);
    facts.uv = ad.uv; facts.up = ad.up; facts.signCount = ad.signCount;
    if (!p256BytesEq(ad.rpIdHash, await zkSha256(new TextEncoder().encode(rpId)))) reasons.push("rpIdHash ≠ SHA256(" + JSON.stringify(rpId) + ")");
    if (!ad.up) reasons.push("UP (user present) flag not set");
    if (requireUv && !ad.uv) reasons.push("UV (user verified) flag not set");
  } catch (e) { reasons.push(e.message); }
  try {
    const cd = parseClientDataJson(a.cdj);
    facts.type = cd.type; facts.origin = cd.origin;
    if (cd.type !== "webauthn.get") reasons.push("clientDataJSON.type is " + JSON.stringify(cd.type) + ", not \"webauthn.get\"");
    try {
      if (!p256BytesEq(b64uToBytes(cd.challenge || ""), a.challenge)) reasons.push("clientDataJSON.challenge is not the expected message");
    } catch (e) { reasons.push("clientDataJSON.challenge is not base64url"); }
    if (!origins.includes(cd.origin)) reasons.push("origin " + JSON.stringify(cd.origin) + " not in allowed " + JSON.stringify(origins));
  } catch (e) { reasons.push(e.message); }
  try {
    const signed = zkCat(a.authData, await zkSha256(a.cdj));
    if (!(await p256Verify(a.pub33, signed, a.sigDer, { pure: a.pure }))) reasons.push("ES256 signature does not verify under the public key");
  } catch (e) { reasons.push("signature/key malformed: " + e.message); }
  return { ok: reasons.length === 0, reasons, facts };
}

/* =============================================================================
 * secp256k1 ECDSA + cosign message + 0x10 multi-signature envelope
 * (bundle §12 - the party-model v2 primitives; N0 scope, the full v5 pipeline
 * lands with runV5).
 *
 * The curve arithmetic REUSES the Pedersen/Bulletproof field and group code at
 * the top of this file (ZK_P/ZK_N/ZK_G, zkMul/zkAdd/zkSqrtP) - what is new here
 * is ECDSA itself: the bulletproofs section never verifies an ECDSA signature.
 * verify-cli/verify.py mirrors every function; fixtures/multisig/kat.mjs pins
 * both against the engine KAT (fixtures/bc30-v2-vectors.json, sections cosign /
 * wallet / multisig / negative_v2).
 * ========================================================================== */
const SECP_HALF_N = ZK_N >> 1n;   // low-s boundary: s ∈ [1, n/2]

/** SEC1 compressed (02/03 ‖ x) → {x, y} on secp256k1. Rejects wrong length,
 * the infinity prefix, x ≥ p and x off-curve (via zkSec1Decode). */
function secpDecompress(pk33) {
  if (!(pk33 instanceof Uint8Array) || pk33.length !== 33 || (pk33[0] !== 2 && pk33[0] !== 3))
    throw new Error("public key must be 33-byte SEC1 compressed (02/03 ‖ x)");
  return zkSec1Decode(pk33);
}

/** low-s = s ∈ [1, n/2]. Enforced for issuer_alg 0x04 ONLY (ingestion
 * normalises high-s to n−s); es256 (0x01/0x02) deliberately does NOT
 * enforce it - fixtures pin the (r, n−s) positive. */
function secpIsLowS(s) { return s >= 1n && s <= SECP_HALF_N; }

/** ECDSA over secp256k1 against a PRECOMPUTED 32-byte digest. The digest is
 * already double-SHA256 of the Bitcoin message - hashing again here would
 * verify a different message, so this function never hashes. */
function secp256k1VerifyDigest(pub33, digest, r, s) {
  const Q = secpDecompress(pub33);
  if (!(digest instanceof Uint8Array) || digest.length !== 32) throw new Error("digest must be 32 bytes");
  if (!(r >= 1n && r < ZK_N && s >= 1n && s < ZK_N)) throw new Error("r/s out of range [1, n-1]");
  const e = zkMod(zkBytesToBig(digest), ZK_N);
  const w = zkInvN(s);
  const X = zkAdd(zkMul(ZK_G, e * w % ZK_N), zkMul(Q, r * w % ZK_N));
  return X !== null && zkMod(X.x, ZK_N) === r;
}

/** Registration proof of possession: recover the signing key from the 65-byte
 * recoverable form header(27..=34) ‖ r ‖ s, once, at registration. Returns the
 * 33-byte compressed key regardless of the header's compression hint; low-s is
 * NOT enforced on this path. Throws on malformed input. */
function secp256k1RecoverPubkey(digest, header, r, s) {
  if (!(header >= 27 && header <= 34)) throw new Error("recovery header must be 27..=34, got " + header);
  if (!(r >= 1n && r < ZK_N && s >= 1n && s < ZK_N)) throw new Error("r/s out of range [1, n-1]");
  const recid = (header - 27) & 3;
  const x = r + (recid >= 2 ? ZK_N : 0n);
  if (x >= ZK_P) throw new Error("recovery x is not a canonical field element");
  let y = zkSqrtP(zkMod(x * x % ZK_P * x + 7n, ZK_P));
  if (y === null) throw new Error("recovery x is not on secp256k1");
  if ((y & 1n) !== BigInt(recid & 1)) y = ZK_P - y;
  const e = zkMod(zkBytesToBig(digest), ZK_N);
  const Q = zkMul(zkAdd(zkMul({ x, y }, s), zkNeg(zkMul(ZK_G, e))), zkInvN(r));
  if (Q === null) throw new Error("recovered key is the point at infinity");
  return zkSec1Encode(Q);
}

/** digest = SHA256(SHA256(0x18 ‖ "Bitcoin Signed Message:\n" ‖ varint(len(msg))
 * ‖ msg)) - varint is the Bitcoin CompactSize encoding. */
async function bitcoinMessageDigest(msg) {
  const prefix = zkCat(Uint8Array.of(0x18), new TextEncoder().encode("Bitcoin Signed Message:\n"));
  const n = msg.length;
  const vi = n < 0xfd ? Uint8Array.of(n)
    : n <= 0xffff ? Uint8Array.of(0xfd, n & 255, (n >>> 8) & 255)
    : Uint8Array.of(0xfe, n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255);
  return zkSha256(await zkSha256(zkCat(prefix, vi, msg)));
}

/* ---------- cosign message + 0x10 multi-signature envelope (§12.2) ---------- */
const COSIGN_TAG = "BC30/cosign/v1";
/** Sort-only constants, never on the wire; the vocabulary is CLOSED (an open
 * list would let an undefined role dodge the tl_proof requirement). */
const COSIGN_ROLE_ORD = { "issuer": 0, "co-issuer": 1, "subject-consent": 2, "endorser": 3 };
const MULTISIG_MAX_LEN = 8192;   // the 8 KB cap applies to the 0x10 envelope ONLY
const MULTISIG_MIN_COUNT = 2, MULTISIG_MAX_COUNT = 8;

/** m_i = SHA256("BC30/cosign/v1" ‖ m ‖ role_len(1) ‖ role_utf8). EVERY 0x10
 * entry signs its own m_i - the first entry included. */
async function cosignMessage(m, role) {
  if (!(m instanceof Uint8Array) || m.length !== 32) throw new Error("m must be 32 bytes");
  const roleB = new TextEncoder().encode(role);
  if (roleB.length < 1 || roleB.length > 32) throw new Error("role must be 1..32 UTF-8 bytes");
  return zkSha256(zkCat(new TextEncoder().encode(COSIGN_TAG), m, Uint8Array.of(roleB.length), roleB));
}

/** Refusal with a stable machine identifier in `.code` - the identifiers match
 * the engine KAT's negative_v2 `error` field (and verify.py's MultisigError). */
function msError(code, detail) { const e = new Error(code + (detail ? ": " + detail : "")); e.code = code; return e; }

/** Parse ONE inner signature frame of a 0x10 entry. A separate function from
 * parseMultisigS so 0x10 nesting is refused HERE and the envelope parser
 * structurally cannot recurse. The frame must consume its bytes exactly. */
function parseInnerSig(inner) {
  if (!(inner instanceof Uint8Array) || inner.length === 0) throw msError("truncated", "empty inner_sig");
  const alg = inner[0];
  if (alg === 0x10) throw msError("nested_multisig", "0x10 inside 0x10");
  if (alg === 0x04) {
    if (inner.length !== 65) throw msError("wallet_sig_length", "0x04 inner must be exactly 65 B, got " + inner.length);
    return { alg, rs: inner.subarray(1), r: zkBytesToBig(inner.subarray(1, 33)), s: zkBytesToBig(inner.subarray(33, 65)) };
  }
  if (alg !== 0x01 && alg !== 0x02) throw msError("unknown_inner_alg", "inner alg 0x" + alg.toString(16));
  let o = 1;
  const take = (n, what) => {
    if (inner.length - o < n) throw msError("truncated", "inner " + what);
    const piece = inner.subarray(o, o + n); o += n; return piece;
  };
  const u16 = (what) => { const b = take(2, what); return (b[0] << 8) + b[1]; };
  const out = { alg };
  if (alg === 0x01) {
    out.authData = take(u16("len16(authenticator_data)"), "authenticator_data");
    const cb = take(4, "len32(client_data_json)");
    out.cdj = take(((cb[0] << 24) >>> 0) + (cb[1] << 16) + (cb[2] << 8) + cb[3], "client_data_json");
  }
  out.sigDer = take(u16("len16(signature_der)"), "signature_der");
  if (o !== inner.length) throw msError("inner_trailing", (inner.length - o) + " byte(s) after the inner frame");
  return out;
}

const msKeyHex = (kid) => { let h = ""; for (const b of kid) h += b.toString(16).padStart(2, "0"); return h; };

/** Strict parser for s = 0x10 ‖ count(1) ‖ [role_len(1) ‖ role ‖ key_id(32) ‖
 * inner_len(2 BE) ‖ inner]×count. The receiver NEVER re-sorts: the first
 * violation refuses the whole envelope. Returns the entry list in wire order. */
function parseMultisigS(sBytes) {
  if (!(sBytes instanceof Uint8Array)) throw msError("not_multisig", "s must be bytes");
  if (sBytes.length > MULTISIG_MAX_LEN) throw msError("too_long", "s is " + sBytes.length + " B, cap " + MULTISIG_MAX_LEN);
  if (sBytes.length < 2 || sBytes[0] !== 0x10) throw msError("not_multisig", "s[0] must be 0x10");
  const count = sBytes[1];
  if (count < MULTISIG_MIN_COUNT || count > MULTISIG_MAX_COUNT)
    throw msError("count_out_of_range", "count " + count + " not in 2..=8 (a single signature uses 0x01/0x02/0x04)");
  let o = 2;
  const take = (n, what) => {
    if (sBytes.length - o < n) throw msError("truncated", what);
    const piece = sBytes.subarray(o, o + n); o += n; return piece;
  };
  const entries = [], seen = new Set();
  let prevOrd = -1, prevKey = "";
  for (let i = 0; i < count; i++) {
    const roleLen = take(1, "role_len")[0];
    if (roleLen < 1 || roleLen > 32) throw msError("bad_role_len", "entry " + i + " role_len " + roleLen);
    let role;
    try { role = new TextDecoder("utf-8", { fatal: true }).decode(take(roleLen, "role")); }
    catch (e) { throw msError("unknown_role", "entry " + i + " role is not UTF-8"); }
    if (!(role in COSIGN_ROLE_ORD)) throw msError("unknown_role", "entry " + i + " role " + JSON.stringify(role) + " not in the closed vocabulary");
    const keyId = take(32, "key_id");
    const lb = take(2, "inner_len");
    const inner = take((lb[0] << 8) + lb[1], "inner_sig");
    const parsed = parseInnerSig(inner);
    const kh = msKeyHex(keyId), ord = COSIGN_ROLE_ORD[role];
    if (seen.has(kh)) throw msError("duplicate_key_id", "entry " + i + " key_id repeats");
    if (ord < prevOrd || (ord === prevOrd && kh <= prevKey))
      throw msError("out_of_order", "entry " + i + " violates strict (role_ord, key_id) ascending order");
    seen.add(kh); prevOrd = ord; prevKey = kh;
    entries.push(Object.assign({ role, roleOrd: ord, keyId, inner }, parsed));
  }
  if (o !== sBytes.length) throw msError("trailing", (sBytes.length - o) + " trailing byte(s) after entry " + count);
  if (!entries.some((e) => e.role === "issuer")) throw msError("no_issuer", "at least one issuer entry is required");
  return entries;
}

/** Reassemble s from {role, keyId(32), inner} entries IN THE GIVEN ORDER. The
 * verifier never sorts - mis-ordered signers[] reassemble to an s that
 * parseMultisigS refuses, which is the intent. */
function assembleMultisigS(entries) {
  if (entries.length < 1 || entries.length > 255) throw new Error("entry count out of range");
  const parts = [Uint8Array.of(0x10, entries.length)];
  for (const e of entries) {
    const roleB = new TextEncoder().encode(e.role);
    if (roleB.length < 1 || roleB.length > 32) throw new Error("role must be 1..32 UTF-8 bytes");
    if (!(e.keyId instanceof Uint8Array) || e.keyId.length !== 32) throw new Error("key_id must be 32 bytes");
    if (e.inner.length > 0xffff) throw new Error("inner_sig longer than a len16 can carry");
    parts.push(Uint8Array.of(roleB.length), roleB, e.keyId,
               Uint8Array.of((e.inner.length >>> 8) & 255, e.inner.length & 255), e.inner);
  }
  return zkCat(...parts);
}


/* ---------- tier 3 inscription envelope (docs/inscription-tier-spec-2026-09-02.md) ----------
 * The reveal witness carries body = R(143) ‖ s, so the record AND the issuer
 * signature bytes come back out of the envelope. MUST 19/20 make that recovery
 * unambiguous: one encoding per body, and the recovered fields must re-serialise
 * to the very same script. index.html keeps its lenient parseEnvelope() for the
 * v1-v3 unified-witness path; nothing below is shared with it. */
const ENVELOPE_TAG_V1 = "BC30/envelope/v1";                        // spec 2.3
const INSC_PROTOCOL_TAG = "bcrt";                                  // spec 2.1
const INSC_CONTENT_TYPE = "application/vnd.bitcert.sig.v1";        // spec 2.1
const INSC_MAX_PUSH = 520;                                         // every chunk but the last is EXACTLY this
const INSC_RECORD_LEN = 143;
const INSC_BODY_MAX = INSC_RECORD_LEN + 8192;                      // 8335 (MUST 19)
const INSC_ENVELOPE_ROOT_NONE_TAG = "BC30/envelope/none";          // ①② keep the constant
const TAPROOT_ANNEX_PREFIX = 0x50, TAPROOT_MAX_MERKLE_DEPTH = 128;

/** Refusal with a stable machine identifier in `.code` - the engine KAT's
 * inscription.negative[].error strings (and verify.py's EnvelopeError). */
function envError(code, detail) { const e = new Error(code + (detail ? ": " + detail : "")); e.code = code; return e; }

/** BIP-340 lift_x: 32 bytes are an x-only KEY only if x < p and x is on the
 * curve. MUST 20 needs it - a leaf whose key is not a point can never be spent
 * and its script cannot be rebuilt. Returns {x, y} with y even. */
function secpLiftX(x32) {
  if (!(x32 instanceof Uint8Array) || x32.length !== 32) throw new Error("x-only key must be 32 bytes");
  const x = zkBytesToBig(x32);
  if (x >= ZK_P) throw new Error("x is not a canonical field element");
  const y = zkSqrtP(M(x * x % ZK_P * x + 7n));
  if (y === null) throw new Error("x is not on secp256k1");
  return { x, y: (y & 1n) === 0n ? y : ZK_P - y };
}

/** The SHORTEST push that can carry this length (MUST 19). Not BIP-62
 * MINIMALDATA: that would demand OP_1..OP_16 for single bytes 0x01..0x10, and
 * those are opcodes - inside an envelope they are forbidden_opcode. Both
 * readings refuse the same scripts. */
function inscPush(data) {
  const n = data.length;
  if (n === 0 || n > INSC_MAX_PUSH) throw envError("non_canonical_chunking", "push of " + n + " bytes (1.." + INSC_MAX_PUSH + ")");
  if (n < 0x4c) return zkCat(Uint8Array.of(n), data);
  if (n <= 0xff) return zkCat(Uint8Array.of(0x4c, n), data);
  return zkCat(Uint8Array.of(0x4d, n & 255, (n >> 8) & 255), data);
}

/** spec 2.1 byte for byte - and MUST 20's reference serialisation:
 *   <script_key(32 B x-only)> OP_CHECKSIG
 *   OP_FALSE OP_IF <protocol_tag> <content_type> <body chunk…> OP_ENDIF   */
function buildInscriptionScript(scriptKey, tag, contentType, body) {
  if (scriptKey.length !== 32) throw envError("invalid_script_key", "script key must be 32 bytes");
  const parts = [inscPush(scriptKey), Uint8Array.of(0xac, 0x00, 0x63), inscPush(tag), inscPush(contentType)];
  for (let i = 0; i < body.length; i += INSC_MAX_PUSH) parts.push(inscPush(body.subarray(i, Math.min(i + INSC_MAX_PUSH, body.length))));
  parts.push(Uint8Array.of(0x68));
  return zkCat(...parts);
}

/** MUST 19 + MUST 20. Returns {scriptKey, protocolTag, contentType, body,
 * chunkLens} or throws. Only `not_an_envelope` means "nothing was claimed". */
function parseInscriptionEnvelope(script) {
  if (!(script instanceof Uint8Array)) throw envError("not_an_envelope", "script must be bytes");
  if (script.length < 37 || script[0] !== 0x20 || script[33] !== 0xac || script[34] !== 0x00 || script[35] !== 0x63)
    throw envError("not_an_envelope", "script does not open with <32 B key> OP_CHECKSIG OP_FALSE OP_IF");
  const scriptKey = script.subarray(1, 33);
  let o = 36, closed = false;
  const n = script.length, pushes = [];
  while (o < n) {
    const op = script[o++];
    if (op === 0x68) { closed = true; break; }                       // OP_ENDIF
    if (op === 0x63 || op === 0x64) throw envError("nested_conditional", "0x" + op.toString(16) + " inside the envelope");
    if (op === 0x00) throw envError("forbidden_opcode", "OP_0 inside the envelope");
    let ln;
    if (op < 0x4c) ln = op;
    else if (op === 0x4c) {
      if (n - o < 1) throw envError("truncated_push", "OP_PUSHDATA1 length byte past the script");
      ln = script[o++];
      if (ln < 0x4c) throw envError("non_minimal_push", ln + " bytes pushed with OP_PUSHDATA1");
    } else if (op === 0x4d) {
      if (n - o < 2) throw envError("truncated_push", "OP_PUSHDATA2 length past the script");
      ln = script[o] + (script[o + 1] << 8); o += 2;
      if (ln <= 0xff) throw envError("non_minimal_push", ln + " bytes pushed with OP_PUSHDATA2");
    } else if (op === 0x4e) throw envError("non_minimal_push", "OP_PUSHDATA4 cannot be the shortest form");
    else throw envError("forbidden_opcode", "opcode 0x" + op.toString(16) + " inside the envelope");
    if (ln > INSC_MAX_PUSH) throw envError("non_canonical_chunking", "push of " + ln + " bytes exceeds " + INSC_MAX_PUSH);
    if (n - o < ln) throw envError("truncated_push", "push of " + ln + " bytes runs past the script");
    pushes.push(script.subarray(o, o + ln)); o += ln;
  }
  if (!closed) throw envError("unterminated_envelope", "no OP_ENDIF");
  if (o !== n) throw envError("trailing_bytes_after_endif", (n - o) + " byte(s) after OP_ENDIF");
  if (pushes.length < 3) throw envError("empty_body", "envelope carries no body chunk");
  const tag = pushes[0], contentType = pushes[1], chunks = pushes.slice(2);
  for (let i = 0; i < chunks.length - 1; i++)
    if (chunks[i].length !== INSC_MAX_PUSH)
      throw envError("non_canonical_chunking", "chunk of " + chunks[i].length + " bytes before the last one (must be " + INSC_MAX_PUSH + ")");
  const body = zkCat(...chunks);
  if (body.length === 0) throw envError("empty_body", "body is zero bytes");
  if (body.length > INSC_BODY_MAX) throw envError("body_too_large", "body is " + body.length + " bytes, cap " + INSC_BODY_MAX);
  try { secpLiftX(scriptKey); } catch (e) { throw envError("invalid_script_key", e.message); }
  // MUST 20 - rebuild the WHOLE script from what was recovered and demand byte
  // identity. This is the line that closes every parser difference.
  const rebuilt = buildInscriptionScript(scriptKey, tag, contentType, body);
  if (rebuilt.length !== script.length || !rebuilt.every((b, i) => b === script[i]))
    throw envError("reserialization_mismatch", "the recovered fields do not re-serialise to this script");
  return { scriptKey, protocolTag: tag, contentType, body, chunkLens: chunks.map((c) => c.length) };
}

/** MUST 18. Read ONLY the indexed stack item (no scanning) after judging the
 * stack: 2+ items, a well-formed control block last, no annex. */
function inscriptionWitnessScript(items, index) {
  if (!Array.isArray(items)) throw envError("no_witness", "this input carries no witness");
  if (items.length >= 2 && items[items.length - 1].length > 0 && items[items.length - 1][0] === TAPROOT_ANNEX_PREFIX)
    throw envError("annex_present", "last stack item starts with 0x50");
  if (items.length < 2) throw envError("witness_too_short", "script-path spend needs [script, control block]");
  const cb = items[items.length - 1];
  if (cb.length < 33 || (cb.length - 33) % 32 !== 0 || (cb.length - 33) / 32 > TAPROOT_MAX_MERKLE_DEPTH || (cb[0] & 0xfe) !== 0xc0)
    throw envError("malformed_control_block", "control block is 0xc0/0xc1 followed by 32k bytes, got " + cb.length + " bytes");
  if (!Number.isInteger(index) || index < 0 || index >= items.length - 1)
    throw envError("witness_index_out_of_range", "witness_item_index " + index + " is not a script item of a " + items.length + "-item stack");
  return items[index];
}

/** spec 2.3 - the ONLY envelope_root preimage. The length prefixes stop
 * (tag, content_type, body) from being re-cut into another triple with the same
 * bytes; tag and content_type are inside so they are committed, not free text. */
async function envelopeRootV1(tag, contentType, body) {
  const u16 = (n) => Uint8Array.of((n >> 8) & 255, n & 255);
  const u32 = (n) => Uint8Array.of((n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255);
  return zkSha256(zkCat(new TextEncoder().encode(ENVELOPE_TAG_V1),
                        u16(tag.length), tag, u16(contentType.length), contentType, u32(body.length), body));
}
async function envelopeRootNoneHex() {
  const h = await zkSha256(new TextEncoder().encode(INSC_ENVELOPE_ROOT_NONE_TAG));
  return msKeyHex(h);
}

/** spec 3 + 4 (MUST 15/16): flags 0b11 is the ONLY ③ discriminator and the
 * three claims stand or fall together
 *   flags bit0 = 1 <-> aux.envelope_root != SHA256("BC30/envelope/none")
 *                  <-> `inscription` present
 * Returns [code, detail] or [null, null]. Pure, so the engine KAT's anchor
 * negatives pin this decision directly. */
function inscriptionEquivalenceError(flags, envelopeRootHex, noneRootHex, hasInscription) {
  const hasEnv = String(envelopeRootHex || "").toLowerCase() !== noneRootHex;
  if (flags === null || flags === undefined) return ["flags_unavailable", "no 86-byte payload to read flags from"];
  if (!(flags & 0b10)) return ["flags_not_identity_bound",
    "flags 0b" + flags.toString(2).padStart(2, "0") + ": the legacy unified-witness path never sets bit 1, so 0b11 stays the sole discriminator"];
  if (flags & 0b01) {
    if (!hasEnv) return ["flags_envelope_root_mismatch", "WITNESS_PRESENT is set but aux.envelope_root is the envelope-none constant"];
    if (!hasInscription) return ["inscription_missing", "WITNESS_PRESENT is set but the bundle carries no `inscription` section"];
    return [null, null];
  }
  if (hasEnv) return ["flags_envelope_root_mismatch", "aux.envelope_root is not the constant but WITNESS_PRESENT (bit 0) is clear"];
  if (hasInscription) return ["inscription_unexpected", "`inscription` is present but WITNESS_PRESENT (bit 0) is clear"];
  return [null, null];
}

/** MUST 25 - ③ is always a one-leaf batch: an empty path, and the root IS
 * H_leaf(leaf_bytes). Returns an error id or null. */
async function inscriptionBatchError(merkle, leafBytes) {
  const want = msKeyHex(await zkSha256(zkCat(Uint8Array.of(0x00), leafBytes)));
  const empty = (a) => Array.isArray(a) && a.length === 0;
  if (!empty(merkle.siblings) || !empty(merkle.directions) || String(merkle.root || "").toLowerCase() !== want)
    return "not_single_leaf_batch";
  return null;
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { verifyZk, zkDeriveNUMS, zkSec1Encode, zkSec1Decode, zkCsDigest, ZK_DST, ZK_G,
    // P-256 / WebAuthn (bundle §9–§10)
    P256_P, P256_N, P256_G, p256Decompress, p256Compress, p256Uncompressed, p256Mul, p256AddPt, derToRawSig,
    p256Verify, p256VerifyPure, bytesToB64u, b64uToBytes, parseAuthenticatorData, parseClientDataJson,
    webauthnVerifyAssertion, zkSha256, zkCat,
    // secp256k1 / cosign / multi-signature (bundle §12)
    ZK_P, ZK_N, SECP_HALF_N, secpDecompress, secpIsLowS, secp256k1VerifyDigest, secp256k1RecoverPubkey,
    bitcoinMessageDigest, COSIGN_TAG, COSIGN_ROLE_ORD, cosignMessage,
    parseInnerSig, parseMultisigS, assembleMultisigS, MULTISIG_MAX_LEN,
    // ③ inscription tier (frozen spec 2026-09-02)
    ENVELOPE_TAG_V1, INSC_PROTOCOL_TAG, INSC_CONTENT_TYPE, INSC_MAX_PUSH, INSC_BODY_MAX,
    secpLiftX, inscPush, buildInscriptionScript, parseInscriptionEnvelope, inscriptionWitnessScript,
    envelopeRootV1, envelopeRootNoneHex, inscriptionEquivalenceError, inscriptionBatchError, msKeyHex };
}
