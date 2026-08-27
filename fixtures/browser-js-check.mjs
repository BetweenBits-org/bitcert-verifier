// Cross-check that the SHIPPED browser JS in index.html produces identical
// results to verify.py. Extracts the pure functions from the single-file HTML,
// evaluates them under Node's Web Crypto, and runs them on the fixtures.
// Run: node fixtures/browser-js-check.mjs
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const html = readFileSync(path.join(here, "..", "index.html"), "utf8");

// pull the <script> body, keep only the pure functions (drop the UI wiring)
const script = html.split("<script>")[1].split("</script>")[0];
const cut = script.indexOf("/* ---------- UI plumbing");
const pure = script.slice(0, cut);

const factory = new Function(
  pure + "\nreturn {hexToBytes,bytesToHex,verifyMerkle,decodeAnchorPayload,txidFromRaw," +
         "payloadHash,verifyChainLinks,verifyPreimage,eqHex," +
         "extractWitnessItems,parseEnvelope,sha256," +
         // bundle v4 (schema §2.3, §9–§12) - builders + SMT + presentation + the legacy §4.1 rule
         "recordBytes,issueMessage,issuerSigBytes,leafInputV2,subjectRefIdHash,subjectRefPubkey,policyHash,policyJcs," +
         "tlEntryBytes,tlLeaf,tlRootNone,envelopeRootNone,auxCommitment,auxCommitmentNone,presentChallenge," +
         "smtVerify,smtEmptyLeaf,smtEmptyRoot,parsePresentationBlob,legacyPayloadProblem,runV4,makeVerifierId," +
         "p256Verify,webauthnVerifyAssertion,bytesToB64u,b64uToBytes};"
);
const F = factory();
if (!globalThis.atob) globalThis.atob = (s) => Buffer.from(s, "base64").toString("binary");
if (!globalThis.btoa) globalThis.btoa = (s) => Buffer.from(s, "binary").toString("base64");

function load(name) {
  return JSON.parse(readFileSync(path.join(here, name), "utf8"));
}

let failures = 0;
function expect(cond, msg) { if (!cond) { console.log("  ✗ " + msg); failures++; } else { console.log("  ✓ " + msg); } }

const valid = load("sample-bundle.valid.json");
const tampered = load("sample-bundle.tampered.json");
const tamperedChain = load("sample-bundle.tampered-chain.json");

console.log("browser-js vs fixtures:");
{
  const m = await F.verifyMerkle(valid.record, valid.merkle);
  expect(m.ok, "valid: merkle inclusion holds");
  const d = F.decodeAnchorPayload(valid.anchor.op_return_payload_hex);
  expect(F.eqHex(d.merkle_root, valid.merkle.root), "valid: anchor output root == merkle root");
  const t = await F.txidFromRaw(valid.anchor.reveal_tx_hex);
  expect(F.eqHex(t.txid, valid.anchor.reveal_txid), "valid: computed txid == reveal_txid (" + t.txid + ")");
  expect(F.eqHex(t.anchorOutputHex, valid.anchor.op_return_payload_hex), "valid: raw-tx anchor output == payload");
  const ph = await F.payloadHash(valid.chain.entry);
  expect(F.eqHex(ph, valid.chain.entry.payload_hash), "valid: chain payload_hash recomputes");
}
{
  const m = await F.verifyMerkle(tampered.record, tampered.merkle);
  expect(!m.ok, "tampered: merkle inclusion correctly FAILS");
}
// §5 chain (link D) - browser JS must gate just like Python
{
  const ph = await F.payloadHash(tamperedChain.chain.entry);
  expect(!F.eqHex(ph, tamperedChain.chain.entry.payload_hash), "tampered-chain: payload_hash correctly does NOT recompute");
  // walk-back continuity: a forged linked entry must break the linkage
  const head = valid.chain.entry;
  const goodPrior = { exchange_id: "demoex", seq: 0, kind: "daily",
    prev_entry_hash: "00".repeat(32), body_hash: "be".repeat(32), business_date: "2026-05-27" };
  goodPrior.payload_hash = await F.payloadHash(goodPrior);
  const linkedHead = { ...head, seq: 1, prev_entry_hash: goodPrior.payload_hash };
  expect((await F.verifyChainLinks([goodPrior], linkedHead)).ok, "chain links: clean walk-back hash-linkage holds");
  const forgedPrior = { ...goodPrior, payload_hash: "ff".repeat(32) };
  expect(!(await F.verifyChainLinks([forgedPrior], linkedHead)).ok, "chain links: forged prior entry correctly breaks continuity");
}
// pinned RFC-6962 test vector must match merkle-batching
{
  const cur = await F.verifyMerkle({ leaf_bytes: "00".repeat(32) },
    { root: "7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9", siblings: [], directions: [] });
  expect(cur.ok, "pinned vector: H_leaf(0x00*32) matches ann-core merkle-batching");
}

// §2.1 preimage (link A) - browser JS must match Python + examples
{
  // daily jcs: self-consistency (no secret), then identity binding (account+salt)
  const self = await F.verifyPreimage(valid.record, null, null, null);
  expect(self.self_ok, "valid(daily): leaf_bytes == hash(declared fields)");
  const ident = await F.verifyPreimage(valid.record, null, "alice@demoex", "5e".repeat(32));
  expect(ident.identity_ok === true, "valid(daily): account+salt -> user_commitment matches");
  const wrong = await F.verifyPreimage(valid.record, null, "mallory", "5e".repeat(32));
  expect(wrong.identity_ok === false, "daily: wrong account -> identity MISMATCH");

  // file scheme: hash the example's original artifact
  const fileBundle = JSON.parse(readFileSync(path.join(here, "..", "examples",
    "01-attestation-file", "bundle.json"), "utf8"));
  const art = new Uint8Array(readFileSync(path.join(here, "..", "examples",
    "01-attestation-file", "original-report.txt")));
  const fp = await F.verifyPreimage(fileBundle.record, art, null, null);
  expect(fp.self_ok, "file scheme: SHA-256(original artifact) == leaf_bytes");
  const tampered2 = await F.verifyPreimage(fileBundle.record, new Uint8Array([1, 2, 3]), null, null);
  expect(tampered2.self_ok === false, "file scheme: altered bytes -> binding FAILS");
}

// §4.4 witness inscription dual-mode (LEGACY + UNIFIED) - the JS witness path
// must reach the SAME mode + rootOk + bound decisions as verify.py. Mirrors
// verify_witness_bundle's logic using the shipped primitives so CI catches any
// py<->js drift on the witness branch (not only the anchor/chain primitives).
async function jsWitnessDecision(b) {
  const anchor = b.anchor, record = b.record, wit = anchor.witness_envelope;
  const leaf = record.leaf_bytes.toLowerCase();
  const items = F.extractWitnessItems(anchor.reveal_tx_hex, (wit && wit.input_index) || 0);
  const env = F.parseEnvelope(items[1]);            // { tag, contentType, body }
  const bodyHash = F.bytesToHex(await F.sha256(env.body));
  let decoded = null;
  try { decoded = F.decodeAnchorPayload(anchor.op_return_payload_hex); } catch { decoded = null; }
  const mode = decoded ? "UNIFIED" : "LEGACY";
  let rootOk;
  if (mode === "UNIFIED") {
    const m = await F.verifyMerkle(record, b.merkle);
    rootOk = m.ok && F.eqHex(m.root || b.merkle.root, decoded.merkle_root);
  } else {
    rootOk = F.eqHex(anchor.op_return_payload_hex, leaf);
  }
  return { mode, rootOk, bound: F.eqHex(bodyHash, leaf) };
}
{
  const legacy = await jsWitnessDecision(load("06-witness-inscription.json"));
  expect(legacy.mode === "LEGACY", "witness 06: mode LEGACY (raw-32 anchor output)");
  expect(legacy.rootOk, "witness 06: anchor output == leaf_bytes");
  expect(legacy.bound, "witness 06: sha256(body) binds to leaf_bytes");

  const unified = await jsWitnessDecision(load("07-witness-unified.json"));
  expect(unified.mode === "UNIFIED", "witness 07: mode UNIFIED (86-byte anchor output)");
  expect(unified.rootOk, "witness 07: merkle root == decoded 86-byte payload merkle_root");
  expect(unified.bound, "witness 07: sha256(PDF body) binds to leaf_bytes");

  const tampered = await jsWitnessDecision(load("07-witness-unified.tampered.json"));
  expect(tampered.mode === "UNIFIED", "witness 07-tampered: still UNIFIED (txid/anchor output intact)");
  expect(tampered.rootOk, "witness 07-tampered: anchor binding still holds (malleable witness)");
  expect(!tampered.bound, "witness 07-tampered: tampered body correctly does NOT bind");
}

// bundle v4 - fixtures/bc30-v2-vectors.json is a byte-identical copy of the ENGINE's
// canonical KAT (ann-core/crates/bc30-leaf/tests/vectors/bc30-v2-kat.json). The
// browser builders must re-derive its fields from its INPUTS byte for byte, and the
// engine's two WebAuthn assertions must pass the browser verifier. runV4 as a whole
// is diffed against the Python oracle by fixtures/v4-grade-check.mjs.
{
  const vec = load("bc30-v2-vectors.json");
  const h = F.hexToBytes, hx = F.bytesToHex;
  expect(vec.schema === "bc30-v2-kat/v1", "engine KAT: schema bc30-v2-kat/v1");
  const policy = { document_type: vec.policy_document_type, jurisdiction: vec.policy_jurisdiction };
  const ph = await F.policyHash(policy);
  expect(F.eqHex(hx(ph), vec.policy_hash) && F.policyJcs(policy) === vec.policy_jcs, "engine KAT: policy_hash + JCS");
  expect(F.eqHex(hx(await F.sha256(new TextEncoder().encode(vec.doc_utf8))), vec.doc_sha256), "engine KAT: doc_sha256 = SHA256(doc_utf8)");
  expect(F.eqHex(hx(await F.subjectRefIdHash(h(vec.record_salt), vec.subject_identifier)), vec.subject_ref_id_hash), "engine KAT: subject_ref 0x01");
  expect(F.eqHex(hx(await F.subjectRefPubkey(1, h(vec.subject_pub33))), vec.subject_ref_pubkey), "engine KAT: subject_ref 0x02");
  const ref = [new Uint8Array(32), h(vec.subject_ref_id_hash), h(vec.subject_ref_pubkey)][vec.subject_type];
  const args = [h(vec.record_salt), h(vec.doc_sha256), vec.subject_type, ref, vec.issued_at, vec.expires_at, ph];
  expect(F.eqHex(hx(F.recordBytes(...args)), vec.R), "engine KAT: R (143 B)");
  const m = await F.issueMessage(...args);
  expect(F.eqHex(hx(m), vec.m) && F.bytesToB64u(m) === vec.challenge_b64u, "engine KAT: m + challenge_b64u");
  const ad = h(vec.authenticator_data), cdj = h(vec.client_data_json), sig = h(vec.signature_der);
  const wa = await F.webauthnVerifyAssertion({ pub33: h(vec.issuer_pub33), authData: ad, cdj, sigDer: sig, challenge: m, rpId: vec.rp_id, origins: [vec.origin] });
  expect(wa.ok && wa.facts.signCount === vec.sign_count, "engine KAT: issuer WebAuthn assertion verifies in the browser (" + wa.reasons.join("; ") + ")");
  expect(await F.p256Verify(h(vec.issuer_pub33), m, h(vec.signature_der_plain)), "engine KAT: es256-plain signature over m verifies in the browser");
  const s1 = F.issuerSigBytes(1, sig, ad, cdj), s2 = F.issuerSigBytes(2, h(vec.signature_der_plain));
  expect(F.eqHex(hx(s1), vec.s_webauthn) && F.eqHex(hx(s2), vec.s_es256_plain), "engine KAT: s_webauthn + s_es256_plain");
  const li1 = await F.leafInputV2(vec.leaf_type, h(vec.R), s1), li2 = await F.leafInputV2(vec.leaf_type, h(vec.R), s2);
  expect(F.eqHex(hx(li1), vec.leaf_input) && F.eqHex(hx(li2), vec.leaf_input_es256_plain), "engine KAT: leaf_input (webauthn + es256-plain)");
  const lh = await F.verifyMerkle({ leaf_bytes: vec.leaf_input }, { root: vec.leaf_hash, siblings: [], directions: [] });
  expect(lh.ok, "engine KAT: leaf_hash = H_leaf(leaf_input)");
  const kid = await F.subjectRefPubkey(1, h(vec.issuer_pub33));
  expect(F.eqHex(hx(kid), vec.tl_key_id), "engine KAT: tl_key_id");
  const eb = F.tlEntryBytes(h(vec.tl_issuer_id), kid, 1, h(vec.issuer_pub33), vec.tl_valid_from, vec.tl_valid_to, vec.tl_revoked_at);
  expect(F.eqHex(hx(eb), vec.tl_entry), "engine KAT: tl_entry (116 B)");
  const tleaf = hx(await F.tlLeaf(eb));
  expect(F.eqHex(tleaf, vec.tl_entry_leaf), "engine KAT: tl_entry_leaf");
  expect((await F.verifyMerkle({ leaf_bytes: tleaf }, { root: vec.tl_root_single, siblings: [], directions: [] })).ok, "engine KAT: tl_root_single = H_leaf(SHA256(entry))");
  const tp = vec.tl_proof_three;
  expect((await F.verifyMerkle({ leaf_bytes: tleaf }, { root: vec.tl_root_three, siblings: tp.siblings, directions: tp.directions })).ok, "engine KAT: tl_proof_three folds to tl_root_three");
  expect(F.eqHex(hx(await F.tlRootNone()), vec.tl_root_none) && F.eqHex(hx(await F.envelopeRootNone()), vec.envelope_root), "engine KAT: tl_root_none + envelope_root");
  expect(F.eqHex(hx(await F.smtEmptyLeaf()), vec.empty_leaf) && F.eqHex(hx(await F.smtEmptyRoot()), vec.smt_empty_root), "engine KAT: EMPTY_LEAF + SMT_EMPTY_ROOT");
  const ai = vec.aux_inputs;
  expect(F.eqHex(hx(await F.auxCommitment(h(ai.tl_root), h(ai.sl_root), h(ai.envelope_root))), vec.aux_commitment), "engine KAT: aux_commitment");
  expect(F.eqHex(hx(await F.auxCommitmentNone()), vec.aux_commitment_none), "engine KAT: AUX_COMMITMENT_NONE");
  const ex = vec.sl_proof_exclusion, inc = vec.sl_proof_inclusion;
  expect(await F.smtVerify(h(ex.key), null, ex.siblings.map(h), h(vec.sl_root)), "engine KAT: SL exclusion proof folds from the pinned EMPTY_LEAF to sl_root");
  expect(await F.smtVerify(h(inc.key), h(inc.value), inc.siblings.map(h), h(vec.sl_root)), "engine KAT: SL inclusion proof folds to sl_root");
  expect(!(await F.smtVerify(h(ex.key), new Uint8Array(32), ex.siblings.map(h), h(vec.sl_root))), "engine KAT: value=0×32 does not masquerade as empty");
  const built = new Uint8Array(86);
  built.set(h("42433330"), 0); built[4] = 0x1f; built[5] = vec.op_return_flags;      // magic bytes, hex only
  built.set(h(vec.op_return_batch_id), 6); built.set(h(vec.op_return_merkle_root), 22); built.set(h(vec.aux_commitment), 54);
  expect(F.eqHex(hx(built), vec.op_return_v31), "engine KAT: op_return_v31 rebuilt (magic ‖ 1f ‖ flags ‖ batch ‖ root ‖ aux)");
  const d31 = F.decodeAnchorPayload(vec.op_return_v31);
  expect(d31.version === 0x1f && d31.flags === vec.op_return_flags && F.eqHex(d31.aux, vec.aux_commitment) && F.eqHex(d31.merkle_root, vec.op_return_merkle_root), "engine KAT: op_return_v31 decodes (0x1F, IDENTITY_BOUND, root, aux)");
  expect((await F.legacyPayloadProblem(d31)) !== null, "§4.1 rule: the bound v31 payload is refused for a legacy bundle");
  const vid = await F.makeVerifierId(vec.present_verifier_label, h(vec.present_verifier_rand16));
  expect(F.eqHex(hx(vid), vec.present_verifier_id), "engine KAT: present_verifier_id");
  const ch = await F.presentChallenge(h(vec.present_nonce), h(vec.leaf_input), vid, vec.present_expiry);
  expect(F.eqHex(hx(ch), vec.present_challenge) && F.bytesToB64u(ch) === vec.present_challenge_b64u, "engine KAT: present_challenge (+ b64u)");
  const pa = await F.webauthnVerifyAssertion({ pub33: h(vec.subject_pub33), authData: h(vec.present_authenticator_data), cdj: h(vec.present_client_data_json),
    sigDer: h(vec.present_signature_der), challenge: ch, rpId: vec.rp_id, origins: [vec.origin] });
  expect(pa.ok && pa.facts.signCount === vec.present_sign_count, "engine KAT: presentation assertion verifies under the subject key (" + pa.reasons.join("; ") + ")");
  const blob = F.parsePresentationBlob(readFileSync(path.join(here, "v4", "valid-pubkey.presentation.txt"), "utf8"));
  expect(blob.nonce.length === 16 && Number.isInteger(blob.expiry), "v4: presentation blob parses (base64url JSON)");
}

console.log(failures ? "\nFAIL (" + failures + ")" : "\nOK - browser JS matches Python + core test vector");
process.exit(failures ? 1 : 0);
