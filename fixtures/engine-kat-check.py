#!/usr/bin/env python3
"""Engine KAT cross-check - permanent CI form of the M0 "three-party vector" gate.

fixtures/bc30-v2-vectors.json is a BYTE-IDENTICAL copy of the engine's canonical
known-answer file, ann-core/crates/bc30-leaf/tests/vectors/bc30-v2-kat.json
(PM decision 2026-08-25: the engine file is the source of truth). This script
takes only the INPUTS of that file (key seeds / private scalars, record_salt,
document, subject_type, issued/expires, policy, trust-list entries, revoked set,
presentation inputs) and re-derives every OUTPUT field with this repository's
code - verify.py's builders and verifier, generate.py's RFC 6979 signer, its
Merkle / sparse-Merkle tree builders - asserting a byte match for each. It also
asserts that the engine's two WebAuthn assertions pass verify.py's verifier.

Nothing is adopted from either side: a difference is reported field by field
and fails the run.

    python3 fixtures/engine-kat-check.py            # checks the committed copy
    ENGINE_KAT=/path/to/bc30-v2-kat.json …          # additionally asserts byte identity with that file

The committed copy is always checked against CANONICAL_SHA256 (pinned below), so
the integrity of the copy is asserted even where ann-core is not checked out.

Standard library only (Python >= 3.8).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "verify-cli"))
sys.path.insert(0, HERE)
import verify as V      # noqa: E402
import generate as G    # noqa: E402  (imports its RFC 6979 signer; main() is not run)

VECTORS = os.path.join(HERE, "bc30-v2-vectors.json")
DEFAULT_ENGINE = os.path.join(HERE, "..", "..", "ann-core", "crates", "bc30-leaf", "tests", "vectors", "bc30-v2-kat.json")
# SHA-256 of the canonical engine file (ann-core feat/party-model-redesign, 2026-08-31:
# the engine re-cut the vectors ADDITIVELY - sections cosign / wallet / multisig /
# policy_open / es256_plain_alternate_s / negative_v2; every pre-existing field is
# byte-identical). Asserted on the committed copy ALWAYS - so CI, which has no
# ann-core checkout, still proves the copy is the canonical bytes. Bump only when
# the engine deliberately re-cuts its vectors (and re-copy the file).
# The new sections are exercised by verify.py --selftest (kat_v2_party_checks),
# fixtures/generate.py and fixtures/multisig/kat.mjs; this script keeps re-deriving
# the original per-field surface.
CANONICAL_SHA256 = "ec36c41f344d812e421e563c9cd5fa2eab6b37bb5cbcee4f53965c28899ea112"

rows = []
def cmp(field, ours, theirs, note=""):
    ok = ours == theirs
    rows.append((field, ok, ours, theirs, note))
    return ok

def s(v):
    return v if isinstance(v, str) else json.dumps(v)

def main():
    h = bytes.fromhex
    with open(VECTORS, "rb") as f:
        raw = f.read()
    E = json.loads(raw.decode("utf-8"))
    cmp("file: sha256 of the committed copy == pinned canonical engine KAT", V.sha256(raw).hex(), CANONICAL_SHA256)
    engine = os.environ.get("ENGINE_KAT") or DEFAULT_ENGINE
    if os.path.exists(engine):
        with open(engine, "rb") as f:
            cmp("file: byte-identical to engine source %s" % os.path.relpath(engine, HERE), V.sha256(raw).hex(), V.sha256(f.read()).hex())
    else:
        print("note: engine source not present at %s - the committed copy is checked against the pinned sha256" % engine)
    cmp("schema", E.get("schema"), "bc30-v2-kat/v1")

    # ---- keys (seed → scalar → compressed point) ----
    ipriv, spriv = int(E["issuer_priv"], 16), int(E["subject_priv"], 16)
    cmp("issuer_priv = SHA256(issuer_seed)", V.sha256(E["issuer_seed"].encode()).hex(), E["issuer_priv"])
    cmp("subject_priv = SHA256(subject_seed)", V.sha256(E["subject_seed"].encode()).hex(), E["subject_priv"])
    cmp("issuer_pub33 = compress(priv·G)", G.p256_pub33(ipriv).hex(), E["issuer_pub33"])
    cmp("subject_pub33 = compress(priv·G)", G.p256_pub33(spriv).hex(), E["subject_pub33"])
    cmp("rp_id_hash = SHA256(rp_id)", V.sha256(E["rp_id"].encode()).hex(), E["rp_id_hash"])

    # ---- record ----
    salt = h(E["record_salt"])
    cmp("doc_sha256 = SHA256(doc_utf8)", V.sha256(E["doc_utf8"].encode("utf-8")).hex(), E["doc_sha256"])
    cmp("subject_ref_none", V.subject_ref_none().hex(), E["subject_ref_none"])
    cmp("subject_ref_id_hash = SHA256(salt ‖ identifier)", V.subject_ref_id_hash(salt, E["subject_identifier"]).hex(), E["subject_ref_id_hash"])
    cmp("subject_ref_pubkey = SHA256(0x02 ‖ 0x01 ‖ pub33)", V.subject_ref_pubkey(V.CURVE_P256, h(E["subject_pub33"])).hex(), E["subject_ref_pubkey"])
    policy = {"document_type": E["policy_document_type"], "jurisdiction": E["policy_jurisdiction"]}
    ph = V.policy_hash(policy)
    cmp("policy_jcs", V.policy_jcs(policy).decode("utf-8"), E["policy_jcs"])
    cmp("policy_hash", ph.hex(), E["policy_hash"])
    st = E["subject_type"]
    ref = {0: V.subject_ref_none(), 1: h(E["subject_ref_id_hash"]), 2: h(E["subject_ref_pubkey"])}[st]
    args = (salt, h(E["doc_sha256"]), st, ref, E["issued_at"], E["expires_at"], ph)
    R, m = V.record_bytes(*args), V.issue_message(*args)
    cmp("R (143 B)", R.hex(), E["R"])
    cmp("m", m.hex(), E["m"])
    cmp("challenge_b64u", V.b64u_encode(m), E["challenge_b64u"])

    # ---- issuer assertion: verify theirs, then REBUILD it from inputs ----
    ad, cdj, sig = h(E["authenticator_data"]), h(E["client_data_json"]), h(E["signature_der"])
    ok, reasons, facts = V.webauthn_verify_assertion(h(E["issuer_pub33"]), ad, cdj, sig, m, E["rp_id"], [E["origin"]])
    cmp("engine issuer assertion verifies (verify.py)", "ok" if ok else "FAIL: " + "; ".join(reasons), "ok")
    cmp("engine issuer assertion facts (UV, signCount)", [facts.get("uv"), facts.get("sign_count")], [True, E["sign_count"]])
    o_ad, o_cdj, o_sig = G.build_assertion(ipriv, E["rp_id"], E["origin"], m, uv=True, sign_count=E["sign_count"])
    cmp("authenticator_data (rebuilt)", o_ad.hex(), E["authenticator_data"])
    cmp("client_data_json (rebuilt: exact bytes, key order, crossOrigin)", o_cdj.hex(), E["client_data_json"])
    cmp("client_data_json_utf8", cdj.decode("utf-8"), E["client_data_json_utf8"])
    cmp("signature_der (re-signed, RFC 6979, no low-s)", o_sig.hex(), E["signature_der"])
    cmp("signature_der_plain (re-signed over m)", G.ecdsa_sign_der(ipriv, m).hex(), E["signature_der_plain"])
    cmp("engine es256-plain signature verifies (verify.py)", "ok" if V.p256_verify(h(E["issuer_pub33"]), m, h(E["signature_der_plain"])) else "FAIL", "ok")
    s1 = V.issuer_sig_bytes(V.ALG_WEBAUTHN_ES256, sig, ad, cdj)
    s2 = V.issuer_sig_bytes(V.ALG_ES256_PLAIN, h(E["signature_der_plain"]))
    cmp("s_webauthn", s1.hex(), E["s_webauthn"])
    cmp("s_es256_plain", s2.hex(), E["s_es256_plain"])
    cmp("leaf_type", E["leaf_type"], V.LEAF_TYPE_ISSUANCE)
    li1, li2 = V.leaf_input_v2(E["leaf_type"], R, s1), V.leaf_input_v2(E["leaf_type"], R, s2)
    cmp("leaf_input (webauthn)", li1.hex(), E["leaf_input"])
    cmp("leaf_input_es256_plain", li2.hex(), E["leaf_input_es256_plain"])
    cmp("leaf_hash", V.leaf_hash(li1).hex(), E["leaf_hash"])
    cmp("leaf_hash_es256_plain", V.leaf_hash(li2).hex(), E["leaf_hash_es256_plain"])

    # ---- trust list ----
    kid = V.key_id(V.CURVE_P256, h(E["issuer_pub33"]))
    cmp("tl_key_id", kid.hex(), E["tl_key_id"])
    eb = V.tl_entry_bytes(h(E["tl_issuer_id"]), kid, V.CURVE_P256, h(E["issuer_pub33"]), E["tl_valid_from"], E["tl_valid_to"], E["tl_revoked_at"])
    cmp("tl_entry (116 B)", eb.hex(), E["tl_entry"])
    cmp("tl_entry_leaf = SHA256(entry)", V.tl_leaf(eb).hex(), E["tl_entry_leaf"])
    cmp("tl_root_single = H_leaf(SHA256(entry))", V.leaf_hash(V.tl_leaf(eb)).hex(), E["tl_root_single"])
    cmp("tl_root_none", V.tl_root_none().hex(), E["tl_root_none"])
    ents = []
    for t in E["tl_entries_three"]:
        e = {k: t[k] for k in ("issuer_id", "key_id", "curve_id", "public_key", "valid_from", "valid_to", "revoked_at")}
        cmp("tl_entries_three[%s].key_id recomputes" % t["key_id"][:8], V.key_id(t["curve_id"], h(t["public_key"])).hex(), t["key_id"])
        cmp("tl_entries_three[%s].entry bytes" % t["key_id"][:8], G.tl_entry_bytes_of(e).hex(), t["entry"])
        cmp("tl_entries_three[%s].entry_leaf" % t["key_id"][:8], V.tl_leaf(G.tl_entry_bytes_of(e)).hex(), t["entry_leaf"])
        ents.append(e)
    root3, proof3, _ = G.build_trust_list(ents, E["tl_proof_three"]["key_id"])
    cmp("tl_root_three (key_id-sorted, duplicate-last)", root3.hex(), E["tl_root_three"])
    cmp("tl_proof_three.leaf_index", proof3["leaf_index"], E["tl_proof_three"]["leaf_index"])
    cmp("tl_proof_three.siblings", proof3["siblings"], E["tl_proof_three"]["siblings"])
    cmp("tl_proof_three.directions", proof3["directions"], E["tl_proof_three"]["directions"])
    _, inc = V.verify_merkle({"leaf_bytes": E["tl_entry_leaf"]}, {"root": E["tl_root_three"], "siblings": E["tl_proof_three"]["siblings"], "directions": E["tl_proof_three"]["directions"]})
    cmp("tl_proof_three folds to tl_root_three (verify.py)", "ok" if inc else "FAIL", "ok")

    # ---- status list (sparse Merkle tree) ----
    smt = G.SMT()
    for r in E["sl_revoked"]:
        cmp("sl_revoked[%d].value = 0×24 ‖ revoked_at" % r["revoked_at"], G.sl_value(r["revoked_at"]).hex(), r["value"])
        smt.insert(h(r["key"]), h(r["value"]))
    cmp("sl_root (SMT over the revoked set)", smt.root().hex(), E["sl_root"])
    cmp("empty_leaf = SHA256(0x11)", V.SMT_EMPTY_LEAF.hex(), E["empty_leaf"])
    cmp("smt_empty_root = defaults[256]", V.SMT_EMPTY_ROOT.hex(), E["smt_empty_root"])
    ex, inc_ = E["sl_proof_exclusion"], E["sl_proof_inclusion"]
    cmp("sl_proof_exclusion.key = leaf_input", ex["key"], E["leaf_input"])
    cmp("sl_proof_exclusion.value", ex["value"], None)
    cmp("sl_proof_exclusion.siblings (our prover)", smt.prove(h(ex["key"]))["siblings"], ex["siblings"])
    cmp("sl_proof_exclusion folds to sl_root (verify.py)", "ok" if V.smt_verify(h(ex["key"]), None, [h(x) for x in ex["siblings"]], h(E["sl_root"])) else "FAIL", "ok")
    cmp("sl_proof_inclusion.siblings (our prover)", smt.prove(h(inc_["key"]))["siblings"], inc_["siblings"])
    cmp("sl_proof_inclusion.value (our prover)", smt.prove(h(inc_["key"]))["value"], inc_["value"])
    cmp("sl_proof_inclusion folds to sl_root (verify.py)", "ok" if V.smt_verify(h(inc_["key"]), h(inc_["value"]), [h(x) for x in inc_["siblings"]], h(E["sl_root"])) else "FAIL", "ok")

    # ---- aux + OP_RETURN v31 ----
    ai = E["aux_inputs"]
    cmp("envelope_root = SHA256(envelope-none tag)", V.envelope_root_none().hex(), E["envelope_root"])
    cmp("aux_inputs.envelope_root", ai["envelope_root"], E["envelope_root"])
    cmp("aux_inputs.sl_root", ai["sl_root"], E["sl_root"])
    cmp("aux_inputs.tl_root (engine commits the single-entry list)", ai["tl_root"], E["tl_root_single"])
    cmp("aux_commitment", V.aux_commitment(h(ai["tl_root"]), h(ai["sl_root"]), h(ai["envelope_root"])).hex(), E["aux_commitment"])
    cmp("aux_commitment_none", V.AUX_COMMITMENT_NONE.hex(), E["aux_commitment_none"])
    cmp("op_return_merkle_root = leaf_hash (single-leaf batch)", E["op_return_merkle_root"], E["leaf_hash"])
    cmp("op_return_flags = IDENTITY_BOUND", E["op_return_flags"], V.FLAG_IDENTITY_BOUND)
    cmp("op_return_v31 (86 B)", V.bc30_v31(h(E["op_return_merkle_root"]), h(E["op_return_batch_id"]), h(E["aux_commitment"]), flags=E["op_return_flags"]).hex(), E["op_return_v31"])
    d = V.decode_anchor_payload(E["op_return_v31"])
    cmp("op_return_v31 decodes (verify.py)", [d["version"], d["flags"], d["merkle_root"], d["aux"], d["batch_id"]],
        [V.OP_RETURN_V31_VERSION, E["op_return_flags"], E["op_return_merkle_root"], E["aux_commitment"], E["op_return_batch_id"]])
    cmp("legacy rule rejects a bound v31 payload for v1–v3", V.legacy_payload_problem(d) is not None, True)

    # ---- presentation ----
    vid = V.make_verifier_id(E["present_verifier_label"], h(E["present_verifier_rand16"]))
    cmp("present_verifier_id", vid.hex(), E["present_verifier_id"])
    ch = V.present_challenge(h(E["present_nonce"]), h(E["leaf_input"]), vid, E["present_expiry"])
    cmp("present_challenge", ch.hex(), E["present_challenge"])
    cmp("present_challenge_b64u", V.b64u_encode(ch), E["present_challenge_b64u"])
    pad, pcdj, psig = h(E["present_authenticator_data"]), h(E["present_client_data_json"]), h(E["present_signature_der"])
    ok, reasons, facts = V.webauthn_verify_assertion(h(E["subject_pub33"]), pad, pcdj, psig, ch, E["rp_id"], [E["origin"]])
    cmp("engine presentation assertion verifies under subject key (verify.py)", "ok" if ok else "FAIL: " + "; ".join(reasons), "ok")
    cmp("engine presentation assertion facts (UV, signCount)", [facts.get("uv"), facts.get("sign_count")], [True, E["present_sign_count"]])
    p_ad, p_cdj, p_sig = G.build_assertion(spriv, E["rp_id"], E["origin"], ch, uv=True, sign_count=E["present_sign_count"])
    cmp("present_authenticator_data (rebuilt)", p_ad.hex(), E["present_authenticator_data"])
    cmp("present_client_data_json (rebuilt)", p_cdj.hex(), E["present_client_data_json"])
    cmp("present_client_data_json_utf8", pcdj.decode("utf-8"), E["present_client_data_json_utf8"])
    cmp("present_signature_der (re-signed with subject_priv)", p_sig.hex(), E["present_signature_der"])
    # the whole presentation round-trips through verify_v4's blob parser
    blob = {"v": 1, "scheme": "bc30-present-v1", "leaf": E["leaf_input"], "nonce": E["present_nonce"], "verifier_id": E["present_verifier_id"],
            "expiry": E["present_expiry"], "authenticator_data": V.b64u_encode(pad), "client_data_json": V.b64u_encode(pcdj), "signature": V.b64u_encode(psig)}
    np_ = V.parse_presentation_blob(V.b64u_encode(json.dumps(blob).encode()))
    cmp("presentation blob (base64url JSON) parses back to the engine bytes", (np_["authenticator_data"] + np_["client_data_json"] + np_["signature"]).hex(), (pad + pcdj + psig).hex())

    bad = [r for r in rows if not r[1]]
    print("engine KAT cross-check - %d fields, %d mismatch(es)\n" % (len(rows), len(bad)))
    for field, ok, ours, theirs, note in rows:
        print("  %s  %s" % ("MATCH   " if ok else "MISMATCH", field))
        if not ok:
            o, t = s(ours), s(theirs)
            print("           ours:   %s" % (o if len(o) < 220 else o[:220] + "…"))
            print("           engine: %s" % (t if len(t) < 220 else t[:220] + "…"))
    print()
    print("OK - every field of the engine KAT re-derives byte-for-byte with verify.py + generate.py" if not bad
          else "FAIL - %d field(s) differ (see MISMATCH lines); do not adjust either side silently" % len(bad))
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
