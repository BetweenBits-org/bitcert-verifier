#!/usr/bin/env python3
"""Generate internally-consistent proof-bundle fixtures AND runnable examples.

Reuses verify.py's hashing/parsing so everything is guaranteed to match what the
verifier checks (no hand-typed hashes that can drift). Produces:

  fixtures/sample-bundle.valid.json      - passes every offline check (CI)
  fixtures/sample-bundle.tampered.json   - leaf altered; Merkle step must FAIL (CI)

  examples/01-attestation-file/          - link A via sha256-file (an original artifact)
  examples/02-daily-balance/             - link A via salted balance commitment (+ secret)
  examples/03-tampered-original/         - original swapped; link A must catch it
  examples/09..14                        - bundle v4 (identity-bound issuance) scenarios
  examples/run.sh                        - runs every example and asserts the exit code

  fixtures/v4/*.json                     - v4 valid ×3 + negatives (schema §12)
  fixtures/v4-expected.json              - the ORACLE: grade / exit code / per-step state
                                           that verify.py produces; the browser JS must match
  fixtures/bc30-v2-vectors.json          - NOT written here: byte-identical copy of the engine's
                                           canonical KAT (ann-core/crates/bc30-leaf/tests/vectors/
                                           bc30-v2-kat.json); fixtures/engine-kat-check.py re-derives it


Deterministic: no randomness, no timestamps (RFC 6979 signatures, seeded keys).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
EX = os.path.join(ROOT, "examples")
sys.path.insert(0, os.path.join(ROOT, "verify-cli"))
import verify as V  # noqa: E402

DAILY_DOMAIN = "attest:daily:leaf\n"

# ---------------- low-level builders ----------------
def merkle4(leaf_preimages):
    """RFC-6962 tree over exactly 4 leaf pre-images. Returns (root, proof_for_0)."""
    l = [V.leaf_hash(x) for x in leaf_preimages]
    n01 = V.node_hash(l[0], l[1])
    n23 = V.node_hash(l[2], l[3])
    root = V.node_hash(n01, n23)
    proof = {"leaf_index": 0, "root": root.hex(),
             "siblings": [l[1].hex(), n23.hex()], "directions": ["right", "right"]}
    return root, proof

def bc30(merkle_root, batch_id, flags=0x00):
    # flags bit 0 = WITNESS_PRESENT (set 0x01 for the unified reveal, §2 of
    # UNIFIED-WITNESS-CONTRACT.md); advisory, not part of the commitment check.
    p = b"BC30" + bytes([0x1E, flags]) + batch_id + merkle_root + (b"\x00" * 32)
    assert len(p) == 86
    return p

def build_reveal_tx(anchor_payload):
    """Structurally-valid segwit reveal tx carrying the anchor output. Not a real
    signed tx - the verifier only needs it to parse and hash to its txid."""
    version = bytes.fromhex("02000000")
    prevout = bytes(32) + bytes.fromhex("00000000")
    vin = b"\x01" + prevout + b"\x00" + bytes.fromhex("fdffffff")
    op_script = b"\x6a\x4c" + bytes([len(anchor_payload)]) + anchor_payload
    out0 = bytes(8) + V._enc_varint(len(op_script)) + op_script
    p2tr = b"\x51\x20" + bytes([0x11] * 32)
    out1 = (9000).to_bytes(8, "little") + V._enc_varint(len(p2tr)) + p2tr
    vout = b"\x02" + out0 + out1
    witness = b"\x01\x40" + bytes(64)
    return (version + b"\x00\x01" + vin + vout + witness + bytes(4)).hex()

# ---------------- §6 unified witness inscription builders (UNIFIED-WITNESS-CONTRACT) ----------------
# A unified reveal carries BOTH the BIP-342 tapscript envelope (the PDF in the
# witness) AND an 86-byte payload(merkle_root) anchor output. The witness is malleable (NOT
# txid-committed), so the recovered body is bound to record.leaf_bytes through
# the single-leaf Merkle proof. These mirror crates/witness-envelope/src/{script,
# lib}.rs (envelope framing) but use a deterministic fake key - the verifier
# never checks the schnorr sig (it is not in the txid), only re-parses the
# envelope and re-hashes the body. See verify.py::parse_envelope.
INSC_INTERNAL_KEY = bytes([0x5B] * 32)   # deterministic x-only "internal" pubkey
INSC_LEAF_VERSION = 0xC1                  # tapscript leaf version (control-block prefix)
INSC_MAX_PUSH = 520                       # MAX_PUSH - body chunked into <=520 B pushes

def _push(data):
    """Minimal-form data push (matches Bitcoin script PUSHBYTES/PUSHDATA1/2/4)."""
    n = len(data)
    if n < 0x4C:  return bytes([n]) + data
    if n <= 0xFF: return b"\x4c" + bytes([n]) + data
    if n <= 0xFFFF: return b"\x4d" + n.to_bytes(2, "little") + data
    return b"\x4e" + n.to_bytes(4, "little") + data

def build_inscription_script(body, tag=b"bcrt", content_type=b"application/pdf",
                             internal_xonly=INSC_INTERNAL_KEY):
    """<x-only key> OP_CHECKSIG  OP_FALSE OP_IF <tag> <content_type> <body…> OP_ENDIF
    (§1.1). Body is plain-concatenated <=520 B pushes after content_type."""
    s = _push(internal_xonly) + b"\xac"          # OP_CHECKSIG
    s += b"\x00\x63"                              # OP_FALSE OP_IF
    s += _push(tag) + _push(content_type)
    for i in range(0, len(body), INSC_MAX_PUSH):
        s += _push(body[i:i + INSC_MAX_PUSH])
    s += b"\x68"                                  # OP_ENDIF
    return s

def build_witness_reveal_tx(anchor_payload, inscription_script,
                            internal_xonly=INSC_INTERNAL_KEY):
    """A unified reveal tx: script-path P2TR spend whose witness is
    [sig(64), inscription_script, control_block(33)] and whose output[0] is
    anchor output(anchor_payload). Structurally valid for the verifier (parses +
    hashes to a stable txid); the schnorr sig is a deterministic placeholder
    because the witness is not txid-committed (§4)."""
    version = bytes.fromhex("02000000")
    prevout = bytes(32) + bytes.fromhex("00000000")
    vin = b"\x01" + prevout + b"\x00" + bytes.fromhex("fdffffff")   # sequence 0xfffffffd (RBF)
    op_script = b"\x6a\x4c" + bytes([len(anchor_payload)]) + anchor_payload
    out0 = bytes(8) + V._enc_varint(len(op_script)) + op_script     # value 0 + anchor output
    p2tr = b"\x51\x20" + bytes([0x11] * 32)                          # OP_1 <32B> P2TR change
    out1 = (9000).to_bytes(8, "little") + V._enc_varint(len(p2tr)) + p2tr
    vout = b"\x02" + out0 + out1
    sig = bytes(64)                                                  # placeholder schnorr sig
    control = bytes([INSC_LEAF_VERSION]) + internal_xonly            # single-leaf control block (33 B)
    def _witem(d): return V._enc_varint(len(d)) + d
    wit = V._enc_varint(3) + _witem(sig) + _witem(inscription_script) + _witem(control)
    return (version + b"\x00\x01" + vin + vout + wit + bytes(4)).hex()


# =============================================================================
# leaf v2 / bundle v4 fixtures (docs/bundle-schema.md §2.3, §9–§11)
#
# Signing lives HERE (never in verify.py - a verifier has no business holding
# a private key). Keys come from fixed seeds, nonces are deterministic (RFC
# 6979), so `python3 fixtures/generate.py` is byte-reproducible and CI can
# `git diff --exit-code`.
# =============================================================================
import hmac
import hashlib

# ---------------- P-256 signing (RFC 6979 deterministic k) ----------------
def _int2octets(x):
    return x.to_bytes(32, "big")

def _bits2int(b):
    # qlen = hlen = 256 for P-256/SHA-256, so the leftmost 256 bits are the whole digest.
    return int.from_bytes(b[:32], "big")

def _rfc6979_k(x, h1):
    """RFC 6979 §3.2 with HMAC-SHA256, q = n (P-256). h1 = SHA256(message)."""
    q = V._P256_N
    bx = _int2octets(x) + _int2octets(_bits2int(h1) % q)     # int2octets(x) || bits2octets(h1)
    Vv, K = b"\x01" * 32, b"\x00" * 32
    K = hmac.new(K, Vv + b"\x00" + bx, hashlib.sha256).digest()
    Vv = hmac.new(K, Vv, hashlib.sha256).digest()
    K = hmac.new(K, Vv + b"\x01" + bx, hashlib.sha256).digest()
    Vv = hmac.new(K, Vv, hashlib.sha256).digest()
    while True:
        T = b""
        while len(T) < 32:
            Vv = hmac.new(K, Vv, hashlib.sha256).digest()
            T += Vv
        k = _bits2int(T)
        if 1 <= k <= q - 1:
            return k
        K = hmac.new(K, Vv + b"\x00", hashlib.sha256).digest()
        Vv = hmac.new(K, Vv, hashlib.sha256).digest()

def ecdsa_sign_der(priv, msg):
    """ECDSA P-256 over SHA-256(msg), RFC 6979 nonce, strict DER out. low-s is
    NOT normalised (the RFC vectors are not, and WebAuthn does not promise it)."""
    n = V._P256_N
    h1 = V.sha256(msg)
    e = _bits2int(h1) % n
    while True:
        k = _rfc6979_k(priv, h1)
        Rp = V._ec_mul(V._P256_G, k)
        r = Rp[0] % n
        s = pow(k, -1, n) * (e + r * priv) % n
        if r and s:
            return V.rs_to_der(r, s)
        h1 = V.sha256(h1)   # unreachable in practice; keeps the loop total

def p256_pub33(priv):
    return V.p256_compress(V._ec_mul(V._P256_G, priv))

# Pin the signer against RFC 6979 §A.2.5 (same vector verify.py --selftest pins
# for verification). A drift here would silently re-sign every fixture.
_RFC = V.RFC6979_A25
_rfc_x = int(_RFC["x"], 16)
assert _rfc6979_k(_rfc_x, V.sha256(b"sample")) == int(_RFC["sample"]["k"], 16), "RFC 6979 k drift (sample)"
assert _rfc6979_k(_rfc_x, V.sha256(b"test")) == int(_RFC["test"]["k"], 16), "RFC 6979 k drift (test)"
assert V.der_to_rs(ecdsa_sign_der(_rfc_x, b"sample")) == (int(_RFC["sample"]["r"], 16), int(_RFC["sample"]["s"], 16)), "RFC 6979 r/s drift"
assert p256_pub33(_rfc_x) == V.p256_compress((int(_RFC["Ux"], 16), int(_RFC["Uy"], 16))), "RFC 6979 pubkey drift"

# ---------------- test keys (fixed seeds - TEST ONLY, never production) ----------------
def _seed_priv(label):
    d = int.from_bytes(V.sha256(label.encode("utf-8")), "big") % V._P256_N
    assert 1 <= d < V._P256_N
    return d

ISSUER_PRIV = _seed_priv("bitcert-verifier:test:issuer:v1")
SUBJECT_PRIV = _seed_priv("bitcert-verifier:test:subject:v1")
ISSUER2_PRIV = _seed_priv("bitcert-verifier:test:issuer2:v1")
ISSUER3_PRIV = _seed_priv("bitcert-verifier:test:issuer3:v1")
ISSUER_PUB, SUBJECT_PUB = p256_pub33(ISSUER_PRIV), p256_pub33(SUBJECT_PRIV)
ISSUER2_PUB, ISSUER3_PUB = p256_pub33(ISSUER2_PRIV), p256_pub33(ISSUER3_PRIV)

ISSUER_ID = bytes.fromhex("7d1c9a3e5b2f4e0a9c8b7a6d5e4f3a2b")        # exchange uuid (16 B)
ISSUER2_ID = bytes.fromhex("11111111222233334444555566667777")
ISSUER3_ID = bytes.fromhex("aaaaaaaabbbbccccddddeeeeffff0000")
KEY_VALID_FROM = 1781000000
ISSUED_AT = 1782000000
BLOCK_TIME = 1782000600
FIXTURE_NOW = 1782000700          # the clock every CI run of a v4 fixture uses (--now)
PRESENT_EXPIRY = 1782000900
POLICY = {"document_type": "audit", "jurisdiction": "GENERIC"}
V4_DOC = b"%PDF-1.4\n1 0 obj<<>>endobj\nBC30 LEAF V2 KAT\n%%EOF\n"
V4_BATCH_ID = bytes.fromhex("0192a3b4c5d6e7f80192a3b4c5d6e7fa")
IDENTIFIER = "alice@example.com"

# ---------------- WebAuthn synthetic assertion ----------------
def build_assertion(priv, rp_id, origin, challenge, uv=True, sign_count=1):
    """authenticatorData = SHA256(rpId) ‖ flags ‖ signCount(4 BE); clientDataJSON as a
    browser emits it (compact, this key order); sig = ES256(authData ‖ SHA256(cdj))."""
    flags = 0x01 | (0x04 if uv else 0x00)
    auth_data = V.sha256(rp_id.encode("utf-8")) + bytes([flags]) + sign_count.to_bytes(4, "big")
    cdj = json.dumps({"type": "webauthn.get", "challenge": V.b64u_encode(challenge),
                      "origin": origin, "crossOrigin": False}, separators=(",", ":")).encode("utf-8")
    sig = ecdsa_sign_der(priv, auth_data + V.sha256(cdj))
    return auth_data, cdj, sig

# ---------------- RFC-6962 variant tree (merkle-batching tree.rs: duplicate-last) ----------------
def merkle_levels(leaf_inputs):
    cur = [V.leaf_hash(x) for x in leaf_inputs]
    levels = [cur]
    while len(cur) > 1:
        nxt = []
        for i in range(0, len(cur), 2):
            left = cur[i]
            right = cur[i + 1] if i + 1 < len(cur) else left
            nxt.append(V.node_hash(left, right))
        cur = nxt
        levels.append(cur)
    return levels

def merkle_proof(levels, index):
    sibs, dirs = [], []
    for level in levels[:-1]:
        if index % 2 == 0:
            sib = level[index + 1] if index + 1 < len(level) else level[index]
            dirs.append("right")
        else:
            sib = level[index - 1]
            dirs.append("left")
        sibs.append(sib.hex())
        index //= 2
    return {"leaf_index": index if not sibs else None, "root": levels[-1][0].hex(), "siblings": sibs, "directions": dirs}

def merkle_root_and_proof(leaf_inputs, index):
    lv = merkle_levels(leaf_inputs)
    p = merkle_proof(lv, index)
    p["leaf_index"] = index
    return lv[-1][0], p

# ---------------- sparse Merkle tree (merkle-batching sparse.rs, Python port) ----------------
class SMT(object):
    def __init__(self):
        self.leaves = {}
    def insert(self, key, value):
        self.leaves[key] = value
    def _bit(self, key, i):
        return (key[i // 8] >> (7 - i % 8)) & 1
    def _subtree(self, level, pairs):
        if not pairs:
            return V.SMT_DEFAULTS[level]
        if level == 0:
            assert len(pairs) == 1
            return V.smt_leaf_hash(pairs[0][0], pairs[0][1])
        bit_idx = V.SMT_HEIGHT - level
        left = [p for p in pairs if self._bit(p[0], bit_idx) == 0]
        right = [p for p in pairs if self._bit(p[0], bit_idx) == 1]
        return V.node_hash(self._subtree(level - 1, left), self._subtree(level - 1, right))
    def root(self):
        return self._subtree(V.SMT_HEIGHT, sorted(self.leaves.items()))
    def prove(self, key):
        pairs = sorted(self.leaves.items())
        siblings = []
        for level in range(V.SMT_HEIGHT, 0, -1):
            bit_idx = V.SMT_HEIGHT - level
            kb = self._bit(key, bit_idx)
            path = [p for p in pairs if self._bit(p[0], bit_idx) == kb]
            other = [p for p in pairs if self._bit(p[0], bit_idx) != kb]
            siblings.append(self._subtree(level - 1, other))
            pairs = path
        siblings.reverse()
        return {"key": key.hex(), "value": (self.leaves[key].hex() if key in self.leaves else None),
                "siblings": [s.hex() for s in siblings]}

def sl_value(revoked_at):
    return bytes(24) + revoked_at.to_bytes(8, "big")

# Two revoked records (other people's leaves) so the exclusion proof is not all-defaults.
SL_REVOKED = [(V.sha256(b"revoked-leaf-1"), 1781500000), (V.sha256(b"revoked-leaf-2"), 1781600000)]

def build_status_list(revoked=SL_REVOKED):
    smt = SMT()
    for k, t in revoked:
        smt.insert(k, sl_value(t))
    return smt

# ---------------- trust list ----------------
def tl_entry(issuer_id, pub33, valid_from=KEY_VALID_FROM, valid_to=0, revoked_at=0):
    kid = V.key_id(V.CURVE_P256, pub33)
    return {"issuer_id": issuer_id.hex(), "key_id": kid.hex(), "curve_id": V.CURVE_P256,
            "public_key": pub33.hex(), "valid_from": valid_from, "valid_to": valid_to, "revoked_at": revoked_at}

def tl_entry_bytes_of(e):
    return V.tl_entry_bytes(bytes.fromhex(e["issuer_id"]), bytes.fromhex(e["key_id"]), e["curve_id"],
                            bytes.fromhex(e["public_key"]), e["valid_from"], e["valid_to"], e["revoked_at"])

def build_trust_list(entries, want_key_id):
    """Sorted by key_id ascending; returns (tl_root, tl_proof for want_key_id, sorted entries)."""
    entries = sorted(entries, key=lambda e: e["key_id"])
    leaves = [V.tl_leaf(tl_entry_bytes_of(e)) for e in entries]
    idx = [e["key_id"] for e in entries].index(want_key_id)
    root, proof = merkle_root_and_proof(leaves, idx)
    return root, {"leaf_index": idx, "siblings": proof["siblings"], "directions": proof["directions"]}, entries

DEFAULT_TL_ENTRIES = lambda issuer_entry: [issuer_entry, tl_entry(ISSUER2_ID, ISSUER2_PUB), tl_entry(ISSUER3_ID, ISSUER3_PUB, revoked_at=1781700000)]

# ---------------- v4 bundle assembler ----------------
def assemble_v4_bundle(name, subject="none", alg="es256-plain", rp_id=V.BC30_RP_ID, origin=V.BC30_ORIGINS[0],
                       uv=True, issued_at=ISSUED_AT, expires_at=0, block_time=BLOCK_TIME, doc=V4_DOC,
                       identifier=IDENTIFIER, payload_version=V.OP_RETURN_V31_VERSION, aux_override=None,
                       issuer_entry=None, content_type="application/pdf"):
    """A complete, internally consistent v4 issuance bundle. Every derived value is
    produced by verify.py's own builders, so nothing here can drift from the
    verifier; the knobs exist only so the negative fixtures can be built
    consistently (a bad rpId, no UV, a wrong aux…) rather than by hand-editing."""
    doc_sha = V.sha256(doc)
    salt = V.sha256(("bitcert-verifier:test:salt:" + name).encode())[:16]
    if subject == "none":
        st, ref = V.SUBJECT_NONE, V.subject_ref_none()
    elif subject == "idhash":
        st, ref = V.SUBJECT_ID_HASH, V.subject_ref_id_hash(salt, identifier)
    elif subject == "pubkey":
        st, ref = V.SUBJECT_PUBKEY, V.subject_ref_pubkey(V.CURVE_P256, SUBJECT_PUB)
    else:
        raise ValueError(subject)
    ph = V.policy_hash(POLICY)
    args = (salt, doc_sha, st, ref, issued_at, expires_at, ph)
    R, m = V.record_bytes(*args), V.issue_message(*args)
    if alg == "webauthn-es256":
        ad, cdj, sig = build_assertion(ISSUER_PRIV, rp_id, origin, m, uv=uv, sign_count=7)
        s = V.issuer_sig_bytes(V.ALG_WEBAUTHN_ES256, sig, ad, cdj)
        assertion = {"authenticator_data": ad.hex(), "client_data_json": cdj.hex(), "signature_der": sig.hex()}
    elif alg == "es256-plain":
        sig = ecdsa_sign_der(ISSUER_PRIV, m)
        s = V.issuer_sig_bytes(V.ALG_ES256_PLAIN, sig)
        assertion = {"signature_der": sig.hex()}
    else:
        raise ValueError(alg)
    li = V.leaf_input_v2(V.LEAF_TYPE_ISSUANCE, R, s)
    others = [V.sha256(b"other-leaf-" + bytes([b])) for b in (1, 2, 3)]
    root, proof = merkle_root_and_proof([li] + others, 0)
    ie = issuer_entry or tl_entry(ISSUER_ID, ISSUER_PUB)
    tl_root, tl_proof, _ = build_trust_list(DEFAULT_TL_ENTRIES(ie), ie["key_id"])
    smt = build_status_list()
    sl_root, sl_proof = smt.root(), smt.prove(li)
    env = V.envelope_root_none()
    aux = V.aux_commitment(tl_root, sl_root, env)
    payload = V.bc30_v31(root, V4_BATCH_ID, aux_override or aux)
    if payload_version != V.OP_RETURN_V31_VERSION:
        payload = payload[:4] + bytes([payload_version]) + payload[5:]
    raw_tx = build_reveal_tx(payload)
    txid, _ = V.txid_from_raw(raw_tx)
    confirmed = {"block_height": 142, "block_hash": "00" * 32, "confirmations": 6}
    if block_time is not None:
        confirmed["block_time"] = block_time
    bundle = {
        "schema": "bitcert-proof-bundle/v4",
        "bitcoin_network": "regtest",
        "generated_at": "2026-06-21T00:10:00Z",
        "record": {
            "kind": "issuance",
            "leaf_bytes": li.hex(),
            "preimage": {
                "scheme": "bc30-leaf-v2", "leaf_type": V.LEAF_TYPE_ISSUANCE,
                "record_salt": salt.hex(), "doc_sha256": doc_sha.hex(),
                "subject_type": st, "subject_ref": ref.hex(),
                "issued_at": issued_at, "expires_at": expires_at,
                "policy": dict(POLICY), "policy_hash": ph.hex(),
            },
            "descriptor": {"exchange_id": "demoex", "attestation_id": "att-" + name},
        },
        "merkle": proof,
        "anchor": {
            "reveal_txid": txid, "commit_txid": "00" * 32,
            "reveal_tx_hex": raw_tx, "op_return_payload_hex": payload.hex(),
            "confirmed": confirmed,
        },
        "issuer": {
            "issuer_id": ie["issuer_id"], "key_id": ie["key_id"], "alg": alg,
            "rp_id": rp_id, "assertion": assertion,
        },
        "aux": {
            "scheme": "bc30-aux-v2",
            "tl_root": tl_root.hex(), "sl_root": sl_root.hex(), "envelope_root": env.hex(),
            "tl_entry": ie, "tl_proof": tl_proof, "sl_proof": sl_proof,
        },
    }
    # content_type is informational and OPTIONAL: a hash-only issuance (the customer
    # sent doc_sha256 and never the file) cannot state a MIME type.
    if content_type is not None:
        bundle["record"]["preimage"]["content_type"] = content_type
    if st == V.SUBJECT_PUBKEY:
        bundle["subject"] = {"curve_id": V.CURVE_P256, "public_key": SUBJECT_PUB.hex()}
    return bundle, {"leaf_input": li, "m": m, "R": R, "s": s, "salt": salt, "doc_sha": doc_sha, "aux": aux,
                    "tl_root": tl_root, "sl_root": sl_root}

# ---------------- presentation (the /present blob a recipient hands the verifier) ----------------
PRESENT_NONCE = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
PRESENT_VERIFIER_ID = V.make_verifier_id("ci-fixture", bytes.fromhex("00112233445566778899aabbccddeeff"))

def build_presentation(leaf_input, nonce=PRESENT_NONCE, verifier_id=PRESENT_VERIFIER_ID, expiry=PRESENT_EXPIRY,
                       priv=SUBJECT_PRIV, rp_id=V.BC30_RP_ID, origin=V.BC30_ORIGINS[0], uv=True):
    ch = V.present_challenge(nonce, leaf_input, verifier_id, expiry)
    ad, cdj, sig = build_assertion(priv, rp_id, origin, ch, uv=uv, sign_count=3)
    obj = {"v": 1, "scheme": "bc30-present-v1", "leaf": leaf_input.hex(), "nonce": nonce.hex(),
           "verifier_id": verifier_id.hex(), "expiry": expiry,
           "credential_id": V.b64u_encode(V.sha256(b"test-credential-id")[:16]),
           "authenticator_data": V.b64u_encode(ad), "client_data_json": V.b64u_encode(cdj),
           "signature": V.b64u_encode(sig)}
    blob = V.b64u_encode(json.dumps(obj, separators=(",", ":")).encode("utf-8"))
    return obj, blob, ch

# ---------------- KAT vectors ----------------
# fixtures/bc30-v2-vectors.json is NOT generated here. It is a byte-identical copy of
# the engine's canonical KAT, ann-core/crates/bc30-leaf/tests/vectors/bc30-v2-kat.json
# (PM decision 2026-08-25). fixtures/engine-kat-check.py re-derives every field of
# that file with verify.py's builders + this file's RFC 6979 signer and fails on any
# byte difference; verify.py --selftest and the node checks pin the same file.

def check_v2_party_sections():
    """Gate generation on the party-model v2 sections of the engine KAT copy
    (cosign / wallet / multisig / policy_open / es256_plain_alternate_s /
    negative_v2, bundle-schema.md §12). Runs the same kat_v2_party_checks()
    that verify.py --selftest runs, so the copy being stale or the primitives
    drifting aborts generation instead of silently shipping fixtures built on a
    different frozen spec. Validation ONLY - nothing is generated from these
    sections yet.

    TODO(N1): generate the bundle v5 fixtures + oracle rows here once the v5
    pipeline (runV5 / verify_v5, MUST 1-13 of bundle-schema.md §12.6) lands:
      - positives: multi-signature signers[] (issuer passkey + subject-consent
        passkey + endorser wallet, appendix C.1 composition), a 0x04 single-sig
        v5 bundle, a 0x02 high-s positive ((r, n−s) must stay VALID)
      - negatives (ALL expected exit 1): role relabel, order violation, 0x10
        nesting, non-low-s 0x04, policy grammar violations, issuer without
        tl_proof, a half tl_entry/tl_proof pair (both directions), an unknown
        signers[] field such as sl_proof
      - warning (expected exit 2): subject-consent key_id != subject_ref
    N0 deliberately freezes the primitives only; building v5 bundles now would
    invent wire bytes ahead of the frozen pipeline.
    """
    with open(os.path.join(HERE, "bc30-v2-vectors.json"), "r", encoding="utf-8") as f:
        vec = json.load(f)
    results = V.kat_v2_party_checks(vec)
    bad = [label for ok, label in results if not ok]
    assert not bad, "engine KAT v2 party sections failed:\n  " + "\n  ".join(bad)
    return len(results)

def v4_expect(rel, bundle, **kw):
    """Run verify.py's pipeline on a fixture and record the oracle row."""
    R = V.verify_v4(bundle, now=FIXTURE_NOW, **kw)
    row = {"file": rel, "now": FIXTURE_NOW}
    if kw.get("identifier") is not None: row["identifier"] = kw["identifier"]
    if kw.get("nonce_hex") is not None: row["nonce"] = kw["nonce_hex"]
    row.update(R.summary())
    return row

def legacy_expect(rel, bundle):
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        grade = V.verify_bundle(bundle)
    return {"file": rel, "legacy": True, "grade": grade, "exit_code": V.GRADE_EXIT[grade]}

def single_leaf_merkle(leaf_bytes):
    """Single-attestation Merkle section (§3): one leaf, root = H_leaf(leaf_bytes),
    empty siblings/directions. The empty-list fold IS the single-leaf check."""
    root = V.leaf_hash(leaf_bytes)
    return root, {"leaf_index": 0, "root": root.hex(), "siblings": [], "directions": []}

def assemble_unified_witness_bundle(pdf_bytes, content_type=b"application/pdf", tag=b"bcrt"):
    """Build a §5 unified witness bundle: the PDF lives in the reveal witness and
    output[0] is anchor output = 86-byte payload(merkle_root) with flags=WITNESS_PRESENT. The
    bundle carries the REQUIRED single-leaf Merkle section so the verifier binds
    the recovered witness body → leaf_bytes → merkle_root → on-chain (§4)."""
    leaf = V.sha256(pdf_bytes)                          # leaf_bytes = sha256(PDF) = sha256(witness body)
    root, merkle = single_leaf_merkle(leaf)             # root = H_leaf(leaf_bytes), single-leaf
    batch_id = bytes.fromhex("0192a3b4c5d6e7f80192a3b4c5d6e7f8")
    payload = bc30(root, batch_id, flags=0x01)          # payload(merkle_root), WITNESS_PRESENT
    script = build_inscription_script(pdf_bytes, tag=tag, content_type=content_type)
    raw_tx = build_witness_reveal_tx(payload, script)
    txid, _ = V.txid_from_raw(raw_tx)
    bundle = {
        "schema": "bitcert-proof-bundle/v1",
        "bitcoin_network": "regtest",
        "generated_at": "2026-05-29T09:00:00Z",
        "record": {
            "kind": "attestation",
            "leaf_bytes": leaf.hex(),
            "preimage": {"scheme": "sha256-file",
                         "content_type": content_type.decode("latin1")},
            "descriptor": {"note": "UNIFIED-WITNESS-CONTRACT KAT - PDF in the reveal "
                                   "witness + 86-byte payload(merkle_root) anchor output (one tx, one anchor)"},
        },
        "merkle": merkle,
        "anchor": {
            "reveal_txid": txid, "commit_txid": "00" * 32,
            "reveal_tx_hex": raw_tx, "op_return_payload_hex": payload.hex(),
            "witness_envelope": {"input_index": 0,
                                 "content_type": content_type.decode("latin1"),
                                 "protocol_tag": tag.decode("latin1")},
            "confirmed": {"block_height": 142, "block_hash": "00" * 32, "confirmations": 6},
        },
    }
    return bundle, root, leaf

def tamper_witness_body(bundle, pdf_bytes, content_type=b"application/pdf", tag=b"bcrt"):
    """Return a copy of a unified bundle whose witness body is flipped by one bit.
    The anchor output/merkle_root and the txid are UNCHANGED (the witness is malleable
    / not txid-committed, §4), so steps 1–2 still pass but step 3 (sha256(body) ==
    leaf_bytes) FAILS - the headline tamper-evidence of a witness inscription."""
    bad = bytearray(pdf_bytes); bad[-2] ^= 0x01        # flip one bit of the body
    bad_script = build_inscription_script(bytes(bad), tag=tag, content_type=content_type)
    payload = bytes.fromhex(bundle["anchor"]["op_return_payload_hex"])
    bad_raw = build_witness_reveal_tx(payload, bad_script)
    out = json.loads(jdump(bundle))
    out["anchor"]["reveal_tx_hex"] = bad_raw
    out["anchor"]["reveal_txid"], _ = V.txid_from_raw(bad_raw)   # same txid: witness not committed
    return out

def assemble_bundle(leaf0_preimage, preimage_decl, record_kind, descriptor,
                    chain=True, override_leaf_bytes=None):
    """Build a complete bundle whose leaf 0 commits `leaf0_preimage`."""
    others = [bytes([b]) * 32 for b in (0xB1, 0xC2, 0xD3)]
    root, proof = merkle4([leaf0_preimage] + others)
    batch_id = bytes.fromhex("0192a3b4c5d6e7f80192a3b4c5d6e7f8")
    payload = bc30(root, batch_id)
    raw_tx = build_reveal_tx(payload)
    txid, _ = V.txid_from_raw(raw_tx)
    bundle = {
        "schema": "bitcert-proof-bundle/v1",
        "bitcoin_network": "regtest",
        "generated_at": "2026-05-29T09:00:00Z",
        "record": {
            "kind": record_kind,
            "leaf_bytes": (override_leaf_bytes or leaf0_preimage).hex(),
            "preimage": preimage_decl,
            "descriptor": descriptor,
        },
        "merkle": proof,
        "anchor": {
            "reveal_txid": txid, "commit_txid": "00" * 32,
            "reveal_tx_hex": raw_tx, "op_return_payload_hex": payload.hex(),
            "confirmed": {"block_height": 142, "block_hash": "00" * 32, "confirmations": 6},
        },
    }
    if chain:
        e = {"exchange_id": descriptor.get("exchange_id", "demoex"), "seq": 1,
             "kind": record_kind if record_kind == "daily" else "monthly",
             "prev_entry_hash": "00" * 32, "body_hash": root.hex(),
             "business_date": descriptor.get("business_date", "2026-05-28")}
        e["payload_hash"] = V.payload_hash(e)
        bundle["chain"] = {"entry": e}
    return bundle, root

def prior_daily_entry(exchange_id, seq, business_date, body_hash, prev_entry_hash):
    """A self-consistent prior chain entry for §5 walk-back links."""
    e = {"exchange_id": exchange_id, "seq": seq, "kind": "daily",
         "prev_entry_hash": prev_entry_hash, "body_hash": body_hash,
         "business_date": business_date}
    e["payload_hash"] = V.payload_hash(e)
    return e

def assemble_daily_v2_bundle(exchange_id, business_date, recon_assets, recon_ok):
    """A v2 daily bundle: the anchor output + chain body_hash carry `day_root`
    (binds the customer-balance root AND the (a)/(b)/(c) reconciliation), and a
    `reconciliation` section ships the §6 inputs the verifier folds back in."""
    others = [bytes([b]) * 32 for b in (0xB1, 0xC2, 0xD3)]
    balances_root, proof = merkle4([DAILY_LEAF] + others)
    rc = V.recon_commitment(exchange_id, business_date, recon_ok, recon_assets)
    dr = V.day_root(exchange_id, business_date, balances_root.hex(), rc)  # the anchored value
    batch_id = bytes.fromhex("0192a3b4c5d6e7f80192a3b4c5d6e7f8")
    payload = bc30(dr, batch_id)                      # anchor output inscribes day_root, not the bare root
    raw_tx = build_reveal_tx(payload)
    txid, _ = V.txid_from_raw(raw_tx)
    e = {"exchange_id": exchange_id, "seq": 1, "kind": "daily",
         "prev_entry_hash": "00" * 32, "body_hash": dr.hex(),  # body_hash = day_root
         "business_date": business_date}
    e["payload_hash"] = V.payload_hash(e)
    bundle = {
        "schema": "bitcert-proof-bundle/v2",
        "bitcoin_network": "regtest",
        "generated_at": "2026-05-29T09:00:00Z",
        "record": {"kind": "daily", "leaf_bytes": DAILY_LEAF.hex(),
                   "preimage": daily_preimage(),
                   "descriptor": {"exchange_id": exchange_id, "business_date": business_date}},
        "merkle": proof,
        "anchor": {"reveal_txid": txid, "commit_txid": "00" * 32,
                   "reveal_tx_hex": raw_tx, "op_return_payload_hex": payload.hex(),
                   "confirmed": {"block_height": 142, "block_hash": "00" * 32, "confirmations": 6}},
        "chain": {"entry": e},
        "reconciliation": {"scheme": "day-root/v1", "reconciliation_ok": recon_ok,
                           "assets": recon_assets, "day_root": dr.hex()},
    }
    return bundle, balances_root, dr

# ---------------- scenario data ----------------
# 01 - file artifact
ARTIFACT = b"BitCert MAS Reg 18H daily attestation report (demo artifact).\n"
ART_LEAF = V.sha256(ARTIFACT)                         # leaf_bytes = SHA-256(file)

# 07 - unified witness inscription: the PINNED KAT PDF from UNIFIED-WITNESS-CONTRACT §6.
# 62 bytes; sha256 == 59db99…db54 (leaf_bytes); H_leaf == 7f19eb…e823 (merkle_root).
# Using the contract's exact bytes keeps every derived value byte-pinned.
UNIFIED_PDF = bytes.fromhex(
    "255044462d312e340a312030206f626a3c3c3e3e656e646f626a0a554e49464945442d"
    "5749544e4553532d434f4e5452414354204b41540a2525454f460a")
assert UNIFIED_PDF == b"%PDF-1.4\n1 0 obj<<>>endobj\nUNIFIED-WITNESS-CONTRACT KAT\n%%EOF\n"
# Pin the content-determined values against the contract (a drift here is wire-breaking).
assert V.sha256(UNIFIED_PDF).hex() == \
    "59db99c5c4bb5da4e7b6344c28456dc5503eaf10d18a10ec4a13ed140d1bdb54", \
    "UNIFIED KAT leaf_bytes drift vs UNIFIED-WITNESS-CONTRACT §6"
assert V.leaf_hash(V.sha256(UNIFIED_PDF)).hex() == \
    "7f19eb1cdb45026b630ba0b21deee4326e5220e5f67e9b7e675b6b5d0791e823", \
    "UNIFIED KAT merkle_root (H_leaf) drift vs UNIFIED-WITNESS-CONTRACT §6"

# 02 - daily balance with salted commitment (salt is the customer's PRIVATE secret)
ACCOUNT = "alice@demoex"
SALT_HEX = "5e" * 32  # 32-byte per-customer secret (deterministic for the fixture)
USER_COMMITMENT = V.derive_user_commitment(SALT_HEX, ACCOUNT)
DAILY_FIELDS = {"asset": "BTC", "balance_minor": "150000000", "user_commitment": USER_COMMITMENT}
DAILY_LEAF = V.sha256(DAILY_DOMAIN.encode() + V._jcs(DAILY_FIELDS))

# ---- cross-language KAT: day_root MUST match the Rust engine's pinned vectors
# (services/daily-settlement/src/domain/anchor.rs::tests::pinned_vectors). Same
# inputs → same recon_commitment + day_root, proving byte-exact agreement across
# Rust ⇄ Python ⇄ JS. A drift here is a wire-breaking change and aborts generation.
_KAT_ASSETS = [
    {"asset": "ETH", "scale": 18, "trust_required": "100", "trust_actual": "130", "residual": "30", "ok": True},
    {"asset": "BTC", "scale": 8,  "trust_required": "150", "trust_actual": "180", "residual": "30", "ok": True},
]
_KAT_BALANCES_ROOT = "d06b635ed3f5665083b6f1b4fb7137fd691ad59725ed109cf4744ba7dc41d085"
_KAT_RC = V.recon_commitment("demo-sgx", "2026-06-04", True, _KAT_ASSETS)
_KAT_DR = V.day_root("demo-sgx", "2026-06-04", _KAT_BALANCES_ROOT, _KAT_RC)
assert _KAT_RC.hex() == "01b727a88b5e76d01b7f9aaf6b26ad290405cf7819cb97e1955fadcbb6b3b67b", \
    "recon_commitment KAT drift vs Rust engine: " + _KAT_RC.hex()
assert _KAT_DR.hex() == "bf28ccbde552f18a211bfd747adc643784e95e37dd8e43d75c5fbd7ba6009916", \
    "day_root KAT drift vs Rust engine: " + _KAT_DR.hex()

# Per-asset (a)/(b)/(c) for the v2 daily example (realistic minor units).
V2_ASSETS = [
    {"asset": "BTC", "scale": 8,  "trust_required": "150000000", "trust_actual": "165000000", "residual": "15000000", "ok": True},
    {"asset": "ETH", "scale": 18, "trust_required": "5000000000000000000", "trust_actual": "5500000000000000000", "residual": "500000000000000000", "ok": True},
]

def daily_preimage():
    return {"scheme": "sha256-jcs-fields", "domain": DAILY_DOMAIN, "fields": DAILY_FIELDS,
            "commitment": {"scheme": "sha256-salt-account", "account_field": "account_id"}}

def file_preimage():
    return {"scheme": "sha256-file", "content_type": "text/plain"}

# ---------------- writers ----------------
def w(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "wb" if isinstance(data, (bytes, bytearray)) else "w"
    with open(path, mode) as f:
        f.write(data)

def jdump(obj):
    return json.dumps(obj, indent=2) + "\n"

def main():
    # party-model v2 KAT gate (validation only - see check_v2_party_sections)
    n_v2 = check_v2_party_sections()

    # ---- examples/01 - file artifact ----
    b01, _r01 = assemble_bundle(ART_LEAF, file_preimage(), "attestation",
                          {"exchange_id": "demoex", "business_date": "2026-05-28"}, chain=False)
    w(os.path.join(EX, "01-attestation-file", "bundle.json"), jdump(b01))
    w(os.path.join(EX, "01-attestation-file", "original-report.txt"), ARTIFACT)
    w(os.path.join(EX, "01-attestation-file", "expected.txt"), "VERIFIED (exit 0)\n")
    w(os.path.join(EX, "01-attestation-file", "README.md"),
      "# 01 · Attestation by file artifact (link A = `sha256-file`)\n\n"
      "`leaf_bytes = SHA-256(original-report.txt)`. The verifier hashes the file you "
      "supply and confirms it equals the anchored leaf.\n\n```bash\n"
      "python3 ../../verify-cli/verify.py bundle.json --original original-report.txt\n```\n\n"
      "Expected: every check ✓ → **VERIFIED**. Try editing `original-report.txt` by one "
      "byte and re-run: step 0 (Original binding) then FAILS - the file no longer matches "
      "what was anchored.\n")

    # ---- examples/02 - daily balance ----
    b02, root02 = assemble_bundle(DAILY_LEAF, daily_preimage(), "daily",
                          {"exchange_id": "demoex", "business_date": "2026-05-28"}, chain=True)
    w(os.path.join(EX, "02-daily-balance", "bundle.json"), jdump(b02))
    w(os.path.join(EX, "02-daily-balance", "customer-secret.txt"),
      "# Held PRIVATELY by the customer (NOT in the public bundle).\n"
      "# Simulates what the exchange/BitCert handed this customer out of band.\n"
      "account_id=%s\nsalt_hex=%s\n" % (ACCOUNT, SALT_HEX))
    w(os.path.join(EX, "02-daily-balance", "expected.txt"), "VERIFIED (exit 0)\n")
    w(os.path.join(EX, "02-daily-balance", "README.md"),
      "# 02 · Daily balance by salted commitment (link A = `sha256-jcs-fields`)\n\n"
      "`leaf_bytes = SHA-256(\"attest:daily:leaf\\n\" || JCS({asset, balance_minor, "
      "user_commitment}))`, and `user_commitment = SHA-256(salt || account_id)`.\n\n"
      "The salt is the **customer's private secret** - it is deliberately NOT in the "
      "public bundle (otherwise anyone could de-anonymize accounts). It lives in "
      "`customer-secret.txt` here to simulate what the customer holds.\n\n"
      "Self-consistency only (no secret needed) - proves the leaf is the hash of the "
      "shown fields:\n```bash\npython3 ../../verify-cli/verify.py bundle.json\n```\n\n"
      "Full identity binding - proves the leaf is *your* row, privately:\n```bash\n"
      "python3 ../../verify-cli/verify.py bundle.json --account %s --salt %s\n```\n\n"
      "Expected: **VERIFIED**, with step 0 reporting `identity … match`. A wrong "
      "`--account`/`--salt` makes the identity check MISMATCH.\n" % (ACCOUNT, SALT_HEX))

    # ---- examples/03 - tampered original (same bundle as 01, swapped file) ----
    w(os.path.join(EX, "03-tampered-original", "bundle.json"), jdump(b01))
    w(os.path.join(EX, "03-tampered-original", "tampered-report.txt"),
      ARTIFACT.replace(b"150000000", b"999999999") if b"150000000" in ARTIFACT
      else ARTIFACT[:-1] + b" [ALTERED]\n")
    w(os.path.join(EX, "03-tampered-original", "expected.txt"), "FAILED (exit 1)\n")
    w(os.path.join(EX, "03-tampered-original", "README.md"),
      "# 03 · Tampered original is caught (link A)\n\n"
      "Same anchored bundle as example 01, but the original file was altered. Links "
      "B/C (Merkle + Bitcoin) still pass - the anchor is real - yet the document no "
      "longer hashes to the anchored leaf, so step 0 FAILS.\n\n```bash\n"
      "python3 ../../verify-cli/verify.py bundle.json --original tampered-report.txt\n```\n\n"
      "Expected: step 0 ✗ → **VERIFICATION FAILED** (exit 1). This is link A doing its "
      "job: proving the *content* you hold is the one that was anchored.\n")

    # ---- examples/04 - tampered chain (link D / §5 must catch it) ----
    # Same anchored daily bundle as 02, but the per-exchange chain entry's
    # payload_hash was forged. Links A/B/C still pass, yet the chain entry no
    # longer recomputes - so §5 (now gating) FAILS the bundle.
    b04 = json.loads(jdump(b02))
    b04["chain"]["entry"]["payload_hash"] = "ff" * 32
    w(os.path.join(EX, "04-tampered-chain", "bundle.json"), jdump(b04))
    w(os.path.join(EX, "04-tampered-chain", "expected.txt"), "FAILED (exit 1)\n")
    w(os.path.join(EX, "04-tampered-chain", "README.md"),
      "# 04 · Tampered per-exchange chain is caught (link D · §5)\n\n"
      "Same anchored daily bundle as example 02, but the chain entry's "
      "`payload_hash` was forged. Links A/B/C (preimage + Merkle + Bitcoin) all "
      "still pass - the day's Merkle root really is anchored - yet the §5 chain "
      "entry no longer recomputes from its preimage, so step 4 FAILS.\n\n"
      "`payload_hash = SHA-256(\"bitcert:chain:v1\\n\" || JCS(entry_core))` - the "
      "verifier recomputes it and also checks `body_hash == merkle.root` for a "
      "daily entry. Both are cryptographic and gate the verdict.\n\n```bash\n"
      "python3 ../../verify-cli/verify.py bundle.json\n```\n\n"
      "Expected: step 4 ✗ → **VERIFICATION FAILED** (exit 1).\n")

    # ---- examples/05 - daily chain walk-back (§5 continuity / links) ----
    # A two-day chain: yesterday (seq 1, genesis prev=zeros) → today (seq 2),
    # where today.prev_entry_hash == payload_hash(yesterday). today's body_hash
    # carries the same Merkle root as 02 (so links B/C stay valid), and the prior
    # entry rides along in chain.links so the verifier can walk the linkage.
    b05 = json.loads(jdump(b02))
    y4 = prior_daily_entry("demoex", 1, "2026-05-27", "be" * 32, "00" * 32)
    today = {"exchange_id": "demoex", "seq": 2, "kind": "daily",
             "prev_entry_hash": y4["payload_hash"], "body_hash": root02.hex(),
             "business_date": "2026-05-28"}
    today["payload_hash"] = V.payload_hash(today)
    b05["chain"] = {"entry": today, "links": [y4]}
    w(os.path.join(EX, "05-daily-chain-walkback", "bundle.json"), jdump(b05))
    w(os.path.join(EX, "05-daily-chain-walkback", "customer-secret.txt"),
      "# Held PRIVATELY by the customer (NOT in the public bundle).\n"
      "account_id=%s\nsalt_hex=%s\n" % (ACCOUNT, SALT_HEX))
    w(os.path.join(EX, "05-daily-chain-walkback", "expected.txt"), "VERIFIED (exit 0)\n")
    w(os.path.join(EX, "05-daily-chain-walkback", "README.md"),
      "# 05 · Daily chain walk-back (§5 continuity via `chain.links`)\n\n"
      "A two-day per-exchange chain. The head entry is today (seq 2); yesterday "
      "(seq 1) rides along in `chain.links`. The verifier confirms each prior "
      "entry recomputes its own `payload_hash` and that "
      "`today.prev_entry_hash == payload_hash(yesterday)` - the tamper-evident "
      "hash linkage that makes a per-exchange chain auditable.\n\n```bash\n"
      "python3 ../../verify-cli/verify.py bundle.json --account %s --salt %s\n```\n\n"
      "Expected: every check ✓ → **VERIFIED**, with step 4 reporting `walked 1 "
      "prior entry + head: hash-linkage holds`. Flip any byte of the linked "
      "entry and step 4 FAILS.\n" % (ACCOUNT, SALT_HEX))

    # ---- examples/06 - daily day_root (v2: the anchor commits the reconciliation) ----
    b06, _root06, _dr06 = assemble_daily_v2_bundle("demoex", "2026-05-28", V2_ASSETS, True)
    w(os.path.join(EX, "06-daily-day-root", "bundle.json"), jdump(b06))
    w(os.path.join(EX, "06-daily-day-root", "customer-secret.txt"),
      "# Held PRIVATELY by the customer (NOT in the public bundle).\n"
      "account_id=%s\nsalt_hex=%s\n" % (ACCOUNT, SALT_HEX))
    w(os.path.join(EX, "06-daily-day-root", "expected.txt"), "VERIFIED (exit 0)\n")
    w(os.path.join(EX, "06-daily-day-root", "README.md"),
      "# 06 · Daily day_root (v2 - the anchor commits the trust reconciliation)\n\n"
      "A **v2** daily bundle. The anchor output no longer carries the bare customer-balance "
      "Merkle root - it carries `day_root`:\n\n```\n"
      "recon_commitment = SHA256(\"attest:daily:recon\\n\"  || JCS{assets_hash, business_date, exchange_id, reconciliation_ok})\n"
      "day_root         = SHA256(\"attest:daily:anchor\\n\" || JCS{balances_root, business_date, exchange_id, recon_commitment})\n```\n\n"
      "So one Bitcoin anchor attests BOTH the customer liabilities (the Merkle root) "
      "AND the (a)/(b)/(c) trust reconciliation. The verifier recomputes `day_root` from "
      "the `reconciliation` section + the Merkle root and asserts it equals the anchor output "
      "(§4) and the chain `body_hash` (§5).\n\n```bash\n"
      "python3 ../../verify-cli/verify.py bundle.json --account %s --salt %s\n```\n\n"
      "Expected: every check ✓ → **VERIFIED**, with step 6 listing the per-asset "
      "(a)/(b)/(c). NOTE: the (a) reserve side is exchange-supplied, not independently "
      "measured. Flip any residual and step 2 (anchor output ≠ recomputed day_root) FAILS.\n"
      % (ACCOUNT, SALT_HEX))

    # ---- examples/07 - unified witness inscription (PDF in witness + 86-byte anchor output) ----
    # One reveal tx that is simultaneously the standard anchor (anchor output =
    # payload(merkle_root)) AND the witness carrier (the PDF inscribed in a BIP-342
    # tapscript envelope). The recovered witness body binds to leaf_bytes, which
    # binds to merkle_root via the single-leaf proof, which is the on-chain root.
    b07, _root07, _leaf07 = assemble_unified_witness_bundle(UNIFIED_PDF)
    w(os.path.join(EX, "07-witness-unified", "bundle.json"), jdump(b07))
    # The exact KAT PDF bytes ship alongside so a reader can re-hash them by hand;
    # the verifier does NOT need this file (the PDF is recovered from the witness).
    w(os.path.join(EX, "07-witness-unified", "original.pdf"), UNIFIED_PDF)
    w(os.path.join(EX, "07-witness-unified", "expected.txt"), "VERIFIED (exit 0)\n")
    w(os.path.join(EX, "07-witness-unified", "README.md"),
      "# 07 · Unified witness inscription (PDF in the witness + `payload(merkle_root)` anchor output)\n\n"
      "One Bitcoin reveal transaction that is **both** the standard Merkle anchor "
      "**and** the witness carrier - replacing the old two-tx (anchor + inscription) "
      "flow for single-mode audit anchors. See `docs/UNIFIED-WITNESS-CONTRACT.md`.\n\n"
      "- `output[0]` = `anchor output(payload(merkle_root))` - **not** `leaf_bytes` (the whole change).\n"
      "- `witness[1]` = the BIP-342 tapscript envelope carrying the audit PDF.\n"
      "- `merkle` = a single-leaf section (`leaf_index 0`, `siblings []`, "
      "`root = H_leaf(leaf_bytes)`).\n\n"
      "The verifier recovers the PDF straight from the witness and binds it through the "
      "chain `body → leaf_bytes → merkle_root → anchor output → txid`:\n\n```bash\n"
      "python3 ../../verify-cli/verify.py bundle.json\n```\n\n"
      "Expected: every check ✓ → **VERIFIED** (no off-bundle file needed - the document "
      "IS on Bitcoin). `original.pdf` ships only so you can re-hash the 62 KAT bytes "
      "yourself: `sha256(original.pdf) == record.leaf_bytes`.\n\n"
      "Because the witness is **malleable** (not committed to the txid), a tampered "
      "witness body leaves the txid and anchor output intact (steps 1–2 still pass) but "
      "fails step 3 (`sha256(body) ≠ leaf_bytes`) - see "
      "`../08-tampered-witness/` and `fixtures/07-witness-unified.tampered.json`.\n")

    # ---- examples/08 - tampered unified witness body (must REJECT) ----
    b08 = tamper_witness_body(b07, UNIFIED_PDF)
    w(os.path.join(EX, "08-tampered-witness", "bundle.json"), jdump(b08))
    w(os.path.join(EX, "08-tampered-witness", "expected.txt"), "FAILED (exit 1)\n")
    w(os.path.join(EX, "08-tampered-witness", "README.md"),
      "# 08 · Tampered unified witness body is caught (step 3)\n\n"
      "Same unified bundle as example 07, but one bit of the **witness body** (the "
      "inscribed PDF) was flipped. The witness is NOT committed to the txid, so the "
      "`reveal_txid` and the `payload(merkle_root)` anchor output are unchanged - steps 1 "
      "(txid binding) and 2 (record binds to the on-chain merkle_root) still pass. "
      "But the recovered body no longer hashes to `record.leaf_bytes`, so step 3 "
      "FAILS.\n\n```bash\n"
      "python3 ../../verify-cli/verify.py bundle.json\n```\n\n"
      "Expected: step 3 ✗ → **VERIFICATION FAILED** (exit 1). This is the headline "
      "tamper-evidence of a witness inscription: the document is bound to a "
      "txid-committed value (`leaf_bytes` via the Merkle proof), so the malleable "
      "witness cannot be altered without detection.\n")

    # ================= bundle v4 - identity-bound issuance (schema §2.3, §9–§12) =================
    V4 = os.path.join(HERE, "v4")
    expected = []

    def wv4(rel, bundle):
        w(os.path.join(HERE, rel), jdump(bundle))

    b_none, d_none = assemble_v4_bundle("valid-none", subject="none", alg="es256-plain")
    b_id, d_id = assemble_v4_bundle("valid-idhash", subject="idhash", alg="webauthn-es256")
    b_pk, d_pk = assemble_v4_bundle("valid-pubkey", subject="pubkey", alg="webauthn-es256")
    # hash-only issuance: the customer sent only doc_sha256, so the bundle states no file type
    b_ho, _d_ho = assemble_v4_bundle("valid-hash-only", subject="idhash", alg="es256-plain", content_type=None)
    pres_obj, pres_blob, _ch = build_presentation(d_pk["leaf_input"])
    wv4("v4/valid-none.json", b_none)
    wv4("v4/valid-idhash.json", b_id)
    wv4("v4/valid-pubkey.json", b_pk)
    wv4("v4/valid-hash-only.json", b_ho)
    w(os.path.join(V4, "valid-pubkey.presentation.txt"), pres_blob + "\n")
    w(os.path.join(V4, "valid-pubkey.presentation.json"), jdump(pres_obj))
    expected.append(v4_expect("v4/valid-none.json", b_none))
    assert "content_type" not in b_ho["record"]["preimage"], "hash-only fixture must not state a file type"
    expected.append(v4_expect("v4/valid-hash-only.json", b_ho))
    expected.append(v4_expect("v4/valid-hash-only.json", b_ho, identifier=IDENTIFIER))
    expected.append(v4_expect("v4/valid-idhash.json", b_id))
    expected.append(v4_expect("v4/valid-idhash.json", b_id, identifier=IDENTIFIER))
    expected.append(v4_expect("v4/valid-idhash.json", b_id, identifier="mallory@example.com"))
    expected.append(v4_expect("v4/valid-pubkey.json", b_pk))
    row = v4_expect("v4/valid-pubkey.json", b_pk, presentation=pres_obj, nonce_hex=PRESENT_NONCE.hex())
    row["presentation"] = "v4/valid-pubkey.presentation.txt"; expected.append(row)
    row = v4_expect("v4/valid-pubkey.json", b_pk, presentation=pres_obj)          # nonce not ours → warning
    row["presentation"] = "v4/valid-pubkey.presentation.txt"; expected.append(row)

    # negatives - each built CONSISTENTLY so exactly the intended step trips.
    b_tsig = json.loads(jdump(b_id))
    sig = bytearray(bytes.fromhex(b_tsig["issuer"]["assertion"]["signature_der"])); sig[10] ^= 0x01
    b_tsig["issuer"]["assertion"]["signature_der"] = bytes(sig).hex()
    b_tref = json.loads(jdump(b_pk)); b_tref["record"]["preimage"]["subject_ref"] = "ff" * 32
    b_swap = json.loads(jdump(b_id)); b_swap["record"]["preimage"]["subject_type"] = 0
    b_rpid, _ = assemble_v4_bundle("bad-rpid", subject="none", alg="webauthn-es256", rp_id="evil.example.com", origin="https://evil.example.com")
    b_nouv, _ = assemble_v4_bundle("no-uv", subject="none", alg="webauthn-es256", uv=False)
    b_exp, _ = assemble_v4_bundle("expired", subject="none", alg="es256-plain", expires_at=1782000500)
    b_aux, _ = assemble_v4_bundle("aux-mismatch", subject="none", alg="es256-plain", aux_override=V.sha256(b"wrong-aux"))
    b_nobt, _ = assemble_v4_bundle("no-blocktime", subject="none", alg="es256-plain", block_time=None)
    b_v30, _ = assemble_v4_bundle("legacy-0x1e", subject="none", alg="es256-plain", payload_version=0x1E)
    b_mtl = json.loads(jdump(b_none)); b_mtl["aux"]["tl_entry"]["valid_from"] = None   # malformed tl_entry → schema rejects, never a traceback
    for rel, b in (("v4/tampered-issuer-sig.json", b_tsig), ("v4/tampered-subject-ref.json", b_tref),
                   ("v4/type-swap.json", b_swap), ("v4/bad-rpid.json", b_rpid), ("v4/no-uv.json", b_nouv),
                   ("v4/expired.json", b_exp), ("v4/aux-mismatch.json", b_aux), ("v4/no-blocktime.json", b_nobt),
                   ("v4/legacy-0x1e.json", b_v30), ("v4/malformed-tl-entry.json", b_mtl)):
        wv4(rel, b); expected.append(v4_expect(rel, b))

    # §4.1 compatibility rule for LEGACY bundles riding on a v31 anchor: unbound
    # (bit 1 clear + AUX_COMMITMENT_NONE) passes as today; bound needs v4.
    def rebase_payload(bundle, payload):
        out = json.loads(jdump(bundle))
        raw = build_reveal_tx(payload)
        out["anchor"]["op_return_payload_hex"] = payload.hex()
        out["anchor"]["reveal_tx_hex"] = raw
        out["anchor"]["reveal_txid"], _ = V.txid_from_raw(raw)
        return out
    b_l31 = rebase_payload(b02, V.bc30_v31(root02, bytes.fromhex("0192a3b4c5d6e7f80192a3b4c5d6e7f8"), V.AUX_COMMITMENT_NONE, flags=0))
    b_l31b = rebase_payload(b02, V.bc30_v31(root02, bytes.fromhex("0192a3b4c5d6e7f80192a3b4c5d6e7f8"), V.AUX_COMMITMENT_NONE, flags=V.FLAG_IDENTITY_BOUND))
    b_l31x = rebase_payload(b02, V.bc30_v31(root02, bytes.fromhex("0192a3b4c5d6e7f80192a3b4c5d6e7f8"), bytes(32), flags=0))
    wv4("v4/legacy-v31-unbound.valid.json", b_l31)
    wv4("v4/legacy-v31-bound.rejected.json", b_l31b)
    wv4("v4/legacy-v31-aux-zero.rejected.json", b_l31x)
    expected.append(legacy_expect("v4/legacy-v31-unbound.valid.json", b_l31))
    expected.append(legacy_expect("v4/legacy-v31-bound.rejected.json", b_l31b))
    expected.append(legacy_expect("v4/legacy-v31-aux-zero.rejected.json", b_l31x))
    assert [r["exit_code"] for r in expected[-3:]] == [0, 1, 1], "legacy v31 compatibility rule drifted"

    # sanity: the oracle must say what the scenarios promise
    want = {"v4/valid-none.json": 0, "v4/valid-hash-only.json": 0, "v4/tampered-issuer-sig.json": 1, "v4/tampered-subject-ref.json": 1,
            "v4/type-swap.json": 1, "v4/bad-rpid.json": 1, "v4/no-uv.json": 1, "v4/expired.json": 2,
            "v4/aux-mismatch.json": 1, "v4/no-blocktime.json": 3, "v4/legacy-0x1e.json": 1, "v4/malformed-tl-entry.json": 1}
    for r in expected:
        if r["file"] in want and "identifier" not in r and "presentation" not in r:
            assert r["exit_code"] == want[r["file"]], "%s: exit %d, expected %d" % (r["file"], r["exit_code"], want[r["file"]])
    assert [r["exit_code"] for r in expected if r["file"] == "v4/valid-idhash.json"] == [0, 0, 1]
    assert [r["exit_code"] for r in expected if r["file"] == "v4/valid-pubkey.json"] == [0, 0, 2]
    assert [r["axes"]["presenter"] for r in expected if r.get("presentation")] == ["confirmed", "not available"]
    w(os.path.join(HERE, "v4-expected.json"), jdump({
        "_comment": "Oracle produced by verify.py (fixtures/generate.py). Rows: file (+identifier/presentation/nonce, now) → "
                    "grade, exit_code, axes, per-step state. fixtures/v4-grade-check.mjs must reproduce every row from index.html's runV4; "
                    "fixtures/v4-rc-matrix.py re-runs the CLI and asserts exit codes.",
        "rows": expected}))

    # ---- examples 09–14 ----
    def ex(name, bundle, expected_txt, readme, extra=None):
        d = os.path.join(EX, name)
        w(os.path.join(d, "bundle.json"), jdump(bundle))
        w(os.path.join(d, "expected.txt"), expected_txt)
        w(os.path.join(d, "README.md"), readme)
        for fn, data in (extra or {}).items():
            w(os.path.join(d, fn), data)
    ex("09-issuance-plain", b_none, "VALID (exit 0)\n",
       "# 09 · Identity-bound issuance, `es256-plain` issuer key (bundle v4)\n\n"
       "The Merkle leaf is no longer the bare document hash. It is `leaf_input = SHA256(leaf-v2 tag ‖ 0x01 ‖ R ‖ s)`, "
       "where `R` is the 143-byte record (salt, `doc_sha256`, subject, times, `policy_hash`) and `s` is the **issuer's "
       "ES256 signature** over `m = SHA256(issue-v2 tag ‖ …)` (the domain tags are listed in docs/bundle-schema.md §2.3). "
       "The issuer key is proven to be in the anchored trust list "
       "(`aux.tl_proof` → `tl_root` → `aux_commitment` on-chain), and an exclusion proof against `sl_root` shows the record "
       "was not revoked when anchored.\n\n```bash\npython3 ../../verify-cli/verify.py bundle.json --now %d\n```\n\n"
       "Expected: **VALID** (exit 0). `--now` pins the clock so the expiry check is reproducible; omit it in real use. "
       "This record has no subject (`subject_type 0`), so attribution is `none` and there is no presenter check.\n" % FIXTURE_NOW)
    ex("10-issuance-passkey", b_id, "VALID (exit 0)\n",
       "# 10 · Passkey (WebAuthn) issuer signature + salted recipient identifier\n\n"
       "The issuer signed with a **passkey**: `s` carries the WebAuthn `authenticatorData`, `clientDataJSON` and DER "
       "signature. The verifier checks `type == webauthn.get`, that the challenge decodes to `m`, the origin, "
       "`rpIdHash == SHA256(\"console.bitcert.io\")` (pinned - the bundle's `rp_id` is only a claim), the UP/UV flags and "
       "the ES256 signature over `authData ‖ SHA256(clientDataJSON)`.\n\n"
       "The recipient is named by a **salted identifier**: `subject_ref = SHA256(record_salt ‖ identifier)`. The identifier "
       "itself is not in the bundle; whoever presents it must know it.\n\n```bash\n"
       "python3 ../../verify-cli/verify.py bundle.json --identifier %s --now %d   # VALID, attribution ✓\n"
       "python3 ../../verify-cli/verify.py bundle.json --identifier mallory@example.com --now %d  # REJECTED (exit 1)\n"
       "python3 ../../verify-cli/verify.py bundle.json --now %d                     # VALID, identifier not checked\n```\n\n"
       "Expected: **VALID** with `attribution: issuer-claim · identifier ✓` when the right identifier is supplied.\n"
       % (IDENTIFIER, FIXTURE_NOW, FIXTURE_NOW, FIXTURE_NOW))
    ex("11-issuance-presentation", b_pk, "VALID (exit 0) - presenter confirmed\n",
       "# 11 · Registered recipient key + presenter check (`/present` blob)\n\n"
       "`subject_type 2`: the record is bound to the recipient's **passkey public key** "
       "(`subject_ref = SHA256(0x02 ‖ curve ‖ pubkey)`; the key itself rides in `subject.public_key`). A verifier can "
       "therefore ask the person in front of them to prove they hold that key:\n\n"
       "1. The verifier generates a `nonce`, an `expiry` and a `verifier_id` (offline - no BitCert API) and builds the link "
       "`https://<console>/present?v=1&leaf=…&nonce=…&vid=…&exp=…` (`--present-url`).\n"
       "2. The recipient opens it on the console origin and signs "
       "`challenge = SHA256(present-v1 tag ‖ nonce ‖ leaf_input ‖ verifier_id ‖ expiry)` with their passkey.\n"
       "3. The page hands back a **blob** (base64url JSON - `presentation.txt` here) which the verifier checks offline: "
       "signature under `subject.public_key`, rpId/origin/UV, expiry, and that the nonce is **its own**.\n\n"
       "`verifier-secret.txt` simulates what the verifier generated in step 1.\n\n```bash\n"
       "python3 ../../verify-cli/verify.py bundle.json --present presentation.txt --nonce %s --now %d   # VALID · presenter: confirmed\n"
       "python3 ../../verify-cli/verify.py bundle.json --present presentation.txt --now %d            # exit 2: nonce ownership not shown\n"
       "python3 ../../verify-cli/verify.py bundle.json --now %d                                       # VALID · presenter: not available\n```\n\n"
       "A missing or failed presentation **degrades** the verdict (`presenter: not available`) - it never rejects, so a "
       "lost phone does not invalidate past issuances.\n" % (PRESENT_NONCE.hex(), FIXTURE_NOW, FIXTURE_NOW, FIXTURE_NOW),
       {"presentation.txt": pres_blob + "\n",
        "verifier-secret.txt": "# Generated by the VERIFIER (offline) before handing over the /present link.\n"
                               "nonce=%s\nverifier_id=%s\nexpiry=%d\nchallenge=%s\n" % (PRESENT_NONCE.hex(), PRESENT_VERIFIER_ID.hex(), PRESENT_EXPIRY, _ch.hex())})
    ex("12-tampered-issuer-sig", b_tsig, "REJECTED (exit 1)\n",
       "# 12 · Tampered issuer signature is caught\n\n"
       "Same bundle as example 10 with **one byte of the DER signature flipped**. The Merkle proof, anchor and trust list "
       "are untouched, but step 5 (ES256 under the trust-list key) fails - and because `s` is part of `leaf_input`, step 6 "
       "fails too: the anchored leaf was computed over the genuine signature.\n\n```bash\n"
       "python3 ../../verify-cli/verify.py bundle.json --now %d\n```\n\nExpected: **REJECTED** (exit 1).\n" % FIXTURE_NOW)
    ex("13-expired-document", b_exp, "WARNING (exit 2)\n",
       "# 13 · Expired document → warning, not rejection\n\n"
       "`expires_at` is in the past relative to `--now`. Every cryptographic check passes - the anchor, signature and "
       "trust list are genuine - so the verdict is **VALID WITH WARNINGS** (exit 2). Whether an expired document is "
       "acceptable is the verifier's policy, not the mathematics.\n\n```bash\n"
       "python3 ../../verify-cli/verify.py bundle.json --now %d\n```\n\nExpected: step 14 `!` → exit 2.\n" % FIXTURE_NOW)
    ex("14-aux-mismatch", b_aux, "REJECTED (exit 1)\n",
       "# 14 · aux_commitment mismatch is caught\n\n"
       "The on-chain `aux_commitment` (bytes 54..86 of the v31 payload) was produced from a different trust list / "
       "status list than the one the bundle carries. Steps 9 (trust-list inclusion) and 15 (revocation exclusion) verify "
       "against the bundle's own roots, but step 11 recomputes `SHA256(aux tag ‖ tl_root ‖ sl_root ‖ envelope_root)` "
       "and finds it is **not** what Bitcoin committed - so the roots are unproven and the bundle is rejected.\n\n"
       "```bash\npython3 ../../verify-cli/verify.py bundle.json --now %d\n```\n\nExpected: step 11 ✗ → **REJECTED** (exit 1).\n" % FIXTURE_NOW)

    # ---- examples/run.sh ----
    run = """#!/usr/bin/env bash
# Runs every example through the offline verifier and asserts the expected result.
set -u
cd "$(dirname "$0")"
CLI="python3 ../verify-cli/verify.py"
fail=0
check () { # $1=label  $2=expected_rc  shift 2 = command
  local label="$1" want="$2"; shift 2
  "$@" >/tmp/bv.out 2>&1; local rc=$?
  if [ "$rc" = "$want" ]; then echo "PASS  $label (rc=$rc)";
  else echo "FAIL  $label (rc=$rc, want $want)"; cat /tmp/bv.out; fail=1; fi
}

echo "== 01 attestation-file (link A: hash the original) =="
check "01 with original"      0 $CLI 01-attestation-file/bundle.json --original 01-attestation-file/original-report.txt
echo "== 02 daily-balance (link A: salted commitment) =="
check "02 self-consistency"   0 $CLI 02-daily-balance/bundle.json
check "02 identity binding"   0 $CLI 02-daily-balance/bundle.json --account alice@demoex --salt %s
echo "== 03 tampered-original (link A must catch it) =="
check "03 tampered original"  1 $CLI 03-tampered-original/bundle.json --original 03-tampered-original/tampered-report.txt
echo "== 04 tampered-chain (link D / §5 must catch it) =="
check "04 tampered chain"     1 $CLI 04-tampered-chain/bundle.json
echo "== 05 daily-chain-walkback (§5 continuity via chain.links) =="
check "05 chain walk-back"    0 $CLI 05-daily-chain-walkback/bundle.json --account alice@demoex --salt %s
echo "== 06 daily day_root (v2: anchor commits the reconciliation) =="
check "06 day_root v2"        0 $CLI 06-daily-day-root/bundle.json --account alice@demoex --salt %s
echo "== 07 witness-unified (PDF in witness + 86-byte anchor output, merkle-bind) =="
check "07 witness unified"    0 $CLI 07-witness-unified/bundle.json
echo "== 08 tampered-witness (malleable body must be caught at step 3) =="
check "08 tampered witness"   1 $CLI 08-tampered-witness/bundle.json

# ---- bundle v4 (identity-bound issuance) - exit 0 valid / 1 rejected / 2 warning / 3 undetermined ----
NOW=%s   # fixed clock so the expiry checks are reproducible
echo "== 09 issuance-plain (es256-plain issuer key, no subject) =="
check "09 issuance plain"      0 $CLI 09-issuance-plain/bundle.json --now $NOW
echo "== 10 issuance-passkey (webauthn-es256 issuer + salted identifier) =="
check "10 identifier matches"  0 $CLI 10-issuance-passkey/bundle.json --identifier %s --now $NOW
check "10 wrong identifier"    1 $CLI 10-issuance-passkey/bundle.json --identifier mallory@example.com --now $NOW
check "10 no identifier"       0 $CLI 10-issuance-passkey/bundle.json --now $NOW
echo "== 11 issuance-presentation (registered recipient key + /present blob) =="
check "11 presenter confirmed" 0 $CLI 11-issuance-presentation/bundle.json --present 11-issuance-presentation/presentation.txt --nonce %s --now $NOW
check "11 nonce not ours"      2 $CLI 11-issuance-presentation/bundle.json --present 11-issuance-presentation/presentation.txt --now $NOW
check "11 no presentation"     0 $CLI 11-issuance-presentation/bundle.json --now $NOW
echo "== 12 tampered-issuer-sig (one byte of the DER signature flipped) =="
check "12 tampered issuer sig" 1 $CLI 12-tampered-issuer-sig/bundle.json --now $NOW
echo "== 13 expired-document (expires_at in the past: warning, exit 2) =="
check "13 expired"             2 $CLI 13-expired-document/bundle.json --now $NOW
echo "== 14 aux-mismatch (on-chain aux_commitment differs from the recomputed one) =="
check "14 aux mismatch"        1 $CLI 14-aux-mismatch/bundle.json --now $NOW

echo; [ "$fail" = 0 ] && echo "ALL EXAMPLES OK" || { echo "SOME EXAMPLES FAILED"; exit 1; }
""" % (SALT_HEX, SALT_HEX, SALT_HEX, FIXTURE_NOW, IDENTIFIER, PRESENT_NONCE.hex())
    run_path = os.path.join(EX, "run.sh")
    w(run_path, run)
    os.chmod(run_path, 0o755)

    # ---- fixtures for CI cross-checks ----
    w(os.path.join(HERE, "sample-bundle.valid.json"), jdump(b02))           # daily, jcs preimage
    tampered = json.loads(jdump(b02)); tampered["record"]["leaf_bytes"] = "ff" * 32
    w(os.path.join(HERE, "sample-bundle.tampered.json"), jdump(tampered))
    # forged §5 chain entry: links A/B/C pass, chain payload_hash does not recompute
    tampered_chain = json.loads(jdump(b02)); tampered_chain["chain"]["entry"]["payload_hash"] = "ff" * 32
    w(os.path.join(HERE, "sample-bundle.tampered-chain.json"), jdump(tampered_chain))
    # v2 day_root fixtures (CI cross-check).
    w(os.path.join(HERE, "sample-bundle.daily-v2.valid.json"), jdump(b06))     # anchor output == day_root
    # tampered reconciliation: bump a residual → recomputed day_root ≠ anchor output → §4.1 FAILS.
    tampered_recon = json.loads(jdump(b06)); tampered_recon["reconciliation"]["assets"][0]["residual"] = "999"
    w(os.path.join(HERE, "sample-bundle.tampered-recon.json"), jdump(tampered_recon))
    # unified witness fixtures (UNIFIED-WITNESS-CONTRACT §6 KAT). 07 = the pinned
    # unified bundle (PDF in witness, anchor output = payload(merkle_root), single-leaf
    # merkle). Its tampered twin flips one witness-body bit: txid + anchor output are
    # unchanged (witness is malleable), so step 3 (sha256(body) == leaf_bytes) FAILS.
    w(os.path.join(HERE, "07-witness-unified.json"), jdump(b07))
    w(os.path.join(HERE, "07-witness-unified.tampered.json"), jdump(b08))

    # index.html is NOT touched here (the in-page sample loaders were removed); the
    # reproducibility gate still diffs it so an accidental write would be caught.

    print("generated fixtures + examples/. daily leaf:", DAILY_LEAF.hex())
    print("  KAT day_root:", _KAT_DR.hex(), "| v2 day_root(06):", _dr06.hex())
    print("  file-artifact leaf:", ART_LEAF.hex(), "| reveal_txid(02):", b02["anchor"]["reveal_txid"])
    print("  unified KAT(07): leaf=%s merkle_root=%s" % (_leaf07.hex(), _root07.hex()))
    print("                   reveal_txid(07)=%s" % b07["anchor"]["reveal_txid"])
    print("  v4: leaf_input(none)=%s" % d_none["leaf_input"].hex())
    print("      leaf_input(pubkey)=%s aux=%s" % (d_pk["leaf_input"].hex(), d_pk["aux"].hex()))
    print("      oracle rows: %d (fixtures/v4-expected.json); KAT file is the engine copy, not regenerated" % len(expected))
    print("  v2 party sections: %d KAT checks green (cosign/wallet/multisig/policy/negatives; v5 fixtures are N1)" % n_v2)

if __name__ == "__main__":
    main()
