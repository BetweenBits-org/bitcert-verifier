#!/usr/bin/env python3
"""Generate internally-consistent proof-bundle fixtures AND runnable examples.

Reuses verify.py's hashing/parsing so everything is guaranteed to match what the
verifier checks (no hand-typed hashes that can drift). Produces:

  fixtures/sample-bundle.valid.json      — passes every offline check (CI)
  fixtures/sample-bundle.tampered.json   — leaf altered; Merkle step must FAIL (CI)

  examples/01-attestation-file/          — link A via sha256-file (an original artifact)
  examples/02-daily-balance/             — link A via salted balance commitment (+ secret)
  examples/03-tampered-original/         — original swapped; link A must catch it
  examples/run.sh                        — runs all three and asserts

Also inlines the daily-balance sample into ../index.html (__SAMPLE_BUNDLE__) so the
single-file HTML ships a self-consistent demo that works over file://.

Deterministic: no randomness, no timestamps.
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

def bc30(merkle_root, batch_id):
    p = b"BC30" + bytes([0x1E, 0x00]) + batch_id + merkle_root + (b"\x00" * 32)
    assert len(p) == 86
    return p

def build_reveal_tx(op_return_payload):
    """Structurally-valid segwit reveal tx carrying the OP_RETURN. Not a real
    signed tx — the verifier only needs it to parse and hash to its txid."""
    version = bytes.fromhex("02000000")
    prevout = bytes(32) + bytes.fromhex("00000000")
    vin = b"\x01" + prevout + b"\x00" + bytes.fromhex("fdffffff")
    op_script = b"\x6a\x4c" + bytes([len(op_return_payload)]) + op_return_payload
    out0 = bytes(8) + V._enc_varint(len(op_script)) + op_script
    p2tr = b"\x51\x20" + bytes([0x11] * 32)
    out1 = (9000).to_bytes(8, "little") + V._enc_varint(len(p2tr)) + p2tr
    vout = b"\x02" + out0 + out1
    witness = b"\x01\x40" + bytes(64)
    return (version + b"\x00\x01" + vin + vout + witness + bytes(4)).hex()

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
    return bundle

# ---------------- scenario data ----------------
# 01 — file artifact
ARTIFACT = b"BitCert MAS Reg 18H daily attestation report (demo artifact).\n"
ART_LEAF = V.sha256(ARTIFACT)                         # leaf_bytes = SHA-256(file)

# 02 — daily balance with salted commitment (salt is the customer's PRIVATE secret)
ACCOUNT = "alice@demoex"
SALT_HEX = "5e" * 32  # 32-byte per-customer secret (deterministic for the fixture)
USER_COMMITMENT = V.derive_user_commitment(SALT_HEX, ACCOUNT)
DAILY_FIELDS = {"asset": "BTC", "balance_minor": "150000000", "user_commitment": USER_COMMITMENT}
DAILY_LEAF = V.sha256(DAILY_DOMAIN.encode() + V._jcs(DAILY_FIELDS))

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
    # ---- examples/01 — file artifact ----
    b01 = assemble_bundle(ART_LEAF, file_preimage(), "attestation",
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
      "byte and re-run: step 0 (Original binding) then FAILS — the file no longer matches "
      "what was anchored.\n")

    # ---- examples/02 — daily balance ----
    b02 = assemble_bundle(DAILY_LEAF, daily_preimage(), "daily",
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
      "The salt is the **customer's private secret** — it is deliberately NOT in the "
      "public bundle (otherwise anyone could de-anonymize accounts). It lives in "
      "`customer-secret.txt` here to simulate what the customer holds.\n\n"
      "Self-consistency only (no secret needed) — proves the leaf is the hash of the "
      "shown fields:\n```bash\npython3 ../../verify-cli/verify.py bundle.json\n```\n\n"
      "Full identity binding — proves the leaf is *your* row, privately:\n```bash\n"
      "python3 ../../verify-cli/verify.py bundle.json --account %s --salt %s\n```\n\n"
      "Expected: **VERIFIED**, with step 0 reporting `identity … match`. A wrong "
      "`--account`/`--salt` makes the identity check MISMATCH.\n" % (ACCOUNT, SALT_HEX))

    # ---- examples/03 — tampered original (same bundle as 01, swapped file) ----
    w(os.path.join(EX, "03-tampered-original", "bundle.json"), jdump(b01))
    w(os.path.join(EX, "03-tampered-original", "tampered-report.txt"),
      ARTIFACT.replace(b"150000000", b"999999999") if b"150000000" in ARTIFACT
      else ARTIFACT[:-1] + b" [ALTERED]\n")
    w(os.path.join(EX, "03-tampered-original", "expected.txt"), "FAILED (exit 1)\n")
    w(os.path.join(EX, "03-tampered-original", "README.md"),
      "# 03 · Tampered original is caught (link A)\n\n"
      "Same anchored bundle as example 01, but the original file was altered. Links "
      "B/C (Merkle + Bitcoin) still pass — the anchor is real — yet the document no "
      "longer hashes to the anchored leaf, so step 0 FAILS.\n\n```bash\n"
      "python3 ../../verify-cli/verify.py bundle.json --original tampered-report.txt\n```\n\n"
      "Expected: step 0 ✗ → **VERIFICATION FAILED** (exit 1). This is link A doing its "
      "job: proving the *content* you hold is the one that was anchored.\n")

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

echo; [ "$fail" = 0 ] && echo "ALL EXAMPLES OK" || { echo "SOME EXAMPLES FAILED"; exit 1; }
""" % SALT_HEX
    run_path = os.path.join(EX, "run.sh")
    w(run_path, run)
    os.chmod(run_path, 0o755)

    # ---- fixtures for CI cross-checks ----
    w(os.path.join(HERE, "sample-bundle.valid.json"), jdump(b02))           # daily, jcs preimage
    tampered = json.loads(jdump(b02)); tampered["record"]["leaf_bytes"] = "ff" * 32
    w(os.path.join(HERE, "sample-bundle.tampered.json"), jdump(tampered))

    # ---- inline the daily sample into index.html ----
    html_path = os.path.join(ROOT, "index.html")
    with open(html_path) as f:
        html = f.read()
    import re
    # NOTE: pass a function as the replacement — a plain string would have its
    # backslash escapes (e.g. the \n inside "attest:daily:leaf\n") interpreted by
    # re.sub, turning them into real newlines and breaking the JS string literal.
    inline = "const SAMPLE=" + json.dumps(b02) + ";"
    html = re.sub(r"const SAMPLE=.*?;", lambda _m: inline, html, count=1, flags=re.S)
    with open(html_path, "w") as f:
        f.write(html)

    print("generated fixtures + examples/. daily leaf:", DAILY_LEAF.hex())
    print("  file-artifact leaf:", ART_LEAF.hex(), "| reveal_txid(02):", b02["anchor"]["reveal_txid"])

if __name__ == "__main__":
    main()
