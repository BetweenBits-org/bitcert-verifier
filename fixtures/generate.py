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
    return bundle, root

def prior_daily_entry(exchange_id, seq, business_date, body_hash, prev_entry_hash):
    """A self-consistent prior chain entry for §5 walk-back links."""
    e = {"exchange_id": exchange_id, "seq": seq, "kind": "daily",
         "prev_entry_hash": prev_entry_hash, "body_hash": body_hash,
         "business_date": business_date}
    e["payload_hash"] = V.payload_hash(e)
    return e

def assemble_daily_v2_bundle(exchange_id, business_date, recon_assets, recon_ok):
    """A v2 daily bundle: the OP_RETURN + chain body_hash carry `day_root`
    (binds the customer-balance root AND the (a)/(b)/(c) reconciliation), and a
    `reconciliation` section ships the §6 inputs the verifier folds back in."""
    others = [bytes([b]) * 32 for b in (0xB1, 0xC2, 0xD3)]
    balances_root, proof = merkle4([DAILY_LEAF] + others)
    rc = V.recon_commitment(exchange_id, business_date, recon_ok, recon_assets)
    dr = V.day_root(exchange_id, business_date, balances_root.hex(), rc)  # the anchored value
    batch_id = bytes.fromhex("0192a3b4c5d6e7f80192a3b4c5d6e7f8")
    payload = bc30(dr, batch_id)                      # OP_RETURN inscribes day_root, not the bare root
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
# 01 — file artifact
ARTIFACT = b"BitCert MAS Reg 18H daily attestation report (demo artifact).\n"
ART_LEAF = V.sha256(ARTIFACT)                         # leaf_bytes = SHA-256(file)

# 02 — daily balance with salted commitment (salt is the customer's PRIVATE secret)
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
    # ---- examples/01 — file artifact ----
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
      "byte and re-run: step 0 (Original binding) then FAILS — the file no longer matches "
      "what was anchored.\n")

    # ---- examples/02 — daily balance ----
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

    # ---- examples/04 — tampered chain (link D / §5 must catch it) ----
    # Same anchored daily bundle as 02, but the per-exchange chain entry's
    # payload_hash was forged. Links A/B/C still pass, yet the chain entry no
    # longer recomputes — so §5 (now gating) FAILS the bundle.
    b04 = json.loads(jdump(b02))
    b04["chain"]["entry"]["payload_hash"] = "ff" * 32
    w(os.path.join(EX, "04-tampered-chain", "bundle.json"), jdump(b04))
    w(os.path.join(EX, "04-tampered-chain", "expected.txt"), "FAILED (exit 1)\n")
    w(os.path.join(EX, "04-tampered-chain", "README.md"),
      "# 04 · Tampered per-exchange chain is caught (link D · §5)\n\n"
      "Same anchored daily bundle as example 02, but the chain entry's "
      "`payload_hash` was forged. Links A/B/C (preimage + Merkle + Bitcoin) all "
      "still pass — the day's Merkle root really is anchored — yet the §5 chain "
      "entry no longer recomputes from its preimage, so step 4 FAILS.\n\n"
      "`payload_hash = SHA-256(\"bitcert:chain:v1\\n\" || JCS(entry_core))` — the "
      "verifier recomputes it and also checks `body_hash == merkle.root` for a "
      "daily entry. Both are cryptographic and gate the verdict.\n\n```bash\n"
      "python3 ../../verify-cli/verify.py bundle.json\n```\n\n"
      "Expected: step 4 ✗ → **VERIFICATION FAILED** (exit 1).\n")

    # ---- examples/05 — daily chain walk-back (§5 continuity / links) ----
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
      "`today.prev_entry_hash == payload_hash(yesterday)` — the tamper-evident "
      "hash linkage that makes a per-exchange chain auditable.\n\n```bash\n"
      "python3 ../../verify-cli/verify.py bundle.json --account %s --salt %s\n```\n\n"
      "Expected: every check ✓ → **VERIFIED**, with step 4 reporting `walked 1 "
      "prior entry + head: hash-linkage holds`. Flip any byte of the linked "
      "entry and step 4 FAILS.\n" % (ACCOUNT, SALT_HEX))

    # ---- examples/06 — daily day_root (v2: the anchor commits the reconciliation) ----
    b06, _root06, _dr06 = assemble_daily_v2_bundle("demoex", "2026-05-28", V2_ASSETS, True)
    w(os.path.join(EX, "06-daily-day-root", "bundle.json"), jdump(b06))
    w(os.path.join(EX, "06-daily-day-root", "customer-secret.txt"),
      "# Held PRIVATELY by the customer (NOT in the public bundle).\n"
      "account_id=%s\nsalt_hex=%s\n" % (ACCOUNT, SALT_HEX))
    w(os.path.join(EX, "06-daily-day-root", "expected.txt"), "VERIFIED (exit 0)\n")
    w(os.path.join(EX, "06-daily-day-root", "README.md"),
      "# 06 · Daily day_root (v2 — the anchor commits the trust reconciliation)\n\n"
      "A **v2** daily bundle. The OP_RETURN no longer carries the bare customer-balance "
      "Merkle root — it carries `day_root`:\n\n```\n"
      "recon_commitment = SHA256(\"attest:daily:recon\\n\"  || JCS{assets_hash, business_date, exchange_id, reconciliation_ok})\n"
      "day_root         = SHA256(\"attest:daily:anchor\\n\" || JCS{balances_root, business_date, exchange_id, recon_commitment})\n```\n\n"
      "So one Bitcoin anchor attests BOTH the customer liabilities (the Merkle root) "
      "AND the (a)/(b)/(c) trust reconciliation. The verifier recomputes `day_root` from "
      "the `reconciliation` section + the Merkle root and asserts it equals the OP_RETURN "
      "(§4) and the chain `body_hash` (§5).\n\n```bash\n"
      "python3 ../../verify-cli/verify.py bundle.json --account %s --salt %s\n```\n\n"
      "Expected: every check ✓ → **VERIFIED**, with step 6 listing the per-asset "
      "(a)/(b)/(c). NOTE: the (a) reserve side is exchange-supplied, not independently "
      "measured. Flip any residual and step 2 (OP_RETURN ≠ recomputed day_root) FAILS.\n"
      % (ACCOUNT, SALT_HEX))

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

echo; [ "$fail" = 0 ] && echo "ALL EXAMPLES OK" || { echo "SOME EXAMPLES FAILED"; exit 1; }
""" % (SALT_HEX, SALT_HEX, SALT_HEX)
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
    w(os.path.join(HERE, "sample-bundle.daily-v2.valid.json"), jdump(b06))     # OP_RETURN == day_root
    # tampered reconciliation: bump a residual → recomputed day_root ≠ OP_RETURN → §4.1 FAILS.
    tampered_recon = json.loads(jdump(b06)); tampered_recon["reconciliation"]["assets"][0]["residual"] = "999"
    w(os.path.join(HERE, "sample-bundle.tampered-recon.json"), jdump(tampered_recon))

    # ---- inline the daily sample into index.html ----
    html_path = os.path.join(ROOT, "index.html")
    with open(html_path) as f:
        html = f.read()
    import re
    # NOTE: pass a function as the replacement — a plain string would have its
    # backslash escapes (e.g. the \n inside "attest:daily:leaf\n") interpreted by
    # re.sub, turning them into real newlines and breaking the JS string literal.
    # Inline the v2 day_root sample so the single-file HTML showcases the new path.
    inline = "const SAMPLE=" + json.dumps(b06) + ";"
    html = re.sub(r"const SAMPLE=.*?;", lambda _m: inline, html, count=1, flags=re.S)
    with open(html_path, "w") as f:
        f.write(html)

    print("generated fixtures + examples/. daily leaf:", DAILY_LEAF.hex())
    print("  KAT day_root:", _KAT_DR.hex(), "| v2 day_root(06):", _dr06.hex())
    print("  file-artifact leaf:", ART_LEAF.hex(), "| reveal_txid(02):", b02["anchor"]["reveal_txid"])

if __name__ == "__main__":
    main()
