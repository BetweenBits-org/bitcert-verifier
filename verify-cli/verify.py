#!/usr/bin/env python3
"""BitCert Independent Proof Verifier - command-line edition.

Trust-minimized by design. This tool calls NO BitCert server. It verifies a
proof bundle (see ../docs/bundle-schema.md) using only:
  (1) math   - SHA-256 / RFC-6962 Merkle (Python's stdlib `hashlib`), and
  (2) Bitcoin - observed through a source YOU choose (--explorer / your node).

Standard library only. No pip install. Works fully offline; the optional
on-chain step (--explorer) is the single Bitcoin-dependent check, and it never
contacts BitCert.

Usage:
    python3 verify.py BUNDLE.json
    python3 verify.py BUNDLE.json --original report.pdf          # bind a file artifact (link A / H(D))
    python3 verify.py BUNDLE.json --account alice --salt <hex>   # bind a daily balance row (link A)
    python3 verify.py BUNDLE.json --explorer https://mempool.space
    python3 verify.py BUNDLE.json --identifier alice@example.com # v4: check a subject_type 1 record
    python3 verify.py BUNDLE.json --present-url [--label L] [--console URL]  # v4: start a presenter check
    python3 verify.py BUNDLE.json --present BLOB|FILE --nonce HEX            # v4: confirm the presenter
    python3 verify.py --selftest                                 # P-256 / DER / SMT known answers
    cat BUNDLE.json | python3 verify.py -

  --original FILE     hash this file and confirm it equals leaf_bytes (sha256-file) / doc_sha256 (v4)
  --account ID        your account id, to reproduce the salted commitment (daily scheme)
  --salt HEX          your per-customer salt (held privately; NOT in the public bundle)
  --explorer URL      a Bitcoin source YOU choose for the on-chain step (never BitCert)
  --identifier STR    v4 subject_type 1: the identifier the issuer wrote (recomputes the salted ref)
  --present BLOB|FILE v4: the /present blob (base64url or JSON) the recipient handed you
  --nonce HEX         v4: the 16-byte nonce YOU generated for that presentation (ownership)
  --present-url       v4: generate nonce/expiry/verifier_id and print the /present link
  --label STR         v4: label folded into verifier_id (default "verifier")
  --console URL       v4: base URL of the signing page (default https://console.bitcert.io)
  --rp-id ID          override the pinned WebAuthn rpId  (default console.bitcert.io)
  --origin URL        override/add an allowed WebAuthn origin (repeatable)
  --now UNIX          clock used for expiry checks (default: system time)

Exit codes: 0 valid · 1 rejected · 2 warning · 3 undetermined · 64 usage / not JSON.
Legacy bundles (v1–v3) keep their 0/1 meaning. Requires Python >= 3.8.
"""
import hashlib
import json
import sys

SCHEMA = "bitcert-proof-bundle/v1"
# v2 adds the daily `reconciliation` section: the anchor output commits `day_root`
# (binds the balance root + the (a)/(b)/(c) reconciliation) instead of the bare
# Merkle root. The verifier accepts both and branches on the `reconciliation`
# section's presence (NOT the version string alone).
SCHEMAS = ("bitcert-proof-bundle/v1", "bitcert-proof-bundle/v2", "bitcert-proof-bundle/v3")
# v3 may carry a `zk` section (bulletproofs). Only the browser verifier implements
# it; this CLI reports that section as UNDETERMINED rather than pretending.
# v4 is the identity-bound issuance bundle (schema §2.3/§9–§11) - see verify_v4.
SCHEMA_V4 = "bitcert-proof-bundle/v4"
CHAIN_DOMAIN = b"bitcert:chain:v1\n"

# ----- ANSI (auto-disabled when not a tty) -----
def _c(code):
    return code if sys.stdout.isatty() else ""
OK, BAD, WARN, SKIP, DIM, RST = (_c("\033[32m"), _c("\033[31m"), _c("\033[33m"),
                                 _c("\033[90m"), _c("\033[2m"), _c("\033[0m"))
UNDET = _c("\033[35m")

# ----- hashing -----
def sha256(b):  return hashlib.sha256(b).digest()
def sha256d(b): return sha256(sha256(b))
def leaf_hash(d):    return sha256(b"\x00" + d)          # RFC-6962 H_leaf
def node_hash(l, r): return sha256(b"\x01" + l + r)      # RFC-6962 H_node

# ----- §3 merkle inclusion -----
def verify_merkle(record, m):
    leaf = bytes.fromhex(record["leaf_bytes"])
    if len(leaf) != 32:
        raise ValueError("leaf_bytes must be 32 bytes")
    sibs, dirs = m["siblings"], m["directions"]
    if len(sibs) != len(dirs):
        raise ValueError("siblings/directions length mismatch")
    cur = leaf_hash(leaf)
    for sib_hex, d in zip(sibs, dirs):
        sib = bytes.fromhex(sib_hex)
        if len(sib) != 32:
            raise ValueError("sibling not 32 bytes")
        if d == "left":
            cur = node_hash(sib, cur)
        elif d == "right":
            cur = node_hash(cur, sib)
        else:
            raise ValueError('direction must be "left"/"right", got %r' % d)
    computed = cur.hex()
    return computed, (computed.lower() == m["root"].lower())

# ----- §4.1 anchor output decode -----
def decode_anchor_payload(payload_hex):
    b = bytes.fromhex(payload_hex)
    magic = b[:4].decode("latin1")
    if magic == "BC01":
        if len(b) != 53:
            raise ValueError("payload with magic 42433031 must be 53 bytes, got %d" % len(b))
        return {"format": "BC01", "version": b[4],
                "merkle_root": b[5:37].hex(), "batch_id": b[37:53].hex()}
    if magic == "BC30":
        if len(b) != 86:
            raise ValueError("payload with magic 42433330 must be 86 bytes, got %d" % len(b))
        return {"format": "BC30", "version": b[4], "flags": b[5],
                "batch_id": b[6:22].hex(), "merkle_root": b[22:54].hex(),
                "aux": b[54:86].hex()}
    raise ValueError("unknown anchor payload magic (expected 42433031 or 42433330)")

def payload_name(decoded):
    """Human name for a decoded anchor payload. The internal `format` codes never
    reach the screen; the magic is shown as hex only."""
    if decoded.get("format") == "BC01":
        return "53-byte payload v%d (0x%02x)" % (decoded.get("version", 0), decoded.get("version", 0))
    v = decoded.get("version", 0)
    return "86-byte payload v%d (0x%02x)" % (v, v)

def legacy_payload_problem(decoded):
    """bundle-schema §4.1 compatibility rule: what a v1–v3 bundle may ride on (86-byte payload).
    0x1E (mined anchors, forever) as today; 0x1F only UNBOUND (bit 1 clear) with
    aux == AUX_COMMITMENT_NONE; a bound 0x1F anchor needs a v4 bundle. Returns
    None when acceptable, else the reason to reject."""
    if decoded.get("format") != "BC30":
        return None
    v, flags = decoded["version"], decoded["flags"]
    if v == OP_RETURN_V30_VERSION:
        return None
    if v == OP_RETURN_V31_VERSION:
        if flags & ~FLAGS_DEFINED_MASK_V31:
            return "undefined flag bits 0x%02x" % flags
        if flags & FLAG_IDENTITY_BOUND:
            return "identity-bound anchor (0x1F, IDENTITY_BOUND) requires a v4 bundle"
        if decoded["aux"].lower() != AUX_COMMITMENT_NONE.hex():
            return "unbound v31 anchor must carry AUX_COMMITMENT_NONE, got aux %s" % decoded["aux"]
        return None
    return "unsupported anchor payload version 0x%02x" % v

# ----- §4.2 raw tx parse + legacy txid -----
class _R:
    def __init__(self, b): self.b, self.o = b, 0
    def take(self, n):
        s = self.b[self.o:self.o + n]
        if len(s) != n:
            raise ValueError("tx truncated")
        self.o += n
        return s
    def u8(self): return self.take(1)[0]
    def varint(self):
        f = self.u8()
        if f < 0xfd: return f
        if f == 0xfd: return int.from_bytes(self.take(2), "little")
        if f == 0xfe: return int.from_bytes(self.take(4), "little")
        return int.from_bytes(self.take(8), "little")

def _enc_varint(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xffffffff: return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")

def parse_tx(hex_str):
    """Return (legacy_serialization_without_witness, [output_scripts])."""
    r = _R(bytes.fromhex(hex_str))
    parts = [r.take(4)]                       # version
    segwit = r.b[r.o:r.o + 2] == b"\x00\x01"
    if segwit:
        r.take(2)                             # marker + flag
    vin = r.varint(); parts.append(_enc_varint(vin))
    for _ in range(vin):
        parts.append(r.take(32))              # prev txid
        parts.append(r.take(4))               # prev vout
        sl = r.varint(); parts.append(_enc_varint(sl)); parts.append(r.take(sl))
        parts.append(r.take(4))               # sequence
    vout = r.varint(); parts.append(_enc_varint(vout))
    scripts = []
    for _ in range(vout):
        value = r.take(8)
        sl = r.varint(); script = r.take(sl)
        parts += [value, _enc_varint(sl), script]
        scripts.append(script)
    if segwit:
        for _ in range(vin):
            for _ in range(r.varint()):
                r.take(r.varint())
    parts.append(r.take(4))                   # locktime
    return b"".join(parts), scripts

def extract_anchor_output(script):
    if len(script) < 1 or script[0] != 0x6a:  # anchor output
        return None
    o = 1
    if o >= len(script): return b""
    op = script[o]; o += 1
    if op <= 0x4b: ln = op
    elif op == 0x4c: ln = script[o]; o += 1
    elif op == 0x4d: ln = int.from_bytes(script[o:o + 2], "little"); o += 2
    elif op == 0x4e: ln = int.from_bytes(script[o:o + 4], "little"); o += 4
    else: return None
    return script[o:o + ln]

def txid_from_raw(hex_str):
    legacy, scripts = parse_tx(hex_str)
    txid = sha256d(legacy)[::-1].hex()        # display (big-endian) order
    anchor_payload = None
    for s in scripts:
        p = extract_anchor_output(s)
        if p is not None:
            anchor_payload = p.hex(); break
    return txid, anchor_payload

# ----- §6 witness inscription (the original bytes live IN the reveal witness) -----
def extract_witness_items(hex_str, input_index):
    """Return the list of witness stack elements for `input_index`, or None for a
    non-segwit tx. The witness is NOT in the txid (malleable) - callers MUST bind
    the recovered bytes to record.leaf_bytes (which IS txid-committed via the
    anchor output), never trust the witness alone."""
    r = _R(bytes.fromhex(hex_str))
    r.take(4)                                  # version
    if r.b[r.o:r.o + 2] != b"\x00\x01":        # not segwit -> no witness
        return None
    r.take(2)                                  # marker + flag
    vin = r.varint()
    for _ in range(vin):
        r.take(32); r.take(4)
        r.take(r.varint()); r.take(4)          # scriptSig + sequence
    vout = r.varint()
    for _ in range(vout):
        r.take(8); r.take(r.varint())          # value + scriptPubKey
    witnesses = []
    for _ in range(vin):
        items = [r.take(r.varint()) for _ in range(r.varint())]
        witnesses.append(items)
    if input_index >= len(witnesses):
        return None
    return witnesses[input_index]

def parse_envelope(script):
    """Walk the inscription tapscript and recover (tag, content_type, body).
    Pushes inside the OP_IF..OP_ENDIF block are [tag, content_type, body chunks…];
    the body is their plain concatenation (bcrt framing, <=520B chunks)."""
    o, n, collecting, pushes = 0, len(script), False, []
    while o < n:
        op = script[o]; o += 1
        data = None
        if op <= 0x4b:
            data = script[o:o + op]; o += op
        elif op == 0x4c:
            ln = script[o]; o += 1; data = script[o:o + ln]; o += ln
        elif op == 0x4d:
            ln = int.from_bytes(script[o:o + 2], "little"); o += 2; data = script[o:o + ln]; o += ln
        elif op == 0x4e:
            ln = int.from_bytes(script[o:o + 4], "little"); o += 4; data = script[o:o + ln]; o += ln
        elif op == 0x63:                        # OP_IF
            collecting = True
        elif op == 0x68:                        # OP_ENDIF
            collecting = False
        if data is not None and collecting:
            pushes.append(data)
    if len(pushes) < 2:
        return None
    return pushes[0], pushes[1], b"".join(pushes[2:])

def verify_witness_bundle(bundle, explorer=None):
    """Verify a witness-INSCRIBED record: the original bytes are recovered from
    the reveal tx WITNESS (no off-bundle file needed) and bound to
    record.leaf_bytes - which IS txid-committed. Dual-mode (UNIFIED-WITNESS-CONTRACT):

      • LEGACY  - anchor output is a raw 32 B = leaf_bytes (no payload magic). The
        inscribed document IS the directly-committed leaf (step 2: anchor output ==
        leaf_bytes; step 3: sha256(body) == leaf_bytes).
      • UNIFIED - anchor output is a 53-/86-byte payload(merkle_root). The leaf is bound to the
        on-chain root THROUGH the Merkle proof (step 2: verify_merkle(record) ==
        decoded.merkle_root; step 3: sha256(body) == leaf_bytes, unchanged).

    Mode is decided by decoding the anchor output: a recognised payload magic → UNIFIED,
    a raw 32-byte payload with no magic → LEGACY. A tampered witness body fails
    the bind; a swapped tx fails the txid check; a forged Merkle proof fails the
    unified root check."""
    anchor, record = bundle["anchor"], bundle["record"]
    wit = anchor["witness_envelope"]
    leaf = record["leaf_bytes"].lower()
    raw = anchor.get("reveal_tx_hex")
    all_ok = True

    if not raw:
        _line("bad", "1 · Transaction binding - no reveal_tx_hex",
              "a witness bundle cannot be verified without the raw reveal tx")
        return False
    try:
        computed_txid, anchor_payload = txid_from_raw(raw)
        txid_ok = computed_txid.lower() == (anchor.get("reveal_txid") or "").lower()
        op_ok = (anchor_payload or "").lower() == anchor["op_return_payload_hex"].lower()
        _line("ok" if txid_ok and op_ok else "bad",
              "1 · Transaction binding - anchor output %s reveal_txid" %
              ("belongs to" if txid_ok and op_ok else "does NOT match"),
              "computed txid: %s\nbundle  txid: %s" % (computed_txid, anchor.get("reveal_txid")))
        all_ok &= txid_ok and op_ok
    except Exception as e:
        _line("bad", "1 · Transaction binding - error", str(e)); return False

    # Mode detection: a recognised payload magic in the anchor output → UNIFIED (merkle-bind);
    # a raw 32-byte payload with no magic → LEGACY (anchor output == leaf_bytes).
    decoded = None
    try:
        decoded = decode_anchor_payload(anchor["op_return_payload_hex"])
    except Exception:
        decoded = None

    if decoded is None:
        # LEGACY - the inscribed document IS the directly-committed leaf.
        root_ok = (anchor_payload or "").lower() == leaf
        _line("ok" if root_ok else "bad",
              "2 · On-chain commitment - anchor output root %s record.leaf_bytes" %
              ("== " if root_ok else "≠ "),
              "on-chain root: %s" % (anchor_payload or ""))
        all_ok &= root_ok
    else:
        # UNIFIED - bind leaf_bytes to the on-chain merkle_root via the proof.
        try:
            prob = legacy_payload_problem(decoded)
            if prob:
                _line("bad", "2 · On-chain commitment - payload rejected", prob); return False
            anchored = decoded["merkle_root"]
            computed_root, merkle_ok = verify_merkle(record, bundle["merkle"])
            root_ok = merkle_ok and computed_root.lower() == anchored.lower()
            _line("ok" if root_ok else "bad",
                  "2 · On-chain commitment - record %s the anchor output merkle_root (%s)" %
                  ("binds to" if root_ok else "does NOT bind to", payload_name(decoded)),
                  "recomputed root:    %s\nanchor output merkle_root: %s" % (computed_root, anchored))
            all_ok &= root_ok
        except Exception as e:
            _line("bad", "2 · On-chain commitment - error", str(e)); return False

    # THE headline: recover the original from the witness, bind to leaf_bytes.
    try:
        items = extract_witness_items(raw, int(wit.get("input_index", 0)))
        if not items or len(items) < 2:
            raise ValueError("input has no script-path witness ([sig, script, control])")
        env = parse_envelope(items[1])
        if not env:
            raise ValueError("witness[1] is not an OP_FALSE OP_IF inscription envelope")
        tag, ct, body = env
        body_hash = sha256(body).hex()
        bound = (body_hash == leaf)             # bind to record.leaf_bytes, NOT self-declared
        detail = ("recovered %d bytes straight from the Bitcoin witness\n"
                  "content_type: %s\nprotocol_tag: %s\nsha256(body): %s"
                  % (len(body), ct.decode("latin1", "replace"),
                     tag.decode("latin1", "replace"), body_hash))
        _line("ok" if bound else "bad",
              "3 · Witness original - recovered bytes %s record.leaf_bytes" %
              ("bind to" if bound else "do NOT bind to"), detail)
        all_ok &= bound
    except Exception as e:
        _line("bad", "3 · Witness original - error", str(e)); return False

    if explorer:
        try:
            confirmed, st = check_on_chain(explorer, computed_txid)
            _line("ok" if confirmed else "warn",
                  "4 · On-chain - %s via %s" % ("confirmed" if confirmed else "seen, unconfirmed", explorer),
                  "block height %s" % st.get("block_height"))
        except Exception as e:
            _line("warn", "4 · On-chain - could not reach explorer",
                  "%s\nsteps 1–3 are already proven offline" % e)
    else:
        _line("skip", "4 · On-chain confirmation - SKIPPED (offline / no --explorer)",
              "txid bound above: %s" % computed_txid)

    print()
    if all_ok:
        print("%s✓ CRYPTOGRAPHICALLY VERIFIED (offline) - original recovered from the Bitcoin witness%s" % (OK, RST))
        print("  No BitCert server, no off-bundle file: the document IS on Bitcoin (tx %s)." % computed_txid)
    else:
        print("%s✗ VERIFICATION FAILED%s" % (BAD, RST))
        print("  This witness bundle does not prove what it claims.")
    return all_ok

# ----- §5 chain continuity -----
def _jcs_entry_core(e):
    # RFC-8785 subset: sorted keys, compact separators.
    core = {k: e[k] for k in ("body_hash", "business_date", "exchange_id",
                              "kind", "prev_entry_hash", "seq")}
    return json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")

def payload_hash(e):
    return sha256(CHAIN_DOMAIN + _jcs_entry_core(e)).hex()

ZERO_HASH = "00" * 32

def _verify_chain_links(links, head):
    """Walk an optional ordered list of prior chain entries (ascending seq) and
    confirm each one (a) recomputes its own payload_hash and (b) hash-links to
    the next: entry[n].prev_entry_hash == payload_hash(entry[n-1]); the last link
    must equal the head entry's prev_entry_hash. Returns (ok, detail)."""
    if not links:
        return True, ""
    chain = list(links) + [head]
    prev_ph = None
    for e in chain:
        ph = payload_hash(e)
        if e is not head:  # head's own payload_hash is checked by the caller
            if ph.lower() != e.get("payload_hash", "").lower():
                return False, "link seq %s: payload_hash does not recompute" % e.get("seq")
        expected_prev = prev_ph if prev_ph is not None else None
        if expected_prev is None:
            # genesis-or-first link: prev_entry_hash should be zeros (or it is the
            # genesis entry itself); we only assert linkage from the 2nd entry on.
            pass
        elif e.get("prev_entry_hash", "").lower() != expected_prev.lower():
            return False, "link seq %s: prev_entry_hash ≠ payload_hash(seq %s)" % (
                e.get("seq"), e.get("seq", 0) - 1 if isinstance(e.get("seq"), int) else "?")
        prev_ph = ph
    return True, "walked %d prior entr%s + head: hash-linkage holds" % (
        len(links), "y" if len(links) == 1 else "ies")

# ----- §2.1 preimage (link A): original record -> leaf_bytes -----
def _jcs(obj):
    # RFC-8785 subset: sorted keys, compact. All values are strings/ints in our schemes.
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

# ----- §6 reconciliation commitment + day_root (v2) -----
# Byte-identical to services/daily-settlement/src/domain/anchor.rs. Reuses the
# flat _jcs (Str/Int values, sorted keys) so all three implementations agree:
#   asset row  = JCS{asset, ok(1|0), residual, scale(int), trust_actual, trust_required}
#   assets_hash      = SHA256("attest:daily:recon-assets\n" || Σ asset_row)   # SORTED by symbol
#   recon_commitment = SHA256("attest:daily:recon\n"  || JCS{assets_hash, business_date, exchange_id, reconciliation_ok(1|0)})
#   day_root         = SHA256("attest:daily:anchor\n" || JCS{balances_root, business_date, exchange_id, recon_commitment})
RECON_ASSETS_DOMAIN = b"attest:daily:recon-assets\n"
RECON_DOMAIN        = b"attest:daily:recon\n"
DAY_ROOT_DOMAIN     = b"attest:daily:anchor\n"

def _asset_row_jcs(a):
    return _jcs({
        "asset": a["asset"],
        "ok": 1 if a["ok"] else 0,
        "residual": a["residual"],
        "scale": int(a["scale"]),
        "trust_actual": a["trust_actual"],
        "trust_required": a["trust_required"],
    })

def assets_hash(assets):
    h = hashlib.sha256()
    h.update(RECON_ASSETS_DOMAIN)
    for a in sorted(assets, key=lambda x: x["asset"]):
        h.update(_asset_row_jcs(a))
    return h.digest()

def recon_commitment(exchange_id, business_date, reconciliation_ok, assets):
    body = _jcs({
        "assets_hash": assets_hash(assets).hex(),
        "business_date": business_date,
        "exchange_id": exchange_id,
        "reconciliation_ok": 1 if reconciliation_ok else 0,
    })
    return sha256(RECON_DOMAIN + body)

def day_root(exchange_id, business_date, balances_root_hex, recon_commit):
    body = _jcs({
        "balances_root": balances_root_hex,
        "business_date": business_date,
        "exchange_id": exchange_id,
        "recon_commitment": recon_commit.hex(),
    })
    return sha256(DAY_ROOT_DOMAIN + body)

def derive_user_commitment(salt_hex, account_id):
    return sha256(bytes.fromhex(salt_hex) + account_id.encode("utf-8")).hex()

def verify_preimage(record, original_bytes=None, account_id=None, salt_hex=None):
    """Recompute leaf_bytes from the ORIGINAL and confirm it matches. Returns a
    dict describing what was checked, or None when the bundle declares no rule."""
    pre = record.get("preimage")
    if not pre:
        return None
    leaf = record["leaf_bytes"].lower()
    scheme = pre.get("scheme")
    res = {"scheme": scheme}
    if scheme == "sha256-file":
        if original_bytes is None:
            res["status"] = "need_original"
            return res
        computed = sha256(original_bytes).hex()
        res.update(computed=computed, self_ok=(computed == leaf), bound=(computed == leaf))
        return res
    if scheme == "sha256-jcs-fields":
        fields = pre["fields"]
        domain = pre.get("domain", "").encode("utf-8")
        computed = sha256(domain + _jcs(fields)).hex()
        res.update(computed=computed, self_ok=(computed == leaf))
        if account_id is not None and salt_hex is not None and pre.get("commitment"):
            uc = derive_user_commitment(salt_hex, account_id)
            res["identity_ok"] = (uc == fields.get("user_commitment", "").lower())
        return res
    raise ValueError("unknown preimage scheme: %r" % scheme)

# =============================================================================
# leaf v2 / bundle v4 (docs/bundle-schema.md §2.3, §4.1, §9–§11)
#
# Everything below is standard library only. P-256 is written out in plain
# affine arithmetic (a verification is two scalar multiplications - fast
# enough, and every line that decides the answer is readable). The same
# routines are mirrored in zk-core.js / index.html; fixtures/v4-expected.json
# is the oracle both must agree on.
# =============================================================================
import base64
import re
import time

# ----- pinned constants (docs/bundle-schema.md §9–§10) -----
BC30_RP_ID = "console.bitcert.io"
BC30_ORIGINS = ["https://console.bitcert.io"]

RECORD_TAG = b"BC30/record/v2"         # 14 B
ISSUE_TAG = b"BC30/issue/v2"           # 13 B
LEAF_TAG_V2 = b"BC30/leaf/v2"          # 12 B
TL_ENTRY_TAG = b"BC30/tl/v1"           # 10 B
AUX_TAG = b"BC30AUX2"                  # 8 B
PRESENT_TAG = b"BC30/present/v1"
VERIFIER_ID_TAG = b"BC30/verifier-id/v1"
RECORD_LEN = 143
TL_ENTRY_LEN = 116

SUBJECT_NONE, SUBJECT_ID_HASH, SUBJECT_PUBKEY = 0, 1, 2
CURVE_P256 = 1
LEAF_TYPE_ISSUANCE = 1
ALG_WEBAUTHN_ES256, ALG_ES256_PLAIN = 1, 2
ALG_NAMES = {"webauthn-es256": ALG_WEBAUTHN_ES256, "es256-plain": ALG_ES256_PLAIN}

OP_RETURN_V30_VERSION = 0x1E           # decode-only (mined anchors exist forever)
OP_RETURN_V31_VERSION = 0x1F
FLAG_WITNESS_PRESENT = 0b01
FLAG_IDENTITY_BOUND = 0b10
FLAGS_DEFINED_MASK_V30 = 0b01
FLAGS_DEFINED_MASK_V31 = 0b11

# ----- P-256 (NIST FIPS 186-4 D.1.2.3) -----
# Every constant is exercised by --selftest against RFC 6979 §A.2.5: x·G must
# land on (Ux,Uy), the point must decompress (b), and the signatures must
# verify (n). A typo in any of them fails the selftest rather than hiding.
_P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
_P256_A = _P256_P - 3
_P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
_P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
_P256_G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
           0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

def _ec_double(P):
    if P is None: return None
    x, y = P
    if y == 0: return None
    lam = (3 * x * x + _P256_A) * pow(2 * y, -1, _P256_P) % _P256_P
    x3 = (lam * lam - 2 * x) % _P256_P
    return (x3, (lam * (x - x3) - y) % _P256_P)

def _ec_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % _P256_P == 0: return None
        return _ec_double(P)
    lam = (y2 - y1) * pow((x2 - x1) % _P256_P, -1, _P256_P) % _P256_P
    x3 = (lam * lam - x1 - x2) % _P256_P
    return (x3, (lam * (x1 - x3) - y1) % _P256_P)

def _ec_mul(P, k):
    R, Q = None, P
    while k > 0:
        if k & 1: R = _ec_add(R, Q)
        Q = _ec_double(Q); k >>= 1
    return R

def _ec_on_curve(P):
    if P is None: return False
    x, y = P
    return (y * y - (x * x * x + _P256_A * x + _P256_B)) % _P256_P == 0

def p256_decompress(pk33):
    """SEC1 compressed (02/03 ‖ x) → (x, y). Rejects wrong length/prefix, x ≥ p,
    and x not on the curve. Raises ValueError."""
    if len(pk33) != 33 or pk33[0] not in (2, 3):
        raise ValueError("public key must be 33-byte SEC1 compressed (02/03 ‖ x)")
    x = int.from_bytes(pk33[1:], "big")
    if x >= _P256_P:
        raise ValueError("public key x is not a canonical field element")
    rhs = (x * x * x + _P256_A * x + _P256_B) % _P256_P
    y = pow(rhs, (_P256_P + 1) // 4, _P256_P)          # p ≡ 3 (mod 4)
    if y * y % _P256_P != rhs:
        raise ValueError("public key x is not on P-256")
    if (y & 1) != (pk33[0] & 1):
        y = _P256_P - y
    return (x, y)

def p256_compress(P):
    x, y = P
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")

def der_to_rs(sig):
    """Strict DER ECDSA-Sig-Value → (r, s). Short-form lengths only, no trailing
    bytes, minimal INTEGER encoding (no superfluous 0x00, no negative), and
    r, s ∈ [1, n−1]. low-s is NOT enforced (WebAuthn does not guarantee it)."""
    def _int(o):
        if o + 2 > len(sig) or sig[o] != 0x02:
            raise ValueError("DER: expected INTEGER")
        ln = sig[o + 1]
        if ln == 0 or ln >= 0x80 or o + 2 + ln > len(sig):
            raise ValueError("DER: bad INTEGER length")
        body = sig[o + 2:o + 2 + ln]
        if body[0] & 0x80:
            raise ValueError("DER: negative INTEGER")
        if ln > 1 and body[0] == 0x00 and not (body[1] & 0x80):
            raise ValueError("DER: non-minimal INTEGER (leading 0x00)")
        return int.from_bytes(body, "big"), o + 2 + ln
    if len(sig) < 8 or sig[0] != 0x30:
        raise ValueError("DER: expected SEQUENCE")
    total = sig[1]
    if total >= 0x80 or 2 + total != len(sig):
        raise ValueError("DER: SEQUENCE length does not match (trailing/short)")
    r, o = _int(2)
    s, o = _int(o)
    if o != len(sig):
        raise ValueError("DER: trailing bytes inside SEQUENCE")
    if not (1 <= r < _P256_N and 1 <= s < _P256_N):
        raise ValueError("DER: r/s out of range [1, n-1]")
    return r, s

def rs_to_der(r, s):
    def _int(v):
        b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
        if b[0] & 0x80: b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b
    body = _int(r) + _int(s)
    return b"\x30" + bytes([len(body)]) + body

def p256_verify(pub33, msg, sig_der):
    """ECDSA P-256 / SHA-256 (ES256). `msg` is hashed here - pass the raw message
    (for WebAuthn: authenticatorData ‖ SHA256(clientDataJSON); for es256-plain: m).
    Returns True/False; raises ValueError on malformed key/signature."""
    Q = p256_decompress(pub33)
    r, s = der_to_rs(sig_der)
    e = int.from_bytes(sha256(msg), "big") % _P256_N
    w = pow(s, -1, _P256_N)
    u1, u2 = e * w % _P256_N, r * w % _P256_N
    X = _ec_add(_ec_mul(_P256_G, u1), _ec_mul(Q, u2))
    if X is None: return False
    return X[0] % _P256_N == r

# ----- base64url (RFC 4648 §5, unpadded - WebAuthn's encoding) -----
def b64u_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def b64u_decode(s):
    if not isinstance(s, str) or not re.match(r"^[A-Za-z0-9_-]*$", s):
        raise ValueError("not base64url")
    pad = "=" * (-len(s) % 4)
    return base64.b64decode(s.replace("-", "+").replace("_", "/") + pad, validate=True)

# ----- WebAuthn assertion pieces (§9.1 of the schema) -----
def parse_authenticator_data(b):
    """rpIdHash(32) ‖ flags(1) ‖ signCount(4 BE) ‖ [extensions…]. Extension bytes are
    ignored here but the SIGNATURE covers the whole buffer."""
    if len(b) < 37:
        raise ValueError("authenticatorData shorter than 37 bytes")
    return {"rp_id_hash": b[:32], "flags": b[32],
            "up": bool(b[32] & 0x01), "uv": bool(b[32] & 0x04),
            "sign_count": int.from_bytes(b[33:37], "big"), "extensions": b[37:]}

def parse_client_data_json(b):
    try:
        cd = json.loads(b.decode("utf-8"))
    except Exception as e:
        raise ValueError("clientDataJSON is not UTF-8 JSON: %s" % e)
    if not isinstance(cd, dict):
        raise ValueError("clientDataJSON is not an object")
    return {"type": cd.get("type"), "challenge": cd.get("challenge"),
            "origin": cd.get("origin"), "cross_origin": cd.get("crossOrigin")}

def webauthn_verify_assertion(pub33, auth_data, client_data_json, sig_der, challenge,
                              rp_id=None, origins=None, require_uv=True):
    """All checks of docs/bundle-schema.md §9.1 / plan §3.2, collected (not
    short-circuited) so a report can show every reason. Returns
    (ok, reasons[], facts{})."""
    rp_id = rp_id or BC30_RP_ID
    origins = list(origins or BC30_ORIGINS)
    reasons, facts = [], {"rp_id": rp_id}
    try:
        ad = parse_authenticator_data(auth_data)
        facts.update(uv=ad["uv"], up=ad["up"], sign_count=ad["sign_count"])
        if ad["rp_id_hash"] != sha256(rp_id.encode("utf-8")):
            reasons.append("rpIdHash ≠ SHA256(%r)" % rp_id)
        if not ad["up"]:
            reasons.append("UP (user present) flag not set")
        if require_uv and not ad["uv"]:
            reasons.append("UV (user verified) flag not set")
    except ValueError as e:
        reasons.append(str(e))
    try:
        cd = parse_client_data_json(client_data_json)
        facts.update(type=cd["type"], origin=cd["origin"])
        if cd["type"] != "webauthn.get":
            reasons.append("clientDataJSON.type is %r, not \"webauthn.get\"" % (cd["type"],))
        try:
            got = b64u_decode(cd["challenge"] or "")
            if got != challenge:
                reasons.append("clientDataJSON.challenge is not the expected message")
        except ValueError:
            reasons.append("clientDataJSON.challenge is not base64url")
        if cd["origin"] not in origins:
            reasons.append("origin %r not in allowed %s" % (cd["origin"], origins))
    except ValueError as e:
        reasons.append(str(e))
    try:
        signed = auth_data + sha256(client_data_json)
        if not p256_verify(pub33, signed, sig_der):
            reasons.append("ES256 signature does not verify under the public key")
    except ValueError as e:
        reasons.append("signature/key malformed: %s" % e)
    return (not reasons), reasons, facts

# ----- BC30 leaf v2 builders (schema §2.3) -----
def _u64(v):
    v = int(v)
    if v < 0 or v >= 1 << 64: raise ValueError("u64 out of range")
    return v.to_bytes(8, "big")

def _need(b, n, what):
    if not isinstance(b, (bytes, bytearray)) or len(b) != n:
        raise ValueError("%s must be %d bytes" % (what, n))
    return bytes(b)

def subject_ref_none():
    return bytes(32)

def subject_ref_id_hash(record_salt, identifier):
    return sha256(_need(record_salt, 16, "record_salt") + identifier.encode("utf-8"))

def subject_ref_pubkey(curve_id, pk33):
    return sha256(b"\x02" + bytes([curve_id]) + _need(pk33, 33, "public_key"))

key_id = subject_ref_pubkey            # same normalisation, by design

def policy_jcs(policy):
    if not isinstance(policy, dict) or not all(isinstance(v, str) for v in policy.values()):
        raise ValueError("policy must be an object of strings")
    return json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def policy_hash(policy):
    return sha256(policy_jcs(policy))

def _record_core(record_salt, doc_sha256, subject_type, subject_ref, issued_at, expires_at, policy_h):
    if subject_type not in (SUBJECT_NONE, SUBJECT_ID_HASH, SUBJECT_PUBKEY):
        raise ValueError("subject_type must be 0/1/2")
    return (_need(record_salt, 16, "record_salt") + _need(doc_sha256, 32, "doc_sha256")
            + bytes([subject_type]) + _need(subject_ref, 32, "subject_ref")
            + _u64(issued_at) + _u64(expires_at) + _need(policy_h, 32, "policy_hash"))

def record_bytes(record_salt, doc_sha256, subject_type, subject_ref, issued_at, expires_at, policy_h):
    R = RECORD_TAG + _record_core(record_salt, doc_sha256, subject_type, subject_ref, issued_at, expires_at, policy_h)
    assert len(R) == RECORD_LEN
    return R

def issue_message(record_salt, doc_sha256, subject_type, subject_ref, issued_at, expires_at, policy_h):
    return sha256(ISSUE_TAG + _record_core(record_salt, doc_sha256, subject_type, subject_ref, issued_at, expires_at, policy_h))

def issuer_sig_bytes(alg, sig_der, auth_data=None, client_data_json=None):
    if alg == ALG_WEBAUTHN_ES256:
        if auth_data is None or client_data_json is None:
            raise ValueError("webauthn-es256 needs authenticator_data + client_data_json")
        return (b"\x01" + len(auth_data).to_bytes(2, "big") + auth_data
                + len(client_data_json).to_bytes(4, "big") + client_data_json
                + len(sig_der).to_bytes(2, "big") + sig_der)
    if alg == ALG_ES256_PLAIN:
        return b"\x02" + len(sig_der).to_bytes(2, "big") + sig_der
    raise ValueError("unsupported issuer alg %r" % (alg,))

def leaf_input_v2(leaf_type, R, s):
    return sha256(LEAF_TAG_V2 + bytes([leaf_type]) + _need(R, RECORD_LEN, "R") + s)

def tl_entry_bytes(issuer_id, kid, curve_id, pk33, valid_from, valid_to, revoked_at):
    e = (TL_ENTRY_TAG + _need(issuer_id, 16, "issuer_id") + _need(kid, 32, "key_id")
         + bytes([curve_id]) + _need(pk33, 33, "public_key")
         + _u64(valid_from) + _u64(valid_to) + _u64(revoked_at))
    assert len(e) == TL_ENTRY_LEN
    return e

def tl_leaf(entry_bytes):
    return sha256(entry_bytes)          # the 32-byte MerkleTree input; H_leaf is applied by the tree

def tl_root_none():
    return sha256(b"BC30/tl/none")

def envelope_root_none():
    return sha256(b"BC30/envelope/none")

def aux_commitment(tl_root, sl_root, envelope_root):
    return sha256(AUX_TAG + _need(tl_root, 32, "tl_root") + _need(sl_root, 32, "sl_root")
                  + _need(envelope_root, 32, "envelope_root"))

def bc30_v31(merkle_root, batch_id, aux, flags=FLAG_IDENTITY_BOUND):
    p = b"BC30" + bytes([OP_RETURN_V31_VERSION, flags]) + _need(batch_id, 16, "batch_id") \
        + _need(merkle_root, 32, "merkle_root") + _need(aux, 32, "aux_commitment")
    assert len(p) == 86
    return p

def present_challenge(nonce, leaf_input, verifier_id, expiry):
    return sha256(PRESENT_TAG + _need(nonce, 16, "nonce") + _need(leaf_input, 32, "leaf_input")
                  + _need(verifier_id, 32, "verifier_id") + _u64(expiry))

def make_verifier_id(label, rand16):
    return sha256(VERIFIER_ID_TAG + label.encode("utf-8") + _need(rand16, 16, "random"))

# ----- sparse Merkle tree (ann-core merkle-batching sparse.rs, 256 levels) -----
SMT_HEIGHT = 256
SMT_EMPTY_LEAF = sha256(b"\x11")                                   # pinned - never read from a proof

def smt_leaf_hash(key, value):
    return sha256(b"\x10" + _need(key, 32, "key") + _need(value, 32, "value"))

def smt_defaults():
    d = [SMT_EMPTY_LEAF]
    for i in range(SMT_HEIGHT):
        d.append(node_hash(d[i], d[i]))
    return d

SMT_DEFAULTS = smt_defaults()
SMT_EMPTY_ROOT = SMT_DEFAULTS[SMT_HEIGHT]
AUX_COMMITMENT_NONE = aux_commitment(tl_root_none(), SMT_EMPTY_ROOT, envelope_root_none())

def _smt_bit(key, index_from_msb):
    return (key[index_from_msb // 8] >> (7 - index_from_msb % 8)) & 1

def smt_fold(key, value, siblings):
    """Fold 256 siblings leaf→root. `value=None` is an exclusion proof and folds
    from the PINNED empty leaf (a proof-supplied empty_leaf is never trusted).
    siblings[i] pairs with key bit (255−i), MSB first; bit 0 ⇒ node(cur, sib)."""
    if len(siblings) != SMT_HEIGHT:
        raise ValueError("SMT proof must carry exactly 256 siblings, got %d" % len(siblings))
    key = _need(key, 32, "key")
    cur = SMT_EMPTY_LEAF if value is None else smt_leaf_hash(key, value)
    for i, sib in enumerate(siblings):
        sib = _need(sib, 32, "sibling %d" % i)
        cur = node_hash(cur, sib) if _smt_bit(key, SMT_HEIGHT - 1 - i) == 0 else node_hash(sib, cur)
    return cur

def smt_verify(key, value, siblings, expected_root):
    return smt_fold(key, value, siblings) == _need(expected_root, 32, "root")

# ----- presentation blob (schema §10) -----
def parse_presentation_blob(text):
    """A `/present` blob is either the JSON object itself or base64url(JSON).
    Returns a normalised dict with bytes; raises ValueError."""
    t = text.strip()
    if not t.startswith("{"):
        t = b64u_decode(t).decode("utf-8")
    obj = json.loads(t)
    return normalize_presentation(obj)

def normalize_presentation(obj):
    if not isinstance(obj, dict):
        raise ValueError("presentation must be an object")
    if obj.get("v") != 1 or obj.get("scheme") != "bc30-present-v1":
        raise ValueError("presentation must have v=1, scheme=\"bc30-present-v1\"")
    out = {"leaf": _hexb(obj.get("leaf"), 32, "leaf"), "nonce": _hexb(obj.get("nonce"), 16, "nonce"),
           "verifier_id": _hexb(obj.get("verifier_id"), 32, "verifier_id")}
    exp = obj.get("expiry")
    if not isinstance(exp, int) or isinstance(exp, bool) or exp < 0:
        raise ValueError("presentation.expiry must be a non-negative integer")
    out["expiry"] = exp
    for k in ("authenticator_data", "client_data_json", "signature"):
        out[k] = b64u_decode(obj.get(k) or "")
    out["credential_id"] = obj.get("credential_id")
    return out

def _hexb(h, n, what):
    if not isinstance(h, str) or len(h) != 2 * n or not re.match(r"^[0-9a-fA-F]*$", h):
        raise ValueError("%s must be %d hex chars" % (what, 2 * n))
    return bytes.fromhex(h)

def _hexb_opt(h, n, what):
    return None if h is None else _hexb(h, n, what)

# ----- v4 pipeline (schema §11) -----
GRADES = ("valid", "warning", "undetermined", "rejected")
GRADE_EXIT = {"valid": 0, "rejected": 1, "warning": 2, "undetermined": 3}
STATE_GRADE = {"ok": "valid", "skip": "valid", "warn": "warning", "undet": "undetermined", "bad": "rejected"}
EXIT_USAGE = 64

def reduce_grade(states):
    worst = "valid"
    for st in states:
        g = STATE_GRADE[st]
        if GRADES.index(g) > GRADES.index(worst): worst = g
    return worst

class V4Report(object):
    """Collects the numbered steps of verify_v4 so the same object serves the CLI
    printer, fixtures/v4-expected.json (the oracle) and browser cross-checks."""
    def __init__(self):
        self.steps, self.axes, self.info = [], {"attribution": "none", "presenter": "not checked"}, {}
    def step(self, num, key, state, title, detail=""):
        self.steps.append({"num": num, "key": key, "state": state, "title": title, "detail": detail})
        return state == "ok"
    @property
    def grade(self): return reduce_grade([s["state"] for s in self.steps])
    @property
    def exit_code(self): return GRADE_EXIT[self.grade]
    def summary(self):
        return {"grade": self.grade, "exit_code": self.exit_code, "axes": dict(self.axes),
                "steps": [{"num": s["num"], "key": s["key"], "state": s["state"]} for s in self.steps]}

def _v4_schema_problems(b):
    p = []
    for k in ("record", "merkle", "anchor", "issuer", "aux"):
        if not isinstance(b.get(k), dict): p.append("missing section %r" % k)
    if p: return p
    known = ("schema", "bitcoin_network", "generated_at", "record", "merkle", "anchor", "issuer", "subject", "aux", "presentation", "chain")
    for k in b:
        if k not in known: p.append("unknown top-level key `%s` (a v4 bundle carries only: %s)" % (k, ", ".join(known)))
    if b.get("reconciliation") is not None: p.append("v4 does not allow `reconciliation`")
    if b["anchor"].get("witness_envelope") is not None: p.append("v4 does not allow `witness_envelope`")
    rec, pre = b["record"], b["record"].get("preimage")
    if rec.get("kind") != "issuance": p.append("record.kind must be \"issuance\"")
    if not isinstance(pre, dict): return p + ["record.preimage missing"]
    if pre.get("scheme") != "bc30-leaf-v2": p.append("preimage.scheme must be \"bc30-leaf-v2\"")
    if pre.get("leaf_type") != LEAF_TYPE_ISSUANCE: p.append("preimage.leaf_type must be 1")
    for k, n in (("record_salt", 16), ("doc_sha256", 32), ("subject_ref", 32), ("policy_hash", 32)):
        try: _hexb(pre.get(k), n, "preimage." + k)
        except ValueError as e: p.append(str(e))
    try: _hexb(rec.get("leaf_bytes"), 32, "record.leaf_bytes")
    except ValueError as e: p.append(str(e))
    st = pre.get("subject_type")
    if st not in (0, 1, 2) or isinstance(st, bool): p.append("preimage.subject_type must be 0/1/2")
    for k in ("issued_at", "expires_at"):
        v = pre.get(k)
        if not isinstance(v, int) or isinstance(v, bool) or v < 0: p.append("preimage.%s must be a non-negative integer" % k)
    if isinstance(pre.get("issued_at"), int) and isinstance(pre.get("expires_at"), int) \
            and pre["expires_at"] != 0 and pre["expires_at"] <= pre["issued_at"]:
        p.append("preimage.expires_at must be 0 or later than issued_at")
    if not isinstance(pre.get("policy"), dict): p.append("preimage.policy must be an object")
    # content_type is OPTIONAL and informational. A hash-only issuance (the customer
    # sent the digest, never the file) has no MIME type to state, so its absence is
    # normal and must not fail the bundle; when present it must at least be a string.
    if "content_type" in pre and (not isinstance(pre["content_type"], str) or not pre["content_type"]):
        p.append("preimage.content_type, when present, must be a non-empty string")
    if st == SUBJECT_PUBKEY:
        sub = b.get("subject")
        if not isinstance(sub, dict): p.append("subject section required for subject_type 2")
        else:
            if sub.get("curve_id") != CURVE_P256: p.append("subject.curve_id must be 1 (P-256)")
            try: _hexb(sub.get("public_key"), 33, "subject.public_key")
            except ValueError as e: p.append(str(e))
    iss = b["issuer"]
    try: _hexb(iss.get("issuer_id"), 16, "issuer.issuer_id")
    except ValueError as e: p.append(str(e))
    try: _hexb(iss.get("key_id"), 32, "issuer.key_id")
    except ValueError as e: p.append(str(e))
    if iss.get("alg") not in ALG_NAMES: p.append("issuer.alg must be webauthn-es256 | es256-plain")
    asn = iss.get("assertion")
    if not isinstance(asn, dict): p.append("issuer.assertion missing")
    else:
        need = ("signature_der",) if iss.get("alg") == "es256-plain" else ("authenticator_data", "client_data_json", "signature_der")
        for k in need:
            v = asn.get(k)
            if not isinstance(v, str) or not v or len(v) % 2 or not re.match(r"^[0-9a-fA-F]*$", v):
                p.append("issuer.assertion.%s must be hex" % k)
    aux = b["aux"]
    if aux.get("scheme") != "bc30-aux-v2": p.append("aux.scheme must be \"bc30-aux-v2\"")
    for k in ("tl_root", "sl_root", "envelope_root"):
        try: _hexb(aux.get(k), 32, "aux." + k)
        except ValueError as e: p.append(str(e))
    tle = aux.get("tl_entry")
    if not isinstance(tle, dict): p.append("aux.tl_entry missing")
    else:
        for k, n in (("issuer_id", 16), ("key_id", 32), ("public_key", 33)):
            try: _hexb(tle.get(k), n, "aux.tl_entry." + k)
            except ValueError as e: p.append(str(e))
        if tle.get("curve_id") != CURVE_P256 or isinstance(tle.get("curve_id"), bool): p.append("aux.tl_entry.curve_id must be 1 (P-256)")
        for k in ("valid_from", "valid_to", "revoked_at"):
            v = tle.get(k)
            if not isinstance(v, int) or isinstance(v, bool) or v < 0: p.append("aux.tl_entry.%s must be a non-negative integer" % k)
    if not isinstance(aux.get("tl_proof"), dict): p.append("aux.tl_proof missing")
    m = b["merkle"]
    if not isinstance(m.get("siblings"), list) or not isinstance(m.get("directions"), list): p.append("merkle.siblings/directions must be arrays")
    if not isinstance(b["anchor"].get("op_return_payload_hex"), str): p.append("anchor.op_return_payload_hex missing")
    return p

def verify_v4(bundle, identifier=None, presentation=None, nonce_hex=None, rp_id=None, origins=None,
              now=None, explorer=None, original_bytes=None):
    """docs/bundle-schema.md §11 - 19 numbered steps (0–18), four grades, two axes.
    Never raises on bundle content; every step records ok/bad/warn/undet/skip."""
    R = V4Report()
    rp_id = rp_id or BC30_RP_ID
    origins = list(origins) if origins else list(BC30_ORIGINS)
    now = int(time.time()) if now is None else int(now)
    R.info.update(rp_id=rp_id, origins=origins, now=now)

    # 0 · schema
    probs = _v4_schema_problems(bundle)
    if probs:
        R.step(0, "schema", "bad", "0 · Schema - bundle is not a well-formed v4 issuance bundle", "\n".join(probs))
        return R
    R.step(0, "schema", "ok", "0 · Schema - bitcert-proof-bundle/v4 issuance · network: %s" % bundle.get("bitcoin_network", "?"),
           "sections: record · merkle · anchor · issuer · aux" + (" · subject" if bundle.get("subject") else "")
           + (" · presentation" if bundle.get("presentation") else ""))
    rec, pre, anchor, iss, aux = bundle["record"], bundle["record"]["preimage"], bundle["anchor"], bundle["issuer"], bundle["aux"]
    st = pre["subject_type"]

    # 1 · payload decode (version 0x1F, IDENTITY_BOUND)
    decoded = None
    try:
        decoded = decode_anchor_payload(anchor["op_return_payload_hex"])
        if decoded["format"] != "BC30":
            R.step(1, "payload", "bad", "1 · Anchor payload - %s cannot carry a bound batch (86-byte payload v31 required)" % payload_name(decoded))
        elif decoded["version"] != OP_RETURN_V31_VERSION:
            R.step(1, "payload", "bad", "1 · Anchor payload - version 0x%02x, v4 requires 0x1F" % decoded["version"],
                   "a legacy (0x1E) anchor cannot be presented as identity-bound")
        elif decoded["flags"] & ~FLAGS_DEFINED_MASK_V31:
            R.step(1, "payload", "bad", "1 · Anchor payload - undefined flag bits 0x%02x" % decoded["flags"])
        elif not decoded["flags"] & FLAG_IDENTITY_BOUND:
            R.step(1, "payload", "bad", "1 · Anchor payload - IDENTITY_BOUND (bit 1) not set",
                   "this anchor is not a bound batch; a v4 bundle cannot ride on it")
        elif decoded["flags"] & FLAG_WITNESS_PRESENT:
            R.step(1, "payload", "warn", "1 · Anchor payload - v31, IDENTITY_BOUND + WITNESS_PRESENT",
                   "a bound batch with a witness is undefined in this revision; treated as a warning")
        else:
            R.step(1, "payload", "ok", "1 · Anchor payload - v31 (0x1F), flags 0b%s, IDENTITY_BOUND" % format(decoded["flags"], "02b"),
                   "batch_id: %s\naux_commitment: %s" % (decoded["batch_id"], decoded["aux"]))
    except Exception as e:
        R.step(1, "payload", "bad", "1 · Anchor payload - error", str(e))

    # 2 · policy_hash
    ph = None
    try:
        ph = policy_hash(pre["policy"])
        ok = ph.hex() == pre["policy_hash"].lower()
        R.step(2, "policy", "ok" if ok else "bad", "2 · Policy hash - %s" % ("recomputes ✓" if ok else "MISMATCH ✗"),
               "JCS: %s\nrecomputed: %s" % (policy_jcs(pre["policy"]).decode("utf-8"), ph.hex()))
    except Exception as e:
        R.step(2, "policy", "bad", "2 · Policy hash - error", str(e))

    # 3 · subject_ref
    salt, ref = bytes.fromhex(pre["record_salt"]), bytes.fromhex(pre["subject_ref"])
    subject_pk = None
    if st == SUBJECT_NONE:
        ok = ref == subject_ref_none()
        R.step(3, "subject", "ok" if ok else "bad", "3 · Subject - none (subject_ref %s)" % ("is zero ✓" if ok else "must be zero ✗"))
        R.axes["attribution"] = "none"
    elif st == SUBJECT_ID_HASH:
        R.axes["attribution"] = "issuer-claim · identifier"
        if identifier is None:
            R.step(3, "subject", "skip", "3 · Subject - identifier hash, not checked",
                   "pass --identifier <the identifier the issuer wrote> to recompute SHA256(record_salt ‖ identifier)")
            R.axes["attribution"] += " · not checked"
        else:
            got = subject_ref_id_hash(salt, identifier)
            ok = got == ref
            R.step(3, "subject", "ok" if ok else "bad", "3 · Subject - identifier %s the salted reference" % ("matches ✓" if ok else "does NOT match ✗"),
                   "SHA256(record_salt ‖ identifier): %s" % got.hex())
            R.axes["attribution"] += " ✓" if ok else " ✗"
    else:
        R.axes["attribution"] = "issuer-claim · pubkey"
        try:
            sub = bundle["subject"]
            subject_pk = bytes.fromhex(sub["public_key"])
            p256_decompress(subject_pk)                       # on-curve, canonical x
            got = subject_ref_pubkey(sub["curve_id"], subject_pk)
            ok = got == ref
            R.step(3, "subject", "ok" if ok else "bad", "3 · Subject - registered key %s subject_ref" % ("normalises to ✓" if ok else "does NOT match ✗"),
                   "SHA256(0x02 ‖ curve 0x01 ‖ pubkey): %s\npublic_key: %s" % (got.hex(), sub["public_key"]))
            if not ok: subject_pk = None
        except Exception as e:
            R.step(3, "subject", "bad", "3 · Subject - public key unusable", str(e))

    # 4 · R and m
    Rb = m = None
    try:
        doc = bytes.fromhex(pre["doc_sha256"])
        args = (salt, doc, st, ref, pre["issued_at"], pre["expires_at"], bytes.fromhex(pre["policy_hash"]))
        Rb, m = record_bytes(*args), issue_message(*args)
        R.info.update(m_hex=m.hex(), m_b64u=b64u_encode(m))
        detail = "m: %s\nchallenge (base64url): %s" % (m.hex(), b64u_encode(m))
        if original_bytes is not None:
            got = sha256(original_bytes)
            if got == doc:
                R.step(4, "record", "ok", "4 · Record R · message m - reconstructed, original binds to H(D) ✓", detail + "\nSHA256(original): %s" % got.hex())
            else:
                R.step(4, "record", "bad", "4 · Record R · message m - supplied original does NOT hash to doc_sha256 ✗",
                       detail + "\nSHA256(original): %s\ndoc_sha256:       %s" % (got.hex(), doc.hex()))
        else:
            R.step(4, "record", "ok", "4 · Record R · message m - reconstructed (143 B record)", detail + "\noriginal not supplied - H(D) taken from the bundle")
    except Exception as e:
        R.step(4, "record", "bad", "4 · Record R · message m - error", str(e))

    # 5 · issuer signature
    s_bytes, issuer_pk = None, None
    try:
        issuer_pk = bytes.fromhex(aux["tl_entry"]["public_key"])
        asn, alg = iss["assertion"], ALG_NAMES[iss["alg"]]
        sig = bytes.fromhex(asn["signature_der"])
        if m is None:
            raise ValueError("message m unavailable")
        if alg == ALG_WEBAUTHN_ES256:
            ad, cdj = bytes.fromhex(asn["authenticator_data"]), bytes.fromhex(asn["client_data_json"])
            ok, reasons, facts = webauthn_verify_assertion(issuer_pk, ad, cdj, sig, m, rp_id, origins)
            s_bytes = issuer_sig_bytes(alg, sig, ad, cdj)
            R.info["issuer_facts"] = facts
            detail = ("rpId: claimed %r · pinned %r\norigin: %s\nUV: %s · UP: %s · signCount: %s"
                      % (iss.get("rp_id"), rp_id, facts.get("origin"), facts.get("uv"), facts.get("up"), facts.get("sign_count")))
            R.step(5, "issuer_sig", "ok" if ok else "bad",
                   "5 · Issuer signature - webauthn-es256 %s" % ("verifies ✓" if ok else "REJECTED ✗"),
                   detail + ("" if ok else "\n" + "\n".join("· " + r for r in reasons)))
        else:
            ok = p256_verify(issuer_pk, m, sig)
            s_bytes = issuer_sig_bytes(alg, sig)
            R.step(5, "issuer_sig", "ok" if ok else "bad",
                   "5 · Issuer signature - es256-plain %s" % ("verifies ✓" if ok else "REJECTED ✗"),
                   "ES256 over m under key_id %s" % iss["key_id"])
    except Exception as e:
        R.step(5, "issuer_sig", "bad", "5 · Issuer signature - error", str(e))

    # 6 · leaf_input
    li = None
    try:
        if Rb is None or s_bytes is None:
            raise ValueError("record or signature bytes unavailable")
        li = leaf_input_v2(LEAF_TYPE_ISSUANCE, Rb, s_bytes)
        ok = li.hex() == rec["leaf_bytes"].lower()
        R.info["leaf_input"] = li.hex()
        R.step(6, "leaf", "ok" if ok else "bad", "6 · leaf_input - SHA256(leaf-v2 tag ‖ 0x01 ‖ R ‖ s) %s record.leaf_bytes" % ("== ✓" if ok else "≠ ✗"),
               "recomputed: %s\nclaimed:    %s" % (li.hex(), rec["leaf_bytes"]))
    except Exception as e:
        R.step(6, "leaf", "bad", "6 · leaf_input - error", str(e))

    # 7 · merkle inclusion (existing verify_merkle over record.leaf_bytes; step 6 bound it to the recomputation)
    merkle_root = None
    claimed_leaf = bytes.fromhex(rec["leaf_bytes"])
    try:
        computed, ok = verify_merkle(rec, bundle["merkle"])
        merkle_root = computed if ok else None
        R.step(7, "merkle", "ok" if ok else "bad", "7 · Merkle inclusion - leaf is %s the root" % ("in" if ok else "NOT in"),
               "recomputed root: %s" % computed + ("" if ok else "\nclaimed root:    %s" % bundle["merkle"].get("root")))
    except Exception as e:
        R.step(7, "merkle", "bad", "7 · Merkle inclusion - error", str(e))

    # 8 · anchor output root
    if decoded is not None and merkle_root is not None:
        ok = decoded["merkle_root"].lower() == merkle_root.lower()
        R.step(8, "root", "ok" if ok else "bad", "8 · Anchor output - merkle_root is %s on-chain" % ("committed ✓" if ok else "NOT committed ✗"),
               "payload merkle_root: %s" % decoded["merkle_root"])
    else:
        R.step(8, "root", "bad", "8 · Anchor output - cannot compare (payload or root unavailable)")

    # 9 · trust-list entry + inclusion
    tle = aux["tl_entry"]
    try:
        pk = bytes.fromhex(tle["public_key"])
        if tle.get("curve_id") != CURVE_P256: raise ValueError("tl_entry.curve_id must be 1")
        kid = key_id(tle["curve_id"], pk)
        probs = []
        if kid.hex() != str(tle.get("key_id", "")).lower(): probs.append("tl_entry.key_id ≠ SHA256(0x02‖curve‖pubkey)")
        if kid.hex() != iss["key_id"].lower(): probs.append("issuer.key_id ≠ tl_entry key")
        if str(tle.get("issuer_id", "")).lower() != iss["issuer_id"].lower(): probs.append("issuer.issuer_id ≠ tl_entry.issuer_id")
        entry = tl_entry_bytes(bytes.fromhex(tle["issuer_id"]), kid, tle["curve_id"], pk,
                               tle["valid_from"], tle["valid_to"], tle["revoked_at"])
        tp = aux["tl_proof"]
        computed, inc = verify_merkle({"leaf_bytes": tl_leaf(entry).hex()},
                                      {"root": aux["tl_root"], "siblings": tp.get("siblings", []), "directions": tp.get("directions", [])})
        if not inc: probs.append("tl_entry is not in tl_root (recomputed %s)" % computed)
        R.step(9, "trust_list", "ok" if not probs else "bad",
               "9 · Trust list - issuer key %s the anchored list" % ("is in ✓" if not probs else "NOT proven ✗"),
               "key_id: %s\nissuer_id: %s\nvalid_from %s · valid_to %s · revoked_at %s" % (kid.hex(), tle["issuer_id"],
                tle["valid_from"], tle["valid_to"], tle["revoked_at"]) + ("" if not probs else "\n" + "\n".join("· " + x for x in probs)))
    except Exception as e:
        R.step(9, "trust_list", "bad", "9 · Trust list - error", str(e))

    # 10 · envelope_root
    ok = aux["envelope_root"].lower() == envelope_root_none().hex()
    R.step(10, "envelope", "ok" if ok else "bad", "10 · Envelope root - %s" % ("constant (envelope-none tag) ✓" if ok else "unexpected value ✗"),
           "" if ok else "expected %s" % envelope_root_none().hex())

    # 11 · aux recompute
    try:
        got = aux_commitment(bytes.fromhex(aux["tl_root"]), bytes.fromhex(aux["sl_root"]), bytes.fromhex(aux["envelope_root"]))
        if decoded is None or decoded.get("format") != "BC30":
            R.step(11, "aux", "bad", "11 · aux_commitment - no 86-byte payload to compare against", "recomputed: %s" % got.hex())
        else:
            ok = got.hex() == decoded["aux"].lower()
            R.step(11, "aux", "ok" if ok else "bad", "11 · aux_commitment - SHA256(aux tag ‖ TL ‖ SL ‖ env) %s on-chain" % ("matches ✓" if ok else "MISMATCH ✗"),
                   "recomputed: %s\non-chain:   %s" % (got.hex(), decoded["aux"]))
    except Exception as e:
        R.step(11, "aux", "bad", "11 · aux_commitment - error", str(e))

    # 12 · key validity at block time (tl_entry fields are schema-checked integers; still never raise)
    bt = None
    try:
        confirmed = anchor.get("confirmed")
        bt = confirmed.get("block_time") if isinstance(confirmed, dict) else None
        if not isinstance(bt, int) or isinstance(bt, bool) or bt <= 0:
            bt = None
            R.step(12, "key_validity", "undet", "12 · Key validity - no block_time in the bundle",
                   "the issuer key's validity window is judged at the BLOCK time, not at issued_at; without it the outcome is undetermined")
        else:
            R.info["block_time"] = bt
            vf, vt, ra = tle["valid_from"], tle["valid_to"], tle["revoked_at"]
            probs = []
            if vf > bt: probs.append("valid_from %d is after block_time %d" % (vf, bt))
            if vt and vt < bt: probs.append("valid_to %d is before block_time %d" % (vt, bt))
            if ra and ra <= bt: probs.append("key revoked at %d, on or before block_time %d" % (ra, bt))
            if probs:
                R.step(12, "key_validity", "bad", "12 · Key validity - issuer key NOT valid at block time ✗", "\n".join(probs))
            elif pre["issued_at"] > bt + 7200:
                R.step(12, "key_validity", "warn", "12 · Key validity - key valid, but issued_at is more than 2 h after the block",
                       "issued_at %d · block_time %d (self-reported time is only sanity-checked)" % (pre["issued_at"], bt))
            else:
                R.step(12, "key_validity", "ok", "12 · Key validity - issuer key valid at block time ✓",
                       "block_time %d · valid_from %d · valid_to %s · revoked_at %s" % (bt, vf, vt or "none", ra or "none"))
    except Exception as e:
        R.step(12, "key_validity", "bad", "12 · Key validity - error", str(e))

    # 13 · txid binding
    txid = anchor.get("reveal_txid")
    raw = anchor.get("reveal_tx_hex")
    if not raw:
        R.step(13, "txid", "undet", "13 · Transaction binding - no reveal_tx_hex", "a v4 bundle without the raw transaction cannot bind the payload to a txid")
    else:
        try:
            computed_txid, anchor_payload = txid_from_raw(raw)
            txid_ok = computed_txid.lower() == (txid or "").lower()
            op_ok = (anchor_payload or "").lower() == anchor["op_return_payload_hex"].lower()
            ok = txid_ok and op_ok
            if ok: txid = computed_txid
            R.step(13, "txid", "ok" if ok else "bad", "13 · Transaction binding - payload %s txid" % ("belongs to ✓" if ok else "does NOT match ✗"),
                   "computed txid: %s\nbundle  txid: %s\npayload in raw tx %s" % (computed_txid, anchor.get("reveal_txid"), "matches ✓" if op_ok else "MISMATCH ✗"))
        except Exception as e:
            R.step(13, "txid", "bad", "13 · Transaction binding - error", str(e))
    R.info["txid"] = txid

    # 14 · document expiry
    exp = pre["expires_at"]
    if exp == 0:
        R.step(14, "expiry", "ok", "14 · Document expiry - none declared")
    elif exp < now:
        R.step(14, "expiry", "warn", "14 · Document expiry - EXPIRED", "expires_at %d < now %d" % (exp, now))
    else:
        R.step(14, "expiry", "ok", "14 · Document expiry - valid until %d" % exp, "now %d" % now)

    # 15 · revocation at anchor time (SL exclusion)
    sp = aux.get("sl_proof")
    if not isinstance(sp, dict):
        R.step(15, "revocation", "undet", "15 · Revocation at anchor - no sl_proof in the bundle",
               "without an exclusion proof against sl_root the revocation status at anchor time is undetermined")
    else:
        try:
            key = _hexb(sp.get("key"), 32, "sl_proof.key")
            if key != claimed_leaf:
                raise ValueError("sl_proof.key is not this record's leaf_input")
            sibs = sp.get("siblings")
            if not isinstance(sibs, list) or len(sibs) != SMT_HEIGHT:
                raise ValueError("sl_proof must carry exactly 256 siblings")
            sibs = [_hexb(x, 32, "sibling") for x in sibs]
            val = _hexb_opt(sp.get("value"), 32, "sl_proof.value")
            folded = smt_fold(key, val, sibs)
            if folded.hex() != aux["sl_root"].lower():
                R.step(15, "revocation", "bad", "15 · Revocation at anchor - proof does NOT fold to sl_root ✗",
                       "folded: %s\nsl_root: %s\n(exclusion folds from the pinned EMPTY_LEAF %s)" % (folded.hex(), aux["sl_root"], SMT_EMPTY_LEAF.hex()))
            elif val is not None:
                ra = int.from_bytes(val[24:], "big")
                R.step(15, "revocation", "bad", "15 · Revocation at anchor - record was ALREADY REVOKED when anchored ✗",
                       "sl value: %s (revoked_at %d)" % (val.hex(), ra))
            else:
                R.step(15, "revocation", "ok", "15 · Revocation at anchor - not revoked (exclusion proof) ✓",
                       "sl_root: %s\nlater revocation needs an online status-list check (not part of this bundle)" % aux["sl_root"])
        except Exception as e:
            R.step(15, "revocation", "bad", "15 · Revocation at anchor - invalid proof", str(e))

    # 16 · presentation (presenter check) - never rejects; degrades to "not available"
    pres = presentation if presentation is not None else bundle.get("presentation")
    if st != SUBJECT_PUBKEY:
        R.axes["presenter"] = "not available"
        R.step(16, "presentation", "skip", "16 · Presenter - not applicable (no registered recipient key)",
               "only a subject_type 2 record can be presented with a passkey" + ("" if pres is None else "\nsupplied presentation ignored"))
    elif pres is None:
        R.axes["presenter"] = "not available"
        R.step(16, "presentation", "skip", "16 · Presenter - no presentation supplied",
               "start a presenter check (--present-url) and pass the /present blob with --present + --nonce to confirm the holder")
    else:
        try:
            p = normalize_presentation(pres) if not (isinstance(pres, dict) and isinstance(pres.get("leaf"), bytes)) else pres
            probs = []
            if p["leaf"] != claimed_leaf: probs.append("presentation is for a different record (leaf mismatch)")
            if nonce_hex is None: probs.append("nonce ownership not established - pass --nonce <hex you generated>")
            elif p["nonce"].hex() != nonce_hex.lower(): probs.append("presentation nonce is not ours (replay from another verifier?)")
            if p["expiry"] < now: probs.append("presentation expired (expiry %d < now %d)" % (p["expiry"], now))
            if subject_pk is None: probs.append("subject key unusable (see step 3)")
            facts = {}
            if subject_pk is not None:
                ch = present_challenge(p["nonce"], p["leaf"], p["verifier_id"], p["expiry"])
                ok, reasons, facts = webauthn_verify_assertion(subject_pk, p["authenticator_data"], p["client_data_json"], p["signature"], ch, rp_id, origins)
                probs += reasons
                R.info["present_challenge"] = ch.hex()
            detail = "nonce %s · expiry %d · verifier_id %s\nrpId pinned %r · origin %s · UV %s" % (
                p["nonce"].hex(), p["expiry"], p["verifier_id"].hex(), rp_id, facts.get("origin"), facts.get("uv"))
            if probs:
                R.axes["presenter"] = "not available"
                R.step(16, "presentation", "warn", "16 · Presenter - NOT confirmed (degraded, not rejected)", detail + "\n" + "\n".join("· " + x for x in probs))
            else:
                R.axes["presenter"] = "confirmed"
                R.step(16, "presentation", "ok", "16 · Presenter - holder of the registered key confirmed ✓", detail)
        except Exception as e:
            R.axes["presenter"] = "not available"
            R.step(16, "presentation", "warn", "16 · Presenter - presentation unreadable (degraded)", str(e))

    # 17 · chain (§5, optional)
    ch = bundle.get("chain")
    if ch and isinstance(ch, dict) and ch.get("entry"):
        try:
            e = ch["entry"]
            phash = payload_hash(e)
            ph_ok = phash.lower() == str(e.get("payload_hash", "")).lower()
            body_ok = True if e.get("kind") != "daily" else (merkle_root is not None and str(e.get("body_hash", "")).lower() == merkle_root.lower())
            link_ok, link_detail = _verify_chain_links(ch.get("links") or [], e)
            ok = ph_ok and body_ok and link_ok
            R.step(17, "chain", "ok" if ok else "bad", "17 · Chain entry - payload_hash %s" % ("recomputes ✓" if ok else "MISMATCH ✗"),
                   "seq %s (%s)\nrecomputed payload_hash: %s%s" % (e.get("seq"), e.get("kind"), phash, ("\n" + link_detail) if link_detail else ""))
        except Exception as e:
            R.step(17, "chain", "bad", "17 · Chain entry - error", str(e))
    else:
        R.step(17, "chain", "skip", "17 · Chain entry - none carried")

    # 18 · on-chain (optional; compares block_time with the source YOU chose)
    if explorer and txid:
        try:
            confirmed, stt = check_on_chain(explorer, txid)
            if not confirmed:
                R.step(18, "onchain", "warn", "18 · On-chain - seen but not yet confirmed via %s" % explorer)
            elif isinstance(bt, int) and stt.get("block_time") not in (None, bt):
                R.step(18, "onchain", "warn", "18 · On-chain - confirmed, but block_time differs from the bundle",
                       "explorer block_time %s · bundle %s" % (stt.get("block_time"), bt))
            else:
                R.step(18, "onchain", "ok", "18 · On-chain - confirmed via %s" % explorer,
                       "block height %s · block_time %s" % (stt.get("block_height"), stt.get("block_time")))
        except Exception as e:
            R.step(18, "onchain", "warn", "18 · On-chain - could not reach explorer", "%s\nsteps 1–15 are already proven offline" % e)
    else:
        R.step(18, "onchain", "skip", "18 · On-chain confirmation - SKIPPED (offline / no --explorer)",
               "txid: %s\npass --explorer <url> (any Bitcoin source, never BitCert) to confirm and compare block_time" % txid)
    return R

def present_url(console, leaf_input_hex, nonce, verifier_id, expiry):
    return "%s/present?v=1&leaf=%s&nonce=%s&vid=%s&exp=%d" % (
        console.rstrip("/"), leaf_input_hex, nonce.hex(), verifier_id.hex(), expiry)

def leaf_input_from_bundle(bundle):
    """Recompute leaf_input from a v4 bundle's preimage + issuer pieces (no verification)."""
    pre, iss, aux = bundle["record"]["preimage"], bundle["issuer"], bundle["aux"]
    args = (bytes.fromhex(pre["record_salt"]), bytes.fromhex(pre["doc_sha256"]), pre["subject_type"],
            bytes.fromhex(pre["subject_ref"]), pre["issued_at"], pre["expires_at"], bytes.fromhex(pre["policy_hash"]))
    asn, alg = iss["assertion"], ALG_NAMES[iss["alg"]]
    sig = bytes.fromhex(asn["signature_der"])
    s = issuer_sig_bytes(alg, sig, bytes.fromhex(asn["authenticator_data"]), bytes.fromhex(asn["client_data_json"])) \
        if alg == ALG_WEBAUTHN_ES256 else issuer_sig_bytes(alg, sig)
    return leaf_input_v2(LEAF_TYPE_ISSUANCE, record_bytes(*args), s)

# ----- --selftest -----
# RFC 6979 §A.2.5 "ECDSA, 256 Bits (Prime Field)" - copied from the RFC text
# (https://www.rfc-editor.org/rfc/rfc6979.txt) and cross-checked against the
# vendored p256-0.13.2 crate (src/ecdsa.rs, test `rfc6979`). Not typed from memory.
RFC6979_A25 = {
    "x":  "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
    "Ux": "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
    "Uy": "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
    "sample": {"k": "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60",
               "r": "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
               "s": "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"},
    "test":   {"k": "D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0",
               "r": "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
               "s": "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"},
}

def selftest(vectors_path=None):
    fails = []
    def check(cond, label):
        _line("ok" if cond else "bad", label)
        if not cond: fails.append(label)
    V = RFC6979_A25
    x = int(V["x"], 16)
    U = _ec_mul(_P256_G, x)
    check(U == (int(V["Ux"], 16), int(V["Uy"], 16)), "RFC 6979 A.2.5 - x·G == (Ux, Uy) (generator, field, arithmetic)")
    pub = p256_compress(U)
    check(p256_decompress(pub) == U, "RFC 6979 A.2.5 - compressed key decompresses to Uy (curve b)")
    check(p256_decompress(bytes([2 + (1 - (U[1] & 1))]) + pub[1:]) == (U[0], _P256_P - U[1]), "decompress - opposite parity prefix yields −y")
    for msg in ("sample", "test"):
        r, s = int(V[msg]["r"], 16), int(V[msg]["s"], 16)
        check(p256_verify(pub, msg.encode(), rs_to_der(r, s)), "RFC 6979 A.2.5 - SHA-256(%r) signature verifies" % msg)
        check(not p256_verify(pub, (msg + "!").encode(), rs_to_der(r, s)), "RFC 6979 A.2.5 - altered message %r fails" % msg)
        check(p256_verify(pub, msg.encode(), rs_to_der(r, _P256_N - s)), "RFC 6979 A.2.5 - (r, n−s) also verifies (low-s deliberately not enforced)")
    r, s = int(V["sample"]["r"], 16), int(V["sample"]["s"], 16)
    good = rs_to_der(r, s)
    def rejects(sig, label):
        try: der_to_rs(sig); check(False, "DER strict - %s rejected" % label)
        except ValueError: check(True, "DER strict - %s rejected" % label)
    rejects(good + b"\x00", "trailing byte")
    rejects(good[:-1], "truncated")
    sint = good[2 + 2 + good[3]:]                                   # the minimal INTEGER for s
    nonmin = b"\x02\x22\x00\x00" + r.to_bytes(32, "big")         # r has its MSB set: one 0x00 is minimal, two are not
    rejects(b"\x30" + bytes([len(nonmin) + len(sint)]) + nonmin + sint, "non-minimal leading 0x00 (MSB-set value)")
    rejects(b"\x30\x07\x02\x02\x00\x01\x02\x01\x01", "non-minimal leading 0x00 (small value)")
    rejects(rs_to_der(r, 0)[:], "s = 0")
    rejects(rs_to_der(_P256_N, s), "r = n")
    rejects(b"\x30\x81" + bytes([len(good) - 2]) + good[2:], "long-form length")
    check(der_to_rs(good) == (r, s), "DER strict - canonical encoding round-trips")
    bad_x = b"\x02" + b"\xff" * 32
    try: p256_decompress(bad_x); check(False, "decompress - x ≥ p rejected")
    except ValueError: check(True, "decompress - x ≥ p rejected")
    check(SMT_EMPTY_LEAF.hex() == sha256(b"\x11").hex() and len(SMT_DEFAULTS) == 257, "SMT - pinned EMPTY_LEAF = SHA256(0x11), 257 defaults")
    check(smt_verify(bytes(32), None, [SMT_DEFAULTS[i] for i in range(256)], SMT_EMPTY_ROOT), "SMT - exclusion proof of an empty tree folds to SMT_EMPTY_ROOT")
    check(not smt_verify(bytes(32), bytes(32), [SMT_DEFAULTS[i] for i in range(256)], SMT_EMPTY_ROOT), "SMT - value=0×32 does NOT masquerade as empty")
    check(b64u_decode(b64u_encode(bytes(range(256)))) == bytes(range(256)), "base64url - round-trip 256 bytes")
    # fixture assertion (bc30-v2-vectors.json) - the same file ann-core and the console pin
    import os
    path = vectors_path or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures", "bc30-v2-vectors.json")
    if os.path.exists(path):
        # fixtures/bc30-v2-vectors.json is a byte-identical copy of the ENGINE's
        # ann-core/crates/bc30-leaf/tests/vectors/bc30-v2-kat.json (the canonical KAT,
        # PM decision 2026-08-25). Every derived field below is recomputed from that
        # file's INPUTS with this verifier's builders and must match byte for byte.
        # fixtures/engine-kat-check.py is the exhaustive version (also rebuilds the
        # trees); this is the subset a standalone verify.py can check by itself.
        with open(path, "r", encoding="utf-8") as f:
            vec = json.load(f)
        h = bytes.fromhex
        policy = {"document_type": vec["policy_document_type"], "jurisdiction": vec["policy_jurisdiction"]}
        ph_ = policy_hash(policy)
        check(ph_.hex() == vec["policy_hash"] and policy_jcs(policy).decode("utf-8") == vec["policy_jcs"], "vectors - policy_hash + JCS")
        check(sha256(vec["doc_utf8"].encode("utf-8")).hex() == vec["doc_sha256"], "vectors - doc_sha256 = SHA256(doc_utf8)")
        salt = h(vec["record_salt"])
        check(subject_ref_none().hex() == vec["subject_ref_none"], "vectors - subject_ref 0x00")
        check(subject_ref_id_hash(salt, vec["subject_identifier"]).hex() == vec["subject_ref_id_hash"], "vectors - subject_ref 0x01 (salted identifier)")
        check(subject_ref_pubkey(CURVE_P256, h(vec["subject_pub33"])).hex() == vec["subject_ref_pubkey"], "vectors - subject_ref 0x02 (registered key)")
        st = vec["subject_type"]
        ref = {0: subject_ref_none(), 1: h(vec["subject_ref_id_hash"]), 2: h(vec["subject_ref_pubkey"])}[st]
        args = (salt, h(vec["doc_sha256"]), st, ref, vec["issued_at"], vec["expires_at"], ph_)
        check(record_bytes(*args).hex() == vec["R"], "vectors - R (143 B, subject_type %d)" % st)
        check(issue_message(*args).hex() == vec["m"], "vectors - m")
        check(b64u_encode(issue_message(*args)) == vec["challenge_b64u"], "vectors - challenge_b64u")
        ad, cdj, sig = h(vec["authenticator_data"]), h(vec["client_data_json"]), h(vec["signature_der"])
        check(ad == sha256(vec["rp_id"].encode()) + b"\x05" + vec["sign_count"].to_bytes(4, "big"), "vectors - authenticator_data = SHA256(rpId) ‖ 0x05 ‖ signCount")
        check(sha256(vec["rp_id"].encode()).hex() == vec["rp_id_hash"], "vectors - rp_id_hash")
        ok, reasons, _ = webauthn_verify_assertion(h(vec["issuer_pub33"]), ad, cdj, sig, h(vec["m"]), vec["rp_id"], [vec["origin"]])
        check(ok, "vectors - engine's issuer WebAuthn assertion verifies" + ("" if ok else " (%s)" % "; ".join(reasons)))
        check(p256_verify(h(vec["issuer_pub33"]), h(vec["m"]), h(vec["signature_der_plain"])), "vectors - engine's es256-plain signature over m verifies")
        s1 = issuer_sig_bytes(ALG_WEBAUTHN_ES256, sig, ad, cdj); s2 = issuer_sig_bytes(ALG_ES256_PLAIN, h(vec["signature_der_plain"]))
        check(s1.hex() == vec["s_webauthn"], "vectors - s_webauthn (0x01)")
        check(s2.hex() == vec["s_es256_plain"], "vectors - s_es256_plain (0x02)")
        check(leaf_input_v2(vec["leaf_type"], h(vec["R"]), s1).hex() == vec["leaf_input"], "vectors - leaf_input (webauthn)")
        check(leaf_input_v2(vec["leaf_type"], h(vec["R"]), s2).hex() == vec["leaf_input_es256_plain"], "vectors - leaf_input_es256_plain")
        check(leaf_hash(h(vec["leaf_input"])).hex() == vec["leaf_hash"] and leaf_hash(h(vec["leaf_input_es256_plain"])).hex() == vec["leaf_hash_es256_plain"], "vectors - leaf_hash (both)")
        kid = key_id(CURVE_P256, h(vec["issuer_pub33"]))
        check(kid.hex() == vec["tl_key_id"], "vectors - tl_key_id = SHA256(0x02‖curve‖pubkey)")
        eb = tl_entry_bytes(h(vec["tl_issuer_id"]), kid, CURVE_P256, h(vec["issuer_pub33"]), vec["tl_valid_from"], vec["tl_valid_to"], vec["tl_revoked_at"])
        check(eb.hex() == vec["tl_entry"], "vectors - tl_entry (116 B)")
        check(tl_leaf(eb).hex() == vec["tl_entry_leaf"], "vectors - tl_entry_leaf = SHA256(entry)")
        check(leaf_hash(tl_leaf(eb)).hex() == vec["tl_root_single"], "vectors - tl_root_single = H_leaf(SHA256(entry))")
        tp = vec["tl_proof_three"]
        _, inc = verify_merkle({"leaf_bytes": vec["tl_entry_leaf"]}, {"root": vec["tl_root_three"], "siblings": tp["siblings"], "directions": tp["directions"]})
        check(inc, "vectors - tl_proof_three folds to tl_root_three")
        check(tl_root_none().hex() == vec["tl_root_none"], "vectors - tl_root_none")
        check(SMT_EMPTY_LEAF.hex() == vec["empty_leaf"] and SMT_EMPTY_ROOT.hex() == vec["smt_empty_root"], "vectors - empty_leaf / smt_empty_root")
        check(envelope_root_none().hex() == vec["envelope_root"], "vectors - envelope_root")
        ai = vec["aux_inputs"]
        check(aux_commitment(h(ai["tl_root"]), h(ai["sl_root"]), h(ai["envelope_root"])).hex() == vec["aux_commitment"], "vectors - aux_commitment")
        check(AUX_COMMITMENT_NONE.hex() == vec["aux_commitment_none"], "vectors - aux_commitment_none")
        check(bc30_v31(h(vec["op_return_merkle_root"]), h(vec["op_return_batch_id"]), h(vec["aux_commitment"]), flags=vec["op_return_flags"]).hex() == vec["op_return_v31"], "vectors - op_return_v31 (86 B)")
        ex, inc_ = vec["sl_proof_exclusion"], vec["sl_proof_inclusion"]
        check(smt_verify(h(ex["key"]), None, [h(x) for x in ex["siblings"]], h(vec["sl_root"])), "vectors - SL exclusion proof folds from the pinned EMPTY_LEAF to sl_root")
        check(smt_verify(h(inc_["key"]), h(inc_["value"]), [h(x) for x in inc_["siblings"]], h(vec["sl_root"])), "vectors - SL inclusion proof folds to sl_root")
        vid = make_verifier_id(vec["present_verifier_label"], h(vec["present_verifier_rand16"]))
        check(vid.hex() == vec["present_verifier_id"], "vectors - present_verifier_id")
        ch = present_challenge(h(vec["present_nonce"]), h(vec["leaf_input"]), vid, vec["present_expiry"])
        check(ch.hex() == vec["present_challenge"] and b64u_encode(ch) == vec["present_challenge_b64u"], "vectors - present_challenge (+ b64u)")
        ok, reasons, _ = webauthn_verify_assertion(h(vec["subject_pub33"]), h(vec["present_authenticator_data"]), h(vec["present_client_data_json"]),
                                                    h(vec["present_signature_der"]), ch, vec["rp_id"], [vec["origin"]])
        check(ok, "vectors - engine's presentation assertion verifies under subject key" + ("" if ok else " (%s)" % "; ".join(reasons)))
    else:
        _line("skip", "vectors - fixtures/bc30-v2-vectors.json not found (skipped)")
    print()
    if fails:
        print("%s✗ SELFTEST FAILED%s - %d check(s)" % (BAD, RST, len(fails)))
        return 1
    print("%s✓ SELFTEST OK%s - P-256/ES256, DER, SMT, base64url, KAT vectors" % (OK, RST))
    return 0

# ----- on-chain (optional, stdlib urllib) -----
def check_on_chain(base, txid):
    import urllib.request
    url = base.rstrip("/") + "/api/tx/" + txid
    with urllib.request.urlopen(url, timeout=15) as r:
        tx = json.loads(r.read().decode("utf-8"))
    st = tx.get("status", {})
    return bool(st.get("confirmed")), st

# ----- driver -----
def _line(state, title, detail=""):
    mark = {"ok": OK + "✓", "bad": BAD + "✗", "warn": WARN + "!",
            "skip": SKIP + "–", "undet": UNDET + "?"}[state] + RST
    print("  %s %s" % (mark, title))
    if detail:
        for d in detail.split("\n"):
            print("      " + DIM + d + RST)

def verify_bundle(bundle, explorer=None, original_bytes=None, account_id=None, salt_hex=None):
    """Legacy (v1–v3) pipeline. Returns a grade: "valid" | "rejected" | "undetermined"
    (the last only when a v3 `zk` section is present - this CLI does not verify it)."""
    if bundle.get("schema") not in SCHEMAS:
        _line("bad", "Unsupported schema", "expected one of %s, got %r" % (", ".join(SCHEMAS + (SCHEMA_V4,)), bundle.get("schema")))
        return "rejected"
    _line("ok", "Schema %s · network: %s" % (bundle["schema"], bundle.get("bitcoin_network", "?")))

    has_anchor = all(isinstance(bundle.get(k), dict) for k in ("record", "merkle", "anchor"))
    undetermined = False
    if bundle.get("zk") is not None:
        undetermined = True
        _line("undet", "zk · Zero-knowledge statement - not verified by this CLI (UNDETERMINED)",
              "the bulletproofs verifier lives in zk-core.js / index.html; open the browser verifier for this section")
        if not has_anchor:
            print()
            print("%s? UNDETERMINED%s - the bundle carries only a zk section, which this CLI cannot check." % (UNDET, RST))
            return "undetermined"
    elif not has_anchor:
        _line("bad", "Nothing to verify", "a bundle must carry record + merkle + anchor (or, for v3, a zk section)")
        return "rejected"

    # Witness-inscription bundles carry the original IN the reveal witness; they
    # verify via a dedicated path (bind recovered bytes -> record.leaf_bytes).
    if bundle.get("anchor", {}).get("witness_envelope"):
        ok = verify_witness_bundle(bundle, explorer)
        return "rejected" if not ok else ("undetermined" if undetermined else "valid")

    all_ok = True

    # §2.1 preimage - original record -> leaf_bytes (link A)
    try:
        pre = verify_preimage(bundle["record"], original_bytes, account_id, salt_hex)
        if pre is None:
            _line("skip", "0 · Original binding - no preimage rule in bundle",
                  "proves a 32-byte digest is anchored, not that it is your document/balance")
        elif pre.get("status") == "need_original":
            _line("warn", "0 · Original binding - supply the original to bind it",
                  "scheme sha256-file: pass --original <file> to hash it and match leaf_bytes")
        else:
            self_ok = pre.get("self_ok", False)
            detail = "scheme %s\nrecomputed leaf_bytes: %s" % (pre["scheme"], pre.get("computed", ""))
            ident = pre.get("identity_ok")
            if ident is not None:
                detail += "\nidentity (account+salt -> user_commitment): %s" % ("match ✓" if ident else "MISMATCH ✗")
            ok = self_ok and (ident is not False)
            label = ("original → leaf_bytes matches" if pre["scheme"] == "sha256-file"
                     else "leaf_bytes = hash(declared fields)")
            _line("ok" if ok else "bad",
                  "0 · Original binding - %s %s" % (label, "✓" if ok else "✗"), detail)
            all_ok &= ok
    except Exception as e:
        all_ok = False; _line("bad", "0 · Original binding - error", str(e))

    # §3 merkle
    merkle_root = None
    try:
        computed, ok = verify_merkle(bundle["record"], bundle["merkle"])
        merkle_root = bundle["merkle"]["root"]
        _line("ok" if ok else "bad",
              "1 · Merkle inclusion - record is %s the root" % ("in" if ok else "NOT in"),
              "recomputed root: %s" % computed + ("" if ok else "\nclaimed root:    %s" % merkle_root))
        all_ok &= ok
    except Exception as e:
        all_ok = False; _line("bad", "1 · Merkle inclusion - error", str(e))

    # §4.1 anchor output - v2 commits the day_root (binds the balance root AND the
    # (a)/(b)/(c) reconciliation); v1 commits the bare merkle_root. The 32-byte
    # anchor output slot is `decoded["merkle_root"]` in both (the field name is
    # historical). Branch on the presence of the reconciliation section.
    decoded = None
    expected_day_root = None  # set in the v2 path; reused by §5 body_hash check
    recon_sec = bundle.get("reconciliation")
    try:
        decoded = decode_anchor_payload(bundle["anchor"]["op_return_payload_hex"])
        anchored = decoded["merkle_root"]
        prob = legacy_payload_problem(decoded)      # §4.1 v30/v31 compatibility rule
        if prob:
            ok = False
            _line("bad", "2 · anchor output commitment - payload rejected (%s)" % payload_name(decoded), prob)
        elif recon_sec:
            ce = (bundle.get("chain") or {}).get("entry") or {}
            rc = recon_commitment(ce.get("exchange_id"), ce.get("business_date"),
                                  recon_sec.get("reconciliation_ok"), recon_sec.get("assets", []))
            expected_day_root = day_root(ce.get("exchange_id"), ce.get("business_date"),
                                         merkle_root, rc).hex()
            ok = merkle_root is not None and expected_day_root.lower() == anchored.lower()
            _line("ok" if ok else "bad",
                  "2 · anchor output commitment - day_root is %s on-chain (%s)" %
                  ("committed" if ok else "NOT committed", payload_name(decoded)),
                  "anchor output day_root:  %s\nrecomputed day_root: %s" % (anchored, expected_day_root))
        else:
            ok = merkle_root is not None and anchored.lower() == merkle_root.lower()
            _line("ok" if ok else "bad",
                  "2 · anchor output commitment - root is %s on-chain (%s)" %
                  ("committed" if ok else "NOT committed", payload_name(decoded)),
                  "anchor output merkle_root: %s" % anchored)
        all_ok &= ok
    except Exception as e:
        all_ok = False; _line("bad", "2 · anchor output commitment - error", str(e))

    # §4.2 txid binding
    txid = bundle["anchor"].get("reveal_txid")
    raw = bundle["anchor"].get("reveal_tx_hex")
    if raw:
        try:
            computed_txid, anchor_payload = txid_from_raw(raw)
            txid_ok = computed_txid.lower() == (bundle["anchor"]["reveal_txid"] or "").lower()
            op_ok = (anchor_payload or "").lower() == bundle["anchor"]["op_return_payload_hex"].lower()
            ok = txid_ok and op_ok
            _line("ok" if ok else "bad",
                  "3 · Transaction binding - anchor output %s the anchor txid" %
                  ("belongs to" if ok else "does NOT match"),
                  "computed txid: %s\nbundle  txid: %s\nanchor output in raw tx %s" %
                  (computed_txid, bundle["anchor"]["reveal_txid"],
                   "matches ✓" if op_ok else "MISMATCH ✗"))
            all_ok &= ok; txid = computed_txid
        except Exception as e:
            all_ok = False; _line("bad", "3 · Transaction binding - error", str(e))
    else:
        _line("warn", "3 · Transaction binding - skipped (no reveal_tx_hex)",
              "cannot bind anchor output to txid; trust level reduced")

    # §5 chain (optional) - per-exchange tamper-evident continuity (link D).
    # Content-consistency is cryptographic and DOES gate the verdict (a forged
    # payload_hash or a body_hash that does not carry the Merkle root means the
    # chain entry does not actually commit this day's settlement). On-chain
    # confirmation (§4.3) stays separate, so a content-valid head entry can still
    # be reported even while its Bitcoin confirmation is pending.
    ch = bundle.get("chain")
    if ch and ch.get("entry"):
        try:
            e = ch["entry"]
            ph = payload_hash(e)
            ph_ok = ph.lower() == e["payload_hash"].lower()
            # body_hash for a daily link carries the anchored root: the day_root
            # for v2 (binds reconciliation), or the bare Merkle root for v1.
            if e.get("kind") != "daily":
                body_ok = True
            elif expected_day_root is not None:
                body_ok = e.get("body_hash", "").lower() == expected_day_root.lower()
            else:
                body_ok = merkle_root is not None and e.get("body_hash", "").lower() == merkle_root.lower()
            committed_label = "day_root" if expected_day_root is not None else "merkle root"
            # optional walk-back: each adjacent pair must hash-link (§5 continuity).
            links = ch.get("links") or []
            link_ok, link_detail = _verify_chain_links(links, e)
            ok = ph_ok and body_ok and link_ok
            extra = ""
            if not body_ok:
                extra += " · body_hash ≠ %s" % committed_label
            if not link_ok:
                extra += " · prev-entry link broken"
            detail = ("seq %s (%s)\nrecomputed payload_hash: %s\nbody_hash %s %s" %
                      (e.get("seq"), e.get("kind"), ph, "=" if body_ok else "≠", committed_label))
            if link_detail:
                detail += "\n" + link_detail
            _line("ok" if ok else "bad",
                  "4 · Chain entry - payload_hash %s%s" %
                  ("recomputes ✓" if ph_ok else "MISMATCH ✗", extra),
                  detail)
            all_ok &= ok
        except Exception as e:
            all_ok = False; _line("bad", "4 · Chain entry - error", str(e))

    # §6 reconciliation (v2, informational) - the (a)/(b)/(c) trust computation
    # the day_root commits to. The commitment is already gated by §2/§4.1 (day_root
    # == anchor output) + §5 (body_hash == day_root); this just renders the figures.
    # NOTE: the (a) reserve side is exchange-supplied, NOT independently measured.
    if recon_sec:
        try:
            rows = recon_sec.get("assets", [])
            table = "\n".join(
                "  %-6s (a) held=%s  (b) liab=%s  (c) resid=%s  %s" % (
                    r.get("asset"), r.get("trust_actual"), r.get("trust_required"),
                    r.get("residual"), "✓ covered" if r.get("ok") else "✗ shortfall")
                for r in rows)
            _line("ok" if recon_sec.get("reconciliation_ok") else "warn",
                  "6 · Trust reconciliation (a−b=c) - %d asset(s), %s" % (
                      len(rows), "all covered" if recon_sec.get("reconciliation_ok") else "shortfall present"),
                  table + "\n  (a) reserve side is exchange-supplied, not independently measured.")
        except Exception as e:
            _line("warn", "6 · Trust reconciliation - display error", str(e))

    # on-chain (optional)
    if explorer and txid:
        try:
            confirmed, st = check_on_chain(explorer, txid)
            if confirmed:
                _line("ok", "5 · On-chain - confirmed via %s" % explorer,
                      "block height %s · block %s" % (st.get("block_height"), st.get("block_hash", "")[:24]))
            else:
                _line("warn", "5 · On-chain - seen but not yet confirmed", "(still in mempool)")
        except Exception as e:
            _line("warn", "5 · On-chain - could not reach explorer",
                  "%s\nsteps 1–3 are already proven offline" % e)
    elif txid:
        _line("skip", "5 · On-chain confirmation - SKIPPED (offline / no --explorer)",
              "txid bound above: %s\npass --explorer <url> (any Bitcoin source, never BitCert) to confirm" % txid)

    print()
    if not all_ok:
        print("%s✗ VERIFICATION FAILED%s" % (BAD, RST))
        print("  This bundle does not prove what it claims.")
        return "rejected"
    if undetermined:
        print("%s? UNDETERMINED%s - the anchor checks pass, but the zk section was not verified here." % (UNDET, RST))
        print("  This record is committed to Bitcoin tx %s; open index.html for the zk statement." % txid)
        return "undetermined"
    print("%s✓ CRYPTOGRAPHICALLY VERIFIED (offline)%s" % (OK, RST))
    print("  This record is committed to Bitcoin tx %s." % txid)
    return "valid"

def _opt(args, name):
    if name in args:
        i = args.index(name)
        if i + 1 >= len(args):
            raise SystemExit(_usage("%s needs a value" % name))
        val = args[i + 1]; del args[i:i + 2]; return val
    return None

def _opt_all(args, name):
    out = []
    while name in args:
        out.append(_opt(args, name))
    return out

def _flag(args, name):
    if name in args:
        args.remove(name); return True
    return False

def _usage(msg):
    print("%s✗ %s%s (see --help)" % (BAD, msg, RST))
    return EXIT_USAGE

def print_v4_report(R, bundle):
    for s in R.steps:
        _line(s["state"], s["title"], s["detail"])
    print()
    g = R.grade
    head = {"valid": OK + "✓ VALID (offline)",
            "warning": WARN + "! VALID WITH WARNINGS",
            "undetermined": UNDET + "? UNDETERMINED",
            "rejected": BAD + "✗ REJECTED"}[g] + RST
    what = {"valid": "every check passed - issuer signature, trust list, revocation and Bitcoin anchor all recompute.",
            "warning": "the cryptographic checks pass; see the ! lines before relying on this record.",
            "undetermined": "no check failed, but at least one could not be decided from this bundle (? lines).",
            "rejected": "at least one check failed (✗ lines). This bundle does not prove what it claims."}[g]
    print("%s - %s" % (head, what))
    print("  attribution: %s · presenter: %s" % (R.axes["attribution"], R.axes["presenter"]))
    if R.info.get("txid"):
        print("  anchor tx %s%s" % (R.info["txid"], (" · block_time %d" % R.info["block_time"]) if R.info.get("block_time") else ""))
    print("  exit code %d" % R.exit_code)

def print_present_url(bundle, R, label, console, now):
    import os
    try:
        li = bytes.fromhex(R.info["leaf_input"]) if R.info.get("leaf_input") else leaf_input_from_bundle(bundle)
    except Exception as e:
        print("%s✗ cannot derive leaf_input for the presenter check: %s%s" % (BAD, e, RST)); return
    nonce, vid, expiry = os.urandom(16), make_verifier_id(label, os.urandom(16)), int(now) + 300
    ch = present_challenge(nonce, li, vid, expiry)
    print()
    print("%sPresenter check - hand this link to the recipient (they sign it with their passkey on %s):%s" % (DIM, console, RST))
    print("  " + present_url(console, li.hex(), nonce, vid, expiry))
    print("  challenge = SHA256(present-v1 tag ‖ nonce ‖ leaf_input ‖ verifier_id ‖ expiry) = %s" % ch.hex())
    print("  expires at %d (300 s). Then run:" % expiry)
    print("  python3 verify.py <bundle> --present <blob> --nonce %s" % nonce.hex())

def main(argv):
    args = list(argv[1:])
    if "--selftest" in args:
        return selftest()
    if not args or args[0] in ("-h", "--help"):
        print(__doc__); return EXIT_USAGE
    try:
        explorer = _opt(args, "--explorer")        # on-chain source (never BitCert)
        original = _opt(args, "--original")        # original file for sha256-file scheme / v4 H(D)
        account = _opt(args, "--account")          # account id for daily identity binding
        salt = _opt(args, "--salt")                # per-customer salt (private; not in bundle)
        identifier = _opt(args, "--identifier")    # v4 subject_type 1
        present = _opt(args, "--present")          # v4 /present blob or a file holding it
        nonce = _opt(args, "--nonce")              # v4 nonce ownership
        rp_id = _opt(args, "--rp-id")
        origins = _opt_all(args, "--origin")
        now = _opt(args, "--now")
        label = _opt(args, "--label") or "verifier"
        console = _opt(args, "--console") or "https://console.bitcert.io"
        want_url = _flag(args, "--present-url")
    except SystemExit as e:
        return e.code
    stray = [a for a in args if a.startswith("--")]
    if stray:
        return _usage("unknown option %s" % stray[0])
    if not args:
        return _usage("no bundle given")
    if now is not None:
        try: now = int(now)
        except ValueError: return _usage("--now must be an integer (unix seconds)")
    if nonce is not None and not re.match(r"^[0-9a-fA-F]{32}$", nonce):
        return _usage("--nonce must be 32 hex chars (16 bytes)")
    src = args[0]
    try:
        raw = sys.stdin.read() if src == "-" else open(src, "r", encoding="utf-8").read()
    except OSError as e:
        return _usage("cannot read %s: %s" % (src, e))
    try:
        bundle = json.loads(raw)
    except json.JSONDecodeError as e:
        return _usage("not valid JSON: %s" % e)
    if not isinstance(bundle, dict):
        return _usage("bundle must be a JSON object")
    original_bytes = open(original, "rb").read() if original else None

    if bundle.get("schema") == SCHEMA_V4:
        pres = None
        if present is not None:
            import os
            text = open(present, "r", encoding="utf-8").read() if os.path.exists(present) else present
            try:
                pres = parse_presentation_blob(text)
            except (ValueError, json.JSONDecodeError) as e:
                return _usage("--present blob unreadable: %s" % e)
        R = verify_v4(bundle, identifier=identifier, presentation=pres, nonce_hex=nonce, rp_id=rp_id,
                      origins=origins or None, now=now, explorer=explorer, original_bytes=original_bytes)
        print_v4_report(R, bundle)
        if want_url:
            print_present_url(bundle, R, label, console, now if now is not None else int(time.time()))
        return R.exit_code

    if present or identifier or want_url:
        _line("skip", "v4 options ignored - this is a %s bundle" % bundle.get("schema"))
    grade = verify_bundle(bundle, explorer, original_bytes, account, salt)
    return GRADE_EXIT[grade]

if __name__ == "__main__":
    sys.exit(main(sys.argv))
