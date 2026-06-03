#!/usr/bin/env python3
"""BitCert Independent Proof Verifier — command-line edition.

Trust-minimized by design. This tool calls NO BitCert server. It verifies a
proof bundle (see ../docs/bundle-schema.md) using only:
  (1) math   — SHA-256 / RFC-6962 Merkle (Python's stdlib `hashlib`), and
  (2) Bitcoin — observed through a source YOU choose (--explorer / your node).

Standard library only. No pip install. Works fully offline; the optional
on-chain step (--explorer) is the single Bitcoin-dependent check, and it never
contacts BitCert.

Usage:
    python3 verify.py BUNDLE.json
    python3 verify.py BUNDLE.json --original report.pdf          # bind a file artifact (link A)
    python3 verify.py BUNDLE.json --account alice --salt <hex>   # bind a daily balance row (link A)
    python3 verify.py BUNDLE.json --explorer https://mempool.space
    cat BUNDLE.json | python3 verify.py -

  --original FILE     hash this file and confirm it equals leaf_bytes (sha256-file scheme)
  --account ID        your account id, to reproduce the salted commitment (daily scheme)
  --salt HEX          your per-customer salt (held privately; NOT in the public bundle)
  --explorer URL      a Bitcoin source YOU choose for the on-chain step (never BitCert)

Exit code 0 = all performed checks passed, non-zero otherwise.
"""
import hashlib
import json
import sys

SCHEMA = "bitcert-proof-bundle/v1"
CHAIN_DOMAIN = b"bitcert:chain:v1\n"

# ----- ANSI (auto-disabled when not a tty) -----
def _c(code):
    return code if sys.stdout.isatty() else ""
OK, BAD, WARN, SKIP, DIM, RST = (_c("\033[32m"), _c("\033[31m"), _c("\033[33m"),
                                 _c("\033[90m"), _c("\033[2m"), _c("\033[0m"))

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

# ----- §4.1 OP_RETURN decode -----
def decode_op_return(payload_hex):
    b = bytes.fromhex(payload_hex)
    magic = b[:4].decode("latin1")
    if magic == "BC01":
        if len(b) != 53:
            raise ValueError("BC01 must be 53 bytes, got %d" % len(b))
        return {"format": "BC01", "version": b[4],
                "merkle_root": b[5:37].hex(), "batch_id": b[37:53].hex()}
    if magic == "BC30":
        if len(b) != 86:
            raise ValueError("BC30 must be 86 bytes, got %d" % len(b))
        return {"format": "BC30", "version": b[4], "flags": b[5],
                "batch_id": b[6:22].hex(), "merkle_root": b[22:54].hex(),
                "aux": b[54:86].hex()}
    raise ValueError("unknown OP_RETURN magic (expected BC01/BC30)")

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

def extract_op_return(script):
    if len(script) < 1 or script[0] != 0x6a:  # OP_RETURN
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
    opret = None
    for s in scripts:
        p = extract_op_return(s)
        if p is not None:
            opret = p.hex(); break
    return txid, opret

# ----- §6 witness inscription (the original bytes live IN the reveal witness) -----
def extract_witness_items(hex_str, input_index):
    """Return the list of witness stack elements for `input_index`, or None for a
    non-segwit tx. The witness is NOT in the txid (malleable) — callers MUST bind
    the recovered bytes to record.leaf_bytes (which IS txid-committed via the
    OP_RETURN), never trust the witness alone."""
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
    record.leaf_bytes — which equals the txid-committed OP_RETURN root. A
    tampered witness body fails the bind; a swapped tx fails the txid check."""
    anchor, record = bundle["anchor"], bundle["record"]
    wit = anchor["witness_envelope"]
    leaf = record["leaf_bytes"].lower()
    raw = anchor.get("reveal_tx_hex")
    all_ok = True

    if not raw:
        _line("bad", "1 · Transaction binding — no reveal_tx_hex",
              "a witness bundle cannot be verified without the raw reveal tx")
        return False
    try:
        computed_txid, opret = txid_from_raw(raw)
        txid_ok = computed_txid.lower() == (anchor.get("reveal_txid") or "").lower()
        op_ok = (opret or "").lower() == anchor["op_return_payload_hex"].lower()
        _line("ok" if txid_ok and op_ok else "bad",
              "1 · Transaction binding — OP_RETURN %s reveal_txid" %
              ("belongs to" if txid_ok and op_ok else "does NOT match"),
              "computed txid: %s\nbundle  txid: %s" % (computed_txid, anchor.get("reveal_txid")))
        all_ok &= txid_ok and op_ok
    except Exception as e:
        _line("bad", "1 · Transaction binding — error", str(e)); return False

    # The inscribed document IS the directly-committed leaf: OP_RETURN == leaf_bytes.
    root_ok = (opret or "").lower() == leaf
    _line("ok" if root_ok else "bad",
          "2 · On-chain commitment — OP_RETURN root %s record.leaf_bytes" %
          ("== " if root_ok else "≠ "),
          "on-chain root: %s" % (opret or ""))
    all_ok &= root_ok

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
              "3 · Witness original — recovered bytes %s record.leaf_bytes" %
              ("bind to" if bound else "do NOT bind to"), detail)
        all_ok &= bound
    except Exception as e:
        _line("bad", "3 · Witness original — error", str(e)); return False

    if explorer:
        try:
            confirmed, st = check_on_chain(explorer, computed_txid)
            _line("ok" if confirmed else "warn",
                  "4 · On-chain — %s via %s" % ("confirmed" if confirmed else "seen, unconfirmed", explorer),
                  "block height %s" % st.get("block_height"))
        except Exception as e:
            _line("warn", "4 · On-chain — could not reach explorer",
                  "%s\nsteps 1–3 are already proven offline" % e)
    else:
        _line("skip", "4 · On-chain confirmation — SKIPPED (offline / no --explorer)",
              "txid bound above: %s" % computed_txid)

    print()
    if all_ok:
        print("%s✓ CRYPTOGRAPHICALLY VERIFIED (offline) — original recovered from the Bitcoin witness%s" % (OK, RST))
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
    # RFC-8785 subset: sorted keys, compact. All values are strings in our schemes.
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

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
            "skip": SKIP + "–"}[state] + RST
    print("  %s %s" % (mark, title))
    if detail:
        for d in detail.split("\n"):
            print("      " + DIM + d + RST)

def verify_bundle(bundle, explorer=None, original_bytes=None, account_id=None, salt_hex=None):
    if bundle.get("schema") != SCHEMA:
        _line("bad", "Unsupported schema", "expected %s, got %r" % (SCHEMA, bundle.get("schema")))
        return False
    _line("ok", "Schema %s · network: %s" % (bundle["schema"], bundle.get("bitcoin_network", "?")))

    # Witness-inscription bundles carry the original IN the reveal witness; they
    # verify via a dedicated path (bind recovered bytes -> record.leaf_bytes).
    if bundle.get("anchor", {}).get("witness_envelope"):
        return verify_witness_bundle(bundle, explorer)

    all_ok = True

    # §2.1 preimage — original record -> leaf_bytes (link A)
    try:
        pre = verify_preimage(bundle["record"], original_bytes, account_id, salt_hex)
        if pre is None:
            _line("skip", "0 · Original binding — no preimage rule in bundle",
                  "proves a 32-byte digest is anchored, not that it is your document/balance")
        elif pre.get("status") == "need_original":
            _line("warn", "0 · Original binding — supply the original to bind it",
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
                  "0 · Original binding — %s %s" % (label, "✓" if ok else "✗"), detail)
            all_ok &= ok
    except Exception as e:
        all_ok = False; _line("bad", "0 · Original binding — error", str(e))

    # §3 merkle
    merkle_root = None
    try:
        computed, ok = verify_merkle(bundle["record"], bundle["merkle"])
        merkle_root = bundle["merkle"]["root"]
        _line("ok" if ok else "bad",
              "1 · Merkle inclusion — record is %s the root" % ("in" if ok else "NOT in"),
              "recomputed root: %s" % computed + ("" if ok else "\nclaimed root:    %s" % merkle_root))
        all_ok &= ok
    except Exception as e:
        all_ok = False; _line("bad", "1 · Merkle inclusion — error", str(e))

    # §4.1 OP_RETURN
    decoded = None
    try:
        decoded = decode_op_return(bundle["anchor"]["op_return_payload_hex"])
        ok = merkle_root is not None and decoded["merkle_root"].lower() == merkle_root.lower()
        _line("ok" if ok else "bad",
              "2 · OP_RETURN commitment — root is %s on-chain (%s)" %
              ("committed" if ok else "NOT committed", decoded["format"]),
              "OP_RETURN merkle_root: %s" % decoded["merkle_root"])
        all_ok &= ok
    except Exception as e:
        all_ok = False; _line("bad", "2 · OP_RETURN commitment — error", str(e))

    # §4.2 txid binding
    txid = bundle["anchor"].get("reveal_txid")
    raw = bundle["anchor"].get("reveal_tx_hex")
    if raw:
        try:
            computed_txid, opret = txid_from_raw(raw)
            txid_ok = computed_txid.lower() == (bundle["anchor"]["reveal_txid"] or "").lower()
            op_ok = (opret or "").lower() == bundle["anchor"]["op_return_payload_hex"].lower()
            ok = txid_ok and op_ok
            _line("ok" if ok else "bad",
                  "3 · Transaction binding — OP_RETURN %s reveal_txid" %
                  ("belongs to" if ok else "does NOT match"),
                  "computed txid: %s\nbundle  txid: %s\nOP_RETURN in raw tx %s" %
                  (computed_txid, bundle["anchor"]["reveal_txid"],
                   "matches ✓" if op_ok else "MISMATCH ✗"))
            all_ok &= ok; txid = computed_txid
        except Exception as e:
            all_ok = False; _line("bad", "3 · Transaction binding — error", str(e))
    else:
        _line("warn", "3 · Transaction binding — skipped (no reveal_tx_hex)",
              "cannot bind OP_RETURN to txid; trust level reduced")

    # §5 chain (optional) — per-exchange tamper-evident continuity (link D).
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
            # body_hash carries the day's Merkle root for daily; report (= merkle root) for monthly.
            body_ok = e.get("kind") != "daily" or (merkle_root is not None and
                      e.get("body_hash", "").lower() == merkle_root.lower())
            # optional walk-back: each adjacent pair must hash-link (§5 continuity).
            links = ch.get("links") or []
            link_ok, link_detail = _verify_chain_links(links, e)
            ok = ph_ok and body_ok and link_ok
            extra = ""
            if not body_ok:
                extra += " · body_hash ≠ merkle root"
            if not link_ok:
                extra += " · prev-entry link broken"
            detail = ("seq %s (%s)\nrecomputed payload_hash: %s\nbody_hash %s merkle root" %
                      (e.get("seq"), e.get("kind"), ph, "=" if body_ok else "≠"))
            if link_detail:
                detail += "\n" + link_detail
            _line("ok" if ok else "bad",
                  "4 · Chain entry — payload_hash %s%s" %
                  ("recomputes ✓" if ph_ok else "MISMATCH ✗", extra),
                  detail)
            all_ok &= ok
        except Exception as e:
            all_ok = False; _line("bad", "4 · Chain entry — error", str(e))

    # on-chain (optional)
    if explorer and txid:
        try:
            confirmed, st = check_on_chain(explorer, txid)
            if confirmed:
                _line("ok", "5 · On-chain — confirmed via %s" % explorer,
                      "block height %s · block %s" % (st.get("block_height"), st.get("block_hash", "")[:24]))
            else:
                _line("warn", "5 · On-chain — seen but not yet confirmed", "(still in mempool)")
        except Exception as e:
            _line("warn", "5 · On-chain — could not reach explorer",
                  "%s\nsteps 1–3 are already proven offline" % e)
    elif txid:
        _line("skip", "5 · On-chain confirmation — SKIPPED (offline / no --explorer)",
              "txid bound above: %s\npass --explorer <url> (any Bitcoin source, never BitCert) to confirm" % txid)

    print()
    if all_ok:
        print("%s✓ CRYPTOGRAPHICALLY VERIFIED (offline)%s" % (OK, RST))
        print("  This record is committed to Bitcoin tx %s." % txid)
    else:
        print("%s✗ VERIFICATION FAILED%s" % (BAD, RST))
        print("  This bundle does not prove what it claims.")
    return all_ok

def _opt(args, name):
    if name in args:
        i = args.index(name); val = args[i + 1]; del args[i:i + 2]; return val
    return None

def main(argv):
    args = argv[1:]
    explorer = _opt(args, "--explorer")        # on-chain source (never BitCert)
    original = _opt(args, "--original")        # original file for sha256-file scheme
    account = _opt(args, "--account")          # account id for daily identity binding
    salt = _opt(args, "--salt")                # per-customer salt (private; not in bundle)
    if not args or args[0] in ("-h", "--help"):
        print(__doc__); return 2
    src = args[0]
    raw = sys.stdin.read() if src == "-" else open(src, "r", encoding="utf-8").read()
    try:
        bundle = json.loads(raw)
    except json.JSONDecodeError as e:
        print("%s✗ not valid JSON:%s %s" % (BAD, RST, e)); return 2
    original_bytes = open(original, "rb").read() if original else None
    ok = verify_bundle(bundle, explorer, original_bytes, account, salt)
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv))
