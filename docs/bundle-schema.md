# Proof Bundle Schema — `bitcert-proof-bundle/v1`

A **proof bundle** is a single self-contained JSON file. Given the bundle and a
*public* view of the Bitcoin blockchain, anyone can confirm — **without contacting
any BitCert server** — that a record was anchored to Bitcoin on a given day and has
not been tampered with.

The only things a verifier must trust are:

1. **Math** — SHA-256 and the RFC-6962 Merkle construction.
2. **The Bitcoin blockchain** — observed through *any* source the verifier chooses
   (their own `bitcoind`, a public explorer, or a self-hosted explorer).

This file is the **authoritative wire contract** shared by:

- the producer — `bitcert-attest-module/services/verification`,
  endpoint `GET /attest/v1/daily/:exchange/:date/bundle` (and the per-attestation
  `GET /v1/proof/:attestation_id` it is built from); and
- the consumers — `index.html` and `verify-cli` in this repository, **plus any
  third-party verifier** anyone writes against this spec.

> Independence means BitCert's verifier is **not** the only possible one. This
> document exists so that a regulator or auditor can implement their own.

---

## 1. Top-level object

```jsonc
{
  "schema": "bitcert-proof-bundle/v2",   // REQUIRED — "/v1" or "/v2"
  "bitcoin_network": "regtest",           // "mainnet" | "testnet" | "signet" | "regtest"
  "generated_at": "2026-05-29T09:00:00Z", // informational only (NOT trusted)

  "record":         { ... },   // REQUIRED — what is being attested (§2)
  "merkle":         { ... },   // REQUIRED — inclusion proof (§3)
  "anchor":         { ... },   // REQUIRED — Bitcoin commitment (§4)
  "chain":          { ... },   // OPTIONAL — per-exchange chaining (§5)
  "reconciliation": { ... }    // OPTIONAL — (a)/(b)/(c) trust computation (§6; v2 daily only)
}
```

A verifier MUST reject any bundle whose `schema` is not one of
`bitcert-proof-bundle/v1` or `bitcert-proof-bundle/v2`. **v2** adds the
`reconciliation` section (§6): the OP_RETURN then commits `day_root` (which binds
the Merkle root AND the reconciliation) instead of the bare Merkle root. A
verifier branches on the **presence of `reconciliation`**, not the version
string alone.

All byte fields are **lowercase hex**, no `0x` prefix, fixed length as noted.

---

## 2. `record` — the attested content

```jsonc
"record": {
  "kind": "daily",                  // "daily" | "monthly" | "attestation"
  "leaf_bytes": "….(64 hex = 32B)", // REQUIRED — the 32-byte value committed as a leaf
  "preimage": { … },                 // OPTIONAL — how leaf_bytes derives from the ORIGINAL (§2.1)
  "descriptor": {                    // OPTIONAL, informational (shown to humans)
    "exchange_id": "demoex",
    "business_date": "2026-05-28"
  }
}
```

`leaf_bytes` is the 32-byte pre-image fed to the Merkle leaf hash
(`H_leaf(leaf_bytes)`). The Merkle proof (§3) only shows that *this 32-byte digest*
is anchored — it does **not**, on its own, show the digest corresponds to your real
document or balance. That binding is **§2.1**, and it is what closes the loop from
the original record all the way to Bitcoin:

```
 original record ──(§2.1 preimage)──▶ leaf_bytes ──(§3 merkle)──▶ root ──(§4 anchor)──▶ Bitcoin
   "link A"                              32 bytes      "link B"             "link C"
```

### 2.1 `preimage` — original → `leaf_bytes` (link A)

Declares the **rule** that produced `leaf_bytes` so a verifier can recompute it from
the original and confirm the match. Optional; if absent, a verifier proves links
B/C only and MUST report link A as *unverified*.

Two schemes:

**(a) `sha256-file` — for a document artifact (PDF/XBRL, monthly report):**

```jsonc
"preimage": { "scheme": "sha256-file", "content_type": "application/pdf" }
```

```
leaf_bytes = SHA-256( original_file_bytes )
```

The verifier hashes the original file the user supplies and checks it equals
`leaf_bytes`. (This matches the existing attest flow, where `report_hash` is exactly
`SHA-256(artifact)` — see `services/ingestion` `derive_report_hash`, and the
browser PDF hashing in `services/widget`.)

**(b) `sha256-jcs-fields` — for a structured row (daily customer balance):**

```jsonc
"preimage": {
  "scheme": "sha256-jcs-fields",
  "domain": "attest:daily:leaf\n",          // ASCII domain tag, prefixed before JCS
  "fields": {                                 // the exact committed fields
    "asset": "BTC",
    "balance_minor": "150000000",            // decimal MINOR units, as a STRING (no floats)
    "user_commitment": "….(64 hex)"          // salted commitment — hides the customer id
  },
  "commitment": {                             // OPTIONAL — lets a customer reproduce user_commitment
    "scheme": "sha256-salt-account",
    "salt_hex": "….",                         // per-customer salt (the customer holds this)
    "account_field": "account_id"             // informational: what the customer types in
  }
}
```

```
leaf_bytes        = SHA-256( domain_bytes || JCS(fields) )
                    JCS = RFC-8785: keys sorted, compact, all values are strings
user_commitment   = SHA-256( hex_decode(salt_hex) || utf8(account_id) )   // if commitment present
```

The verifier always recomputes `leaf_bytes` from the declared `fields` and checks
it equals `leaf_bytes` (**self-consistency** — proves the leaf really is the hash of
*these* fields). If the user supplies their `account_id` (+ the `salt_hex`), the
verifier additionally derives `user_commitment` and checks it equals
`fields.user_commitment` (**identity binding** — proves the leaf is *this customer's*
row), without ever exposing other customers' data.

> **Privacy:** `fields.user_commitment` is a salted hash; raw `account_id` never
> appears in the bundle. Only the customer (who holds their salt) can reproduce it.

**Pinned test vectors** (regenerate via `fixtures/generate.py`):
- `sha256-file`: `SHA-256("hello\n") =`
  `5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03`
- `sha256-jcs-fields` and `sha256-salt-account`: see `examples/02-daily-balance/`.

---

## 3. `merkle` — RFC-6962 inclusion proof

Byte-for-byte identical to `ann-core/crates/merkle-batching` and the browser
recomputation in `services/widget`.

```jsonc
"merkle": {
  "leaf_index": 0,                       // 0-based position
  "root": "….(64 hex = 32B)",           // claimed Merkle root
  "siblings":   ["….(64 hex)", "…"],    // bottom-up sibling hashes
  "directions": ["left", "right", "…"]   // parallel to siblings; "left" | "right"
}
```

`siblings.length` MUST equal `directions.length`.

**Hashing (domain-separated, RFC-6962 §2.1):**

```
H_leaf(d)    = SHA-256( 0x00 || d )           // d = 32-byte leaf_bytes
H_node(l, r) = SHA-256( 0x01 || l || r )      // order matters
```

**Verification algorithm:**

```
cur = H_leaf(record.leaf_bytes)
for (sib, dir) in zip(siblings, directions):
    cur = (dir == "left")  ? H_node(sib, cur)   // sibling is the LEFT child
        : (dir == "right") ? H_node(cur, sib)   // sibling is the RIGHT child
        : REJECT
assert cur == merkle.root      // else: record not in this root → REJECT
```

**Pinned test vector** (must never drift): `H_leaf(0x00×32) =`
`7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9`.

---

## 4. `anchor` — the Bitcoin commitment

```jsonc
"anchor": {
  "reveal_txid": "….(64 hex, big-endian/display order)", // REQUIRED
  "commit_txid": "….(64 hex)",                            // OPTIONAL, informational
  "reveal_tx_hex": "0200…",   // REQUIRED for offline binding — full raw reveal tx
  "op_return_payload_hex": "4243333001…", // REQUIRED — OP_RETURN data (no 0x6a/push)
  "confirmed": {              // OPTIONAL — a *claim*; the verifier re-checks on-chain
    "block_height": 142,
    "block_hash": "….(64 hex)",
    "confirmations": 6
  }
}
```

### 4.1 OP_RETURN payload layout

Two encodings exist (selected at anchor time). The verifier MUST detect by the
4-byte ASCII magic and extract `merkle_root`.

**`BC01` — 53 bytes:**

| offset | len | field |
|--------|-----|-------|
| 0..4   | 4   | magic `BC01` (`42 43 30 31`) |
| 4..5   | 1   | version `0x01` |
| 5..37  | 32  | **merkle_root** |
| 37..53 | 16  | batch_id (UUIDv7 raw) |

**`BC30` — 86 bytes:**

| offset | len | field |
|--------|-----|-------|
| 0..4   | 4   | magic `BC30` (`42 43 33 30`) |
| 4..5   | 1   | version `0x1E` (30) |
| 5..6   | 1   | flags (bit 0 = WITNESS_PRESENT) |
| 6..22  | 16  | batch_id (UUIDv7 raw) |
| 22..54 | 32  | **merkle_root** |
| 54..86 | 32  | aux_commitment (zero for MVP) |

**Commitment check:** the 32-byte root extracted from the OP_RETURN payload (the
`merkle_root` slot above) MUST equal:
  * **v1** (no `reconciliation` section) — `merkle.root` recomputed in §3 (the
    customer-balance liability root); or
  * **v2** (`reconciliation` present) — the `day_root` recomputed in §6, which
    itself binds `merkle.root` + the reconciliation commitment.

The slot is the same 32 bytes either way; only what it must equal differs. (This
proves the day's settlement — liabilities, and for v2 the trust reconciliation —
was committed on-chain.)

> A `BC30` OP_RETURN also appears in the **unified witness** mode (§4.4.2): one
> reveal that carries both the inscribed document (witness) and `BC30(merkle_root)`.
> There the `merkle_root` slot binds the witness-recovered `leaf_bytes` through the
> Merkle proof — see §4.4.2 for that path. The raw-32-byte (no-magic) OP_RETURN is
> reserved for **legacy** witness reveals (§4.4.1), where the slot *is* `leaf_bytes`.

### 4.2 Offline txid binding (trustless, no network)

`reveal_tx_hex` is the complete raw reveal transaction. The verifier:

1. Locates the `OP_RETURN` output (scriptPubKey begins with `0x6a`), reads its
   pushed data, and confirms it equals `op_return_payload_hex`.
2. Computes the transaction id as Bitcoin does — **double-SHA-256 of the
   *non-witness* (legacy) serialization**, then reverses the bytes to display
   order — and confirms it equals `reveal_txid`.

This cryptographically binds the OP_RETURN bytes (hence the Merkle root) to the
exact `reveal_txid`, with **zero network access**. A bundle that omits
`reveal_tx_hex` can still be checked, but only at "trust the stated txid" strength.

### 4.3 On-chain confirmation (the one Bitcoin-dependent step)

To prove the txid is actually *in the chain* with enough confirmations, the
verifier consults a **Bitcoin source of the user's choosing — never BitCert**:

- the user's own `bitcoind` (`getrawtransaction <txid> true`),
- a public explorer (`mempool.space`, Blockstream Esplora),
- a self-hosted explorer (BitCert's demo `electrs`/`esplora` stack).

The `anchor.confirmed` block in the bundle is only a *claim*; a strict verifier
re-fetches and ignores it. Offline runs report steps §3, §4.1, §4.2 as proven and
mark §4.3 as `SKIPPED (no Bitcoin source)`.

### 4.4 `witness_envelope` — original bytes inscribed IN the reveal witness (OPTIONAL, additive)

For an **inscribed** record the original document is not supplied off-bundle — it
rides in the reveal transaction's **witness** (a BIP-342 tapscript envelope). The
bundle stays self-contained: anyone can recover the original from the chain alone.

The presence of `witness_envelope` selects the **witness-verification path**. That
path has **two modes**, distinguished by the OP_RETURN payload:

| | **legacy** witness reveal | **unified** witness reveal |
|---|---|---|
| `anchor.op_return_payload_hex` | raw 32 B = `leaf_bytes` (`sha256(doc)`) | `BC30(merkle_root)` — 86 B (§4.1) |
| `merkle` section | **absent** | **REQUIRED** (§3) |
| reveal txs on-chain | two (separate anchor + witness) | **one** (anchor **and** witness in the same tx) |
| `anchor.reveal_txid` | the witness reveal txid | the **unified** reveal = the standard-anchor txid (one tx) |
| binding to `leaf_bytes` | direct: `OP_RETURN == leaf_bytes` | via Merkle: `leaf → merkle.root → OP_RETURN(merkle_root) → txid` |
| verifier branch selector | `decode_op_return` finds no BC magic (raw 32 B) | `decode_op_return` finds a `BC01`/`BC30` magic |

A verifier MUST support **both** modes. It selects the mode by decoding the
OP_RETURN (`decode_op_return`): a recognised `BC01`/`BC30` magic ⇒ **unified**;
a raw 32-byte payload with no magic ⇒ **legacy**.

**On-chain envelope layout** (identical in both modes — in `witness[input_index][1]`,
the tapscript):

```
<x-only pubkey> OP_CHECKSIG OP_FALSE OP_IF <protocol_tag> <content_type> <body 520B-chunks…> OP_ENDIF
```

The witness stack is `[schnorr_sig, inscription_script, control_block]` (3 elements).
The body is the **plain concatenation** of the pushes after `content_type`, inside
the `OP_IF … OP_ENDIF` block. (The script-path sig signs with the **untweaked**
internal key — BIP-342; this is a property of how the tx is built, not something the
verifier re-checks.)

#### 4.4.1 LEGACY mode — `OP_RETURN == leaf_bytes`, no `merkle` section

The reveal's OP_RETURN is the raw 32-byte document digest; the inscribed document
**is** the committed leaf, so the binding is direct (no Merkle hop). There is no
`merkle` section for a legacy-mode witness bundle.

```jsonc
"anchor": {
  …,
  "op_return_payload_hex": "…(64 hex = 32B)",   // = record.leaf_bytes (the inscribed doc IS the committed leaf)
  "reveal_tx_hex": "0200…",                       // REQUIRED — its witness carries the body
  "witness_envelope": {                           // presence selects the witness-verification path
    "input_index": 0,                             // which input's witness holds the envelope
    "content_type": "application/pdf",            // GENERIC / opaque — informational only
    "protocol_tag": "bcrt"                         // informational only
  }
}
```

**Verification (the load-bearing rule):**

```
1. txid(reveal_tx_hex) == anchor.reveal_txid                      (§4.2 — txid binding)
2. OP_RETURN(reveal_tx_hex) == op_return_payload_hex == leaf_bytes (the doc IS the committed leaf)
3. body = concat(envelope pushes after content_type)
   ASSERT  sha256(body) == record.leaf_bytes        ← bind to leaf_bytes, FAIL on mismatch
4. (optional §4.3) confirm reveal_txid on a Bitcoin source of your choosing
```

#### 4.4.2 UNIFIED mode — `OP_RETURN == BC30(merkle_root)`, `merkle` REQUIRED

The **unified** reveal collapses the standard Merkle anchor and the witness
inscription into **one** transaction: a single script-path spend whose witness
carries the document **and** whose OP_RETURN carries `BC30(merkle_root)` (§4.1).
There is only one reveal tx, so `anchor.reveal_txid` is simultaneously the
standard-anchor txid and the witness-carrier txid. Because the OP_RETURN now
commits `merkle_root` (not `leaf_bytes`), the `merkle` section (§3) is **REQUIRED**:
it is the link from `leaf_bytes` to the on-chain root.

```jsonc
"merkle": {                                       // REQUIRED in unified mode (§3)
  "leaf_index": 0,
  "root": "…(64 hex)",                            // = decode_op_return(op_return).merkle_root
  "siblings":   [],                               // single-leaf: root = H_leaf(leaf_bytes)
  "directions": []
},
"anchor": {
  …,
  "reveal_txid": "…(64 hex)",                     // the ONE unified reveal = the standard-anchor txid
  "op_return_payload_hex": "424333301e01…(172 hex = 86B)",  // BC30(merkle_root), NOT leaf_bytes (§4.1)
  "reveal_tx_hex": "0200…",                        // REQUIRED — same tx carries witness AND BC30 OP_RETURN
  "witness_envelope": {                            // presence selects the witness-verification path
    "input_index": 0,
    "content_type": "application/pdf",             // GENERIC / opaque — informational only
    "protocol_tag": "bcrt"                          // informational only
  }
}
```

**Verification (the load-bearing rule):**

```
1. txid(reveal_tx_hex) == anchor.reveal_txid                       (§4.2 — txid binding)
   AND OP_RETURN(reveal_tx_hex) == op_return_payload_hex           (raw-tx self-consistency)
2. decoded = decode_op_return(op_return_payload_hex)               (BC30 → merkle_root slot, §4.1)
3. (computed_root, ok) = verify_merkle(record, merkle)            (§3 — H_leaf fold)
   ASSERT ok                                                       (record.leaf_bytes IS in this root)
   ASSERT computed_root == merkle.root == decoded.merkle_root      (anchored root == proven root)
4. body = concat(envelope pushes after content_type)
   ASSERT  sha256(body) == record.leaf_bytes        ← bind recovered witness body to leaf_bytes
5. (optional §4.3) confirm reveal_txid on a Bitcoin source of your choosing
```

For a single attestation the Merkle tree has exactly one leaf, so
`merkle.root = H_leaf(leaf_bytes) = SHA-256(0x00 || leaf_bytes)` with
`siblings = directions = []`; the §3 empty-list fold reduces step 3 to
`H_leaf(leaf_bytes) == merkle.root`. The full binding chain is:

```
PDF bytes ─(recover from witness)→ body
sha256(body) == record.leaf_bytes               (step 4 — witness → leaf)
H_leaf(record.leaf_bytes) == merkle.root        (step 3 — leaf → root)
merkle.root == decoded.merkle_root (OP_RETURN)  (step 3 — root → on-chain)
OP_RETURN ⊂ txid-committed (non-witness) bytes  (step 1 — on-chain → Bitcoin)
```

> The authoritative byte-and-bundle spec for unified mode is
> `docs/UNIFIED-WITNESS-CONTRACT.md`; this is the v2.1-minor delta folded into the
> wire contract. Schema-wise a unified witness bundle is a
> `bitcert-proof-bundle/v2` bundle (the `merkle` section is required and the
> OP_RETURN is a BC30 envelope, as in any v1/v2 standard anchor); it does **not**
> carry a `reconciliation` section.

> **Why bind to `record.leaf_bytes` and NOT a self-declared value:** the witness is
> **not committed in the txid** (it is malleable). `record.leaf_bytes` IS committed —
> in legacy mode it equals the OP_RETURN payload directly; in unified mode it is
> reached *through the Merkle proof* (`merkle_root = H_leaf(leaf_bytes)`), and the
> root is the OP_RETURN payload. Either way every link is txid-bound and confirmed
> on-chain, so a tampered witness body fails the body-bind step while leaving the
> txid intact. A verifier that instead trusted `witness_envelope` for the expected
> hash would be checking the data against itself (circular). `content_type` /
> `protocol_tag` are informational — never trusted for the security decision, and
> `content_type` MUST be HTML/URL-escaped before display (untrusted bytes).

> **Privacy / one-way door:** inscribing is **irreversibly public and permanent**. Use
> the witness path (either mode) ONLY for `sha256-file`-style documents that are
> cleared for public chain — **NEVER** for `sha256-jcs-fields` daily PII (customer
> balances/identifiers).

---

## 5. `chain` — per-exchange chaining (OPTIONAL, `v1-draft`)

Links daily/monthly records into a tamper-evident per-exchange chain. Present only
once `services/daily-settlement` emits it; verifier skips this section if absent.

```jsonc
"chain": {
  "entry": {
    "exchange_id": "demoex",
    "seq": 12,
    "kind": "daily",                       // "daily" | "monthly" | "genesis"
    "prev_entry_hash": "….(64 hex)",       // payload_hash of seq-1 (zeros for genesis)
    "body_hash": "….(64 hex)",             // == merkle.root for daily; report hash for monthly
    "business_date": "2026-05-28",
    "payload_hash": "….(64 hex)"           // value actually anchored (== merkle.root carrier)
  },
  "links": [ /* optional: prior {seq, payload_hash, prev_entry_hash} to walk back */ ]
}
```

**`payload_hash` preimage (canonical, must match `daily-settlement`):**

```
payload_hash = SHA-256( DOMAIN_TAG || JCS(entry_core) )
DOMAIN_TAG   = ASCII "bitcert:chain:v1\n"  (17 bytes: 62 69 74 63 65 72 74 3a 63 68 61 69 6e 3a 76 31 0a)
entry_core   = { "body_hash", "business_date", "exchange_id", "kind",
                 "prev_entry_hash", "seq" }   // RFC-8785 JCS: keys sorted, no spaces
```

**Continuity check:** for each adjacent pair, `entry[n].prev_entry_hash ==
payload_hash(entry[n-1])`, and each `entry.payload_hash` recomputes from its
preimage. Content-consistency (§5) and on-chain confirmation (§4.3) are reported
**separately** — a head entry may be content-valid while its Bitcoin confirmation
is still pending (reorg/RBF safety, see plan §3).

> **Privacy:** because bundles are shared publicly, `leaf_bytes` and chain fields
> MUST be salted commitments / hashes — never raw customer identifiers. Producers
> expose sibling hashes only. See plan §4.

---

## 6. `reconciliation` — the trust computation the anchor commits (v2)

Present on **v2 daily** bundles. Carries the per-asset MAS Reg-18H `(a)/(b)/(c)`
computation, and is the preimage the verifier folds into `day_root`.

```jsonc
"reconciliation": {
  "scheme": "day-root/v1",
  "reconciliation_ok": true,            // AND over every asset's `ok`
  "assets": [
    { "asset": "BTC", "scale": 8,
      "trust_required": "150000000",    // (b) aggregate customer liability, minor units (string)
      "trust_actual":   "165000000",    // (a) reserve trust held, minor units (string)
      "residual":       "15000000",     // (c) = (a) − (b), minor units (string)
      "ok": true }                      // (c) ≥ 0
  ],
  "day_root": "c6eb…"                   // informational mirror; the verifier RECOMPUTES it
}
```

**Derivation** (every hash uses the flat JCS of §2.1b — sorted keys, compact;
`ok`/`reconciliation_ok` committed as the integer `1`/`0`, `scale` as an integer,
decimals as the minor-unit strings):

```
asset_row        = JCS({asset, ok, residual, scale, trust_actual, trust_required})
assets_hash      = SHA-256( "attest:daily:recon-assets\n" || Σ asset_row )   // assets SORTED by symbol
recon_commitment = SHA-256( "attest:daily:recon\n"
                            || JCS({assets_hash, business_date, exchange_id, reconciliation_ok}) )
day_root         = SHA-256( "attest:daily:anchor\n"
                            || JCS({balances_root, business_date, exchange_id, recon_commitment}) )
```

`business_date` and `exchange_id` come from `chain.entry`; `balances_root` is the
hex of `merkle.root`. The verifier recomputes `day_root` and asserts it equals
**both** the OP_RETURN 32-byte slot (§4.1) **and** `chain.entry.body_hash` (§5).
Tampering with any `(a)/(b)/(c)` figure changes `recon_commitment` → `day_root`,
which then no longer matches the OP_RETURN, so the bundle is rejected.

> **Honesty.** `day_root` makes the reconciliation *tamper-evident*, not *true*:
> the `(a)` reserve side is supplied by the exchange (in the demo it is
> simulated), NOT independently measured. Coverage here is a system computation,
> not a solvency proof or an audit opinion.

## 7. Versioning

`schema` is bumped (`/v2`, …) on any breaking change. Verifiers reject unknown
majors but accept every supported major listed in §1. The producer and the
verifiers in this repo share fixtures (`fixtures/*.json`) cross-checked in CI on
both sides to prevent drift; the `day_root` derivation is additionally pinned as
a known-answer vector shared with the Rust engine
(`services/daily-settlement/src/domain/anchor.rs`).

The **unified witness** mode (§4.4.2) is a **minor** (v2.1, non-breaking)
addition: it reuses the existing v2 shape (BC30 OP_RETURN + required `merkle`
section) and adds no new top-level field, so it needs no `schema` major bump.
Verifiers MUST support **both** witness modes (legacy §4.4.1 and unified §4.4.2),
selecting per-bundle by decoding the OP_RETURN as described in §4.4. Its
known-answer vector is pinned in `docs/UNIFIED-WITNESS-CONTRACT.md` §6 and
emitted as a unified fixture (`fixtures/07-unified-witness-inscription.json`).
