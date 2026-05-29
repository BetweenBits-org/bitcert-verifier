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
  "schema": "bitcert-proof-bundle/v1",   // REQUIRED, exact string
  "bitcoin_network": "regtest",           // "mainnet" | "testnet" | "signet" | "regtest"
  "generated_at": "2026-05-29T09:00:00Z", // informational only (NOT trusted)

  "record":  { ... },   // REQUIRED — what is being attested (§2)
  "merkle":  { ... },   // REQUIRED — inclusion proof (§3)
  "anchor":  { ... },   // REQUIRED — Bitcoin commitment (§4)
  "chain":   { ... }    // OPTIONAL — per-exchange chaining (§5)
}
```

A verifier MUST reject any bundle whose `schema` is not exactly
`bitcert-proof-bundle/v1`.

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

**Commitment check:** the `merkle_root` extracted from the OP_RETURN payload MUST
equal `merkle.root` recomputed in §3. (This proves the root was committed.)

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

## 6. Versioning

`schema` is bumped (`/v2`, …) on any breaking change. Verifiers reject unknown
majors. The producer and the verifiers in this repo share a fixture
(`fixtures/*.json`) that is cross-checked in CI on both sides to prevent drift
(plan §1.2나 requirement 5).
