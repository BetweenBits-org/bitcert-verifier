# Proof Bundle Schema - `bitcert-proof-bundle` v1 · v2 · v3 · v4 · v5

A **proof bundle** is a single self-contained JSON file. Given the bundle and a
*public* view of the Bitcoin blockchain, anyone can confirm - **without contacting
any BitCert server** - that a record was anchored to Bitcoin on a given day and has
not been tampered with.

The only things a verifier must trust are:

1. **Math** - SHA-256, the RFC-6962 Merkle construction and (v4) ECDSA P-256.
2. **The Bitcoin blockchain** - observed through *any* source the verifier chooses
   (their own `bitcoind`, a public explorer, or a self-hosted explorer).

For a **v4 identity-bound issuance** bundle (§9–§11) one more thing is pinned, not
trusted: the passkey relying party `console.bitcert.io` (§10.1). The bundle's own
`rp_id` is a claim; the verifier compares against the pin.

This file is the **authoritative wire contract** shared by:

- the producer - `bitcert-attest-module/services/verification`,
  endpoint `GET /attest/v1/daily/:exchange/:date/bundle` (and the per-attestation
  `GET /v1/proof/:attestation_id` it is built from; v4 issuance bundles come from
  `GET /attest/v1/proof/:id/bundle`); and
- the consumers - `index.html` and `verify-cli` in this repository, **plus any
  third-party verifier** anyone writes against this spec.

> Independence means BitCert's verifier is **not** the only possible one. This
> document exists so that a regulator or auditor can implement their own.

---

## 1. Top-level object

```jsonc
{
  "schema": "bitcert-proof-bundle/v2",   // REQUIRED - "/v1" | "/v2" | "/v3" | "/v4"
  "bitcoin_network": "regtest",           // "mainnet" | "testnet" | "signet" | "regtest"
  "generated_at": "2026-05-29T09:00:00Z", // informational only (NOT trusted)

  "record":         { ... },   // REQUIRED in v1/v2/v4 - what is being attested (§2)
  "merkle":         { ... },   // REQUIRED in v1/v2/v4 - inclusion proof (§3)
  "anchor":         { ... },   // REQUIRED in v1/v2/v4 - Bitcoin commitment (§4)
  "chain":          { ... },   // OPTIONAL - per-exchange chaining (§5)
  "reconciliation": { ... },   // OPTIONAL - (a)/(b)/(c) trust computation (§6; v2 daily only; FORBIDDEN in v4)
  "zk":             { ... },   // OPTIONAL, v3+ - zero-knowledge statement proof (§8)
  "issuer":         { ... },   // REQUIRED in v4 - issuer key + ES256 signature pieces (§9.1)
  "subject":        { ... },   // v4, REQUIRED iff subject_type == 2 - recipient public key (§9.2)
  "aux":            { ... },   // REQUIRED in v4 - trust-list / revocation roots + proofs (§9.3)
  "presentation":   { ... }    // OPTIONAL, v4 - a /present assertion (§10); usually supplied at verify time
}
```

A verifier MUST reject any bundle whose `schema` is not one of
`bitcert-proof-bundle/v1`, `/v2`, `/v3` or `/v4`.

**v4** is the **identity-bound issuance** bundle: the Merkle leaf is no longer a bare
document hash but a signed issuance record (§2.3), the anchor payload is the 86-byte
payload **v31** with the `IDENTITY_BOUND` flag and an active `aux_commitment` (§4.1), and the
verdict has four grades and two axes (§11). v4 carries **only** the keys listed
above - any other top-level key (including `reconciliation`) and
`anchor.witness_envelope` are rejected at step 0.

**v3** relaxes `record`/`merkle`/`anchor` from REQUIRED to OPTIONAL and adds the
`zk` section (§8). A zero-knowledge proof stands on its own mathematics - it
needs no Bitcoin anchor to be checkable - so a bundle may carry only `zk`. A v3
bundle MUST contain **at least one** of: the anchor group (`record` + `merkle` +
`anchor`), or `zk`. Older verifiers reject `/v3` outright, which is the safe
direction: they refuse rather than silently skipping a section they cannot
check. **v2** adds the
`reconciliation` section (§6): the anchor output then commits `day_root` (which binds
the Merkle root AND the reconciliation) instead of the bare Merkle root. A
verifier branches on the **presence of `reconciliation`**, not the version
string alone.

All byte fields are **lowercase hex**, no `0x` prefix, fixed length as noted.

---

## 2. `record` - the attested content

```jsonc
"record": {
  "kind": "daily",                  // "daily" | "monthly" | "attestation" | "issuance" (v4, §2.3)
  "leaf_bytes": "….(64 hex = 32B)", // REQUIRED - the 32-byte value committed as a leaf
  "preimage": { … },                 // OPTIONAL - how leaf_bytes derives from the ORIGINAL (§2.1)
  "descriptor": {                    // OPTIONAL, informational (shown to humans)
    "exchange_id": "demoex",
    "business_date": "2026-05-28"
  }
}
```

`leaf_bytes` is the 32-byte pre-image fed to the Merkle leaf hash
(`H_leaf(leaf_bytes)`). The Merkle proof (§3) only shows that *this 32-byte digest*
is anchored - it does **not**, on its own, show the digest corresponds to your real
document or balance. That binding is **§2.1**, and it is what closes the loop from
the original record all the way to Bitcoin:

```
 original record ──(§2.1 preimage)──▶ leaf_bytes ──(§3 merkle)──▶ root ──(§4 anchor)──▶ Bitcoin
   "link A"                              32 bytes      "link B"             "link C"
```

### 2.1 `preimage` - original → `leaf_bytes` (link A)

Declares the **rule** that produced `leaf_bytes` so a verifier can recompute it from
the original and confirm the match. Optional; if absent, a verifier proves links
B/C only and MUST report link A as *unverified*.

Two schemes:

**(a) `sha256-file` - for a document artifact (PDF/XBRL, monthly report):**

```jsonc
"preimage": { "scheme": "sha256-file", "content_type": "application/pdf" }
```

```
leaf_bytes = SHA-256( original_file_bytes )
```

The verifier hashes the original file the user supplies and checks it equals
`leaf_bytes`. (This matches the existing attest flow, where `report_hash` is exactly
`SHA-256(artifact)` - see `services/ingestion` `derive_report_hash`, and the
browser PDF hashing in `services/widget`.)

**(b) `sha256-jcs-fields` - for a structured row (daily customer balance):**

```jsonc
"preimage": {
  "scheme": "sha256-jcs-fields",
  "domain": "attest:daily:leaf\n",          // ASCII domain tag, prefixed before JCS
  "fields": {                                 // the exact committed fields
    "asset": "BTC",
    "balance_minor": "150000000",            // decimal MINOR units, as a STRING (no floats)
    "user_commitment": "….(64 hex)"          // salted commitment - hides the customer id
  },
  "commitment": {                             // OPTIONAL - lets a customer reproduce user_commitment
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
it equals `leaf_bytes` (**self-consistency** - proves the leaf really is the hash of
*these* fields). If the user supplies their `account_id` (+ the `salt_hex`), the
verifier additionally derives `user_commitment` and checks it equals
`fields.user_commitment` (**identity binding** - proves the leaf is *this customer's*
row), without ever exposing other customers' data.

> **Privacy:** `fields.user_commitment` is a salted hash; raw `account_id` never
> appears in the bundle. Only the customer (who holds their salt) can reproduce it.

**Pinned test vectors** (regenerate via `fixtures/generate.py`):
- `sha256-file`: `SHA-256("hello\n") =`
  `5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03`
- `sha256-jcs-fields` and `sha256-salt-account`: see `examples/02-daily-balance/`.

### 2.3 `bc30-leaf-v2` - signed issuance record (v4)

In a v4 bundle `leaf_bytes` is **`leaf_input`**: the hash of a fixed-width record `R`
and the issuer's signature `s` over it. The verifier rebuilds both from the
`preimage` and the `issuer` section and refuses the bundle if `leaf_bytes` differs.

```jsonc
"record": {
  "kind": "issuance",                              // leaf_type 0x01
  "leaf_bytes": "….(64 hex)",                     // == leaf_input - RECOMPUTED, never trusted
  "preimage": {
    "scheme": "bc30-leaf-v2", "leaf_type": 1,
    "record_salt": "….(32 hex = 16 B)",           // per-record CSPRNG; also the salt of a type-1 subject_ref
    "doc_sha256":  "….(64 hex)",                  // H(D) = SHA-256(document bytes)
    "subject_type": 0,                             // 0 none | 1 identifier hash | 2 registered public key
    "subject_ref":  "….(64 hex)",
    "issued_at": 1782000000, "expires_at": 0,      // u64 unix seconds; 0 = no expiry
    "policy": { "document_type": "audit", "jurisdiction": "GENERIC" },
    "policy_hash": "….(64 hex)",                  // SHA-256(JCS(policy)) - RECOMPUTED
    "content_type": "application/pdf"              // OPTIONAL, informational - absent for a hash-only issuance
  },
  "descriptor": { "exchange_id": "…", "attestation_id": "…" }   // informational
}
```

**Derivation** (all integers big-endian, all tags ASCII without a terminator):

```
subject_ref  = 0x00 × 32                                          subject_type 0
             = SHA-256( record_salt ‖ utf8(identifier) )          subject_type 1  (identifier is NOT in the bundle)
             = SHA-256( 0x02 ‖ curve_id ‖ compressed_pubkey(33) ) subject_type 2  (curve_id 0x01 = P-256; key in §9.2)
policy_hash  = SHA-256( JCS(policy) )        JCS = RFC 8785: keys sorted, compact, UTF-8, values are strings
R  = "BC30/record/v2" ‖ record_salt(16) ‖ doc_sha256(32) ‖ subject_type(1) ‖ subject_ref(32)
     ‖ issued_at(8) ‖ expires_at(8) ‖ policy_hash(32)                                    = 143 bytes
m  = SHA-256( "BC30/issue/v2" ‖ record_salt ‖ doc_sha256 ‖ subject_type ‖ subject_ref
              ‖ issued_at ‖ expires_at ‖ policy_hash )                                   ← what the issuer signs
s  = issuer signature bytes (§9.1): 0x01 ‖ len16(authenticatorData) ‖ authenticatorData ‖ len32(clientDataJSON)
     ‖ clientDataJSON ‖ len16(sig_der) ‖ sig_der                       (webauthn-es256)
     0x02 ‖ len16(sig_der) ‖ sig_der                                    (es256-plain)
leaf_input = SHA-256( "BC30/leaf/v2" ‖ leaf_type(0x01) ‖ R ‖ s )       ← record.leaf_bytes; the tree applies H_leaf as in §3
```

`content_type` is **optional**: it never enters `R` or `m`, and a *hash-only*
issuance - where the customer sent only `doc_sha256` and the platform never held the
file - has no MIME type to state. A verifier MUST accept its absence (and, when
present, treat it as an untrusted display string). Supplying the original still binds
it either way: the check is `SHA-256(original) == doc_sha256`.

`subject_type` sits in both `R` and `m`, so a type cannot be swapped after signing;
`policy_hash` sits in `m`, so the document type cannot be relabelled after signing.
`expires_at` MUST be 0 or greater than `issued_at`. A verifier MUST recompute
`policy_hash`, `subject_ref` (type 0 always; type 1 when the identifier is supplied;
type 2 from `subject.public_key`), `m`, `s`, and `leaf_input`, and compare each
against the bundle.

Known-answer vectors for every step: `fixtures/bc30-v2-vectors.json` - a
byte-identical copy of the engine's canonical
`ann-core/crates/bc30-leaf/tests/vectors/bc30-v2-kat.json`, re-derived by
`fixtures/engine-kat-check.py` and pinned by `verify.py --selftest`,
`fixtures/browser-js-check.mjs` and the console.

---

## 3. `merkle` - RFC-6962 inclusion proof

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

## 4. `anchor` - the Bitcoin commitment

```jsonc
"anchor": {
  "reveal_txid": "….(64 hex, big-endian/display order)", // REQUIRED
  "commit_txid": "….(64 hex)",                            // OPTIONAL, informational
  "reveal_tx_hex": "0200…",   // REQUIRED for offline binding - full raw reveal tx
  "op_return_payload_hex": "4243333001…", // REQUIRED - anchor output data (no 0x6a/push)
  "confirmed": {              // OPTIONAL - a *claim*; the verifier re-checks on-chain
    "block_height": 142,
    "block_hash": "….(64 hex)",
    "confirmations": 6,
    "block_time": 1782000600  // v4: the ONLY clock used for key-validity windows (§9.3); absent ⇒ undetermined
  }
}
```

### 4.1 anchor output payload layout

Two encodings exist (selected at anchor time). The verifier MUST detect by the
4-byte ASCII magic and extract `merkle_root`.

**53-byte payload (magic `42 43 30 31`):**

| offset | len | field |
|--------|-----|-------|
| 0..4   | 4   | magic (`42 43 30 31`) |
| 4..5   | 1   | version `0x01` |
| 5..37  | 32  | **merkle_root** |
| 37..53 | 16  | batch_id (UUIDv7 raw) |

**86-byte payload - magic `42 43 33 30` (the ASCII letters "BC30"), two versions, same size:**

| offset | len | field | v30 - version `0x1E` (30) | v31 - version `0x1F` (31) |
|--------|-----|-------|---|---|
| 0..4   | 4   | magic (`42 43 33 30`) | same | same |
| 4..5   | 1   | version | `0x1E` | **`0x1F`** |
| 5..6   | 1   | flags | bit 0 = `WITNESS_PRESENT`; **flags are not checked** by this verifier on legacy `0x1E` (today's behaviour, kept) | bit 0 = `WITNESS_PRESENT` · **bit 1 = `IDENTITY_BOUND`**; other bits refused |
| 6..22  | 16  | batch_id | random 16 B | same |
| 22..54 | 32  | **merkle_root** | leaves = document hashes | leaves = `leaf_input` (bound batch, §2.3) or document hashes (unbound) |
| 54..86 | 32  | aux_commitment | always zero | **active** (§9.3): the real commitment for a bound batch, the constant `AUX_COMMITMENT_NONE` for an unbound anchor |

`IDENTITY_BOUND` = 1 means *every* leaf of the batch is a signed issuance record
(§2.3) and `aux_commitment` binds the trust list / revocation list; such an anchor
is only meaningful with a **v4** bundle. `0x1E` anchors exist on-chain forever and
MUST keep decoding.

**Compatibility rule - which bundle may ride on which payload:**

| anchor payload | bundle schema | verdict |
|---|---|---|
| 53-byte payload, or 86-byte payload `0x1E` (aux zero) | v1–v3 | as before |
| 86-byte payload `0x1F`, bit 1 = 0, aux = `AUX_COMMITMENT_NONE` | v1–v3 | legacy path, aux constant compared |
| 86-byte payload `0x1F`, bit 1 = 1, aux ≠ 0 | **v4** | v4 pipeline (§11) |
| 86-byte payload `0x1F`, bit 1 = 1 | v1–v3 | **reject** - "identity-bound anchor requires a v4 bundle" |
| 86-byte payload `0x1F`, bit 1 = 0, aux ≠ `AUX_COMMITMENT_NONE` | v1–v3 | **reject** |
| 53-byte payload or 86-byte payload `0x1E` | v4 | **reject** |
| any other version | - | **reject** |

**Commitment check:** the 32-byte root extracted from the anchor output payload (the
`merkle_root` slot above) MUST equal:
  * **v1** (no `reconciliation` section) - `merkle.root` recomputed in §3 (the
    customer-balance liability root); or
  * **v2** (`reconciliation` present) - the `day_root` recomputed in §6, which
    itself binds `merkle.root` + the reconciliation commitment.

The slot is the same 32 bytes either way; only what it must equal differs. (This
proves the day's settlement - liabilities, and for v2 the trust reconciliation -
was committed on-chain.)

> A 86-byte payload anchor output also appears in the **unified witness** mode (§4.4.2): one
> reveal that carries both the inscribed document (witness) and `payload(merkle_root)`.
> There the `merkle_root` slot binds the witness-recovered `leaf_bytes` through the
> Merkle proof - see §4.4.2 for that path. The raw-32-byte (no-magic) anchor output is
> reserved for **legacy** witness reveals (§4.4.1), where the slot *is* `leaf_bytes`.

### 4.2 Offline txid binding (trustless, no network)

`reveal_tx_hex` is the complete raw reveal transaction. The verifier:

1. Locates the `anchor output` output (scriptPubKey begins with `0x6a`), reads its
   pushed data, and confirms it equals `op_return_payload_hex`.
2. Computes the transaction id as Bitcoin does - **double-SHA-256 of the
   *non-witness* (legacy) serialization**, then reverses the bytes to display
   order - and confirms it equals `reveal_txid`.

This cryptographically binds the anchor output bytes (hence the Merkle root) to the
exact `reveal_txid`, with **zero network access**. A bundle that omits
`reveal_tx_hex` can still be checked, but only at "trust the stated txid" strength.

### 4.3 On-chain confirmation (the one Bitcoin-dependent step)

To prove the txid is actually *in the chain* with enough confirmations, the
verifier consults a **Bitcoin source of the user's choosing - never BitCert**:

- the user's own `bitcoind` (`getrawtransaction <txid> true`),
- a public explorer (`mempool.space`, Blockstream Esplora),
- a self-hosted explorer (BitCert's demo `electrs`/`esplora` stack).

The `anchor.confirmed` block in the bundle is only a *claim*; a strict verifier
re-fetches and ignores it. Offline runs report steps §3, §4.1, §4.2 as proven and
mark §4.3 as `SKIPPED (no Bitcoin source)`.

### 4.4 `witness_envelope` - original bytes inscribed IN the reveal witness (OPTIONAL, additive)

For an **inscribed** record the original document is not supplied off-bundle - it
rides in the reveal transaction's **witness** (a BIP-342 tapscript envelope). The
bundle stays self-contained: anyone can recover the original from the chain alone.

The presence of `witness_envelope` selects the **witness-verification path**. That
path has **two modes**, distinguished by the anchor output payload:

| | **legacy** witness reveal | **unified** witness reveal |
|---|---|---|
| `anchor.op_return_payload_hex` | raw 32 B = `leaf_bytes` (`sha256(doc)`) | `payload(merkle_root)` - 86 B (§4.1) |
| `merkle` section | **absent** | **REQUIRED** (§3) |
| reveal txs on-chain | two (separate anchor + witness) | **one** (anchor **and** witness in the same tx) |
| `anchor.reveal_txid` | the witness reveal txid | the **unified** reveal = the standard-anchor txid (one tx) |
| binding to `leaf_bytes` | direct: `anchor output == leaf_bytes` | via Merkle: `leaf → merkle.root → anchor output(merkle_root) → txid` |
| verifier branch selector | `decode_op_return` finds no BC magic (raw 32 B) | `decode_op_return` finds a recognised payload magic |

A verifier MUST support **both** modes. It selects the mode by decoding the
anchor output (`decode_op_return`): a recognised payload magic (`42433031`/`42433330`) ⇒ **unified**;
a raw 32-byte payload with no magic ⇒ **legacy**.

**On-chain envelope layout** (identical in both modes - in `witness[input_index][1]`,
the tapscript):

```
<x-only pubkey> OP_CHECKSIG OP_FALSE OP_IF <protocol_tag> <content_type> <body 520B-chunks…> OP_ENDIF
```

The witness stack is `[schnorr_sig, inscription_script, control_block]` (3 elements).
The body is the **plain concatenation** of the pushes after `content_type`, inside
the `OP_IF … OP_ENDIF` block. (The script-path sig signs with the **untweaked**
internal key - BIP-342; this is a property of how the tx is built, not something the
verifier re-checks.)

#### 4.4.1 LEGACY mode - `anchor output == leaf_bytes`, no `merkle` section

The reveal's anchor output is the raw 32-byte document digest; the inscribed document
**is** the committed leaf, so the binding is direct (no Merkle hop). There is no
`merkle` section for a legacy-mode witness bundle.

```jsonc
"anchor": {
  …,
  "op_return_payload_hex": "…(64 hex = 32B)",   // = record.leaf_bytes (the inscribed doc IS the committed leaf)
  "reveal_tx_hex": "0200…",                       // REQUIRED - its witness carries the body
  "witness_envelope": {                           // presence selects the witness-verification path
    "input_index": 0,                             // which input's witness holds the envelope
    "content_type": "application/pdf",            // GENERIC / opaque - informational only
    "protocol_tag": "bcrt"                         // informational only
  }
}
```

**Verification (the load-bearing rule):**

```
1. txid(reveal_tx_hex) == anchor.reveal_txid                      (§4.2 - txid binding)
2. anchor output(reveal_tx_hex) == op_return_payload_hex == leaf_bytes (the doc IS the committed leaf)
3. body = concat(envelope pushes after content_type)
   ASSERT  sha256(body) == record.leaf_bytes        ← bind to leaf_bytes, FAIL on mismatch
4. (optional §4.3) confirm reveal_txid on a Bitcoin source of your choosing
```

#### 4.4.2 UNIFIED mode - `anchor output == payload(merkle_root)`, `merkle` REQUIRED

The **unified** reveal collapses the standard Merkle anchor and the witness
inscription into **one** transaction: a single script-path spend whose witness
carries the document **and** whose anchor output carries `payload(merkle_root)` (§4.1).
There is only one reveal tx, so `anchor.reveal_txid` is simultaneously the
standard-anchor txid and the witness-carrier txid. Because the anchor output now
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
  "op_return_payload_hex": "424333301e01…(172 hex = 86B)",  // payload(merkle_root), NOT leaf_bytes (§4.1)
  "reveal_tx_hex": "0200…",                        // REQUIRED - same tx carries witness AND 86-byte anchor output
  "witness_envelope": {                            // presence selects the witness-verification path
    "input_index": 0,
    "content_type": "application/pdf",             // GENERIC / opaque - informational only
    "protocol_tag": "bcrt"                          // informational only
  }
}
```

**Verification (the load-bearing rule):**

```
1. txid(reveal_tx_hex) == anchor.reveal_txid                       (§4.2 - txid binding)
   AND anchor output(reveal_tx_hex) == op_return_payload_hex           (raw-tx self-consistency)
2. decoded = decode_op_return(op_return_payload_hex)               (86-byte payload → merkle_root slot, §4.1)
3. (computed_root, ok) = verify_merkle(record, merkle)            (§3 - H_leaf fold)
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
sha256(body) == record.leaf_bytes               (step 4 - witness → leaf)
H_leaf(record.leaf_bytes) == merkle.root        (step 3 - leaf → root)
merkle.root == decoded.merkle_root (anchor output)  (step 3 - root → on-chain)
anchor output ⊂ txid-committed (non-witness) bytes  (step 1 - on-chain → Bitcoin)
```

> The authoritative byte-and-bundle spec for unified mode is
> `docs/UNIFIED-WITNESS-CONTRACT.md`; this is the v2.1-minor delta folded into the
> wire contract. Schema-wise a unified witness bundle is a
> `bitcert-proof-bundle/v2` bundle (the `merkle` section is required and the
> anchor output is a 86-byte payload, as in any v1/v2 standard anchor); it does **not**
> carry a `reconciliation` section.

> **Why bind to `record.leaf_bytes` and NOT a self-declared value:** the witness is
> **not committed in the txid** (it is malleable). `record.leaf_bytes` IS committed -
> in legacy mode it equals the anchor output payload directly; in unified mode it is
> reached *through the Merkle proof* (`merkle_root = H_leaf(leaf_bytes)`), and the
> root is the anchor output payload. Either way every link is txid-bound and confirmed
> on-chain, so a tampered witness body fails the body-bind step while leaving the
> txid intact. A verifier that instead trusted `witness_envelope` for the expected
> hash would be checking the data against itself (circular). `content_type` /
> `protocol_tag` are informational - never trusted for the security decision, and
> `content_type` MUST be HTML/URL-escaped before display (untrusted bytes).

> **Privacy / one-way door:** inscribing is **irreversibly public and permanent**. Use
> the witness path (either mode) ONLY for `sha256-file`-style documents that are
> cleared for public chain - **NEVER** for `sha256-jcs-fields` daily PII (customer
> balances/identifiers).

---

## 5. `chain` - per-exchange chaining (OPTIONAL, `v1-draft`)

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
**separately** - a head entry may be content-valid while its Bitcoin confirmation
is still pending (reorg/RBF safety, see plan §3).

> **Privacy:** because bundles are shared publicly, `leaf_bytes` and chain fields
> MUST be salted commitments / hashes - never raw customer identifiers. Producers
> expose sibling hashes only. See plan §4.

---

## 6. `reconciliation` - the trust computation the anchor commits (v2)

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

**Derivation** (every hash uses the flat JCS of §2.1b - sorted keys, compact;
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
**both** the anchor output 32-byte slot (§4.1) **and** `chain.entry.body_hash` (§5).
Tampering with any `(a)/(b)/(c)` figure changes `recon_commitment` → `day_root`,
which then no longer matches the anchor output, so the bundle is rejected.

> **Honesty.** `day_root` makes the reconciliation *tamper-evident*, not *true*:
> the `(a)` reserve side is supplied by the exchange (in the demo it is
> simulated), NOT independently measured. Coverage here is a system computation,
> not a solvency proof or an audit opinion.

## 7. Versioning

`schema` is bumped (`/v2`, `/v3`, …) on any breaking change. Verifiers reject unknown
majors but accept every supported major listed in §1. The producer and the
verifiers in this repo share fixtures (`fixtures/*.json`) cross-checked in CI on
both sides to prevent drift; the `day_root` derivation is additionally pinned as
a known-answer vector shared with the Rust engine
(`services/daily-settlement/src/domain/anchor.rs`).

The **unified witness** mode (§4.4.2) is a **minor** (v2.1, non-breaking)
addition: it reuses the existing v2 shape (86-byte anchor output + required `merkle`
section) and adds no new top-level field, so it needs no `schema` major bump.
Verifiers MUST support **both** witness modes (legacy §4.4.1 and unified §4.4.2),
selecting per-bundle by decoding the anchor output as described in §4.4. Its
known-answer vector is pinned in `docs/UNIFIED-WITNESS-CONTRACT.md` §6 and
emitted as a unified fixture (`fixtures/07-witness-unified.json`).

**v4** (`bitcert-proof-bundle/v4`) is a **major**: the leaf derivation changes
(§2.3), three sections are required (`issuer`, `aux`, and `subject` for a
registered recipient), the anchor payload MUST be the 86-byte payload v31 with `IDENTITY_BOUND`,
and `reconciliation` / `witness_envelope` are forbidden. Older verifiers reject
`/v4` outright - again the safe direction. The unbound v31 payload (bit 1 clear +
`AUX_COMMITMENT_NONE`) is accepted by the v1–v3 path, so a producer can switch its
encoder to v31 **before** any v4 bundle exists (decoder first, encoder second).

## 8. `zk` - zero-knowledge statement proof (OPTIONAL, v3+)

A `zk` section proves a **statement about hidden values** - e.g. "the sum of
these committed reserve amounts is at least the issued supply" - without
revealing the values or, for comparison statements, even the sum.

```jsonc
"zk": {
  "spec": "zk-transparent-statements-spec/v2.1.0",  // REQUIRED - wire contract version
  "variant": "bulletproofs",                        // "bulletproofs" | "sigma-fs"
  "statement": "committed-sum-cmp",                 // see §8.1
  "context": {                                      // REQUIRED - transcript binding
    "org_id":  "00000000-0000-4000-8000-00000000d1a6",
    "run_ref": "diag-mint-ms72ms9c"
  },
  "public_inputs": {                                // REQUIRED - statement dependent
    "n": 5,
    "threshold": "12400000000",                     // cmp only, u64 decimal STRING
    "direction": "ge"                               // cmp only, "ge" | "le"
    // range only: "total": "13020000000"
  },
  "envelope_b64": "WktUUwECAg…"                     // REQUIRED - proof bytes, base64
}
```

### 8.1 Statements

| `statement` | Proves | Sum revealed? |
|---|---|---|
| `committed-sum-range` | Σvᵢ equals the public `total`, and every vᵢ ∈ [0, 2⁶⁴) | Yes (`total`) |
| `committed-sum-cmp` | Σvᵢ ≥ `threshold` (`direction: ge`) or ≤ it (`le`), and every vᵢ ∈ [0, 2⁶⁴) | **No** |

`committed-sum-cmp` is carried by `bulletproofs` only.

### 8.2 Why `context` and `public_inputs` are separate from the envelope

**They are not decoration - the proof cannot be checked without them, and they
must not be read out of the proof.**

The Fiat–Shamir transcript binds `org_id`, `run_ref` and the public inputs, so a
verifier rebuilds the challenge stream from them. If it took those values from
inside the envelope instead, the prover would be choosing *which statement it
proved* - it could mint a proof for a threshold of 1 and present it as a proof
for a threshold of a billion. So:

> A verifier MUST populate `context` and `public_inputs` from **its own
> records** and treat the bundle's copies as untrusted claims to be compared
> against them. Accepting the bundle's values unchecked makes the result
> meaningless.

For `committed-sum-cmp` the sum is deliberately absent - publishing it would
defeat the statement's purpose. `n` and the threshold are public by design.

### 8.3 What a `zk`-only bundle does NOT prove

A bundle with `zk` and no anchor group proves the statement **but says nothing
about when it was made**. Nothing stops a prover from generating it today and
claiming it describes last quarter. A verifier MUST report that gap explicitly
rather than let "verified" imply a timestamp.

Adding the anchor group closes it: the same bundle then proves the statement AND
that the claim existed at a block height nobody can backdate.

### 8.4 Verification outline

1. Reject unknown `spec` versions. The wire contract is frozen per version and
   v1.x/v2.x envelopes are **not** interchangeable (the curve changed).
2. Parse the envelope: `"ZKTS"` ‖ version ‖ variant ‖ statement ‖ body.
   Reject a mismatch against the JSON `variant`/`statement` fields.
3. Re-derive the generators (try-and-increment, spec §14.4) - do not trust any
   value in the bundle for these.
4. Recompute `cs_digest` from the received commitments and compare.
5. Rebuild the transcript from `context` + `public_inputs` and verify the
   bulletproofs equations (spec §8.2) - for `committed-sum-cmp`, derive the
   surplus commitment D yourself (spec §11.3) rather than reading it.

The normative source for every step is the frozen spec
`zk-transparent-statements-spec.md`; this section is the bundle envelope around it.

---

## 9. v4 sections - `issuer`, `subject`, `aux`

Conventions: byte fields are lowercase hex, no `0x`. `client_data_json` is the
**exact bytes** the authenticator signed over, as hex - never re-serialised.
Integers are JSON numbers (u64 unix seconds, 0 = none).

### 9.1 `issuer` - who signed the record

```jsonc
"issuer": {
  "issuer_id": "….(32 hex = 16 B)",          // exchange uuid; MUST equal aux.tl_entry.issuer_id
  "key_id":    "….(64 hex)",                 // MUST equal aux.tl_entry.key_id (the key itself lives in tl_entry)
  "alg": "webauthn-es256",                    // "webauthn-es256" (passkey) | "es256-plain" (customer KMS / API)
  "rp_id": "console.bitcert.io",              // a CLAIM - the verifier uses its pinned value (§10.1)
  "assertion": {                              // es256-plain carries signature_der only
    "authenticator_data": "….(hex)",
    "client_data_json":   "….(hex, exact bytes)",
    "signature_der":      "….(hex)"
  }
}
```

`s` is **not** carried whole; the verifier reassembles it from `alg` + `assertion`
(§2.3) so there is a single source of truth.

**Signature verification** (public key = `aux.tl_entry.public_key`, SEC1 compressed P-256):

- `webauthn-es256`: parse `authenticator_data` as `rpIdHash(32) ‖ flags(1) ‖
  signCount(4 BE) ‖ [extensions]`; parse `client_data_json`. Require
  `type == "webauthn.get"`, `base64url-decode(challenge) == m` (byte comparison),
  `origin ∈` allowed origins, `rpIdHash == SHA-256(rpId)` with the **pinned** rpId,
  flags `UP` (0x01) and `UV` (0x04) set, and ES256 over
  `authenticator_data ‖ SHA-256(client_data_json)` under the key.
- `es256-plain`: ES256 over `m` (i.e. ECDSA P-256 of `SHA-256(m)`, per the ES256
  convention the message is hashed again).
- DER parsing is **strict**: short-form lengths, no trailing bytes, minimal
  INTEGERs, `r, s ∈ [1, n−1]`. `low-s` is **not** enforced (WebAuthn does not
  guarantee it).

### 9.2 `subject` - the registered recipient key (REQUIRED iff `subject_type == 2`)

```jsonc
"subject": { "curve_id": 1, "public_key": "….(66 hex = 33 B, SEC1 compressed)" }
```

The verifier decompresses the key (must be on P-256, canonical x) and checks
`SHA-256(0x02 ‖ curve_id ‖ public_key) == preimage.subject_ref`.

### 9.3 `aux` - what the anchor's `aux_commitment` binds

```jsonc
"aux": {
  "scheme": "bc30-aux-v2",
  "tl_root":       "….(64 hex)",             // issuer trust list at anchor time
  "sl_root":       "….(64 hex)",             // revocation list (sparse Merkle tree) at anchor time
  "envelope_root": "….(64 hex)",             // constant SHA-256("BC30/envelope/none") in this revision
  "tl_entry": { "issuer_id": "….(32 hex)", "key_id": "….(64 hex)", "curve_id": 1,
                "public_key": "….(66 hex)", "valid_from": 0, "valid_to": 0, "revoked_at": 0 },
  "tl_proof": { "leaf_index": 0, "siblings": ["…"], "directions": ["left"|"right"] },   // §3 proof
  "sl_proof": { "key": "….(64 hex)", "value": null, "siblings": ["….(64 hex)" × 256] }  // REQUIRED; null = exclusion
}
```

```
key_id         = SHA-256( 0x02 ‖ curve_id ‖ public_key )                         (same normalisation as subject_ref type 2)
TL entry       = "BC30/tl/v1" ‖ issuer_id(16) ‖ key_id(32) ‖ curve_id(1) ‖ public_key(33)
                 ‖ valid_from(8) ‖ valid_to(8) ‖ revoked_at(8)                    = 116 bytes
TL_root        = §3 tree over leaves SHA-256(entry), entries sorted by key_id ascending
                 (single entry ⇒ root = H_leaf(SHA-256(entry))); revoked keys stay in with revoked_at set
TL_ROOT_NONE   = SHA-256("BC30/tl/none")                                          (unbound anchors only)

SL (sparse Merkle tree, 256 levels - ann-core merkle-batching sparse.rs)
  key          = leaf_input(32)          value = 0x00 × 24 ‖ revoked_at(8 BE)     (present only for revoked records)
  leaf         = SHA-256( 0x10 ‖ key ‖ value )
  EMPTY_LEAF   = SHA-256( 0x11 )   ← PINNED CONSTANT. A verifier MUST fold an exclusion proof from this value and
                                     MUST ignore any empty-leaf value a proof might carry (otherwise a prover
                                     could pass an arbitrary "empty" hash and forge non-membership).
  node         = SHA-256( 0x01 ‖ left ‖ right )
  defaults[0]  = EMPTY_LEAF, defaults[i+1] = node(defaults[i], defaults[i]);  SMT_EMPTY_ROOT = defaults[256]
  fold         : cur = value == null ? EMPTY_LEAF : leaf(key, value)
                 for i in 0..255: bit = key bit (255 − i), MSB-first  ⇒  cur = bit == 0 ? node(cur, siblings[i]) : node(siblings[i], cur)
                 accept iff cur == sl_root

envelope_root       = SHA-256("BC30/envelope/none")
aux_commitment      = SHA-256( "BC30AUX2" ‖ TL_root ‖ SL_root ‖ envelope_root )
AUX_COMMITMENT_NONE = aux_commitment( TL_ROOT_NONE, SMT_EMPTY_ROOT, envelope_root )    (unbound v31 anchors)
```

Pinned values (`fixtures/bc30-v2-vectors.json`): `EMPTY_LEAF`, `SMT_EMPTY_ROOT`,
`TL_ROOT_NONE`, `envelope_root`, `AUX_COMMITMENT_NONE`.

Verifier duties: recompute `key_id` from `tl_entry.public_key` and require it to
equal both `tl_entry.key_id` and `issuer.key_id`; require `tl_entry.issuer_id ==
issuer.issuer_id`; fold `tl_proof` to `tl_root`; require `envelope_root` to equal
the constant; recompute `aux_commitment` and require it to equal bytes 54..86 of
the payload; judge the key window **at `anchor.confirmed.block_time`** (`valid_from ≤
block_time`, `valid_to == 0 || block_time ≤ valid_to`, `revoked_at == 0 || block_time <
revoked_at`) - with no `block_time` the outcome is *undetermined*; fold `sl_proof`
(key MUST equal `leaf_bytes`, exactly 256 siblings) - `value != null` means the record
was already revoked when anchored → reject; a missing `sl_proof` → *undetermined*.
Revocation **after** the anchor is outside the bundle and needs an online status-list
query.

`anchor.confirmed` gains `"block_time": <u64>` in v4 - the only clock the verifier
uses for validity windows. `issued_at` is self-reported and only sanity-checked
(`issued_at > block_time + 7200` → warning).

---

## 10. `presentation` - proving the presenter holds the registered key (v4, `subject_type 2`)

Optional and normally **supplied at verification time**, not carried in the bundle.
The verifier generates everything itself - there is no server API:

```
nonce       = 16 random bytes            (the verifier's own - ownership is what makes the check meaningful)
expiry      = now + 300 s                (u64 unix seconds)
verifier_id = SHA-256( "BC30/verifier-id/v1" ‖ utf8(label) ‖ random16 )
challenge   = SHA-256( "BC30/present/v1" ‖ nonce(16) ‖ leaf_input(32) ‖ verifier_id(32) ‖ expiry(8 BE) )
```

**Signing page URL** (the recipient opens it on the console origin - passkeys are
bound to the rpId, so the signature can only be made there):

```
https://<console>/present?v=1&leaf=<64 hex leaf_input>&nonce=<32 hex>&vid=<64 hex verifier_id>&exp=<expiry, decimal>
```

The page calls `navigator.credentials.get({ challenge, rpId, allowCredentials: [],
userVerification: "required" })` and returns a **blob**:

```jsonc
{ "v": 1, "scheme": "bc30-present-v1",
  "leaf": "<64 hex>", "nonce": "<32 hex>", "verifier_id": "<64 hex>", "expiry": 1782000900,
  "credential_id":      "<base64url>",        // informational
  "authenticator_data": "<base64url>",
  "client_data_json":   "<base64url, exact bytes>",
  "signature":          "<base64url DER>" }
```

Wire form: the JSON object itself **or** `base64url(UTF-8 JSON)` - the verifier
accepts both (`--present BLOB|FILE`, or paste). The page may also
`postMessage({ type: "bc30.presentation.v1", blob }, "*")` to its opener; the verifier
accepts the message only from an allowed origin.

### 10.1 Pinned relying party

```
BC30_RP_ID   = "console.bitcert.io"
BC30_ORIGINS = ["https://console.bitcert.io"]
```

Overridable (`--rp-id`, `--origin`; the browser's *Identity → advanced* inputs) for
staging / regtest only. Applies to the issuer's WebAuthn signature (§9.1) and to the
presentation alike.

### 10.2 Checks and the degradation rule

1. `type == "webauthn.get"`, `challenge` decodes to the recomputed 32-byte challenge, `origin ∈` allowed.
2. `rpIdHash == SHA-256(rpId)` (pinned), `UP` and `UV` set.
3. ES256 over `authenticator_data ‖ SHA-256(client_data_json)` under `subject.public_key`.
4. `blob.leaf == record.leaf_bytes`; `blob.expiry ≥ now`.
5. **Nonce ownership**: `blob.nonce` MUST equal the nonce *this verifier* generated
   (`--nonce`, or the browser's own ceremony). A presentation whose nonce is not ours
   proves nothing about *this* encounter (it could be a replay from another verifier).

A presentation is **never** a reason to reject. No presentation → step 16 `skip`,
axis `presenter: not available`. A failed check (including an unknown nonce or an
expired blob) → step 16 `warning`, axis `presenter: not available`. All checks pass →
`presenter: confirmed`. Records of `subject_type` 0/1 have no presenter check.

---

## 11. v4 verdict - steps, grades, axes, exit codes

**Grades** - `valid < warning < undetermined < rejected`. The verdict is the **worst**
step. Nothing is upgraded to valid by absence of evidence.

| # | step | on failure | notes |
|---|---|---|---|
| 0 | schema / shape | rejected | required sections, `scheme`s, only the top-level keys of §1 (anything else is unknown → rejected), no `witness_envelope`, `expires_at` 0 or > `issued_at` |
| 1 | payload decode | rejected | magic · 86 B · version `0x1F` · bit 1 set · no undefined bits; bit 0 set ⇒ warning |
| 2 | `policy_hash` recompute | rejected | |
| 3 | `subject_ref` | rejected / skip | type 0: zero; type 2: key on-curve + normalises; type 1: compared when the identifier is supplied, else skip |
| 4 | `R` · `m` | rejected | prints `m` (hex + base64url); binds a supplied original to `doc_sha256` |
| 5 | issuer signature | rejected | §9.1 per alg, pinned rpId, origin, UP/UV |
| 6 | `leaf_input` | rejected | ≠ `record.leaf_bytes` |
| 7 | Merkle inclusion | rejected | §3 over `record.leaf_bytes` |
| 8 | payload root | rejected | `merkle_root` slot ≠ recomputed root |
| 9 | trust-list entry + inclusion | rejected | `key_id` recompute, ids match, `tl_proof` folds |
| 10 | `envelope_root` | rejected | ≠ constant |
| 11 | `aux_commitment` | rejected | ≠ payload bytes 54..86 |
| 12 | key validity @ `block_time` | rejected / undetermined | window violated ⇒ rejected; no `block_time` ⇒ undetermined; `issued_at > bt + 7200` ⇒ warning |
| 13 | txid binding | rejected / undetermined | no `reveal_tx_hex` ⇒ undetermined |
| 14 | document expiry | warning | `expires_at != 0 && expires_at < now` |
| 15 | revocation at anchor (SL) | rejected / undetermined | bad key / ≠ 256 siblings / bad fold / `value != null` ⇒ rejected; missing ⇒ undetermined |
| 16 | presentation | warning / skip | §10.2 - never rejects |
| 17 | chain (§5) | rejected | if carried |
| 18 | on-chain | warning / skip | via a source of the verifier's choosing; compares `block_time`; unreachable ⇒ warning; offline ⇒ skip |

**Axes** (reported next to the grade):
- *attribution*: `none` · `issuer-claim · identifier` (`✓` / `✗` / `not checked`) · `issuer-claim · pubkey`
- *presenter*: `confirmed` · `not available`

**CLI exit codes** (`verify-cli/verify.py`): `0` valid · `1` rejected · `2` warning · `3`
undetermined · `64` usage error / not JSON. Legacy bundles (v1–v3) keep their
historical `0` / `1`; a v3 bundle with a `zk` section is reported as *undetermined*
(`3`) by the CLI, which does not implement the zk verifier (the browser does).

Oracle and cross-checks: `fixtures/v4-expected.json` (Python's grade / exit code /
axes / per-step states), `fixtures/v4-rc-matrix.py` (CLI subprocess exit codes),
`fixtures/v4-grade-check.mjs` (the shipped browser `runV4` must reproduce every row).

## 12. bundle v5 - role-labelled multi-signature issuance (`bitcert-proof-bundle/v5`)

**v4/v5 boundary.** A bundle is `/v5` as soon as it uses ANY of: the `0x10`
multi-signature envelope, the `0x04` wallet (secp256k1) issuer signature, or a
free-key policy (§12.1) beyond the two v4 keys. A single-P-256 issuance with the
two-key policy stays **v4, byte-identical** - v5 changes nothing behind it.
Verifiers that predate this section reject `/v5` as an unsupported schema
(REJECTED, exit 1) - the safe direction, but one that makes deployment notice
mandatory: ship the verifier before the first v5 bundle exists.

Everything of §2.3 (record `R`, message `m`, `leaf_input`), §3-§4 (Merkle,
anchor), §9.3 (`aux`) and §11 (grades) carries over unchanged. v5 adds three
things: an open policy grammar, two new issuer algorithms, and a `signers[]`
section that replaces `issuer` when more than one party signs.

### 12.1 policy - open key-value object

`preimage.policy` is no longer limited to two keys. The grammar is a hard gate
(violation ⇒ REJECTED), because `policy_hash` pins whatever bytes were signed -
the gate is what keeps those bytes displayable and unambiguous:

- **Required keys**: `document_type`, `jurisdiction`. Absence is refusal - an
  empty policy would defeat post-issuance document-type relabel protection.
- **Key grammar**: `^[a-z][a-z0-9_]{0,31}$`, at most **16** pairs. Keys are
  ASCII-closed on purpose: RFC 8785 sorts by UTF-16 code units while some
  implementations sort by code point, and the two orders only diverge outside
  the BMP - closing keys to ASCII extinguishes the divergence instead of
  trusting four implementations to agree.
- **Values**: UTF-8 strings only, at most **256 bytes** each; control characters
  (Unicode category Cc: C0, DEL, C1) and the bidirectional control characters
  (U+202A..U+202E, U+2066..U+2069) are refused; the whole JCS is at most
  **2048 bytes**. **Duplicate keys are refused** (a silent last-wins overwrite
  would let two readers see two different policies under one hash).
- Customer keys carry the `x_` prefix; un-prefixed new keys are reserved.
  `content_author_type` values (`display_name` · `business_no` · `org_uuid` ·
  `did` · `url`) are display vocabulary, not closed by the verifier.
- NFC normalisation is the producer's job (same precedent as wallet low-s
  normalisation): the hash pins exact bytes, the verifier does not re-normalise.
- Rendering policy values in a UI MUST HTML-escape them (they are attacker-
  chosen strings under a valid signature).

`policy_hash = SHA-256(JCS(policy))` is unchanged.

### 12.2 the `0x10` multi-signature envelope

```
m_i = SHA-256( "BC30/cosign/v1" ‖ m ‖ role_len(1) ‖ role_utf8 )
s   = 0x10 ‖ count(1) ‖ [ role_len(1) ‖ role_utf8 ‖ key_id(32) ‖ inner_len(2 BE) ‖ inner_sig ] × count
```

**Every entry signs its own `m_i` - the first entry included.** The role lives
inside the signed message, so a collected signature cannot be re-labelled into a
different role by whoever assembles `s` (the "commit it inside `m`" principle
this schema already uses for `subject_type` and `policy_hash`, §2.3). No entry
signs the bare `m`: a single exception would re-open cross-use between the
single-signature algorithms and `0x10` entries.

**Roles** are a CLOSED vocabulary. `role_ord` is a sort-only constant - it never
appears on the wire:

| `role_ord` | role | organisation key | `tl_proof` |
|---|---|---|---|
| 0 | `issuer` | required (requesting org) | REQUIRED |
| 1 | `co-issuer` | required (may be another org) | REQUIRED |
| 2 | `subject-consent` | not required | optional |
| 3 | `endorser` | not required | optional |

A role outside this table is refused - an open list would let an undefined role
dodge the `tl_proof` requirement. Extending the vocabulary changes what is
signed (`m_i` commits the role), so it requires a schema major bump, never a
silent addition.

**Per-algorithm signing target**: `0x01` (webauthn-es256) signs with
`challenge == base64url(m_i)`; `0x02` (es256-plain) signs `m_i` directly;
`0x04` (wallet) signs `msg = "BC30 cosign " ‖ lowercase_hex(m_i)` (§12.3).
low-s is enforced for `0x04` ONLY: WebAuthn authenticators do not guarantee it
for `0x01`, and enforcing it retroactively on `0x02` would turn already-anchored
high-s records into permanent rejections (the KAT pins an accepted `(r, n−s)`
es256-plain positive for exactly this reason).

**Strict parse rules** - the receiver NEVER re-sorts; the first violation
refuses the whole `s`:

1. `count` in `2..=8`. `count == 1` is refused (a single signature uses
   `0x01`/`0x02`/`0x04`).
2. At least one `issuer` entry (several = joint issuance).
3. `key_id` unique across ALL entries, no exceptions.
4. Entries in strictly ascending `(role_ord, key_id)` order.
5. `role_len` in `1..=32`, closed vocabulary.
6. Inner algorithms `0x01`/`0x02`/`0x04` only; **`0x10` nesting is refused**
   (parse the inner frame with a function that structurally cannot recurse).
7. `inner_len` must be consumed exactly - no surplus bytes inside an inner
   frame; a `0x04` inner is exactly 65 bytes.
8. The whole `s` is at most **8192 bytes** (this cap applies to `0x10` only).

**What uniqueness honestly covers**: parsing is deterministic and no re-sort or
re-label can produce a second valid byte string for the same signature set; but
P-256 low-s cannot be enforced (rule above), so `leaf_input` commits to the
SUBMITTED byte string, not to an abstract signature set - exactly as in v4.
And `0x10` proves no forgery, not completeness: the assembler can omit a
collected signature. Omission-proofing would need a second pass over a signed
signer-list digest and is out of scope.

### 12.3 wallet issuer signature (`issuer_alg 0x04`, `curve_id 2`)

```
curve_id 2 = secp256k1 (1 = P-256)
s      = 0x04 ‖ r(32) ‖ s(32)                          - exactly 65 B, no length prefix, no recovery header
msg    = "BC30 issuance "        ‖ lowercase_hex(m)     (single signature, 78 chars)
       | "BC30 cosign "          ‖ lowercase_hex(m_i)   (0x10 entry,        76 chars)
       | "BC30 key registration " ‖ lowercase_hex(challenge)   (registration proof of possession)
digest = SHA-256( SHA-256( 0x18 ‖ "Bitcoin Signed Message:\n" ‖ varint(len(msg)) ‖ msg ) )
```

- `varint` is the Bitcoin CompactSize encoding (§4.2 already implements it).
- **ECDSA verifies the `digest` DIRECTLY.** The message scheme hashes twice by
  itself; a library that hashes its input again verifies a different message.
  The KAT pins a re-hashed-digest failure to catch exactly this mistake.
- **No recovery header in `s`**: ingestion verifies against the registered key
  and stores `r ‖ s` only, so one signature has one encoding.
- **low-s is enforced**: `s > n/2` is refused. Normalising a wallet's high-s to
  `n − s` is ingestion's job, before anything is committed; both scalars must be
  in `[1, n−1]`.
- **Registration** uses the 65-byte recoverable form `header(1) ‖ r(32) ‖ s(32)`
  with `header` accepted across the whole `27..=34` range (the compression hint
  in the header is ignored; recovery id = `(header − 27) & 3`). The key is
  recovered ONCE at registration and returned/stored as the 33-byte SEC1
  compressed key; low-s is NOT enforced on this path.
- The domain tags above are mandatory: an untagged signature could be replayed
  from another protocol, and a wallet user could not tell what they are signing.
- First revision supports P2WPKH keys only (taproot's tweaked x-only output keys
  are incompatible with legacy recovery; BIP-322 is a later decision).

### 12.4 `signers[]` - the multi-signature section

When `s` is the `0x10` envelope, the bundle carries `signers[]` INSTEAD of the
§9.1 `issuer` section, and `aux` carries NO `tl_entry`/`tl_proof` (each signer
brings their own). One array entry per `0x10` entry, in the same order:

```jsonc
"signers": [
  {
    "role": "issuer",                       // closed vocabulary of §12.2
    "alg": "webauthn-es256",                // "webauthn-es256" | "es256-plain" | "wallet-secp256k1"
    "curve_id": 1,                          // es256 family ⇒ 1, wallet-secp256k1 ⇒ 2
    "public_key": "….(66 hex = 33 B)",     // SEC1 compressed
    "key_id": "….(64 hex)",                // SHA-256(0x02 ‖ curve_id ‖ public_key) - RECOMPUTED
    "rp_id": "console.bitcert.io",          // webauthn only; a CLAIM (§10.1 pin applies)
    "assertion": { /* per alg, below */ },
    "tl_entry": { /* §9.3 shape */ },       // optional pair with tl_proof - see MUST 2
    "tl_proof": { "leaf_index": 0, "siblings": [], "directions": [] }
  }
]
```

`assertion` per `alg`: `webauthn-es256` carries `authenticator_data` +
`client_data_json` + `signature_der` (hex, exact bytes); `es256-plain` carries
`signature_der`; `wallet-secp256k1` carries `signature_rs` (**128 hex** = the
64-byte `r ‖ s`, wallet only). The fields listed here are the ONLY fields a
`signers[]` entry may carry. There is deliberately NO per-signer `sl_proof`:
the status list is keyed by `leaf_input` (record revocation), so a per-signer
proof cannot exist - record revocation stays `aux.sl_proof`, singular.

### 12.5 reassembly model

The bundle does NOT carry `s` whole - exactly as in v4 (§9.1), the verifier
reassembles it so there is a single source of truth:

```
inner_sig_i = 0x01 ‖ len16(authenticator_data) ‖ authenticator_data
                   ‖ len32(client_data_json) ‖ client_data_json
                   ‖ len16(signature_der) ‖ signature_der            (webauthn-es256)
            | 0x02 ‖ len16(signature_der) ‖ signature_der            (es256-plain)
            | 0x04 ‖ r(32) ‖ s(32)                                   (wallet-secp256k1)

s = 0x10 ‖ count ‖ [ role_len ‖ role ‖ key_id ‖ inner_len(2 BE) ‖ inner_sig ] × count
    count = signers.length; role and key_id are taken from signers[i] IN ARRAY ORDER
```

All scalars (`count`, `role_len`, `len16`, `len32`, `inner_len`) are unsigned
big-endian; empty fields are refused. The verifier never sorts: a mis-ordered
`signers[]` reassembles into an `s` that the §12.2 parse rules refuse, which is
the intended failure.

### 12.6 verifier obligations (MUST, 13 items)

1. **Reassemble** `s` by §12.5.
2. **Shape**: the §12.2 parse rules (count `2..=8`, strict `(role_ord, key_id)`
   ascending, unique `key_id`, closed roles, exact `inner_len`, no surplus,
   8 KB). `tl_entry` and `tl_proof` are BOTH present or BOTH absent - one
   without the other is refused. A `signers[]` entry carrying any field outside
   the §12.4 list (`sl_proof` included) is refused.
3. **alg ↔ curve**: es256 family ⇒ `curve_id 1`, wallet ⇒ `curve_id 2`.
   Mismatch is refused.
4. **Entry self-binding**: recompute `key_id == SHA-256(0x02 ‖ curve_id ‖
   public_key)`. Mismatch is refused.
5. **`tl_entry` binding**: when present, its `key_id`, `public_key` and
   `curve_id` must ALL equal the entry's. (Without this, a foreign
   `tl_entry`+`tl_proof` could be pasted in to render someone else's key as
   "an organisation key".)
6. **Signatures**: recompute each entry's `m_i` from the role PARSED OUT OF
   `s`, then verify the `assertion` per §12.2. The verification key is
   `tl_entry.public_key` when a `tl_entry` is present, else the entry's
   `public_key` (new in v5 - v4 had no fallback; the safety argument is not the
   v4 precedent but that `key_id` sits inside `s`, hence inside the anchored
   `leaf_input`, and MUST 4 re-binds the public key to it).
7. **Trust list**: rebuild `tl_entry` bytes, fold `tl_proof`, compare against
   the `aux` `TL_root`. ALL proven entries fold to the SAME `TL_root` - the
   trust list is one platform-wide tree; the organisation lives in
   `tl_entry.issuer_id`. A folding `tl_proof` proves LISTING only; the
   organisation's approval of THIS record is proven only by the `m_i` signature.
8. **Key validity**: for every proven `tl_entry`, judge
   `valid_from`/`valid_to`/`revoked_at` at the anchor `block_time` (§11 step 12
   semantics, per signer).
9. **`tl_proof` requirement**: an `issuer` or `co-issuer` entry without one is
   refused.
10. **Record revocation**: `aux.sl_proof` exactly as in v4 (§11 step 15).
11. **Policy grammar**: a §12.1 violation is refused.
12. **Anchor binding**: reassembled `s` → `leaf_input` → Merkle → anchor
    output payload - the v4 chain (§11 steps 6-8) over the v5 `s`.
13. **Subject binding**: when `subject_type == 0x02` and a `subject-consent`
    entry exists, compare its `key_id` against `subject_ref`. A mismatch is NOT
    a rejection: report "not the subject's own consent" and grade WARNING.

What actually stops re-labelling and re-ordering is 12 plus `m_i` - editing the
JSON changes the reassembled `s`, and the Merkle no longer folds. Items 2-5 are
early checks so the failure is NAMED instead of surfacing as a bare root
mismatch.

### 12.7 grades for invalid keys

| situation | grade |
|---|---|
| `issuer`/`co-issuer` key invalid or revoked at block time | REJECTED |
| `subject-consent`/`endorser` key invalid or revoked | WARNING (flag that entry; verdict stands) |
| entry without `tl_entry`/`tl_proof` | VALID (display "unlisted key - revocation not provable", nothing more) |
| record revoked via `aux.sl_proof` | REJECTED |

### 12.8 one canonical envelope

A v5 bundle has exactly one shape per signature form; mixtures and duplicates
are refused:

```
signers[] present  ⇔  no issuer section  ⇔  no aux.tl_entry / aux.tl_proof  ⇔  reassembled s[0] == 0x10
```

A **single** `0x04` wallet signature is a v5 bundle WITHOUT `signers[]`: it
keeps the v4 pipeline and the §9.1 `issuer` section (with
`assertion.signature_rs`, `alg "wallet-secp256k1"`, `curve_id 2`) and
additionally applies MUST 3, 11 and 12; a low-s violation is refused.

Reserved and refused (placeholders, not implemented): `subject_type 0x03`
(participant-set Merkle root), `issuer_alg 0x03` (BIP-340 Schnorr). A verifier
MUST refuse them rather than guess.

### 12.9 fixtures and expected grades

Known answers for every §12 primitive live in the engine KAT copy
`fixtures/bc30-v2-vectors.json`, sections `cosign`, `wallet`, `multisig`,
`policy_open`, `es256_plain_alternate_s` and `negative_v2` (27 refusal cases,
each naming its stage - parse / verify / policy - and its error identifier).
`verify-cli/verify.py --selftest` and `fixtures/multisig/kat.mjs` both replay
all of them; `fixtures/generate.py` refuses to generate on any drift.

v5 BUNDLE fixtures live in `fixtures/v5/` with their oracle
`fixtures/v5-expected.json` (written by `fixtures/generate.py` from
`verify.py::verify_v5`); `fixtures/v5-rc-matrix.py` re-runs the CLI per row and
`fixtures/v5-grade-check.mjs` replays the browser `runV5` against every grade,
axis and step. They grade as:

- **negative → REJECTED (exit 1)**, all of: role relabel · order violation ·
  `0x10` nesting · non-low-s `0x04` · policy grammar violation · `issuer`
  without `tl_proof` · `tl_entry` without `tl_proof` and vice versa · a
  `signers[]` entry with an unknown field such as `sl_proof`.
- **positive → VALID (exit 0)**: a high-s `0x02` signature, `(r, n−s)`
  included, stays valid.
- **warning → exit 2**: `subject-consent` `key_id != subject_ref` (MUST 13).

The verifier grade scale is unchanged: `0` valid · `1` rejected · `2` warning.
