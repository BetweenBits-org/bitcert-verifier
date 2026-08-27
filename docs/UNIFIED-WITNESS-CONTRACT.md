# Unified Witness Contract - audit-anchor consolidation (W1 single source of truth)

> **Status:** CONTRACT (frozen for the W2/W3 implementation agents). This is the
> authoritative byte-and-bundle specification for **audit-anchor consolidation**:
> one Bitcoin reveal transaction that carries **both** the Merkle anchor
> (`anchor output = payload(merkle_root)`) **and** the audit PDF (BIP-342 tapscript
> witness), replacing today's **two separate** transactions for *single-mode*
> audit anchors.
>
> Read alongside `bundle-schema.md` (the general wire contract); this document
> defines the **v2.1 delta** and the new **unified** witness-verification branch.
> Where the two disagree on the unified case, **this file wins** until the delta
> is folded back into `bundle-schema.md`.

---

## 0. Why this exists (the one-paragraph rationale)

Today an *inscribed* single-mode audit anchor needs **two** reveal txs:

- **① the anchor reveal** - `services/anchoring`, key-path P2TR spend, output[0] =
  `anchor output(payload(merkle_root))` (`bitcoin_tx.rs` + `op_return_placeholder.rs` /
  the 86-byte payload encoder). The Merkle root is txid-committed and walked back to a block.
- **② the witness reveal** - `services/inscription`, script-path P2TR spend, the
  PDF bytes inscribed in a BIP-342 tapscript envelope, output[0] = `anchor output =
  leaf_bytes` (raw 32 B = `sha256(PDF)`). See `executor.rs` today.

The **unified** target collapses ① and ② into **one reveal**: a script-path
spend whose witness carries the PDF envelope **and** whose `anchor output` carries
`payload(merkle_root)` (the standard anchor). One tx, one fee, one confirmation -
and the bundle's `anchor` is simultaneously the standard anchor *and* the witness
carrier.

**Load-bearing consequence:** in the unified tx, `anchor output` is **no longer**
equal to `leaf_bytes`. It is `payload(merkle_root)`. The verifier must bind the
recovered witness body to `record.leaf_bytes` **through the Merkle proof**, not by
the legacy `anchor output == leaf_bytes` short-circuit. Both branches must coexist
(backward compat with the existing 4-tx / legacy-② bundles already on-chain).

---

## 1. Unified reveal transaction layout

One reveal tx, **script-path** spend (BIP-342) of the inscription commit output -
the same envelope mechanism as legacy ②, **only the `anchor output` payload differs**.

```
reveal tx (version 2):
  input[0]:
    previous_output = inscription commit output (P2TR, single-leaf tapscript tree)
    sequence        = 0xfffffffd  (ENABLE_RBF_NO_LOCKTIME)
    witness         = [ schnorr_sig(64B),            // witness[0] - script-path BIP-340 sig (UNTWEAKED internal key)
                        inscription_script,           // witness[1] - the tapscript envelope (carries the PDF)
                        control_block(33B) ]          // witness[2] - single-leaf control block
  output[0]:
    value           = 0
    scriptPubKey    = anchor output <push payload(merkle_root)>   // ← 86-byte payload, NOT leaf_bytes (this is the whole change)
  output[1]:
    value           = change (commit_value − reveal_fee, > P2TR dust)
    scriptPubKey    = P2TR change back to the wallet
  locktime          = 0
```

### 1.1 Witness - `inscription_script` (`witness[1]`)

Built by `crates/witness-envelope` (`script.rs::build_inscription_script`),
identical to legacy ②:

```
<x-only internal pubkey> OP_CHECKSIG
OP_FALSE OP_IF
  <protocol_tag>          // default b"bcrt" (DEFAULT_TAG); informational only
  <content_type>          // e.g. b"application/pdf"; OPAQUE, informational only
  <body chunk_1> … <body chunk_n>   // each ≤ 520 B (MAX_PUSH); body = PDF bytes
OP_ENDIF
```

- **Opcodes:** `OP_FALSE = OP_PUSHBYTES_0 (0x00)`, `OP_IF (0x63)`, `OP_ENDIF (0x68)`.
- **Body reassembly:** plain concatenation of every push **after** `content_type`
  inside the `OP_IF … OP_ENDIF` block (no separators). A single-byte tamper flips
  `sha256(body)`.
- **Signing (load-bearing):** the script-path sig signs the leaf sighash with the
  **untweaked internal key** (`witness-envelope/src/sign.rs`). Reusing the
  tap-tweaked key-path signer yields "Invalid Schnorr signature" at relay.
- **`leaf_sha256(body) = sha256(body)`** (`witness-envelope/src/lib.rs`) - the
  value the verifier reassembles and binds to `record.leaf_bytes`.

> `protocol_tag` / `content_type` are NEVER trusted for the security decision and
> `content_type` MUST be HTML/URL-escaped before display.

### 1.2 Same envelope as legacy ②, one difference

| | legacy ② witness reveal | unified reveal |
|---|---|---|
| witness `[sig, script, control]` | yes | yes (identical) |
| spend type | script-path (BIP-342) | script-path (BIP-342) |
| `anchor output` payload | **raw 32 B = `leaf_bytes` = `sha256(PDF)`** | **`payload(merkle_root)` - 86 B** |
| merkle section in bundle | absent | **REQUIRED** |
| verifier branch | legacy (`anchor output == leaf_bytes`) | unified (merkle-bind) |

---

## 2. 86-byte anchor output exact byte layout (reproducible)

The anchor output **data payload** (the bytes pushed after `anchor output`, i.e. without
the `0x6a` opcode and without the push opcode/length) is **86 bytes**:

```
offset  len  field
------  ---  --------------------------------------------------------------
0..4     4   magic (4 B)             = 42 43 33 30
4..5     1   version 0x1E (= 30)     ( = anchoring_engine OP_RETURN_V30_VERSION; 0x1F = v31, see below )
5..6     1   flags                   ( bit 0 = WITNESS_PRESENT ; set 0x01 for unified )
6..22   16   batch_id (random 16 B)
22..54  32   merkle_root             ← the 32-byte slot the verifier extracts
54..86  32   aux_commitment          ( zero on 0x1E; AUX_COMMITMENT_NONE on an unbound 0x1F )
------  ---
total   86
```

> **v31 delta (`bundle-schema.md` §4.1, development plan §3.5).** Once the encoder
> moves to version **`0x1F`**, a unified witness reveal is written as
> `magic ‖ 0x1F ‖ flags=0x01 ‖ batch_id ‖ merkle_root ‖ AUX_COMMITMENT_NONE`, where
> `AUX_COMMITMENT_NONE = SHA256(aux tag ‖ TL_ROOT_NONE ‖ SMT_EMPTY_ROOT ‖ envelope_root)` (the exact domain-tag
> strings are listed in `bundle-schema.md` §9.3; the value is pinned in `fixtures/bc30-v2-vectors.json`). Bit 1
> (`IDENTITY_BOUND`) marks a batch of signed issuance records (bundle v4). **A bound
> batch with a witness (`flags = 0x03`) is undefined in this revision**: the encoder
> refuses it and the verifier treats it as a warning on the v4 path and rejects it
> on the legacy path. The verifier keeps decoding `0x1E` (mined anchors exist
> forever) and accepts a legacy bundle on an unbound `0x1F` payload only when the
> aux slot carries `AUX_COMMITMENT_NONE`.

This mirrors `bundle-schema.md` §4.1 and the verifier decoders
(`verify.py::decode_op_return`, `index.html::decodeOpReturn`):
`magic = b[:4]`, `version = b[4]`, `flags = b[5]`, `batch_id = b[6:22]`,
`merkle_root = b[22:54]`, `aux = b[54:86]`; length **MUST** be exactly 86. Version
and flags are then checked against the compatibility rule of `bundle-schema.md` §4.1
(`verify.py::legacy_payload_problem`, `index.html::legacyPayloadProblem`).

**On-the-wire scriptPubKey** for output[0] (86 B > 75, so `OP_PUSHDATA1` is used,
matching `bitcoin_tx.rs` `bc30_encoder_produces_86_byte_op_return`):

```
6a 4c 56 <86 payload bytes>
└┬ └┬ └┬─ length = 0x56 = 86
 │  └─── OP_PUSHDATA1 (0x4c)
 └────── anchor output (0x6a)
```

> **Flags note for W2:** the legacy single-anchor 86-byte payload (`services/anchoring`)
> writes `flags = 0x00`. The *unified* reveal SHOULD set `flags = 0x01`
> (`WITNESS_PRESENT`) so a chain observer can tell, from the anchor output alone, that
> the reveal also inscribes the artifact in its witness. The flags byte is **not**
> part of the commitment check (verifiers extract only the `merkle_root` slot);
> it is advisory. Keep `aux_commitment = 00 × 32`.
>
> **Reference: 53-byte legacy placeholder (53 B)** - still accepted by the
> verifier for older anchors: `magic 42433031 (4) | version 0x01(1) | merkle_root(32,
> at 5..37) | batch_id(16, at 37..53)`. The merkle_root slot is `b[5:37]`.

### 2.1 W2 change (informative, not part of the wire contract)

`services/inscription/src/witness/executor.rs` today builds output[0] as
`ScriptBuf::new_op_return(req.payload_hash)` (raw 32 B). W2 replaces that with
`anchor output(payload(merkle_root))` for the unified single-mode path. The `payload_hash`
field is no longer the anchor output content in unified mode; the binding to the PDF is
now `record.leaf_bytes` reached via the Merkle proof (§3, §4).

---

## 3. Single-mode Merkle bundle section

For a **single** attestation the Merkle tree has exactly **one leaf**. Per RFC
6962 §2.1 (`MTH({d0}) = SHA-256(0x00 || d0)`) and confirmed in
`ann-core/crates/merkle-batching/src/lib.rs` ("A tree with exactly one leaf has
`root = H_leaf(leaf)` - no self-pair") and
`services/verification/src/domain/proof_view.rs::single_leaf_tree_has_empty_proof_and_verifies`:

```
leaf_bytes  = sha256(PDF)                 // the document digest (record.leaf_bytes)
merkle_root = H_leaf(leaf_bytes)
            = SHA-256( 0x00 || leaf_bytes )
```

So the `merkle` section the producer emits for a single-mode unified bundle is:

```jsonc
"merkle": {
  "leaf_index": 0,
  "root": "<hex of H_leaf(leaf_bytes)>",   // = sha256(0x00 || leaf_bytes)
  "siblings":   [],                         // empty
  "directions": []                          // empty
}
```

### 3.1 Empty-siblings fold (verifier behaviour)

`verify.py::verify_merkle` / `index.html::verifyMerkle` compute:

```
cur = H_leaf(record.leaf_bytes)          # = SHA-256(0x00 || leaf_bytes)
for (sib, dir) in zip(siblings, directions):   # ← zero iterations when empty
    …
assert cur == merkle.root
```

With `siblings = directions = []` the loop body never runs, so
`cur == H_leaf(leaf_bytes)`, and the assertion reduces to
`H_leaf(leaf_bytes) == merkle.root` - exactly the single-leaf root. No special
case in the verifier is needed; the empty-list fold *is* the single-mode check.

**Pinned cross-reference vector (must never drift):**
`H_leaf(0x00 × 32) = 7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9`
(matches `bundle-schema.md` §3, `merkle-batching` `leaf_hash_of_zero_is_stable`,
and `proof_view.rs` `leaf_hash_matches_rfc6962_domain_tag`).

---

## 4. Verifier dual-mode specification

The verifier decides mode by **decoding the anchor output**:

```
decoded = decode_op_return(anchor.op_return_payload_hex)
if decoded recognises a BC01/payload magic   →  UNIFIED mode  (merkle-bind)
else (raw 32 B, no magic)                 →  LEGACY mode   (anchor output == leaf_bytes)
```

Both branches run only when `anchor.witness_envelope` is present (the witness
path). A non-witness standard anchor continues to use the normal `verify_bundle`
flow (§3/§4 of `bundle-schema.md`); it is unaffected.

### 4.1 LEGACY branch - UNCHANGED (backward compat)

Existing legacy-② / 4-tx witness bundles where `anchor output == leaf_bytes` and there
is **no** Merkle section. Verbatim today's `verify_witness_bundle` /
`verifyWitnessBundle`:

```
1. txid(reveal_tx_hex) == anchor.reveal_txid                       (§4.2 txid binding)
2. anchor output(reveal_tx_hex) == op_return_payload_hex == leaf_bytes (the doc IS the committed leaf)
3. body = concat(envelope pushes after content_type)
   ASSERT sha256(body) == record.leaf_bytes        ← bind to leaf_bytes
4. (optional) confirm reveal_txid on a Bitcoin source of your choosing
```

Detection: `decode_op_return` raises "unknown anchor output magic" → the 32-byte raw
payload is *not* a BC0x envelope → LEGACY. (Equivalently: `op_return_payload_hex`
is 64 hex chars / 32 bytes with no BC magic.)

### 4.2 UNIFIED branch - NEW (merkle-bind)

When `decode_op_return` succeeds (BC01 or 86-byte payload) **and** `witness_envelope` is
present:

```
1. txid(reveal_tx_hex) == anchor.reveal_txid                       (§4.2 txid binding)
   AND anchor output(reveal_tx_hex) == op_return_payload_hex           (raw-tx self-consistency)

2. decoded = decode_op_return(op_return_payload_hex)               (86-byte payload → merkle_root slot, b[22:54])

3. (computed_root, ok) = verify_merkle(record, merkle)            (§3 - H_leaf fold)
   ASSERT ok                                                       (record.leaf_bytes is in this root)
   ASSERT computed_root == decoded.merkle_root                     (the anchored root == the proven root)
   #  i.e. verify_merkle(record, merkle) == merkle.root == decoded["merkle_root"]

4. items = extract_witness_items(reveal_tx_hex, witness_envelope.input_index)
   env   = parse_envelope(items[1])           (recover tag, content_type, body)
   body  = concat(pushes after content_type)
   ASSERT sha256(body) == record.leaf_bytes   ← bind recovered witness body to leaf_bytes

5. (optional) confirm reveal_txid on a Bitcoin source of your choosing  (§4.3)
```

**The binding chain (unified):**
```
PDF bytes ─(recover from witness)→ body
sha256(body) == record.leaf_bytes               (step 4 - witness → leaf)
H_leaf(record.leaf_bytes) == merkle.root        (step 3 - leaf → root, single-leaf fold)
merkle.root == decoded.merkle_root (anchor output)  (step 3 - root → on-chain)
anchor output ⊂ txid-committed (non-witness) bytes  (step 1 - on-chain → Bitcoin)
```

Every link is to a **txid-committed** value (anchor output is in the non-witness
serialization; the witness is malleable). A tampered witness body fails step 4
while leaving the txid intact; a forged Merkle proof fails step 3; a swapped tx
fails step 1. The verifier MUST NOT accept `witness_envelope.leaf_sha256` (or any
self-declared field) as the expected hash - that would be circular.

> **Why not reuse the legacy "anchor output == leaf_bytes" check in unified mode?**
> In the unified tx `anchor output = payload(merkle_root) ≠ leaf_bytes`. The leaf binding
> is reached *through the Merkle proof* (single-leaf: `merkle_root =
> H_leaf(leaf_bytes)`), so it is still fully txid-committed - just one hop longer.

---

## 5. `bundle-schema` v2.1 delta - unified witness bundle

A **unified witness bundle** is a `bitcert-proof-bundle/v1` bundle that combines
the §3 Merkle section with the §4.4 `witness_envelope`. The deltas vs. the legacy
§4.4 example:

| field | legacy ② witness bundle | **unified** witness bundle |
|---|---|---|
| `record.kind` | `"attestation"` | `"attestation"` |
| `record.preimage` | `{scheme:"sha256-file", content_type:"application/pdf"}` | same |
| `record.leaf_bytes` | `sha256(PDF)` | `sha256(PDF)` (unchanged - still the doc digest) |
| **`merkle`** | **absent** | **REQUIRED** - `leaf_index:0, siblings:[], directions:[], root = H_leaf(leaf_bytes)` |
| `anchor.reveal_txid` | the witness reveal txid | the **unified** reveal txid (= the standard anchor txid; there is only one) |
| `anchor.reveal_tx_hex` | witness-carrying reveal | the **same** unified reveal (carries witness **and** 86-byte anchor output) |
| **`anchor.op_return_payload_hex`** | raw 32 B = `leaf_bytes` | **`payload(merkle_root)` - 172 hex / 86 B** |
| `anchor.witness_envelope` | `{input_index, content_type, protocol_tag}` | same (presence selects the witness path) |

Key invariants for the unified bundle:

1. `anchor.reveal_txid` (the standard-anchor reveal) **==** the
   `witness_envelope`-carrying reveal tx - they are one and the same transaction.
2. `merkle` section is **REQUIRED** (it is the link from `leaf_bytes` to the
   on-chain `merkle_root`).
3. `op_return_payload_hex` is a **86-byte payload** payload (decodes via §2), **not** a raw
   `leaf_bytes`. This is what flips the verifier into the unified branch (§4).
4. `op_return_payload_hex` decoded `merkle_root` slot **== `merkle.root` == the
   single-leaf `H_leaf(leaf_bytes)`**.

Example unified `anchor` (abbreviated):

```jsonc
"record": {
  "kind": "attestation",
  "leaf_bytes": "<sha256(PDF)>",
  "preimage": { "scheme": "sha256-file", "content_type": "application/pdf" }
},
"merkle": {
  "leaf_index": 0,
  "root": "<H_leaf(leaf_bytes)>",
  "siblings": [],
  "directions": []
},
"anchor": {
  "reveal_txid": "<unified reveal txid>",
  "reveal_tx_hex": "0200…",                       // witness carries PDF; anchor output = 86-byte payload
  "op_return_payload_hex": "424333301e01…",       // payload(merkle_root), 86 bytes
  "witness_envelope": { "input_index": 0, "content_type": "application/pdf", "protocol_tag": "bcrt" }
}
```

> **Privacy / one-way door (unchanged):** inscribing is irreversibly public and
> permanent. Unified witness anchoring is ONLY for `sha256-file`-style audit
> documents cleared for public chain - NEVER for `sha256-jcs-fields` daily PII.

---

## 6. Concrete KAT vector (computed; show your work)

Fixed input PDF (62 bytes), and every derived value. The fixture generator
(`fixtures/generate.py`) will build the full *signed* tx from these (sig +
control block depend on the test key + commit UTXO; the values below are the
content-determined ones).

```
pdf_bytes (62 B), hex =
  255044462d312e340a312030206f626a3c3c3e3e656e646f626a0a554e49464945442d
  5749544e4553532d434f4e5452414354204b41540a2525454f460a
  (ASCII: "%PDF-1.4\n1 0 obj<<>>endobj\nUNIFIED-WITNESS-CONTRACT KAT\n%%EOF\n")
```

Step-by-step:

```
leaf_bytes  = sha256(pdf_bytes)
            = 59db99c5c4bb5da4e7b6344c28456dc5503eaf10d18a10ec4a13ed140d1bdb54
            ( = record.leaf_bytes ; also = sha256(witness body), bound in §4 step 4 )

merkle_root = H_leaf(leaf_bytes) = sha256(0x00 || leaf_bytes)       // single-leaf, §3
            = 7f19eb1cdb45026b630ba0b21deee4326e5220e5f67e9b7e675b6b5d0791e823
            ( = merkle.root ; siblings = [], directions = [] )

batch_id    = 0192a3b4c5d6e7f80192a3b4c5d6e7f8      // 16 B UUIDv7 raw (fixture constant)
version     = 0x1E (30)
flags       = 0x01 (WITNESS_PRESENT)
aux         = 00 × 32

op_return_payload_hex (86-byte payload, 86 B) =
  42 43 33 30          "86-byte payload"
  1e                   version 30
  01                   flags (WITNESS_PRESENT)
  0192a3b4c5d6e7f80192a3b4c5d6e7f8                                    batch_id
  7f19eb1cdb45026b630ba0b21deee4326e5220e5f67e9b7e675b6b5d0791e823    merkle_root (= b[22:54])
  0000000000000000000000000000000000000000000000000000000000000000    aux_commitment

  = 424333301e010192a3b4c5d6e7f80192a3b4c5d6e7f87f19eb1cdb45026b630ba0b21deee4326e5220e5f67e9b7e675b6b5d0791e8230000000000000000000000000000000000000000000000000000000000000000

op_return scriptPubKey (output[0]) = 6a 4c 56 <86 payload bytes>      // anchor output OP_PUSHDATA1 86
```

Verifier round-trip assertions this vector must satisfy:

```
decode_op_return(op_return_payload_hex)["merkle_root"] == merkle_root  ✓  (b[22:54])
verify_merkle({leaf_bytes}, {root:merkle_root, siblings:[], directions:[]})
    → computed_root == merkle_root                                     ✓  (empty-fold = H_leaf)
sha256(pdf_bytes) == leaf_bytes                                        ✓  (witness body bind)
H_leaf(leaf_bytes) == merkle_root == decoded.merkle_root              ✓  (full chain)
```

Cross-check constant (independent of the PDF):
`H_leaf(0x00 × 32) = 7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9`.

---

## 7. Reference touch-points for the W2/W3 agents

- **anchor output encoder / 86-byte layout:**
  `services/anchoring/src/bitcoin/op_return_placeholder.rs` (BC01) +
  `anchoring_engine::OpReturnV30Payload::encode` (86-byte payload, patent encoder);
  byte assertions in `bitcoin_tx.rs::bc30_encoder_produces_86_byte_op_return`.
- **Witness envelope (PDF-in-witness):** `crates/witness-envelope/src/{lib,script,sign}.rs`
  (`leaf_sha256`, `Inscription`, untwawked script-path sig).
- **W2 anchor output change site:** `services/inscription/src/witness/executor.rs`
  (replace `ScriptBuf::new_op_return(req.payload_hash)` → `anchor output(payload(merkle_root))`).
- **Bundle assembler (producer):** `services/verification/src/domain/bundle.rs`
  (`AnchorBundleSection`, `MerkleProofSection`, `build_attestation_bundle`).
- **Verifier (consumers, dual-mode):** `verify-cli/verify.py`
  (`decode_op_return`, `verify_merkle`, `verify_witness_bundle`) and
  `index.html` (`decodeOpReturn`, `verifyMerkle`, `verifyWitnessBundle`).
- **Fixture generator:** `fixtures/generate.py` (`bc30`, `merkle4`,
  `build_reveal_tx`, `assemble_bundle`) - extend to emit a **unified** fixture
  (`07-unified-witness-inscription.json`) from the §6 KAT.
- **Single-leaf root law:** `ann-core/crates/merkle-batching/src/lib.rs` (root =
  H_leaf(leaf) for one leaf) + `proof_view.rs::single_leaf_tree_has_empty_proof_and_verifies`.
- **General wire contract:** `docs/bundle-schema.md` §3 (merkle), §4.1
  (anchor output), §4.2 (txid binding), §4.4 (witness_envelope).
