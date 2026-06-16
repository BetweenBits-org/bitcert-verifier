# 07 · Unified witness inscription (PDF in the witness + `BC30(merkle_root)` anchor output)

One Bitcoin reveal transaction that is **both** the standard Merkle anchor **and** the witness carrier — replacing the old two-tx (anchor + inscription) flow for single-mode audit anchors. See `docs/UNIFIED-WITNESS-CONTRACT.md`.

- `output[0]` = `anchor output(BC30(merkle_root))` — **not** `leaf_bytes` (the whole change).
- `witness[1]` = the BIP-342 tapscript envelope carrying the audit PDF.
- `merkle` = a single-leaf section (`leaf_index 0`, `siblings []`, `root = H_leaf(leaf_bytes)`).

The verifier recovers the PDF straight from the witness and binds it through the chain `body → leaf_bytes → merkle_root → anchor output → txid`:

```bash
python3 ../../verify-cli/verify.py bundle.json
```

Expected: every check ✓ → **VERIFIED** (no off-bundle file needed — the document IS on Bitcoin). `original.pdf` ships only so you can re-hash the 62 KAT bytes yourself: `sha256(original.pdf) == record.leaf_bytes`.

Because the witness is **malleable** (not committed to the txid), a tampered witness body leaves the txid and anchor output intact (steps 1–2 still pass) but fails step 3 (`sha256(body) ≠ leaf_bytes`) — see `../08-tampered-witness/` and `fixtures/07-witness-unified.tampered.json`.
