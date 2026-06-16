# 08 · Tampered unified witness body is caught (step 3)

Same unified bundle as example 07, but one bit of the **witness body** (the inscribed PDF) was flipped. The witness is NOT committed to the txid, so the `reveal_txid` and the `BC30(merkle_root)` anchor output are unchanged — steps 1 (txid binding) and 2 (record binds to the on-chain merkle_root) still pass. But the recovered body no longer hashes to `record.leaf_bytes`, so step 3 FAILS.

```bash
python3 ../../verify-cli/verify.py bundle.json
```

Expected: step 3 ✗ → **VERIFICATION FAILED** (exit 1). This is the headline tamper-evidence of a witness inscription: the document is bound to a txid-committed value (`leaf_bytes` via the Merkle proof), so the malleable witness cannot be altered without detection.
