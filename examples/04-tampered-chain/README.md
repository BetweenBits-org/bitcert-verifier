# 04 · Tampered per-exchange chain is caught (link D · §5)

Same anchored daily bundle as example 02, but the chain entry's `payload_hash` was forged. Links A/B/C (preimage + Merkle + Bitcoin) all still pass — the day's Merkle root really is anchored — yet the §5 chain entry no longer recomputes from its preimage, so step 4 FAILS.

`payload_hash = SHA-256("bitcert:chain:v1\n" || JCS(entry_core))` — the verifier recomputes it and also checks `body_hash == merkle.root` for a daily entry. Both are cryptographic and gate the verdict.

```bash
python3 ../../verify-cli/verify.py bundle.json
```

Expected: step 4 ✗ → **VERIFICATION FAILED** (exit 1).
