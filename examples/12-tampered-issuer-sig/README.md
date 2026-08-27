# 12 · Tampered issuer signature is caught

Same bundle as example 10 with **one byte of the DER signature flipped**. The Merkle proof, anchor and trust list are untouched, but step 5 (ES256 under the trust-list key) fails - and because `s` is part of `leaf_input`, step 6 fails too: the anchored leaf was computed over the genuine signature.

```bash
python3 ../../verify-cli/verify.py bundle.json --now 1782000700
```

Expected: **REJECTED** (exit 1).
