# 03 · Tampered original is caught (link A)

Same anchored bundle as example 01, but the original file was altered. Links B/C (Merkle + Bitcoin) still pass - the anchor is real - yet the document no longer hashes to the anchored leaf, so step 0 FAILS.

```bash
python3 ../../verify-cli/verify.py bundle.json --original tampered-report.txt
```

Expected: step 0 ✗ → **VERIFICATION FAILED** (exit 1). This is link A doing its job: proving the *content* you hold is the one that was anchored.
