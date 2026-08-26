# 01 · Attestation by file artifact (link A = `sha256-file`)

`leaf_bytes = SHA-256(original-report.txt)`. The verifier hashes the file you supply and confirms it equals the anchored leaf.

```bash
python3 ../../verify-cli/verify.py bundle.json --original original-report.txt
```

Expected: every check ✓ → **VERIFIED**. Try editing `original-report.txt` by one byte and re-run: step 0 (Original binding) then FAILS - the file no longer matches what was anchored.
