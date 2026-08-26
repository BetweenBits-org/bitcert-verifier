# 13 · Expired document → warning, not rejection

`expires_at` is in the past relative to `--now`. Every cryptographic check passes - the anchor, signature and trust list are genuine - so the verdict is **VALID WITH WARNINGS** (exit 2). Whether an expired document is acceptable is the verifier's policy, not the mathematics.

```bash
python3 ../../verify-cli/verify.py bundle.json --now 1782000700
```

Expected: step 14 `!` → exit 2.
