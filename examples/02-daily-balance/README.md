# 02 · Daily balance by salted commitment (link A = `sha256-jcs-fields`)

`leaf_bytes = SHA-256("attest:daily:leaf\n" || JCS({asset, balance_minor, user_commitment}))`, and `user_commitment = SHA-256(salt || account_id)`.

The salt is the **customer's private secret** - it is deliberately NOT in the public bundle (otherwise anyone could de-anonymize accounts). It lives in `customer-secret.txt` here to simulate what the customer holds.

Self-consistency only (no secret needed) - proves the leaf is the hash of the shown fields:
```bash
python3 ../../verify-cli/verify.py bundle.json
```

Full identity binding - proves the leaf is *your* row, privately:
```bash
python3 ../../verify-cli/verify.py bundle.json --account alice@demoex --salt 5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e
```

Expected: **VERIFIED**, with step 0 reporting `identity … match`. A wrong `--account`/`--salt` makes the identity check MISMATCH.
