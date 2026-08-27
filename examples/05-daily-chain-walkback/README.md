# 05 · Daily chain walk-back (§5 continuity via `chain.links`)

A two-day per-exchange chain. The head entry is today (seq 2); yesterday (seq 1) rides along in `chain.links`. The verifier confirms each prior entry recomputes its own `payload_hash` and that `today.prev_entry_hash == payload_hash(yesterday)` - the tamper-evident hash linkage that makes a per-exchange chain auditable.

```bash
python3 ../../verify-cli/verify.py bundle.json --account alice@demoex --salt 5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e
```

Expected: every check ✓ → **VERIFIED**, with step 4 reporting `walked 1 prior entry + head: hash-linkage holds`. Flip any byte of the linked entry and step 4 FAILS.
