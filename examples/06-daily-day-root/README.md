# 06 · Daily day_root (v2 — the anchor commits the trust reconciliation)

A **v2** daily bundle. The anchor output no longer carries the bare customer-balance Merkle root — it carries `day_root`:

```
recon_commitment = SHA256("attest:daily:recon\n"  || JCS{assets_hash, business_date, exchange_id, reconciliation_ok})
day_root         = SHA256("attest:daily:anchor\n" || JCS{balances_root, business_date, exchange_id, recon_commitment})
```

So one Bitcoin anchor attests BOTH the customer liabilities (the Merkle root) AND the (a)/(b)/(c) trust reconciliation. The verifier recomputes `day_root` from the `reconciliation` section + the Merkle root and asserts it equals the anchor output (§4) and the chain `body_hash` (§5).

```bash
python3 ../../verify-cli/verify.py bundle.json --account alice@demoex --salt 5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e
```

Expected: every check ✓ → **VERIFIED**, with step 6 listing the per-asset (a)/(b)/(c). NOTE: the (a) reserve side is exchange-supplied, not independently measured. Flip any residual and step 2 (anchor output ≠ recomputed day_root) FAILS.
