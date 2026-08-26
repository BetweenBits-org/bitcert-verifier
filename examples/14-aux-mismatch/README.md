# 14 · aux_commitment mismatch is caught

The on-chain `aux_commitment` (bytes 54..86 of the v31 payload) was produced from a different trust list / status list than the one the bundle carries. Steps 9 (trust-list inclusion) and 15 (revocation exclusion) verify against the bundle's own roots, but step 11 recomputes `SHA256(aux tag ‖ tl_root ‖ sl_root ‖ envelope_root)` and finds it is **not** what Bitcoin committed - so the roots are unproven and the bundle is rejected.

```bash
python3 ../../verify-cli/verify.py bundle.json --now 1782000700
```

Expected: step 11 ✗ → **REJECTED** (exit 1).
