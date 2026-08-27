# 09 · Identity-bound issuance, `es256-plain` issuer key (bundle v4)

The Merkle leaf is no longer the bare document hash. It is `leaf_input = SHA256(leaf-v2 tag ‖ 0x01 ‖ R ‖ s)`, where `R` is the 143-byte record (salt, `doc_sha256`, subject, times, `policy_hash`) and `s` is the **issuer's ES256 signature** over `m = SHA256(issue-v2 tag ‖ …)` (the domain tags are listed in docs/bundle-schema.md §2.3). The issuer key is proven to be in the anchored trust list (`aux.tl_proof` → `tl_root` → `aux_commitment` on-chain), and an exclusion proof against `sl_root` shows the record was not revoked when anchored.

```bash
python3 ../../verify-cli/verify.py bundle.json --now 1782000700
```

Expected: **VALID** (exit 0). `--now` pins the clock so the expiry check is reproducible; omit it in real use. This record has no subject (`subject_type 0`), so attribution is `none` and there is no presenter check.
