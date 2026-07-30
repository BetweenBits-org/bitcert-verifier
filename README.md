# bitcert-verifier

**Independent, offline verifier for Bitcoin-anchored proof bundles.**
Confirm a record was anchored to Bitcoin and not tampered with — using only
**math** and the **Bitcoin blockchain**. This tool never contacts BitCert.

[![verify](https://github.com/BetweenBits-org/bitcert-verifier/actions/workflows/verify.yml/badge.svg)](https://github.com/BetweenBits-org/bitcert-verifier/actions/workflows/verify.yml)

---

## Why this exists

When BitCert says *"this record is anchored to Bitcoin and verified"*, you
shouldn't have to take BitCert's word for it. The whole point of anchoring to
Bitcoin is that you can check it **yourself** — even if BitCert lies, is hacked,
or disappears entirely.

That only works if the verifier is something you can **read, rebuild, and run
without us**. So this verifier is:

- **Open source** (MIT) — read every line; fork it; write your own.
- **Self-contained** — `index.html` is a single file with **zero dependencies**.
  Save it and run it offline, forever, from `file://`.
- **Hosted independently of BitCert** — served from GitHub Pages / Releases, not
  a BitCert server.
- **Spec-published** — the [proof bundle format](docs/bundle-schema.md) is
  documented so a regulator or auditor can build a *different* verifier and get
  the same answer.

The only things you trust are **SHA-256** and the **Bitcoin blockchain**. Not us.

> This repository is **family-agnostic**: it verifies any anchored proof bundle
> (BitCert Attest daily/monthly, and future products) that conforms to
> [`docs/bundle-schema.md`](docs/bundle-schema.md).

### Zero-knowledge statements (bundle §8)

Bundles may also carry a **zk** section proving a statement about hidden values
— "the sum of these committed reserves is at least the issued supply" — without
revealing the values, or for comparison statements even the sum. The verifier
checks it with the same rules as everything else here: no dependencies, no
network, plain BigInt over secp256k1 you can read in
[`zk-core.js`](zk-core.js).

Two things worth knowing before you trust a green tick on a zk bundle:

- **The public inputs must be YOUR values.** The transcript binds `org_id`,
  `run_ref` and the threshold, so a verifier that reads them out of the bundle
  is letting the prover choose which statement it proved. This page has no
  independent record of yours, so it uses the bundle's own and says so.
- **A zk-only bundle has no timestamp.** It proves the statement, not when the
  claim was made. Add the anchor group and Bitcoin supplies the date.

---

## Use it

### Browser (no install, works offline)

1. Download [`index.html`](index.html) from this repo and open it in any browser
   (it works straight from `file://` and makes no network calls on its own).
2. Paste or drop a proof bundle JSON.
3. Click **Verify offline**.

### Command line (Python 3, standard library only)

```bash
python3 verify-cli/verify.py bundle.json
cat bundle.json | python3 verify-cli/verify.py -
# optional: confirm it's in a block via a Bitcoin source YOU pick (never BitCert)
python3 verify-cli/verify.py bundle.json --explorer https://mempool.space
```

Exit code `0` = all cryptographic checks passed.

---

## The chain of trust

```
 original record ──link A──▶ leaf_bytes ──link B──▶ merkle root ──link C──▶ Bitcoin
  (your PDF /                  32 bytes      (inclusion          (anchor output → txid → block)
   your balance)                              proof)
```

- **Link B + C** are proven by the verifier with pure offline cryptography — always.
- **Link A** (is that 32-byte leaf really *your* document/balance?) is proven when
  you supply the original. Without it, the verifier proves only that *some* digest
  is anchored — see step 0 below.

## What it checks

| # | Check | Needs network? |
|---|-------|----------------|
| 0 | **Original binding** *(link A, optional)* — recompute `leaf_bytes` from the original you supply: `SHA-256(file)` for a document, or `SHA-256(domain‖JCS{asset,balance_minor,user_commitment})` for a daily balance (and `user_commitment=SHA-256(salt‖account)`). | No |
| 1 | **Merkle inclusion** — the leaf folds up to the claimed Merkle root (RFC-6962, `H_leaf=SHA256(0x00‖d)`, `H_node=SHA256(0x01‖l‖r)`). | No |
| 2 | **anchor output commitment** — that root is the value committed inside the transaction's `anchor output` (BC01/BC30). | No |
| 3 | **Transaction binding** — those `anchor output` bytes belong to *exactly* the stated anchor txid, by recomputing the txid as double-SHA-256 of the raw transaction. | No |
| 4 | **Chain continuity** *(optional)* — per-exchange `payload_hash`/`prev_entry_hash` links recompute. | No |
| 5 | **On-chain confirmation** *(optional)* — the txid sits in a block with enough confirmations, via a Bitcoin source **you** choose. | Yes — your node / any explorer, **never BitCert** |

Steps 0–4 are pure offline cryptography. Step 5 is the single Bitcoin-dependent
check; offline, the verifier reports it as `SKIPPED` and the binding from step 3
still holds.

See [`docs/bundle-schema.md`](docs/bundle-schema.md) for the exact wire format.

## Try it — worked examples

The [`examples/`](examples/) folder has runnable scenarios, each with a bundle and
its original record. Run them all at once:

```bash
bash examples/run.sh
```

Or step through them — each subfolder has its own `README.md`:

```bash
# 1) A document artifact: hash the original and bind it to the anchored leaf (link A)
python3 verify-cli/verify.py examples/01-attestation-file/bundle.json \
    --original examples/01-attestation-file/original-report.txt        # → VERIFIED

# 2) A daily balance: prove the leaf is YOUR row, privately, from your account + salt
#    (the salt is your secret — it is NOT in the public bundle; see customer-secret.txt)
python3 verify-cli/verify.py examples/02-daily-balance/bundle.json \
    --account alice@demoex --salt 5e5e...5e                             # → VERIFIED (identity match)

# 3) A swapped original is caught: Merkle/Bitcoin still pass, but step 0 FAILS
python3 verify-cli/verify.py examples/03-tampered-original/bundle.json \
    --original examples/03-tampered-original/tampered-report.txt        # → FAILED (exit 1)
```

In the **browser**, open `index.html`, click **Load sample** (a daily-balance
bundle), then use the **0 · Original record** card: drop a file for a document
bundle, or type your `account id` + `salt` for a daily bundle, and click
**Verify offline**.

---

## Reproducible build & trust

There is no build step — `index.html` *is* the artifact. To convince yourself the
hosted page equals this source:

```bash
# hash the file you're about to trust
shasum -a 256 index.html
```

CI publishes the same `SHA256(index.html)` as a build artifact on every run, so any
copy you obtain can be matched byte-for-byte against this repository. The verifier
vendors **no** third-party code (no CDN, no npm), so there is no supply-chain surface
at runtime.

## Tests

```bash
python3 fixtures/generate.py            # regenerate fixtures + examples + inline HTML sample
bash    examples/run.sh                  # run every worked example, assert pass/fail
python3 verify-cli/verify.py fixtures/sample-bundle.valid.json      # → VERIFIED, rc 0
python3 verify-cli/verify.py fixtures/sample-bundle.tampered.json   # → FAILED,   rc 1
node    fixtures/browser-js-check.mjs   # browser JS == Python == ann-core test vector
```

The fixture cross-check pins `H_leaf(0x00×32) =`
`7f9c9e31…7396ce9`, the same vector asserted in
`ann-core/crates/merkle-batching`, so this verifier cannot silently drift from the
production Merkle tree.

## License

MIT — see [LICENSE](LICENSE). Fork it, ship it, audit it.
