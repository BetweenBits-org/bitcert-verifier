# bitcert-verifier

**Independent, offline verifier for Bitcoin-anchored proof bundles.**
Confirm a record was anchored to Bitcoin and not tampered with - using only
**math** and the **Bitcoin blockchain**. This tool never contacts BitCert.

[![verify](https://github.com/BetweenBits-org/bitcert-verifier/actions/workflows/verify.yml/badge.svg)](https://github.com/BetweenBits-org/bitcert-verifier/actions/workflows/verify.yml)

---

## Why this exists

When BitCert says *"this record is anchored to Bitcoin and verified"*, you
shouldn't have to take BitCert's word for it. The whole point of anchoring to
Bitcoin is that you can check it **yourself** - even if BitCert lies, is hacked,
or disappears entirely.

That only works if the verifier is something you can **read, rebuild, and run
without us**. So this verifier is:

- **Open source** (MIT) - read every line; fork it; write your own.
- **Self-contained** - `index.html` is a single file with **zero dependencies**.
  Save it and run it offline, forever, from `file://`.
- **Hosted independently of BitCert** - served from GitHub Pages / Releases, not
  a BitCert server.
- **Spec-published** - the [proof bundle format](docs/bundle-schema.md) is
  documented so a regulator or auditor can build a *different* verifier and get
  the same answer.

The only things you trust are **SHA-256**, **ECDSA P-256** (for signed issuance
records) and the **Bitcoin blockchain**. Not us.

> This repository is **family-agnostic**: it verifies any anchored proof bundle
> (BitCert Attest daily/monthly, and future products) that conforms to
> [`docs/bundle-schema.md`](docs/bundle-schema.md).

### Zero-knowledge statements (bundle §8)

Bundles may also carry a **zk** section proving a statement about hidden values
- "the sum of these committed reserves is at least the issued supply" - without
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
- **The CLI does not implement the zk verifier.** `verify.py` reports a `zk`
  section as *undetermined* (exit 3) rather than pretending; use the browser.

### Identity-bound issuance (bundle v4, §2.3 / §9–§11)

A **v4** bundle anchors more than a document hash. Its Merkle leaf is a signed
issuance record: the **issuer's ES256 signature** (a browser passkey or a
customer KMS key) over the document hash, a salted recipient reference, the
issue/expiry times and the document type. The same anchor commits, in its
`aux_commitment` slot, the issuer **trust list** and the **revocation list** at
anchor time - so "who issued this" and "was it revoked when anchored" are proven
offline, not asserted. A recipient who registered a passkey can additionally
prove, in front of the verifier, that they hold that key (a one-time challenge
this verifier generates itself - no BitCert API).

Verdicts on v4 bundles have **four grades** - `valid < warning < undetermined <
rejected` (the worst step wins; missing evidence never rounds up to valid) - and
two **axes**: *attribution* (`none` · `issuer-claim · identifier` · `issuer-claim ·
pubkey`) and *presenter* (`confirmed` · `not available`). The passkey relying party
is **pinned** to `console.bitcert.io`; the bundle's own `rp_id` is only a claim.

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

# bundle v4 (identity-bound issuance)
python3 verify-cli/verify.py bundle.json --identifier alice@example.com   # subject_type 1: check the salted reference
python3 verify-cli/verify.py bundle.json --present-url                   # subject_type 2: print the one-time /present link
python3 verify-cli/verify.py bundle.json --present BLOB --nonce HEX      # …then check the recipient's signed blob
python3 verify-cli/verify.py --selftest                                  # P-256 (RFC 6979 A.2.5), DER, SMT, KAT vectors
```

Requires Python **3.8+** (standard library only). Exit codes: `0` valid · `1`
rejected · `2` warning · `3` undetermined · `64` usage / not JSON. Legacy bundles
(v1–v3) keep their historical `0` / `1`. `--rp-id` / `--origin` / `--now` override
the pinned relying party and the clock for staging or reproducible runs.

---

## The chain of trust

```
 original record ──link A──▶ leaf_bytes ──link B──▶ merkle root ──link C──▶ Bitcoin
  (your PDF /                  32 bytes      (inclusion          (anchor output → txid → block)
   your balance)                              proof)
```

- **Link B + C** are proven by the verifier with pure offline cryptography - always.
- **Link A** (is that 32-byte leaf really *your* document/balance?) is proven when
  you supply the original. Without it, the verifier proves only that *some* digest
  is anchored - see step 0 below.

## What it checks

| # | Check | Needs network? |
|---|-------|----------------|
| 0 | **Original binding** *(link A, optional; also binds a hash-only issuance, whose bundle states no file type)* - recompute `leaf_bytes` from the original you supply: `SHA-256(file)` for a document, or `SHA-256(domain‖JCS{asset,balance_minor,user_commitment})` for a daily balance (and `user_commitment=SHA-256(salt‖account)`). | No |
| 1 | **Merkle inclusion** - the leaf folds up to the claimed Merkle root (RFC-6962, `H_leaf=SHA256(0x00‖d)`, `H_node=SHA256(0x01‖l‖r)`). | No |
| 2 | **anchor output commitment** - that root is the value committed inside the transaction's `anchor output` (53- or 86-byte payload). | No |
| 3 | **Transaction binding** - those `anchor output` bytes belong to *exactly* the stated anchor txid, by recomputing the txid as double-SHA-256 of the raw transaction. | No |
| 4 | **Chain continuity** *(optional)* - per-exchange `payload_hash`/`prev_entry_hash` links recompute. | No |
| 5 | **On-chain confirmation** *(optional)* - the txid sits in a block with enough confirmations, via a Bitcoin source **you** choose. | Yes - your node / any explorer, **never BitCert** |
| 6 | **Issuer signature** *(v4)* - rebuild the 143-byte record `R` and `m = SHA-256(issue-v2 tag ‖ …)`; verify the issuer's ES256 signature (`webauthn-es256`: challenge = `m`, pinned rpId, origin, UP/UV, `authData ‖ SHA-256(clientDataJSON)`; `es256-plain`: over `m`); `leaf_bytes == SHA-256(leaf-v2 tag ‖ 0x01 ‖ R ‖ s)`. | No |
| 7 | **Trust list + aux commitment** *(v4)* - the signing key's entry folds to `tl_root`; `SHA-256(aux tag ‖ tl_root ‖ sl_root ‖ envelope_root)` equals bytes 54..86 of the v31 payload (`IDENTITY_BOUND` flag required). | No |
| 8 | **Key validity at block time** *(v4)* - `valid_from` / `valid_to` / `revoked_at` judged at `block_time`, never at the self-reported `issued_at`. No `block_time` ⇒ *undetermined*. | No |
| 9 | **Not revoked when anchored** *(v4)* - 256-level sparse-Merkle exclusion proof folded from the **pinned** empty leaf `SHA-256(0x11)` to `sl_root`; a present value ⇒ revoked ⇒ rejected. | No |
| 10 | **Recipient / presenter** *(v4)* - `subject_ref` recomputed (zero · `SHA-256(salt ‖ identifier)` · `SHA-256(0x02 ‖ curve ‖ pubkey)`); for a registered key, the holder signs a challenge this verifier generated (`nonce ‖ leaf ‖ verifier_id ‖ expiry`). Missing/failed ⇒ *presenter: not available*, never rejected. | No (the signing itself needs the console origin) |
| 11 | **Expiry** *(v4)* - `expires_at` in the past ⇒ warning, never rejection. | No |

Steps 0–4 and 6–11 are pure offline cryptography. Step 5 is the single
Bitcoin-dependent check; offline, the verifier reports it as `SKIPPED` and the
binding from step 3 still holds. The full v4 pipeline (19 numbered steps, four
grades, two axes) is in [`docs/bundle-schema.md`](docs/bundle-schema.md) §11.

See [`docs/bundle-schema.md`](docs/bundle-schema.md) for the exact wire format.

## Try it - worked examples

The [`examples/`](examples/) folder has runnable scenarios, each with a bundle and
its original record. Run them all at once:

```bash
bash examples/run.sh
```

Or step through them - each subfolder has its own `README.md`:

```bash
# 1) A document artifact: hash the original and bind it to the anchored leaf (link A)
python3 verify-cli/verify.py examples/01-attestation-file/bundle.json \
    --original examples/01-attestation-file/original-report.txt        # → VERIFIED

# 2) A daily balance: prove the leaf is YOUR row, privately, from your account + salt
#    (the salt is your secret - it is NOT in the public bundle; see customer-secret.txt)
python3 verify-cli/verify.py examples/02-daily-balance/bundle.json \
    --account alice@demoex --salt 5e5e...5e                             # → VERIFIED (identity match)

# 3) A swapped original is caught: Merkle/Bitcoin still pass, but step 0 FAILS
python3 verify-cli/verify.py examples/03-tampered-original/bundle.json \
    --original examples/03-tampered-original/tampered-report.txt        # → FAILED (exit 1)

# 9–14) Identity-bound issuance (bundle v4). --now pins the clock so expiry checks reproduce.
python3 verify-cli/verify.py examples/09-issuance-plain/bundle.json --now 1782000700              # → VALID (es256-plain issuer key)
python3 verify-cli/verify.py examples/10-issuance-passkey/bundle.json \
    --identifier alice@example.com --now 1782000700                                                # → VALID, attribution ✓ (passkey issuer)
python3 verify-cli/verify.py examples/11-issuance-presentation/bundle.json \
    --present examples/11-issuance-presentation/presentation.txt \
    --nonce 0f1e2d3c4b5a69788796a5b4c3d2e1f0 --now 1782000700                                     # → VALID, presenter: confirmed
python3 verify-cli/verify.py examples/12-tampered-issuer-sig/bundle.json --now 1782000700         # → REJECTED (exit 1)
python3 verify-cli/verify.py examples/13-expired-document/bundle.json --now 1782000700            # → WARNING (exit 2)
python3 verify-cli/verify.py examples/14-aux-mismatch/bundle.json --now 1782000700                # → REJECTED (exit 1)
```

In the **browser**, open `index.html` and drop or paste a bundle (any
`examples/*/bundle.json` works). The **0 · Original record** card takes the
original file (its SHA-256 is compared with the fingerprint in the bundle - for
issuance bundles too) or, for a daily-balance bundle only, `account id` + `salt`.
For a v4 bundle the Issuer, Recipient, Trust roots and (for a registered
recipient key) Presenter sections appear; *Start presenter check* builds the
one-time `/present` link (copy it or open it as a popup; the signed blob is
pasted back or arrives by `postMessage` from the console origin). The page is
bilingual (`KR | EN` toggle, top right; defaults to the browser language).

---

## Reproducible build & trust

There is no build step - `index.html` *is* the artifact. To convince yourself the
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
python3 fixtures/generate.py            # regenerate fixtures + examples + inline HTML samples (must leave no diff)
bash    examples/run.sh                  # run every worked example (01–14), assert the exit code
python3 verify-cli/verify.py --selftest # P-256 vs RFC 6979 A.2.5, strict DER, SMT, base64url, bc30-v2 KAT vectors
python3 fixtures/engine-kat-check.py    # every field of the engine KAT re-derives byte-for-byte here
python3 fixtures/v4-rc-matrix.py        # CLI exit codes 0/1/2/3/64 over fixtures/v4-expected.json (subprocess)
node    fixtures/browser-js-check.mjs   # browser JS == Python == ann-core test vector (+ v4 builders vs KAT)
node    fixtures/p256/kat.mjs           # zk-core.js P-256/WebAuthn, crypto.subtle AND pure-BigInt paths
node    fixtures/v4-grade-check.mjs     # index.html runV4 reproduces Python's oracle: grade, axes, every step
node    tools/inline-zk.mjs --check     # the inlined crypto in index.html equals zk-core.js
node    fixtures/zk/conformance.mjs && node fixtures/zk/browser-path.mjs
```

The fixture cross-check pins `H_leaf(0x00×32) =`
`7f9c9e31…7396ce9`, the same vector asserted in
`ann-core/crates/merkle-batching`, so this verifier cannot silently drift from the
production Merkle tree. For v4, `fixtures/bc30-v2-vectors.json` is a
**byte-identical copy** of the engine's canonical known-answer file,
`ann-core/crates/bc30-leaf/tests/vectors/bc30-v2-kat.json` (the console pins the
same file). It is not generated here: `fixtures/engine-kat-check.py` re-derives
every field of it from its inputs with `verify.py`'s builders and `generate.py`'s
RFC 6979 signer and fails on any byte difference; `verify.py --selftest`,
`browser-js-check.mjs`, `p256/kat.mjs` and `browser-path.mjs` pin the same file
from Python and from the shipped JS. `fixtures/v4-expected.json` is the Python
oracle the browser must match. Test keys are derived from fixed seeds and
signatures use RFC 6979, so every fixture is byte-reproducible.

## License

MIT - see [LICENSE](LICENSE). Fork it, ship it, audit it.
