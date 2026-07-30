# zk conformance fixtures

These are produced by the **Go engine** (`ann-capabilities`, package
`internal/zkts`) and consumed by the JS verifier here. They are the only thing
that keeps two independent implementations of a frozen cryptographic contract
from drifting apart.

| file | what it is |
|---|---|
| `vectors.txt` | Generators, commitments, `cs_digest`, and the **full challenge stream** of `bulletproofs.proof` |
| `bulletproofs.proof` | A `committed-sum-range` envelope (sum published) |
| `cmp-ge.proof` | A `committed-sum-cmp` envelope — reserves ≥ supply, **sum hidden** |

## Why the challenge stream is in there

Verification is one boolean. When an independent implementation disagrees, "it
does not verify" tells you nothing — the bug could be a DST, a byte order, a
transcript binding, or the algebra. `vectors.txt` records every Fiat–Shamir
challenge in protocol order, so `conformance.mjs` reports *"you diverge at
bp-ipa:3"* instead.

That is not hypothetical. Building this verifier turned up two real defects
this way: gnark's hash-to-curve does not match the RFC 9380 suite libraries
use for secp256k1 (found before a line of verifier code was written, by
comparing generators), and the IPA rounds are serialised as per-round **pairs**
`[L_k ‖ R_k]`, not grouped — a grouped reader parses cleanly and produces a
plausible, wrong challenge stream.

## Regenerating

From the engine repo:

```sh
cd ann-capabilities/services/zk-proving-runtime
rm -rf internal/zkts/testdata            # the golden test refuses to overwrite
UPDATE_GOLDEN=1 go test ./internal/zkts/ -run TestGoldenVectorsAndProofs
EMIT_CMP=1     go test ./internal/zkts/ -run TestEmitCmpFixture
cp internal/zkts/testdata/{vectors.txt,bulletproofs.proof,cmp-ge.proof} \
   ../../../bitcert-verifier/fixtures/zk/
```

Regenerating is a **contract change**. The frozen spec version in
`vectors.txt` must move with it, and the reason belongs in the commit message.
