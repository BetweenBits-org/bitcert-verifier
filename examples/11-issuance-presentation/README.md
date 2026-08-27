# 11 · Registered recipient key + presenter check (`/present` blob)

`subject_type 2`: the record is bound to the recipient's **passkey public key** (`subject_ref = SHA256(0x02 ‖ curve ‖ pubkey)`; the key itself rides in `subject.public_key`). A verifier can therefore ask the person in front of them to prove they hold that key:

1. The verifier generates a `nonce`, an `expiry` and a `verifier_id` (offline - no BitCert API) and builds the link `https://<console>/present?v=1&leaf=…&nonce=…&vid=…&exp=…` (`--present-url`).
2. The recipient opens it on the console origin and signs `challenge = SHA256(present-v1 tag ‖ nonce ‖ leaf_input ‖ verifier_id ‖ expiry)` with their passkey.
3. The page hands back a **blob** (base64url JSON - `presentation.txt` here) which the verifier checks offline: signature under `subject.public_key`, rpId/origin/UV, expiry, and that the nonce is **its own**.

`verifier-secret.txt` simulates what the verifier generated in step 1.

```bash
python3 ../../verify-cli/verify.py bundle.json --present presentation.txt --nonce 0f1e2d3c4b5a69788796a5b4c3d2e1f0 --now 1782000700   # VALID · presenter: confirmed
python3 ../../verify-cli/verify.py bundle.json --present presentation.txt --now 1782000700            # exit 2: nonce ownership not shown
python3 ../../verify-cli/verify.py bundle.json --now 1782000700                                       # VALID · presenter: not available
```

A missing or failed presentation **degrades** the verdict (`presenter: not available`) - it never rejects, so a lost phone does not invalidate past issuances.
