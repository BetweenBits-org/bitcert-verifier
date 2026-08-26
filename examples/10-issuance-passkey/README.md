# 10 · Passkey (WebAuthn) issuer signature + salted recipient identifier

The issuer signed with a **passkey**: `s` carries the WebAuthn `authenticatorData`, `clientDataJSON` and DER signature. The verifier checks `type == webauthn.get`, that the challenge decodes to `m`, the origin, `rpIdHash == SHA256("console.bitcert.io")` (pinned - the bundle's `rp_id` is only a claim), the UP/UV flags and the ES256 signature over `authData ‖ SHA256(clientDataJSON)`.

The recipient is named by a **salted identifier**: `subject_ref = SHA256(record_salt ‖ identifier)`. The identifier itself is not in the bundle; whoever presents it must know it.

```bash
python3 ../../verify-cli/verify.py bundle.json --identifier alice@example.com --now 1782000700   # VALID, attribution ✓
python3 ../../verify-cli/verify.py bundle.json --identifier mallory@example.com --now 1782000700  # REJECTED (exit 1)
python3 ../../verify-cli/verify.py bundle.json --now 1782000700                     # VALID, identifier not checked
```

Expected: **VALID** with `attribution: issuer-claim · identifier ✓` when the right identifier is supplied.
