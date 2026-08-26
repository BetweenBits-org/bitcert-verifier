#!/usr/bin/env bash
# Runs every example through the offline verifier and asserts the expected result.
set -u
cd "$(dirname "$0")"
CLI="python3 ../verify-cli/verify.py"
fail=0
check () { # $1=label  $2=expected_rc  shift 2 = command
  local label="$1" want="$2"; shift 2
  "$@" >/tmp/bv.out 2>&1; local rc=$?
  if [ "$rc" = "$want" ]; then echo "PASS  $label (rc=$rc)";
  else echo "FAIL  $label (rc=$rc, want $want)"; cat /tmp/bv.out; fail=1; fi
}

echo "== 01 attestation-file (link A: hash the original) =="
check "01 with original"      0 $CLI 01-attestation-file/bundle.json --original 01-attestation-file/original-report.txt
echo "== 02 daily-balance (link A: salted commitment) =="
check "02 self-consistency"   0 $CLI 02-daily-balance/bundle.json
check "02 identity binding"   0 $CLI 02-daily-balance/bundle.json --account alice@demoex --salt 5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e
echo "== 03 tampered-original (link A must catch it) =="
check "03 tampered original"  1 $CLI 03-tampered-original/bundle.json --original 03-tampered-original/tampered-report.txt
echo "== 04 tampered-chain (link D / §5 must catch it) =="
check "04 tampered chain"     1 $CLI 04-tampered-chain/bundle.json
echo "== 05 daily-chain-walkback (§5 continuity via chain.links) =="
check "05 chain walk-back"    0 $CLI 05-daily-chain-walkback/bundle.json --account alice@demoex --salt 5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e
echo "== 06 daily day_root (v2: anchor commits the reconciliation) =="
check "06 day_root v2"        0 $CLI 06-daily-day-root/bundle.json --account alice@demoex --salt 5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e
echo "== 07 witness-unified (PDF in witness + 86-byte anchor output, merkle-bind) =="
check "07 witness unified"    0 $CLI 07-witness-unified/bundle.json
echo "== 08 tampered-witness (malleable body must be caught at step 3) =="
check "08 tampered witness"   1 $CLI 08-tampered-witness/bundle.json

# ---- bundle v4 (identity-bound issuance) - exit 0 valid / 1 rejected / 2 warning / 3 undetermined ----
NOW=1782000700   # fixed clock so the expiry checks are reproducible
echo "== 09 issuance-plain (es256-plain issuer key, no subject) =="
check "09 issuance plain"      0 $CLI 09-issuance-plain/bundle.json --now $NOW
echo "== 10 issuance-passkey (webauthn-es256 issuer + salted identifier) =="
check "10 identifier matches"  0 $CLI 10-issuance-passkey/bundle.json --identifier alice@example.com --now $NOW
check "10 wrong identifier"    1 $CLI 10-issuance-passkey/bundle.json --identifier mallory@example.com --now $NOW
check "10 no identifier"       0 $CLI 10-issuance-passkey/bundle.json --now $NOW
echo "== 11 issuance-presentation (registered recipient key + /present blob) =="
check "11 presenter confirmed" 0 $CLI 11-issuance-presentation/bundle.json --present 11-issuance-presentation/presentation.txt --nonce 0f1e2d3c4b5a69788796a5b4c3d2e1f0 --now $NOW
check "11 nonce not ours"      2 $CLI 11-issuance-presentation/bundle.json --present 11-issuance-presentation/presentation.txt --now $NOW
check "11 no presentation"     0 $CLI 11-issuance-presentation/bundle.json --now $NOW
echo "== 12 tampered-issuer-sig (one byte of the DER signature flipped) =="
check "12 tampered issuer sig" 1 $CLI 12-tampered-issuer-sig/bundle.json --now $NOW
echo "== 13 expired-document (expires_at in the past: warning, exit 2) =="
check "13 expired"             2 $CLI 13-expired-document/bundle.json --now $NOW
echo "== 14 aux-mismatch (on-chain aux_commitment differs from the recomputed one) =="
check "14 aux mismatch"        1 $CLI 14-aux-mismatch/bundle.json --now $NOW

echo; [ "$fail" = 0 ] && echo "ALL EXAMPLES OK" || { echo "SOME EXAMPLES FAILED"; exit 1; }
