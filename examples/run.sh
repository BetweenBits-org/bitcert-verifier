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

echo; [ "$fail" = 0 ] && echo "ALL EXAMPLES OK" || { echo "SOME EXAMPLES FAILED"; exit 1; }
