#!/usr/bin/env python3
"""Exit-code matrix for verify.py over fixtures/v5-expected.json.

Same convention as v4-rc-matrix.py: the oracle is produced in-process by
generate.py; this re-runs the CLI as a SUBPROCESS for every row and asserts the
process exit code, so the v5 dispatch (signers[] vs single-signature), the
printer and the grade→exit mapping are covered - not just the pure pipeline.

    python3 fixtures/v5-rc-matrix.py
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(HERE, "..", "verify-cli", "verify.py")

def run(args, stdin=None):
    p = subprocess.run([sys.executable, CLI] + args, input=stdin, capture_output=True, text=True)
    return p.returncode, p.stdout

def main():
    rows = json.load(open(os.path.join(HERE, "v5-expected.json"), encoding="utf-8"))["rows"]
    fails = 0
    for r in rows:
        args = [os.path.join(HERE, r["file"]), "--now", str(r["now"])]
        rc, out = run(args)
        label = " ".join([r["file"]] + args[1:]).replace(HERE + os.sep, "")
        if rc == r["exit_code"]:
            print("PASS  rc=%d  %s" % (rc, label))
        else:
            print("FAIL  rc=%d want %d  %s" % (rc, r["exit_code"], label)); print(out); fails += 1
    print()
    print("ALL %d ROWS OK" % len(rows) if not fails else "%d FAILURE(S)" % fails)
    return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(main())
