#!/usr/bin/env python3
"""Exit-code matrix for verify.py over fixtures/v4-expected.json.

The oracle is produced in-process by generate.py; this re-runs the CLI as a
SUBPROCESS for every row (file + option set) and asserts the process exit code,
so the argument parsing, the printer and the grade→exit mapping are covered -
not just the pure pipeline. Also pins the usage exit code (64).

    python3 fixtures/v4-rc-matrix.py
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
    rows = json.load(open(os.path.join(HERE, "v4-expected.json"), encoding="utf-8"))["rows"]
    fails = 0
    for r in rows:
        args = [os.path.join(HERE, r["file"])]
        if not r.get("legacy"):
            args += ["--now", str(r["now"])]
        if r.get("identifier") is not None:
            args += ["--identifier", r["identifier"]]
        if r.get("presentation"):
            args += ["--present", os.path.join(HERE, r["presentation"])]
        if r.get("nonce"):
            args += ["--nonce", r["nonce"]]
        rc, out = run(args)
        label = " ".join([r["file"]] + args[1:]).replace(HERE + os.sep, "")
        if rc == r["exit_code"]:
            print("PASS  rc=%d  %s" % (rc, label))
        else:
            print("FAIL  rc=%d want %d  %s" % (rc, r["exit_code"], label)); print(out); fails += 1
    # usage / JSON errors are 64, never confused with a verdict
    for label, args, stdin in (("unknown option", [os.path.join(HERE, "v4", "valid-none.json"), "--bogus"], None),
                               ("not JSON", ["-"], "{not json"),
                               ("bad --nonce", [os.path.join(HERE, "v4", "valid-none.json"), "--nonce", "zz"], None),
                               ("no args", [], None)):
        rc, _ = run(args, stdin)
        if rc == 64: print("PASS  rc=64  usage: %s" % label)
        else: print("FAIL  rc=%d want 64  usage: %s" % (rc, label)); fails += 1
    rc, _ = run(["--selftest"])
    if rc == 0: print("PASS  rc=0   --selftest")
    else: print("FAIL  rc=%d  --selftest" % rc); fails += 1
    print()
    print("ALL %d ROWS OK" % len(rows) if not fails else "%d FAILURE(S)" % fails)
    return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(main())
