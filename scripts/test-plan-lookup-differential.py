#!/usr/bin/env python3
"""Compare pinned baseline and working lookup, including mutation side effects.
Requires C compiler and local git baseline, no network or router access.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bench", ROOT / "scripts/benchmark-plans.py")
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default=bench.BASE)
    parser.add_argument("--sanitize", action="store_true")
    parser.add_argument("--candidate", type=Path, help="optional saved experimental source")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    baseline = subprocess.check_output(["git", "-C", str(ROOT), "show",
                                        args.baseline + ":datapath/plans.c"], text=True)
    current = (args.candidate or ROOT / "datapath/plans.c").read_text()
    # Freeze baseline regression coverage: later intentional bug fixes may add
    # tests which correctly fail against the historical implementation.
    original_tests = subprocess.check_output(["git", "-C", str(ROOT), "show",
                                               args.baseline + ":datapath/test_plans.c"], text=True)
    traces = []
    with tempfile.TemporaryDirectory(prefix="d2s-differential-") as directory:
        tmp = Path(directory)
        frozen_tests = tmp / "original_test_plans.c"
        frozen_tests.write_text(original_tests)
        for label, code in (("baseline", baseline), ("current", current)):
            source, binary = tmp / (label + ".c"), tmp / label
            source.write_text(code)
            bench.build(source, binary, fixture="test_plans_differential.c", sanitize=args.sanitize)
            trace = subprocess.check_output([str(binary)])
            traces.append(trace)
            # Execute all existing lifecycle/priority tests against each implementation too.
            wrapper = tmp / (label + "-existing.c")
            wrapper.write_text('#include "' + str(source) + '"\n#include "' + str(frozen_tests) + '"\n')
            bench.build(source, binary, fixture=str(wrapper), sanitize=args.sanitize)
            subprocess.run([str(binary)], check=True, stdout=subprocess.DEVNULL)
        if traces[0] != traces[1]:
            before, after = [trace.splitlines() for trace in traces]
            for i, (a, b) in enumerate(zip(before, after)):
                if a != b:
                    raise AssertionError(f"lookup {i} differs: {a!r} vs {b!r}")
            raise AssertionError("different trace lengths")
    result = {"baseline": args.baseline, "baseline_sha256": hashlib.sha256(baseline.encode()).hexdigest(),
              "current_sha256": hashlib.sha256(current.encode()).hexdigest(), "sanitize": args.sanitize,
              "equal": True, "lookups": len(traces[0].splitlines()),
              "trace_sha256": hashlib.sha256(traces[0]).hexdigest(),
              "coverage": "all original test_plans against both sources; explicit hash collision, case, families, timestamps, trial isolation, suffix/bypass, LRU/delete/replace, expiry; deterministic mutation traces"}
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
