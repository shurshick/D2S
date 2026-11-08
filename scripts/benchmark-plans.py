#!/usr/bin/env python3
"""Release lookup timing plus a separately instrumented visit-count run.
Example: python3 scripts/benchmark-plans.py --ref 8ce4118 --out /tmp/before.json
No repository/router mutations. The reference must exist in local git history.
"""
import argparse
import csv
import io
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DP = ROOT / "datapath"
BASE = "8ce411883f2d925d836f68829accaa180a4a767c"


def build(source, output, counted=False, fixture="bench_plans.c", sanitize=False):
    compiler = os.environ.get("CC", "cc")
    flags = ["-std=c99", "-O2", "-Wall", "-Wextra", "-Werror", "-I" + str(DP),
             "-I" + str(DP / "include"), "-I" + str(ROOT / "core/include")]
    if "static uint32_t name_hash(" in Path(source).read_text():
        flags += ["-DD2S_PLANS_HAS_HASH"]
    if sanitize:
        flags += ["-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-no-pie"]
    if counted:
        flags += ["-DD2S_BENCH_COUNT"]
    flags += ['-DD2S_BENCH_SOURCE="' + str(source) + '"']
    sources = [str(DP / fixture), str(DP / "plan_parse.c"), str(DP / "plan_apply.c")]
    sources += [str(ROOT / "core" / (x + ".c")) for x in
                ("quic", "quicsnap", "quicwire", "crypto", "ipfrag", "httpup_logic")]
    subprocess.run([compiler, *flags, *sources, "-o", str(output)], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", default="worktree")
    parser.add_argument("--source", type=Path, help="explicit saved source instead of --ref")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cpu", type=int, help="pin all timing runs to this logical CPU")
    parser.add_argument("--runs", type=int, default=5)
    args = parser.parse_args()
    if args.runs < 3:
        parser.error("use at least three independent runs")
    cpu = args.cpu if args.cpu is not None else min(os.sched_getaffinity(0))
    os.sched_setaffinity(0, {cpu})
    source = args.source.read_text() if args.source else (DP / "plans.c").read_text() if args.ref == "worktree" else subprocess.check_output(
        ["git", "-C", str(ROOT), "show", args.ref + ":datapath/plans.c"], text=True)
    with tempfile.TemporaryDirectory(prefix="d2s-lookup-") as directory:
        tmp = Path(directory)
        original, instrumented = tmp / "original.c", tmp / "counted.c"
        original.write_text(source)
        # Catalogue, suffix/bypass and flow-probe entry visits; no production counter.
        pattern = r"(for\s*\(size_t i\s*=\s*0;\s*i\s*<\s*t->(?:used|suffix_used|bypass_used|cap);\s*i\+\+\)\s*\{)"
        counted, replacements = re.subn(pattern, r"\1 D2S_BENCH_VISIT();", source)
        assert replacements >= 8, "visit instrumentation no longer matches source"
        instrumented.write_text(counted)
        timing, counter = tmp / "timing", tmp / "counter"
        build(original, timing)
        build(instrumented, counter, counted=True)
        rows, visits = [], {}
        for workload in ("common_prefix", "varied_names"):
            command = [] if workload == "common_prefix" else ["varied"]
            for run in range(args.runs):
                result = subprocess.check_output([str(timing), *command], text=True)
                rows += [{**r, "run": run, "workload": workload} for r in csv.DictReader(io.StringIO(result))]
            visits.update({(workload, r["size"], r["case"]): int(r["visits"]) for r in csv.DictReader(
                io.StringIO(subprocess.check_output([str(counter), *command], text=True)))})
    for row in rows:
        row["visits"] = visits[row["workload"], row["size"], row["case"]]
    output = {"source_ref": str(args.source) if args.source else args.ref, "source_sha256": __import__("hashlib").sha256(source.encode()).hexdigest(),
              "compiler": subprocess.check_output([os.environ.get("CC", "cc"), "--version"], text=True).splitlines()[0],
              "flags": "-std=c99 -O2 -Wall -Wextra -Werror (assertions enabled)",
              "platform": platform.platform(), "cpu": platform.processor(), "logical_cpu": cpu,
              "entry_visits_scope": "catalogue + suffix/bypass + flow-probe scans", "runs": args.runs, "samples": 101, "lookups_per_sample": 64,
              "percentiles": "median/p95/p99: 101 batch means; lookup_*_raw_ns: 1025 individual lookups including two clock reads", "rows": rows}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(output, indent=2) + "\n")
    print("Saved", len(rows), "rows to", args.out)


if __name__ == "__main__":
    main()
