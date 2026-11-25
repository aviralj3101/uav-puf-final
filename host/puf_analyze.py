#!/usr/bin/env python3
"""
puf_analyze.py -- decide whether a memory block on your ESP32 is usable as a PUF, and with which settings.

Input: the .jsonl files made by puf_collect.py, one file per board. Give it ALL your boards (the ESP32-CAM,
the old UAV ESP32, the base ESP32): comparing boards is how it tells a real fingerprint from a block that
the program overwrites or that holds leftover data.

    python puf_analyze.py puf_data/espcam.jsonl puf_data/esp32_a.jsonl puf_data/esp32_b.jsonl

For each board and memory block (region 0 = RTC slow memory, region 1 = main SRAM) it reports:
  - how many cells keep the same value in every reading ("stable cells") and how many you need
  - how many of the stable cells are 1s (about half is healthy)
  - how often a stable cell still flips (measured on readings that were NOT used to choose the cells)
  - the chance that a boot fails to rebuild the key, for several group sizes, and a recommended size
and a verdict. Across boards it reports how different the boards' fingerprints are (about 50% is healthy).

The thresholds are this project's own sanity checks, not a security proof. They can reject a bad block;
they cannot certify a good one.
"""

import argparse
import itertools
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from puf_lib import boot_fail_prob, unpack_bits  # noqa: E402

GROUPS = 256
DEFAULT_N = 15
N_CHOICES = (5, 7, 9, 11, 15, 21, 31)
TARGET_FAIL = 1e-4          # acceptable chance that one boot fails to rebuild the key
MIN_READINGS = 10
ONES_OK = (0.40, 0.60)      # fraction of ones among stable cells
OVERALL_ONES_OK = (0.30, 0.70)
BOARD_HD_OK = (0.40, 0.60)  # difference between two boards' fingerprints
REGION_NAMES = {0: "RTC slow memory", 1: "main SRAM (.noinit)"}


def load(path):
    recs = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                recs.append(json.loads(line))
    return recs


def readings_by_group(records, region):
    """{('sleep', off_ms) or ('powerup', None): [bytes, ...]} using only fresh readings."""
    groups = {}
    for r in records:
        if not r.get("fresh"):
            continue
        key = ("sleep", r.get("off_ms")) if r["reset"] == "DEEPSLEEP" else ("powerup", None)
        groups.setdefault(key, []).append(bytes.fromhex(r[f"r{region}"]))
    return groups


def analyze_group(readings, groups=GROUPS):
    bits = np.array([unpack_bits(r) for r in readings], dtype=np.uint8)
    m, cells = bits.shape
    out = {"readings": m, "cells": cells, "ones_overall": float(bits.mean())}
    stable = bits.min(axis=0) == bits.max(axis=0)
    out["stable_cells"] = int(stable.sum())
    out["stable_fraction"] = float(stable.mean())
    out["ones_stable"] = float(bits[0][stable].mean()) if stable.any() else float("nan")

    # how noisy are the cells, measured honestly: choose stable cells from the first half of the readings,
    # then count flips against them in the second half
    if m >= 8:
        half = m // 2
        sel = bits[:half].min(axis=0) == bits[:half].max(axis=0)
        ref = bits[0]
        later = bits[half:][:, sel]
        flips = (later != ref[sel]).mean() if sel.any() else float("nan")
        out["flip_rate"] = float(flips)
        out["flip_eval_cells"] = int(sel.sum())
        out["flip_eval_readings"] = int(m - half)
    else:
        out["flip_rate"] = float("nan")

    # raw difference between two readings (all cells, not only stable ones)
    pairs = list(itertools.islice(itertools.combinations(range(m), 2), 60))
    out["pair_diff"] = float(np.mean([(bits[i] != bits[j]).mean() for i, j in pairs])) if pairs else float("nan")

    p = out["flip_rate"]
    p_used = max(p if p == p else 0.0, 1e-3)           # a measured 0 only means "below what this run can see"
    out["p_used"] = p_used
    table = []
    for n in N_CHOICES:
        table.append({"n": n, "cells_needed": groups * n, "enough_cells": groups * n <= out["stable_cells"],
                      "fail_per_boot": boot_fail_prob(p_used, n, groups)})
    out["table"] = table
    rec = next((t["n"] for t in table if t["enough_cells"] and t["fail_per_boot"] <= TARGET_FAIL), None)
    out["recommended_n"] = rec
    return out


def majority_reference(readings):
    bits = np.array([unpack_bits(r) for r in readings], dtype=np.uint8)
    return (bits.mean(axis=0) >= 0.5).astype(np.uint8)


def verdict(stats, groups=GROUPS):
    problems = []
    if stats["readings"] < MIN_READINGS:
        problems.append(f"only {stats['readings']} readings (need at least {MIN_READINGS})")
    lo, hi = OVERALL_ONES_OK
    if not (lo <= stats["ones_overall"] <= hi):
        problems.append(f"block is {stats['ones_overall']:.0%} ones overall: it looks constant, "
                        f"leftover data or overwritten by the program")
    lo, hi = ONES_OK
    if stats["stable_cells"] and not (lo <= stats["ones_stable"] <= hi):
        problems.append(f"stable cells are {stats['ones_stable']:.0%} ones (healthy is 40-60%)")
    if stats["recommended_n"] is None:
        problems.append(f"no group size reaches a failure rate of {TARGET_FAIL:g} per boot with "
                        f"{stats['stable_cells']} stable cells (noise estimate {stats['p_used']:.1%})")
    return problems


def analyze_files(paths, groups=GROUPS):
    """Returns a dict for the report/tests: boards -> region -> group -> stats, plus board comparison."""
    result = {"boards": {}, "compare": {}}
    refs = {}
    for path in paths:
        name = os.path.splitext(os.path.basename(path))[0]
        recs = load(path)
        board = {}
        for region in (0, 1):
            per_group = {}
            all_fresh = []
            for key, reads in readings_by_group(recs, region).items():
                per_group[key] = analyze_group(reads, groups)
                per_group[key]["verdict_problems"] = verdict(per_group[key], groups)
                all_fresh.extend(reads)
            board[region] = per_group
            if len(all_fresh) >= 3:
                refs[(name, region)] = majority_reference(all_fresh)
        result["boards"][name] = board
    names = list(result["boards"])
    for region in (0, 1):
        for a, b in itertools.combinations(names, 2):
            if (a, region) in refs and (b, region) in refs:
                result["compare"][(a, b, region)] = float((refs[(a, region)] != refs[(b, region)]).mean())
    return result


def fmt_group_key(key):
    return "after a real power-up" if key[0] == "powerup" else f"deep sleep, memory off {key[1]} ms"


def print_report(result, groups=GROUPS, out=print):
    out(f"Settings assumed: {groups} key bits; target failure rate {TARGET_FAIL:g} per boot.\n")
    overall = {}
    for name, board in result["boards"].items():
        out(f"=== board: {name} ===")
        for region in (0, 1):
            out(f"-- {REGION_NAMES[region]} --")
            if not board[region]:
                out("   no fresh readings for this region (check the reset reasons in the file)\n")
                continue
            for key, s in sorted(board[region].items(), key=lambda kv: str(kv[0])):
                out(f"   {fmt_group_key(key)}: {s['readings']} readings")
                out(f"     stable cells {s['stable_cells']} of {s['cells']} ({s['stable_fraction']:.0%}); "
                    f"ones overall {s['ones_overall']:.0%}, ones among stable {s['ones_stable']:.0%}")
                if s["flip_rate"] == s["flip_rate"]:
                    out(f"     flip rate of stable cells on unseen readings {s['flip_rate']:.3%} "
                        f"({s['flip_eval_cells']} cells x {s['flip_eval_readings']} readings); used: {s['p_used']:.2%}")
                out("     group size n -> chance a boot fails to rebuild the key:")
                for t in s["table"]:
                    flag = "" if t["enough_cells"] else "  (not enough stable cells)"
                    out(f"        n={t['n']:<2} needs {t['cells_needed']:>5} cells: {t['fail_per_boot']:.1e}{flag}")
                out(f"     recommended n: {s['recommended_n'] if s['recommended_n'] else 'none'}")
                if s["verdict_problems"]:
                    for p in s["verdict_problems"]:
                        out(f"     PROBLEM: {p}")
                else:
                    out("     verdict: looks usable")
                overall.setdefault((name, region), []).append(not s["verdict_problems"])
            out("")
    if result["compare"]:
        out("=== how different are the boards? (50% is ideal; the same chip read twice would be near 0%) ===")
        for (a, b, region), hd in sorted(result["compare"].items()):
            lo, hi = BOARD_HD_OK
            tag = "ok" if lo <= hd <= hi else "PROBLEM: too similar or too different"
            out(f"   {REGION_NAMES[region]}: {a} vs {b}: {hd:.1%}  {tag}")
        out("")
    out("=== summary ===")
    for region in (0, 1):
        verdicts = [any(v) for (n, r), v in overall.items() if r == region]
        board_ok = [any(v) for (n, r), v in overall.items() if r == region]
        cmp_ok = [BOARD_HD_OK[0] <= hd <= BOARD_HD_OK[1] for (a, b, r), hd in result["compare"].items() if r == region]
        ok = bool(board_ok) and all(board_ok) and all(cmp_ok)
        out(f"   {REGION_NAMES[region]}: {'PASS' if ok else 'FAIL'}"
            + ("" if cmp_ok else "  (only one board given: cannot check that boards differ)"))
    out("A PASS means this block is worth enrolling. It is not proof of security.")
    return overall


def main():
    ap = argparse.ArgumentParser(description="Analyse collected PUF readings")
    ap.add_argument("files", nargs="+", help="one .jsonl file per board")
    ap.add_argument("--groups", type=int, default=GROUPS, help="key bits (default 256)")
    args = ap.parse_args()
    result = analyze_files(args.files, args.groups)
    print_report(result, args.groups)


if __name__ == "__main__":
    main()
