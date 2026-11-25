#!/usr/bin/env python3
"""
puf_enroll.py -- enroll the ESP32-CAM's PUF (once per board, on the ground, wired).

What it does
  1. collects fresh power-up readings of the chosen memory block (deep-sleep power cycles),
  2. keeps only cells that never changed, picks groups of them, and makes the helper data,
  3. sends the helper data to the board, which stores it in its flash,
  4. proves it works: power-cycles the board repeatedly and checks that it rebuilds its key each time.

The key itself is never shown, saved or sent. Only the helper data leaves this script, and it is not
secret. The raw readings stay in this script's memory and are discarded.

Do this with the board powered the way it will be used (same USB power or the same regulator you will fly
with), because how fast the supply rises changes the power-up pattern slightly.

    python puf_enroll.py --port COM7 --region rtc --readings 30 --n 15 --groups 256 --verify 20

Run puf_collect.py and puf_analyze.py FIRST and only enroll a region that passed.
After this, run enroll.py to enroll challenge/response pairs on the base station.

Install:  pip install pyserial numpy
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import puf_lib as P  # noqa: E402
from puf_collect import DeviceError, PufDevice, collect, open_port_factory  # noqa: E402


def enroll_puf(dev, region, readings=30, off_ms=1000, n=15, groups=256, verify=20,
               allow_biased=False, save_helper=None, rng=None, log=print):
    """Returns a summary dict. Raises DeviceError / P.EnrollmentError with a readable message."""
    if region not in P.REGION_NAMES:
        raise ValueError("region must be 'rtc' or 'sram'")
    region_id = P.REGION_NAMES[region]
    info = dev.sync()
    if info.get("mode") == "emulated":
        raise DeviceError("this firmware was built with PUF_MODE_REAL 0 (emulated fallback); nothing to enroll")
    addr = info["rtc_addr"] if region_id == P.REGION_RTC else info["sram_addr"]
    log(f"board: PUF block '{region}' at address 0x{addr:08x}, {info['region_bytes']} bytes")
    log(f"collecting {readings} fresh power-up readings (memory off for {off_ms} ms each)...")
    recs = collect(dev, readings, [off_ms], out_path=None, label="enroll", log=lambda m: None)
    fresh = [bytes.fromhex(r[f"r{region_id}"]) for r in recs if r["fresh"]]
    addrs = {r[f"addr{region_id}"] for r in recs}
    if len(addrs) != 1:
        raise DeviceError("the block address changed between readings; something is wrong with the firmware")
    log(f"got {len(fresh)} fresh readings")

    built = P.build_helper(fresh, region_id, addr, n=n, groups=groups, rng=rng, allow_biased=allow_biased)
    rep = built["report"]
    log(f"stable cells: {rep['stable_cells']} ({rep['stable_fraction']:.0%} of the block); "
        f"selected {rep['selected']} = {groups} groups x {n}; ones among selected {rep['ones_fraction']:.0%}")
    if save_helper:
        with open(save_helper + ".a.bin", "wb") as f:
            f.write(built["blob_a"])
        with open(save_helper + ".m.bin", "wb") as f:
            f.write(built["blob_m"])
        log(f"helper data (public) saved to {save_helper}.a.bin / .m.bin")

    ok, line = dev.provision(P.provision_payload(built["blob_a"], built["blob_m"]))
    if not ok:
        raise DeviceError(f"the board refused the helper data: {line}")
    log("helper data stored on the board")
    del recs, fresh, built   # the readings and the key are not kept

    results = []
    for i in range(verify):
        dev.power_cycle(off_ms)
        v = dev.verify()
        results.append(v)
        log(f"verify {i + 1}/{verify}: " + (f"key rebuilt, {v['corrected']} cells corrected"
                                            if v["ok"] else f"FAILED ({v['reason']}, {v['corrected']} cells differed)"))
    n_ok = sum(1 for v in results if v["ok"])
    corr = [v["corrected"] for v in results]
    summary = {"verify_total": verify, "verify_ok": n_ok,
               "corrected_mean": (sum(corr) / len(corr)) if corr else 0.0, "corrected_max": max(corr) if corr else 0,
               "selected": rep["selected"], "n": n, "groups": groups}
    if verify:
        p_hat = summary["corrected_mean"] / rep["selected"]
        summary["flip_rate"] = p_hat
        summary["predicted_fail"] = P.boot_fail_prob(max(p_hat, 1e-3), n, groups)
        log("")
        log(f"result: the key was rebuilt {n_ok} of {verify} times")
        log(f"cells that differed from enrollment per boot: mean {summary['corrected_mean']:.1f}, "
            f"max {summary['corrected_max']} of {rep['selected']} ({p_hat:.2%})")
        log(f"predicted chance that a boot fails to rebuild the key: about {summary['predicted_fail']:.1e}")
        if n_ok < verify:
            log("WARNING: some verifications failed. Do not rely on this enrollment: use a larger --n, "
                "collect more readings, or run puf_analyze.py again to check the block.")
    dev.exit_maintenance()
    return summary


def main():
    ap = argparse.ArgumentParser(description="Enroll the ESP32-CAM PUF")
    ap.add_argument("--port", required=True)
    ap.add_argument("--baud", type=int, default=921600)
    ap.add_argument("--region", choices=["rtc", "sram"], required=True, help="the block that passed puf_analyze.py")
    ap.add_argument("--readings", type=int, default=30)
    ap.add_argument("--off-ms", type=int, default=1000, help="power-off time per reading (use the one you analysed)")
    ap.add_argument("--n", type=int, default=15, help="cells per key bit (odd); use the value puf_analyze.py recommended")
    ap.add_argument("--groups", type=int, default=256, help="key bits (multiple of 8)")
    ap.add_argument("--verify", type=int, default=20, help="power cycles used to check the enrollment")
    ap.add_argument("--allow-biased", action="store_true", help="enroll even if the chosen cells are far from 50%% ones (not recommended)")
    ap.add_argument("--save-helper", default=None, help="also save the public helper data to PATH.a.bin / PATH.m.bin")
    args = ap.parse_args()

    try:
        ser = open_port_factory(args.port, args.baud)()
    except Exception as e:
        sys.exit(f"Could not open {args.port}: {e}\n(Close the Arduino Serial Monitor and other scripts.)")
    try:
        enroll_puf(PufDevice(ser), args.region, args.readings, args.off_ms, args.n, args.groups, args.verify,
                   args.allow_biased, args.save_helper)
    except (DeviceError, P.EnrollmentError) as e:
        sys.exit(f"ENROLLMENT FAILED: {e}")
    finally:
        ser.close()
    print("\nNext: python enroll.py --uav-port <this port> --base-port <base port> --count 20")


if __name__ == "__main__":
    main()
