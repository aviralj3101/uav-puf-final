#!/usr/bin/env python3
"""
Wired enrollment for the PUF chaos system. Run this ONCE (and again whenever the base runs out of
unused pairs), with both boards plugged into this laptop and the other two scripts NOT running
(they would be holding the COM ports).

For each pair it
    1. makes a random 16-byte challenge C,
    2. sends C to the UAV over the UAV's USB cable and reads back the PUF response R,
    3. sends (C, R) to the base over the base's USB cable, which stores it in its flash.

R only ever travels over the two USB cables. It is never transmitted by radio and never written
to disk or printed by this script.

Install:  pip install pyserial
Run:      python enroll.py --uav-port COM7 --base-port COM10 --count 10
"""

import argparse
import os
import re
import sys
import time

import serial

# ===================== USER SETTINGS (can also be passed as arguments) =====================
DEFAULT_UAV_PORT = "COM7"
DEFAULT_BASE_PORT = "COM10"
DEFAULT_BAUD = 921600        # must match SERIAL_BAUD in both firmwares
# ===========================================================================================

UAV_CMD = b"\xE1\x4F"        # command header understood by the UAV firmware


def open_port(port, baud):
    ser = serial.Serial()
    ser.port = port
    ser.baudrate = baud
    ser.timeout = 0.2
    ser.write_timeout = 5
    ser.dtr = False          # avoid resetting the ESP32 on connect (some boards reset anyway)
    ser.rts = False
    ser.open()
    return ser


def read_until(ser, predicate, timeout, seen=None):
    """Read lines until predicate(line_text) is true; return that line or None on timeout.
    Every line read is appended to 'seen' (if given) so failures can show what the board said."""
    deadline = time.time() + timeout
    buf = b""
    while time.time() < deadline:
        chunk = ser.readline()
        if not chunk:
            continue
        buf += chunk
        if not buf.endswith(b"\n"):
            continue
        text = buf.decode(errors="replace").strip()
        buf = b""
        if seen is not None and text:
            seen.append(text)
        if predicate(text):
            return text
    return None


def get_response(uav, challenge):
    uav.reset_input_buffer()
    uav.write(UAV_CMD + challenge)
    uav.flush()
    line = read_until(uav, lambda t: "PUFRESP:" in t, 3.0)
    if line is None:
        return None
    hexpart = line.split("PUFRESP:", 1)[1].strip()
    try:
        r = bytes.fromhex(hexpart)
    except ValueError:
        return None
    return r if len(r) == 16 else None


def base_status(base, timeout=3.0):
    """Ask the base for its status and return how many CRPs it stores (None if it does not answer)."""
    base.reset_input_buffer()
    base.write(b"T")
    base.flush()
    line = read_until(base, lambda t: "CRPs stored" in t, timeout)
    if line is None:
        return None
    m = re.search(r"CRPs stored:\s*(\d+)", line)
    return int(m.group(1)) if m else None


def wait_ready(base, total=12.0):
    """Wait until the base answers (it may still be booting after the port was opened)."""
    deadline = time.time() + total
    while time.time() < deadline:
        n = base_status(base, 2.0)
        if n is not None:
            return n
    return None


def store_pair(base, challenge, response, count_before):
    """Returns (ok, message). Falls back to counting stored pairs if the confirmation line is missed."""
    base.reset_input_buffer()
    seen = []
    base.write(b"P" + challenge + response)
    base.flush()
    line = read_until(base, lambda t: "enrolled CRP" in t or "FAILED" in t, 6.0, seen)
    if line is not None and "FAILED" not in line:
        return True, line
    if line is None:
        n = base_status(base)
        if n is not None and count_before is not None and n == count_before + 1:
            return True, f"stored (confirmation line was missed); base now holds {n}"
        if n is not None and count_before is not None and n == count_before:
            heard = " | ".join(seen) if seen else "nothing"
            return False, ("the base did not store the pair. It said: " + heard +
                           ". If it did not mention 'enrolled CRP', the base is probably still running the OLD "
                           "firmware - reflash base_puf_chaos.ino.")
        return False, "no confirmation and the base did not answer a status request"
    return False, line


def enroll(uav, base, count, log=print):
    n = wait_ready(base)
    if n is None:
        log("the base board does not answer - check the port, close the Serial Monitor, and press its EN button")
        return 0
    log(f"base is ready and already holds {n} pair(s)")
    ok = 0
    for i in range(count):
        challenge = os.urandom(16)
        r = get_response(uav, challenge)
        if r is None:
            log(f"[{i + 1}/{count}] no valid response from the UAV (check the port and that the NEW UAV firmware is running)")
            break
        good, msg = store_pair(base, challenge, r, n)
        if not good:
            log(f"[{i + 1}/{count}] {msg}")
            break
        n += 1
        ok += 1
        log(f"[{i + 1}/{count}] {msg}")
    return ok


def main():
    ap = argparse.ArgumentParser(description="Wired CRP enrollment")
    ap.add_argument("--uav-port", default=DEFAULT_UAV_PORT)
    ap.add_argument("--base-port", default=DEFAULT_BASE_PORT)
    ap.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    ap.add_argument("--count", type=int, default=10, help="number of pairs to enroll (base holds at most 40)")
    args = ap.parse_args()

    try:
        uav = open_port(args.uav_port, args.baud)
        base = open_port(args.base_port, args.baud)
    except serial.SerialException as e:
        sys.exit(f"Could not open a port: {e}\n(Close the Arduino Serial Monitor and the other scripts.)")
    time.sleep(3)            # give the boards time to boot if opening the port reset them
    uav.reset_input_buffer()
    base.reset_input_buffer()

    ok = enroll(uav, base, args.count)
    print(f"enrolled {ok} of {args.count} pairs")
    n = base_status(base)
    if n is not None:
        print(f"the base now holds {n} pair(s)")
    uav.close()
    base.close()
    sys.exit(0 if ok == args.count else 1)


if __name__ == "__main__":
    main()
