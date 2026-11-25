#!/usr/bin/env python3
"""
puf_collect.py -- collect fresh power-up readings of the PUF blocks from the ESP32-CAM.

The board must be running uav_espcam.ino and be plugged into this laptop (USB-serial). Each reading
is taken like this: the script tells the board to zero its PUF blocks and go into deep sleep with the
memory powered off, the board wakes up (a fresh power-up of that memory), and the script reads a copy
of what the memory contained at boot. That repeats until enough readings are collected.

Readings are appended to a .jsonl file, one line per reading, for puf_analyze.py. They contain the raw
power-up pattern of this chip, so do not publish them.

    python puf_collect.py --port COM7 --count 30 --off-ms 1000 --out puf_data/espcam.jsonl
    python puf_collect.py --port COM7 --count 30 --off-ms 50,500,2000 --out puf_data/espcam.jsonl
    python puf_collect.py --port COM7 --manual 10 --out puf_data/espcam.jsonl     (also unplug the USB cable)

Install:  pip install pyserial
"""

import argparse
import json
import os
import struct
import sys
import time

CMD = b"\xE1"
FRESH_REASONS = ("POWERON", "DEEPSLEEP")


class DeviceError(Exception):
    pass


def parse_ready(line):
    """PUFREADY,1,<reset>,<wake>,0x<rtc>,0x<sram>,<bytes>,<mode>  ->  dict"""
    f = line.strip().split(",")
    if len(f) < 8 or f[0] != "PUFREADY":
        raise DeviceError(f"unexpected banner: {line!r}")
    return {"version": int(f[1]), "reset": f[2], "wake": f[3], "rtc_addr": int(f[4], 16),
            "sram_addr": int(f[5], 16), "region_bytes": int(f[6]), "mode": f[7]}


class PufDevice:
    """Talks to the board's maintenance commands. 'ser' is a pyserial Serial (or anything that looks like one)."""

    def __init__(self, ser, log=print):
        self.ser = ser
        self.log = log
        self.info = None

    # ---- low level
    def _send(self, cmd, payload=b""):
        self.ser.write(CMD + cmd + payload)
        self.ser.flush()

    def _read_line(self, deadline):
        buf = b""
        while time.time() < deadline:
            chunk = self.ser.readline()
            if not chunk:
                continue
            buf += chunk
            if buf.endswith(b"\n"):
                return buf.decode(errors="replace").strip()
        return None

    def wait_for(self, prefix, timeout):
        """Return the first line that contains 'prefix', or None on timeout."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self._read_line(deadline)
            if line is None:
                return None
            if prefix in line:
                return line[line.index(prefix):]
        return None

    # ---- getting into maintenance mode
    def _enter_maintenance(self, attempts=40):
        for _ in range(attempts):
            self._send(b"M")
            if self.wait_for("PUFMAINT,ok", 0.15):
                return True
        return False

    def sync(self, timeout=25.0):
        """Get the board into maintenance mode after a (re)boot. Returns the PUFREADY info."""
        deadline = time.time() + timeout
        info = None
        while time.time() < deadline:
            line = self.wait_for("PUFREADY", min(2.0, max(0.2, deadline - time.time())))
            if line:
                info = parse_ready(line)
                if self._enter_maintenance():
                    self.info = info
                    return info
        # maybe it is already running and past its start-up window: ask directly
        if self._enter_maintenance(attempts=6):
            self.info = info or self.info or {"reset": "UNKNOWN", "wake": "NONE", "rtc_addr": 0,
                                              "sram_addr": 0, "region_bytes": 0, "mode": "?", "version": 1}
            return self.info
        raise DeviceError("the board did not enter maintenance mode. Is uav_espcam.ino running? "
                          "Press the board's reset button and try again; close other programs using the port.")

    # ---- commands
    def dump(self):
        self._send(b"D")
        blocks = {}
        deadline = time.time() + 15
        while time.time() < deadline:
            line = self._read_line(deadline)
            if line is None:
                break
            if line.startswith("PUFDUMPEND"):
                break
            if line.startswith("PUFDUMP,"):
                _, region, hexdata = line.split(",", 2)
                blocks[int(region)] = bytes.fromhex(hexdata)
        if 0 not in blocks or 1 not in blocks:
            raise DeviceError("incomplete dump from the board")
        return blocks[0], blocks[1]

    def sleep(self, ms):
        self._send(b"S", struct.pack("<I", int(ms)))
        if not self.wait_for("PUFSLEEP,", 3.0):
            raise DeviceError("the board did not acknowledge the sleep command")

    def provision(self, payload):
        self._send(b"P", payload)
        line = self.wait_for("PUFPROV,", 8.0)
        return (line == "PUFPROV,ok"), line

    def verify(self):
        """Returns dict(ok, corrected, reason)."""
        self._send(b"V")
        line = self.wait_for("PUFVERIFY,", 5.0)
        if line is None:
            raise DeviceError("no answer to the verify command")
        f = line.split(",")
        if f[1] == "ok":
            return {"ok": True, "corrected": int(f[2]), "reason": ""}
        return {"ok": False, "corrected": int(f[3]) if len(f) > 3 else 0, "reason": f[2] if len(f) > 2 else "?"}

    def wipe(self):
        self._send(b"W")
        return self.wait_for("PUFWIPE,ok", 3.0) is not None

    def exit_maintenance(self):
        self._send(b"X")
        self.wait_for("PUFMAINT,exit", 2.0)

    # ---- power-cycle and come back
    def power_cycle(self, off_ms):
        self.sleep(off_ms)
        return self.sync(timeout=off_ms / 1000.0 + 25.0)


# ---------------------------------------------------------------- collecting
def count_fresh(readings):
    return sum(1 for r in readings if r["fresh"])


def _record(info, prev_off, r0, r1, label):
    reset = info.get("reset", "UNKNOWN")
    return {"t": round(time.time(), 3), "label": label, "reset": reset,
            "off_ms": prev_off if reset == "DEEPSLEEP" else None,
            "fresh": reset in FRESH_REASONS,
            "addr0": info.get("rtc_addr"), "addr1": info.get("sram_addr"),
            "r0": r0.hex(), "r1": r1.hex()}


def collect(dev, count, off_ms_list, out_path=None, label="", log=print, max_extra=10):
    """Collect 'count' fresh readings by power-cycling the board with deep sleep. Returns all records."""
    records = []
    info = dev.sync()
    prev_off = None
    cycles = 0
    out = open(out_path, "a") if out_path else None
    try:
        while True:
            r0, r1 = dev.dump()
            rec = _record(info, prev_off, r0, r1, label)
            records.append(rec)
            if out:
                out.write(json.dumps(rec) + "\n")
                out.flush()
            n = count_fresh(records)
            log(f"reading {n}/{count} ({'fresh' if rec['fresh'] else 'not fresh: ' + rec['reset']}"
                f"{', off ' + str(rec['off_ms']) + ' ms' if rec['off_ms'] else ''})")
            if n >= count or cycles >= count + max_extra:
                break
            prev_off = off_ms_list[cycles % len(off_ms_list)]
            info = dev.power_cycle(prev_off)
            cycles += 1
    finally:
        if out:
            out.close()
    return records


def collect_manual(open_port, count, out_path=None, label="manual", log=print):
    """Readings after a REAL power loss: you unplug and replug the USB cable each time."""
    records = []
    out = open(out_path, "a") if out_path else None
    try:
        for i in range(count):
            input(f"[{i + 1}/{count}] Unplug the board's USB cable, wait 10 seconds, plug it back in, then press Enter... ")
            ser = open_port()
            try:
                dev = PufDevice(ser, log)
                info = dev.sync(timeout=40)
                r0, r1 = dev.dump()
                rec = _record(info, None, r0, r1, label)
                records.append(rec)
                if out:
                    out.write(json.dumps(rec) + "\n")
                    out.flush()
                log(f"reading {i + 1}/{count}: reset reason {rec['reset']} ({'fresh' if rec['fresh'] else 'NOT fresh'})")
                dev.exit_maintenance()
            finally:
                ser.close()
    finally:
        if out:
            out.close()
    return records


def open_port_factory(port, baud):
    import serial  # imported here so the library functions above work without pyserial

    def _open():
        deadline = time.time() + 40
        while True:
            try:
                ser = serial.Serial()
                ser.port = port
                ser.baudrate = baud
                ser.timeout = 0.2
                ser.write_timeout = 5
                ser.dtr = False
                ser.rts = False
                ser.open()
                return ser
            except (serial.SerialException, OSError):
                if time.time() > deadline:
                    raise
                time.sleep(0.5)
    return _open


def main():
    ap = argparse.ArgumentParser(description="Collect fresh PUF power-up readings from the ESP32-CAM")
    ap.add_argument("--port", required=True)
    ap.add_argument("--baud", type=int, default=921600)
    ap.add_argument("--count", type=int, default=30, help="fresh readings to collect by deep-sleep power cycles")
    ap.add_argument("--off-ms", default="1000", help="power-off time(s) in ms, comma separated, used in turn")
    ap.add_argument("--manual", type=int, default=0, help="extra readings after a real USB unplug (asks you each time)")
    ap.add_argument("--out", default="puf_data/readings.jsonl")
    ap.add_argument("--label", default="")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    off_list = [int(x) for x in args.off_ms.split(",") if x.strip()]
    open_port = open_port_factory(args.port, args.baud)
    try:
        ser = open_port()
    except Exception as e:
        sys.exit(f"Could not open {args.port}: {e}\n(Close the Arduino Serial Monitor and other scripts.)")
    try:
        if args.count > 0:
            dev = PufDevice(ser)
            try:
                collect(dev, args.count, off_list, args.out, args.label)
            except DeviceError as e:
                sys.exit(str(e))
            dev.exit_maintenance()
    finally:
        ser.close()
    if args.manual > 0:
        collect_manual(open_port, args.manual, args.out, label=(args.label or "manual"))
    print(f"readings saved to {args.out}")


if __name__ == "__main__":
    main()
