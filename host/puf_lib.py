#!/usr/bin/env python3
"""
puf_lib.py -- helper-data maths shared by the PUF tools (enrollment, analysis, tests).

It builds the helper data that the board stores in flash, and can rebuild the root key from a
snapshot exactly as the firmware does (firmware/common/puf_real.h). The two are tested against
each other in tests/test_puf_real.py.

Nothing here writes a secret to disk. build_helper() returns the root key in memory only, so the
caller can use it for a check and then drop it.
"""

import hashlib
import random
import secrets
import struct
import zlib
from math import comb

import numpy as np

MAGIC = b"PUF1"
VERSION = 1
HEADER_BYTES = 24
REGION_RTC = 0
REGION_SRAM = 1
REGION_NAMES = {"rtc": REGION_RTC, "sram": REGION_SRAM}


class EnrollmentError(Exception):
    """Raised when the readings cannot support a safe enrollment."""


def sha256(b):
    return hashlib.sha256(bytes(b)).digest()


def unpack_bits(b):
    """Bytes -> array of bits, least significant bit of each byte first (cell c = bit c&7 of byte c>>3)."""
    return np.unpackbits(np.frombuffer(bytes(b), dtype=np.uint8), bitorder="little")


def pack_bits(bits):
    return np.packbits(np.asarray(bits, dtype=np.uint8), bitorder="little").tobytes()


def derive(kbits):
    """Key bits -> (root16, check4). Same derivation as pr::reconstruct."""
    kb = pack_bits(kbits)
    root = sha256(b"PUF-ROOT-v1" + kb)[:16]
    chk = sha256(b"PUF-CHK-v1" + root)[:4]
    return root, chk


# ---------------------------------------------------------------- statistics
def group_fail_prob(p, n):
    """Probability that a majority vote over n cells is wrong when each cell flips with probability p."""
    return sum(comb(n, k) * p ** k * (1 - p) ** (n - k) for k in range(n // 2 + 1, n + 1))


def boot_fail_prob(p, n, groups):
    """Probability that at least one of the groups is wrong, i.e. the whole key is wrong."""
    g = group_fail_prob(p, n)
    return 1.0 - (1.0 - g) ** groups


# ---------------------------------------------------------------- enrollment
def stable_mask(readings):
    """Boolean array: cells whose value was identical in every reading."""
    bits = np.array([unpack_bits(r) for r in readings], dtype=np.uint8)
    return bits.min(axis=0) == bits.max(axis=0), bits


def build_helper(readings, region, addr, n=15, groups=256, rng=None, kbytes=None, allow_biased=False):
    """
    readings : list of equal-length byte strings, each a fresh power-up snapshot of the PUF block
    region   : REGION_RTC or REGION_SRAM
    addr     : absolute address of the block on the board (the firmware refuses a different one)
    Returns a dict: blob_a, blob_m, root (bytes, keep in memory only), chk, report
    """
    if len(readings) < 5:
        raise EnrollmentError(f"need at least 5 fresh readings, got {len(readings)}")
    lengths = {len(r) for r in readings}
    if len(lengths) != 1:
        raise EnrollmentError("readings have different lengths")
    region_bytes = lengths.pop()
    if n % 2 == 0 or n < 3:
        raise EnrollmentError("group size n must be odd and at least 3")
    if groups % 8 != 0:
        raise EnrollmentError("groups must be a multiple of 8")
    n_sel = groups * n
    if n_sel > region_bytes * 8:
        raise EnrollmentError("block too small for this many groups")

    stable, bits = stable_mask(readings)
    idx = np.flatnonzero(stable)
    if len(idx) < n_sel:
        raise EnrollmentError(
            f"only {len(idx)} cells were identical in all {len(readings)} readings, but {n_sel} are needed "
            f"({groups} groups x {n} cells). Use fewer readings, smaller n or groups, or another region.")

    rng = rng or secrets.SystemRandom()
    sel = np.array(sorted(rng.sample([int(i) for i in idx], n_sel)), dtype=np.int64)
    ref = bits[0][sel]
    ones_frac = float(ref.mean())
    if not allow_biased and not (0.40 <= ones_frac <= 0.60):
        raise EnrollmentError(
            f"the chosen cells are {ones_frac:.0%} ones. A real PUF block should be close to 50%; a skewed "
            f"value usually means leftover data or a region the program writes. Check the analysis first.")

    if kbytes is None:
        kbytes = secrets.token_bytes(groups // 8)
    kbits = unpack_bits(kbytes)[:groups]
    group_of = np.arange(n_sel) % groups
    w = ref ^ kbits[group_of]
    root, chk = derive(kbits)

    mask_bits = np.zeros(region_bytes * 8, dtype=np.uint8)
    mask_bits[sel] = 1
    blob_m = pack_bits(mask_bits)
    offsets = pack_bits(w)
    header = struct.pack("<4sBBBBHHI4sHH", MAGIC, VERSION, region, n, 0, groups, region_bytes, addr, chk, n_sel, 0)
    blob_a = header + offsets
    assert len(header) == HEADER_BYTES

    report = {
        "readings": len(readings), "stable_cells": int(len(idx)), "stable_fraction": float(len(idx)) / (region_bytes * 8),
        "selected": int(n_sel), "ones_fraction": ones_frac, "n": n, "groups": groups,
    }
    return {"blob_a": blob_a, "blob_m": blob_m, "root": root, "chk": chk, "report": report}


# ---------------------------------------------------------------- reconstruction (mirrors the firmware)
def parse_helper(blob_a, blob_m):
    if len(blob_a) < HEADER_BYTES or blob_a[:4] != MAGIC or blob_a[4] != VERSION:
        raise ValueError("bad helper header")
    (_, _, region, n, _, groups, region_bytes, addr, chk, n_sel, _) = struct.unpack("<4sBBBBHHI4sHH", blob_a[:HEADER_BYTES])
    if n % 2 == 0 or n < 3 or n > 63 or groups % 8 or groups < 8 or n_sel != groups * n:
        raise ValueError("inconsistent helper parameters")
    if len(blob_a) != HEADER_BYTES + (n_sel + 7) // 8 or len(blob_m) != region_bytes:
        raise ValueError("helper blob sizes do not match")
    offsets = unpack_bits(blob_a[HEADER_BYTES:])[:n_sel]
    mask = unpack_bits(blob_m)
    if int(mask.sum()) != n_sel:
        raise ValueError("mask does not select the announced number of cells")
    return {"region": region, "n": n, "groups": groups, "region_bytes": region_bytes, "addr": addr,
            "chk": chk, "n_sel": n_sel, "offsets": offsets, "mask": mask}


def reconstruct(snapshot, blob_a, blob_m):
    """Returns (ok, root16, corrected_cells)."""
    h = parse_helper(blob_a, blob_m)
    if len(snapshot) != h["region_bytes"]:
        raise ValueError("snapshot has the wrong length")
    sel = np.flatnonzero(h["mask"])
    raw = unpack_bits(snapshot)[sel]
    w = h["offsets"]
    group_of = np.arange(h["n_sel"]) % h["groups"]
    counts = np.bincount(group_of, weights=(raw ^ w), minlength=h["groups"])
    k = (counts * 2 > h["n"]).astype(np.uint8)
    expected = w ^ k[group_of]
    corrected = int((expected != raw).sum())
    root, chk = derive(k)
    return chk == h["chk"], root, corrected


# ---------------------------------------------------------------- serial payload for the board
def provision_payload(blob_a, blob_m):
    """lenA u16 | lenM u16 | blob A | blob M | crc32 u32  (crc over everything before it)."""
    body = struct.pack("<HH", len(blob_a), len(blob_m)) + blob_a + blob_m
    return body + struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)


# ---------------------------------------------------------------- synthetic chip for tests
class SyntheticPuf:
    """A made-up SRAM block: most cells strongly prefer 0 or 1, some are weak. Not a model of a real chip."""

    def __init__(self, seed, region_bytes=2048, weak_fraction=0.10, strong_flip=0.002):
        r = np.random.default_rng(seed)
        cells = region_bytes * 8
        self.region_bytes = region_bytes
        pref = r.integers(0, 2, cells)
        p1 = np.where(pref == 1, 1 - strong_flip, strong_flip).astype(float)
        weak = r.random(cells) < weak_fraction
        p1[weak] = r.uniform(0.2, 0.8, weak.sum())
        self.p1 = p1
        self.rng = np.random.default_rng(seed + 1000)

    def power_up(self, extra_noise=0.0):
        bits = (self.rng.random(self.p1.size) < self.p1).astype(np.uint8)
        if extra_noise > 0:
            flip = self.rng.random(bits.size) < extra_noise
            bits = bits ^ flip.astype(np.uint8)
        return pack_bits(bits)
