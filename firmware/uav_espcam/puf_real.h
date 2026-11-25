/*
 * puf_real.h  --  rebuild a stable root key from a noisy SRAM power-up pattern
 *
 * Pure C++ (no Arduino), so the same file runs on the ESP32 and in the PC tests, where it is checked
 * against the Python version in host/puf_lib.py.
 *
 * Method (code-offset fuzzy extractor with a repetition code, plus stable-cell selection):
 *
 *   ENROLLMENT (laptop, once, see host/puf_lib.py)
 *     - read the PUF block many times; keep only cells that gave the same value every time;
 *     - pick groups*n of them (the "mask"); cell number i of the picked cells belongs to group i % groups;
 *     - draw a random key bit k[g] per group; helper bit w[i] = reference_bit[i] XOR k[group(i)];
 *     - root = first 16 bytes of SHA-256("PUF-ROOT-v1" || packed k);   check = first 4 bytes of
 *       SHA-256("PUF-CHK-v1" || root).
 *     The helper data (mask, w, check) is stored in the board's flash. It is public: it does not
 *     contain the key or the reference bits.
 *
 *   EVERY BOOT (this file)
 *     - read the same cells again (a few may have flipped); v[i] = observed[i] XOR w[i];
 *     - majority vote of v over the n cells of each group gives k[g] again, despite flipped cells;
 *     - recompute root and compare its check value; a mismatch means reconstruction failed.
 *
 * Helper blob A = 24-byte header + offsets; blob M = mask bitmap. Cell c is bit (c & 7) of byte (c >> 3).
 *   header: "PUF1" | version u8=1 | region u8 | n u8 | 0 | groups u16 | region_bytes u16 | addr u32 |
 *           check[4] | n_selected u16 | 0 u16          (little-endian)
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "puf_chaos.h"

namespace pr {

constexpr size_t MAX_REGION_BYTES = 4096;
constexpr int    MAX_GROUPS       = 512;
constexpr size_t MAX_SELECTED     = 16384;
constexpr size_t HEADER_BYTES     = 24;

enum Status : int { OK = 0, ERR_FORMAT = 1, ERR_CHECK = 2 };

struct Helper {
  uint8_t  region;          // 0 = RTC slow memory, 1 = main SRAM (.noinit)
  uint8_t  n;               // cells per group (odd)
  uint16_t groups;          // number of key bits
  uint16_t regionBytes;
  uint32_t addr;            // absolute address of the PUF block when this helper data was made
  uint8_t  chk[4];
  uint16_t nSel;            // groups * n
  const uint8_t* offsets;   // nSel bits
  const uint8_t* mask;      // regionBytes bytes
};

inline int popcount8(uint8_t v) { int c = 0; while (v) { c += v & 1; v >>= 1; } return c; }

inline bool parse_helper(const uint8_t* a, size_t alen, const uint8_t* m, size_t mlen, Helper& h) {
  if (alen < HEADER_BYTES) return false;
  if (memcmp(a, "PUF1", 4) != 0 || a[4] != 1) return false;
  h.region      = a[5];
  h.n           = a[6];
  h.groups      = (uint16_t)(a[8] | (a[9] << 8));
  h.regionBytes = (uint16_t)(a[10] | (a[11] << 8));
  h.addr        = pc::le32(a + 12);
  memcpy(h.chk, a + 16, 4);
  h.nSel        = (uint16_t)(a[20] | (a[21] << 8));
  if (h.region > 1) return false;
  if (h.n < 3 || h.n > 63 || (h.n % 2) == 0) return false;
  if (h.groups < 8 || h.groups > MAX_GROUPS || (h.groups % 8) != 0) return false;
  if (h.regionBytes == 0 || h.regionBytes > MAX_REGION_BYTES) return false;
  if ((uint32_t)h.nSel != (uint32_t)h.groups * h.n || h.nSel > MAX_SELECTED) return false;
  if ((size_t)h.nSel > (size_t)h.regionBytes * 8) return false;
  if (alen != HEADER_BYTES + ((size_t)h.nSel + 7) / 8) return false;
  if (mlen != h.regionBytes) return false;
  size_t ones = 0;
  for (size_t i = 0; i < mlen; i++) ones += popcount8(m[i]);
  if (ones != h.nSel) return false;
  h.offsets = a + HEADER_BYTES;
  h.mask = m;
  return true;
}

// snap must hold h.regionBytes bytes. Returns OK, or ERR_CHECK if the rebuilt key fails its check value.
// 'corrected' (optional) receives how many selected cells differed from their enrolled value.
inline int reconstruct(const Helper& h, const uint8_t* snap, uint8_t root16[16], uint16_t* corrected) {
  uint8_t counts[MAX_GROUPS];
  memset(counts, 0, h.groups);
  const size_t cells = (size_t)h.regionBytes * 8;

  size_t i = 0;
  for (size_t c = 0; c < cells; c++) {
    if (!((h.mask[c >> 3] >> (c & 7)) & 1)) continue;
    uint8_t raw = (snap[c >> 3] >> (c & 7)) & 1;
    uint8_t w   = (h.offsets[i >> 3] >> (i & 7)) & 1;
    counts[i % h.groups] += (uint8_t)(raw ^ w);
    i++;
  }

  uint8_t kb[MAX_GROUPS / 8];
  memset(kb, 0, sizeof(kb));
  for (int g = 0; g < h.groups; g++)
    if ((int)counts[g] * 2 > h.n) kb[g >> 3] |= (uint8_t)(1u << (g & 7));

  uint16_t errs = 0;
  i = 0;
  for (size_t c = 0; c < cells; c++) {
    if (!((h.mask[c >> 3] >> (c & 7)) & 1)) continue;
    uint8_t raw = (snap[c >> 3] >> (c & 7)) & 1;
    uint8_t w   = (h.offsets[i >> 3] >> (i & 7)) & 1;
    size_t g    = i % h.groups;
    uint8_t k   = (kb[g >> 3] >> (g & 7)) & 1;
    errs += ((uint8_t)(w ^ k) != raw);
    i++;
  }
  if (corrected) *corrected = errs;

  uint8_t buf[11 + MAX_GROUPS / 8], d[32];
  memcpy(buf, "PUF-ROOT-v1", 11);
  memcpy(buf + 11, kb, h.groups / 8);
  pc::sha256(buf, 11 + h.groups / 8, d);
  memcpy(root16, d, 16);

  uint8_t cb[10 + 16];
  memcpy(cb, "PUF-CHK-v1", 10);
  memcpy(cb + 10, root16, 16);
  pc::sha256(cb, sizeof(cb), d);
  return memcmp(d, h.chk, 4) == 0 ? OK : ERR_CHECK;
}

}  // namespace pr
