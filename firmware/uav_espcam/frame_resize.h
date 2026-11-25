/*
 * frame_resize.h -- crop the centre square of a grayscale camera frame and shrink it to N x N.
 * Integer box averaging, no floating point. Pure C++ so it is tested on a PC (tests/test_frame_resize.py).
 *
 * Example: a 320 x 240 frame -> centre 240 x 240 square -> 128 x 128. Each output pixel is the average of
 * the block of source pixels it covers, with block edges at floor(k * side / N).
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

namespace fr {

inline void gray_to_square(const uint8_t* src, int w, int h, uint8_t* dst, int N) {
  const int s  = (w < h) ? w : h;
  const int x0 = (w - s) / 2;
  const int y0 = (h - s) / 2;
  for (int dy = 0; dy < N; dy++) {
    int ys = (dy * s) / N;
    int ye = ((dy + 1) * s) / N;
    if (ye <= ys) ye = ys + 1;
    for (int dx = 0; dx < N; dx++) {
      int xs = (dx * s) / N;
      int xe = ((dx + 1) * s) / N;
      if (xe <= xs) xe = xs + 1;
      uint32_t sum = 0;
      for (int y = ys; y < ye; y++) {
        const uint8_t* row = src + (size_t)(y0 + y) * w + x0;
        for (int x = xs; x < xe; x++) sum += row[x];
      }
      dst[dy * N + dx] = (uint8_t)(sum / (uint32_t)((ye - ys) * (xe - xs)));
    }
  }
}

}  // namespace fr
