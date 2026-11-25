#!/usr/bin/env python3
"""Copy the shared headers from firmware/common into each sketch folder (Arduino only sees its own folder)."""
import pathlib, shutil
R = pathlib.Path(__file__).resolve().parent.parent / "firmware"
for sketch, files in (("uav_espcam", ["puf_chaos.h", "puf_real.h", "frame_resize.h"]), ("base_station", ["puf_chaos.h"])):
    for f in files:
        shutil.copyfile(R / "common" / f, R / sketch / f)
        print(f"copied {f} -> {sketch}/")
