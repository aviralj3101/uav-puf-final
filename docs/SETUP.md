# Setup guide: ESP32-CAM drone node + ESP32 base station, real PUF

## What has and has not been tested

Tested on a PC: the PUF key-rebuild code (C++ and Python agree on 300 noisy snapshots), the cipher (C++ = Python),
the camera resize, the analyzer on simulated data, and both sketches compile under strict warnings. The UAV
firmware also boots and answers its USB commands when built as a PC program.
NOT tested: anything on real hardware (camera, deep sleep, RTC memory behaviour, ESP-NOW between these two
boards), and the host scripts puf\_collect.py and puf\_enroll.py against a board. Expect to fix small things.
Whether your chip's memory works as a PUF is unknown until step 6.

## Steps

1. **Install.** Arduino IDE with the ESP32 board package (note its version); `pip install pyserial numpy opencv-python`.
2. **MAC addresses.** Flash `firmware/print\\\_mac` to both boards (Serial Monitor 115200) and write each MAC down.
3. **Edit** `PEER\\\_MAC` at the top of `uav\\\_espcam.ino` (the BASE board's MAC) and of `base\\\_station.ino` (the ESP32-CAM's MAC).
If you ever edit `firmware/common/\\\*.h`, run `python tools/sync\\\_headers.py`.
4. **Flash the base** (`firmware/base\\\_station`): your plain ESP32 board. Close the Serial Monitor afterwards.
5. **Flash the ESP32-CAM** (`firmware/uav\\\_espcam`) through its development board: Board "AI Thinker ESP32-CAM",
PSRAM Enabled, Partition scheme "Huge APP". Hold the board's IO0/GP0 button while uploading if it will not enter
download mode, then press reset. For a first bench test without the camera, set `USE\\\_TEST\\\_PATTERN 1`.
6. **Is your memory a PUF?** (do this first; about 2 minutes per board)

   * `python host/puf\\\_collect.py --port COM7 --count 30 --off-ms 1000 --out puf\\\_data/espcam.jsonl`
   * Repeat for your other ESP32 boards (flash the same sketch with `USE\\\_TEST\\\_PATTERN 1`) into `puf\\\_data/esp32\\\_a.jsonl`, `esp32\\\_b.jsonl`.
   * `python host/puf\\\_analyze.py puf\\\_data/\\\*.jsonl`
   * Enroll only a region that says PASS. If both say FAIL, set `PUF\\\_MODE\\\_REAL 0` (emulated fallback) and send me the report.
   * Optional: `--manual 10` adds readings after a real USB unplug, to compare with the sleep cycles.
7. **Enroll the PUF:** `python host/puf\\\_enroll.py --port COM7 --region rtc --n <recommended n> --verify 20`
(use `sram` if that is the region that passed; its address changes when you change the firmware, so re-enroll after any reflash).
Every verify line should say the key was rebuilt.
8. **Enroll challenge/response pairs:** `python host/enroll.py --uav-port COM7 --base-port COM10 --count 20`
9. **Run:** `python host/base\\\_receiver.py --port COM10`, type `s` (start session), then press Enter to capture.
The base prints "decrypt check OK" when the frame decrypted correctly.
10. **Before flying:** repeat step 9 powered from the supply you will fly with, then do a range test on the ground.
The board's LED: 2 short blinks = ready; 6 fast blinks = PUF key or camera problem.

## If something goes wrong

|Symptom|Likely cause|
|-|-|
|puf\_collect cannot enter maintenance mode|wrong port, Serial Monitor open, or old firmware; press reset and retry|
|analyzer FAIL: block looks constant|memory is overwritten or leftover data; try the other region or a longer `--off-ms`|
|enrollment says not enough stable cells|use a smaller `--n`, fewer `--groups`, or the other region|
|`PUFSTATUS,fail,badaddr` after reflashing|the sram region moved; re-run puf\_enroll.py (rtc region never moves)|
|session refused, status 2|the board could not rebuild its PUF key; check the boot messages|
|camera init failed|PSRAM not enabled, wrong board selected, or weak 5 V supply|



