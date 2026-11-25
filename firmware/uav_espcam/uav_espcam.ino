/*
 * UAV node: AI-Thinker ESP32-CAM.  Captures a frame when the base station asks, encrypts it with the
 * PUF chaos cipher and sends it over ESP-NOW.  Needs puf_chaos.h, puf_real.h and frame_resize.h in the
 * same folder (tools/sync_headers.py copies them).
 *
 * Arduino IDE settings:  Board "AI Thinker ESP32-CAM", PSRAM "Enabled", Partition scheme "Huge APP".
 *
 * THE PUF (PUF_MODE_REAL 1)
 *   At every boot, before anything else, the first thing setup() does is copy two blocks of memory that the
 *   program never writes into RAM: a block of RTC slow memory at a fixed address, and a block in main SRAM
 *   (.noinit). Their power-up values are the chip's fingerprint. Helper data stored in flash (made once by
 *   host/puf_enroll.py) lets this firmware rebuild the same 128-bit root key from a slightly noisy copy.
 *   The root key lives in RAM only. It is never written to flash.
 *   If the key cannot be rebuilt (check value mismatch), the board power-cycles itself and retries,
 *   then refuses sessions and blinks its LED.
 *   PUF_MODE_REAL 0 is the fallback: an HMAC key kept in flash (an emulation, NOT a PUF).
 *
 * USB COMMANDS (0xE1 <cmd> ...), used by the host tools while the board is plugged into the laptop:
 *   M            enter maintenance mode (answers "PUFMAINT,ok"); X leaves it
 *   D            dump the boot-time snapshots of both blocks (PUFDUMP lines)
 *   S <ms:u32>   zero the blocks, power them off in deep sleep for ms, reboot (a fresh power-up sample)
 *   P <payload>  store helper data (made by puf_enroll.py)
 *   V            rebuild the key from this boot's snapshot and report ("PUFVERIFY,...")
 *   W            wipe helper data
 *   O <chal:16>  answer a challenge: "PUFRESP:<hex>"  (used by enroll.py to enroll challenge/response pairs)
 *
 * RADIO PACKETS (ESP-NOW, max 250 bytes), all start with [type][txn]
 *   CMD           0x01 [txn][frame_id u32]
 *   SESSION_INIT  0x02 [txn][C 16][N 16]
 *   SESSION_ACK   0x03 [txn][status]            status 0 = ok, 2 = PUF failure
 *   START         0x10 [txn][len u32][crc32 u32][num_pkts u16][frame_id u32][tag 8]   (24 bytes)
 *   DATA          0x11 [txn][seq u16][n u8][payload <=240]
 *   ERR           0x20 [txn][code]              1 camera, 5 no session, 6 replayed frame id
 *
 * NOTE: debug text printed on Serial never contains byte 0x01.
 */

#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <esp_system.h>
#if __has_include(<esp_random.h>)
#include <esp_random.h>
#endif
#include <esp_sleep.h>
#include <esp_camera.h>
#include <Preferences.h>
#include "puf_chaos.h"
#include "puf_real.h"
#include "frame_resize.h"

// ===================== USER SETTINGS =====================
#define SERIAL_BAUD        921600     // must match the host scripts
#define ESPNOW_CHANNEL     1          // must be identical on both boards
// TODO: set to the MAC address of the BASE STATION board (print_mac sketch, or the base's boot message).
static const uint8_t PEER_MAC[6] = {0xE0, 0x8C, 0xFE, 0xE6, 0x6C, 0x20};

#ifndef PUF_MODE_REAL
#define PUF_MODE_REAL      0          // 1 = real SRAM PUF, 0 = emulated fallback (key in flash)
#endif
#ifndef USE_TEST_PATTERN
#define USE_TEST_PATTERN   0          // 1 = send a synthetic image (no camera needed, for bench tests)
#endif

#define PUF_REGION_BYTES   2048       // size of each PUF block (must match the helper data)
#define PUF_RTC_OFFSET     0x1800     // byte offset of the block inside the 8 KB RTC slow memory
#define PUF_ZERO_BEFORE_SLEEP 1       // write zeros before a power-cycle sleep (avoids leftover data)
#define PUF_MAX_ATTEMPTS   3          // boots tried before giving up on rebuilding the key
#define PUF_RETRY_OFF_MS   1500       // power-off time for the automatic retry
#define MAINT_WINDOW_MS    1500       // after boot, how long to wait for the host tools
// =========================================================

#define DATA_PAYLOAD   240
#define APP_TRIES      10
#define HELPER_A_MAX   1100           // header + offsets (up to 8192 selected cells)
#define LED_PIN        33             // red LED on the AI-Thinker board, active LOW

static_assert(PUF_REGION_BYTES % 4 == 0, "PUF block must be a whole number of 32-bit words");
static_assert(PUF_RTC_OFFSET + PUF_REGION_BYTES <= 8192, "PUF block does not fit in RTC slow memory");

enum : uint8_t { PKT_CMD = 0x01, PKT_SESSION_INIT = 0x02, PKT_SESSION_ACK = 0x03,
                 PKT_START = 0x10, PKT_DATA = 0x11, PKT_ERR = 0x20 };
enum : uint8_t { ERR_CAMERA = 1, ERR_NO_SESSION = 5, ERR_REPLAY = 6 };
enum : uint8_t { ACK_OK = 0, ACK_PUF_FAIL = 2 };
enum : int { PUF_OK = 0, PUF_NOHELPER = 1, PUF_BADADDR = 2, PUF_CHECK = 3, PUF_FORMAT = 4 };
enum : int { CMD_NONE = 0, CMD_MAINT = 1, CMD_EXIT = 2 };

// ---------------------------------------------------------------- PUF memory blocks
// Never written by this program (except the optional zero-fill right before a deliberate power-cycle).
static volatile uint8_t pufNoinit[PUF_REGION_BYTES] __attribute__((section(".noinit")));
#define RTC_SLOW_BASE   0x50000000UL
#ifndef RTC_REGION_ADDR            // (the PC simulator in tests/ overrides this)
#define RTC_REGION_ADDR (RTC_SLOW_BASE + PUF_RTC_OFFSET)
#endif
static uint8_t snap[2][PUF_REGION_BYTES];          // [0] = RTC block, [1] = main-SRAM block, copied at boot

static uint32_t addrNoinit() { return (uint32_t)(uintptr_t)&pufNoinit[0]; }

static void pufSnapshot() {                        // must be the first thing setup() does
  volatile uint32_t* r = (volatile uint32_t*)RTC_REGION_ADDR;
  for (size_t i = 0; i < PUF_REGION_BYTES / 4; i++) {
    uint32_t w = r[i];
    snap[0][4 * i]     = (uint8_t)w;
    snap[0][4 * i + 1] = (uint8_t)(w >> 8);
    snap[0][4 * i + 2] = (uint8_t)(w >> 16);
    snap[0][4 * i + 3] = (uint8_t)(w >> 24);
  }
  for (size_t i = 0; i < PUF_REGION_BYTES; i++) snap[1][i] = pufNoinit[i];
}

// Power the PUF blocks off (deep sleep with RTC memory off) and reboot: the next boot sees a fresh power-up.
static void pufPowerCycle(uint32_t offMs) {
#if PUF_ZERO_BEFORE_SLEEP
  volatile uint32_t* r = (volatile uint32_t*)RTC_REGION_ADDR;
  for (size_t i = 0; i < PUF_REGION_BYTES / 4; i++) r[i] = 0;
  for (size_t i = 0; i < PUF_REGION_BYTES; i++) pufNoinit[i] = 0;
#endif
  esp_sleep_pd_config(ESP_PD_DOMAIN_RTC_SLOW_MEM, ESP_PD_OPTION_OFF);
  esp_sleep_enable_timer_wakeup((uint64_t)offMs * 1000ULL);
  Serial.flush();
  esp_deep_sleep_start();
}

// ---------------------------------------------------------------- state
static uint8_t* imgBuf  = nullptr;
static uint8_t* workBuf = nullptr;
static uint8_t* ksBuf   = nullptr;
static pc::Session sess;
static Preferences prefs;
static uint8_t pufRoot[16];
static bool pufRootValid = false;
static uint8_t helperA[HELPER_A_MAX];
static uint8_t helperM[PUF_REGION_BYTES];
static bool helperLoaded = false;
static pr::Helper helper;
static bool cameraOk = false;
static uint8_t lastTxn = 0;
static bool haveTxn = false;
static uint32_t lastFrameId = 0;
static bool haveFrame = false;

// ---------------------------------------------------------------- receive ring (filled in the ESP-NOW callback)
#define RING_SLOTS 16
struct Slot { uint8_t len; uint8_t data[250]; };
static Slot ring[RING_SLOTS];
static volatile uint8_t ringHead = 0, ringTail = 0;

void onRecv(const void* info, const uint8_t* data, int len) {
  (void)info;
  if (len <= 0 || len > 250) return;
  uint8_t next = (ringHead + 1) % RING_SLOTS;
  if (next == ringTail) return;
  memcpy(ring[ringHead].data, data, len);
  ring[ringHead].len = (uint8_t)len;
  ringHead = next;
}

bool ringPop(uint8_t* out, uint8_t& len) {
  if (ringTail == ringHead) return false;
  len = ring[ringTail].len;
  memcpy(out, ring[ringTail].data, len);
  ringTail = (ringTail + 1) % RING_SLOTS;
  return true;
}

static volatile bool sendDone = false, sendOk = false;

void onSent(const void* info, esp_now_send_status_t status) {
  (void)info;
  sendOk = (status == ESP_NOW_SEND_SUCCESS);
  sendDone = true;
}

// ---------------------------------------------------------------- helpers
static inline void put16(uint8_t* p, uint16_t v) { p[0] = v & 0xFF; p[1] = v >> 8; }
static inline void put32(uint8_t* p, uint32_t v) {
  p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
}
static inline uint32_t get32(const uint8_t* p) { return pc::le32(p); }

uint32_t crc32_calc(const uint8_t* d, size_t n) {
  uint32_t c = 0xFFFFFFFFu;
  for (size_t i = 0; i < n; i++) {
    c ^= d[i];
    for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
  }
  return ~c;
}

static void printHex(const uint8_t* p, size_t n) {
  static const char* d = "0123456789abcdef";
  char line[129];
  for (size_t off = 0; off < n; off += 64) {
    size_t m = (n - off < 64) ? (n - off) : 64;
    for (size_t j = 0; j < m; j++) { line[2 * j] = d[p[off + j] >> 4]; line[2 * j + 1] = d[p[off + j] & 15]; }
    line[2 * m] = 0;
    Serial.print(line);
  }
}

static void printHash(const char* label, const uint8_t* buf, size_t n) {
  uint8_t h[32];
  pc::sha256(buf, n, h);
  Serial.printf("[UAV] %s sha256: %02x%02x%02x%02x\n", label, h[0], h[1], h[2], h[3]);
}

static void ledBlink(int times, int onMs, int offMs) {
  for (int i = 0; i < times; i++) {
    digitalWrite(LED_PIN, LOW); delay(onMs);
    digitalWrite(LED_PIN, HIGH); delay(offMs);
  }
}

static bool readExact(uint8_t* dst, size_t n, uint32_t idleTimeoutMs) {
  size_t got = 0;
  uint32_t last = millis();
  while (got < n) {
    int avail = Serial.available();
    if (avail > 0) {
      size_t want = n - got;
      size_t take = (size_t)avail < want ? (size_t)avail : want;
      got += Serial.readBytes(dst + got, take);
      last = millis();
    } else {
      if (millis() - last > idleTimeoutMs) return false;
      delay(1);
    }
  }
  return true;
}

static void drain(size_t n) {
  uint8_t b[64];
  while (n > 0) {
    size_t t = n < sizeof(b) ? n : sizeof(b);
    if (!readExact(b, t, 300)) return;
    n -= t;
  }
}

static const char* rstName(esp_reset_reason_t r) {
  switch (r) {
    case ESP_RST_POWERON:   return "POWERON";
    case ESP_RST_EXT:       return "EXT";
    case ESP_RST_SW:        return "SW";
    case ESP_RST_PANIC:     return "PANIC";
    case ESP_RST_INT_WDT:   return "WDT";
    case ESP_RST_TASK_WDT:  return "WDT";
    case ESP_RST_WDT:       return "WDT";
    case ESP_RST_DEEPSLEEP: return "DEEPSLEEP";
    case ESP_RST_BROWNOUT:  return "BROWNOUT";
    default:                return "OTHER";
  }
}

static const char* pufStatusName(int st) {
  switch (st) {
    case PUF_OK:       return "ok";
    case PUF_NOHELPER: return "nohelper";
    case PUF_BADADDR:  return "badaddr";
    case PUF_CHECK:    return "check";
    default:           return "format";
  }
}

// ---------------------------------------------------------------- PUF: helper data and key rebuild
static bool loadHelper() {
  helperLoaded = false;
  size_t la = prefs.getBytesLength("hd_a"), lm = prefs.getBytesLength("hd_m");
  if (la == 0 || lm == 0 || la > HELPER_A_MAX || lm > PUF_REGION_BYTES) return false;
  prefs.getBytes("hd_a", helperA, la);
  prefs.getBytes("hd_m", helperM, lm);
  if (!pr::parse_helper(helperA, la, helperM, lm, helper)) return false;
  helperLoaded = true;
  return true;
}

static uint32_t expectedAddr(uint8_t region) { return region == 0 ? (uint32_t)RTC_REGION_ADDR : addrNoinit(); }

// Rebuild the root key from this boot's snapshot. Returns a PUF_* status.
static int pufTryReconstruct(uint8_t out[16], uint16_t* corrected) {
  if (corrected) *corrected = 0;
  if (!helperLoaded) return PUF_NOHELPER;
  if (helper.regionBytes != PUF_REGION_BYTES) return PUF_FORMAT;
  if (helper.addr != expectedAddr(helper.region)) return PUF_BADADDR;   // firmware layout changed: re-enroll
  int rc = pr::reconstruct(helper, snap[helper.region], out, corrected);
  return rc == pr::OK ? PUF_OK : PUF_CHECK;
}

static void pufBoot() {
  uint16_t corrected = 0;
  int st = pufTryReconstruct(pufRoot, &corrected);
  uint8_t att = prefs.getUChar("att", 0);
  if (st == PUF_OK) {
    pufRootValid = true;
    if (att) prefs.putUChar("att", 0);
    Serial.printf("PUFSTATUS,ok,%u,%u\n", corrected, att);      // corrected cells, earlier failed attempts
    return;
  }
  if (st == PUF_CHECK && (uint8_t)(att + 1) < PUF_MAX_ATTEMPTS) {
    prefs.putUChar("att", att + 1);
    Serial.printf("PUFSTATUS,retry,%s,%u\n", pufStatusName(st), corrected);
    pufPowerCycle(PUF_RETRY_OFF_MS);                              // does not return
  }
  prefs.putUChar("att", 0);
  pufRootValid = false;
  Serial.printf("PUFSTATUS,fail,%s,%u\n", pufStatusName(st), corrected);
  Serial.println("[UAV] PUF key could not be rebuilt - sessions will be refused");
}

// Fallback (PUF_MODE_REAL 0): a random secret kept in flash. This is an emulation, not a PUF.
static void emulatedBoot() {
  if (prefs.getBytes("sec", pufRoot, 16) != 16) {
    for (size_t i = 0; i < 16; i += 4) {
      uint32_t r = esp_random();
      for (size_t k = 0; k < 4; k++) pufRoot[i + k] = (uint8_t)(r >> (8 * k));
    }
    prefs.putBytes("sec", pufRoot, 16);
    Serial.println("[UAV] EMULATED PUF: secret generated and stored in flash");
  } else {
    Serial.println("[UAV] EMULATED PUF: secret loaded from flash");
  }
  pufRootValid = true;
}

static void pufResponse(const uint8_t chal[16], uint8_t resp[16]) {
  pc::puf_response(pufRoot, chal, resp);
}

// ---------------------------------------------------------------- USB commands
static void cmdDump() {
  Serial.print("PUFDUMP,0,"); printHex(snap[0], PUF_REGION_BYTES); Serial.println();
  Serial.print("PUFDUMP,1,"); printHex(snap[1], PUF_REGION_BYTES); Serial.println();
  Serial.println("PUFDUMPEND");
}

static void cmdProvision() {
  uint8_t hdr[4];
  if (!readExact(hdr, 4, 1000)) { Serial.println("PUFPROV,fail,timeout"); return; }
  size_t la = hdr[0] | (hdr[1] << 8), lm = hdr[2] | (hdr[3] << 8);
  if (la == 0 || la > HELPER_A_MAX || lm != PUF_REGION_BYTES) {
    drain(la + lm + 4);
    Serial.println("PUFPROV,fail,size");
    return;
  }
  size_t total = 4 + la + lm;
  uint8_t* tmp = (uint8_t*)malloc(total + 4);
  if (!tmp) { drain(la + lm + 4); Serial.println("PUFPROV,fail,memory"); return; }
  memcpy(tmp, hdr, 4);
  if (!readExact(tmp + 4, la + lm + 4, 2000)) { free(tmp); Serial.println("PUFPROV,fail,timeout"); return; }
  uint32_t crcRx = get32(tmp + total);
  if (crc32_calc(tmp, total) != crcRx) { free(tmp); Serial.println("PUFPROV,fail,crc"); return; }
  pr::Helper hp;
  if (!pr::parse_helper(tmp + 4, la, tmp + 4 + la, lm, hp)) { free(tmp); Serial.println("PUFPROV,fail,format"); return; }
  if (hp.regionBytes != PUF_REGION_BYTES || hp.addr != expectedAddr(hp.region)) {
    free(tmp);
    Serial.println("PUFPROV,fail,addr");      // helper data was made for a different firmware layout
    return;
  }
  prefs.putBytes("hd_a", tmp + 4, la);
  prefs.putBytes("hd_m", tmp + 4 + la, lm);
  free(tmp);
  prefs.putUChar("att", 0);
  bool ok = loadHelper();
  Serial.println(ok ? "PUFPROV,ok" : "PUFPROV,fail,store");
}

static void cmdVerify() {
#if PUF_MODE_REAL
  uint8_t root[16];
  uint16_t corrected = 0;
  int st = pufTryReconstruct(root, &corrected);
  if (st == PUF_OK) {
    memcpy(pufRoot, root, 16);
    pufRootValid = true;
    Serial.printf("PUFVERIFY,ok,%u\n", corrected);
  } else {
    Serial.printf("PUFVERIFY,fail,%s,%u\n", pufStatusName(st), corrected);
  }
#else
  Serial.println("PUFVERIFY,fail,emulated,0");
#endif
}

static void cmdWipe() {
  prefs.remove("hd_a");
  prefs.remove("hd_m");
  prefs.putUChar("att", 0);
  helperLoaded = false;
  Serial.println("PUFWIPE,ok");
}

static int handleCommand(uint8_t cmd) {
  switch (cmd) {
    case 0x4D:  Serial.println("PUFMAINT,ok"); return CMD_MAINT;                    // 'M'
    case 0x58:  Serial.println("PUFMAINT,exit"); return CMD_EXIT;                   // 'X'
    case 0x44:  cmdDump(); break;                                                   // 'D'
    case 0x53: {                                                                    // 'S'
      uint8_t b[4];
      if (!readExact(b, 4, 500)) { Serial.println("PUFSLEEP,fail"); break; }
      uint32_t ms = get32(b);
      if (ms < 50) ms = 50;
      if (ms > 60000) ms = 60000;
      Serial.printf("PUFSLEEP,%lu\n", (unsigned long)ms);
      pufPowerCycle(ms);                                                            // does not return
      break;
    }
    case 0x50:  cmdProvision(); break;                                              // 'P'
    case 0x56:  cmdVerify(); break;                                                 // 'V'
    case 0x57:  cmdWipe(); break;                                                   // 'W'
    case 0x4F: {                                                                    // 'O': enrollment challenge
      uint8_t chal[16], R[16];
      if (!readExact(chal, 16, 500)) break;
      if (!pufRootValid) { Serial.println("PUFRESP:ERR"); break; }
      pufResponse(chal, R);
      Serial.print("PUFRESP:"); printHex(R, 16); Serial.println();
      break;
    }
    default: break;
  }
  return CMD_NONE;
}

// Reads one 0xE1-framed command from USB, if present. Returns CMD_*.
static int pollCommand() {
  static uint32_t firstSeen = 0;
  if (!Serial.available()) { firstSeen = 0; return CMD_NONE; }
  if (Serial.peek() != 0xE1) { Serial.read(); firstSeen = 0; return CMD_NONE; }     // discard noise
  if (Serial.available() < 2) {
    if (firstSeen == 0) firstSeen = millis();
    if (millis() - firstSeen > 500) { Serial.read(); firstSeen = 0; }
    return CMD_NONE;
  }
  Serial.read();
  uint8_t cmd = (uint8_t)Serial.read();
  firstSeen = 0;
  return handleCommand(cmd);
}

static void maintenanceLoop() {
  for (;;) {
    if (pollCommand() == CMD_EXIT) return;
    delay(1);
  }
}

static bool waitMaintenance(uint32_t ms) {
  uint32_t t0 = millis();
  uint8_t prev = 0;
  while (millis() - t0 < ms) {
    if (Serial.available()) {
      uint8_t b = (uint8_t)Serial.read();
      if (prev == 0xE1 && b == 0x4D) return true;
      prev = b;
    } else {
      delay(1);
    }
  }
  return false;
}

// ---------------------------------------------------------------- camera
static bool initCamera() {
#if USE_TEST_PATTERN
  return true;
#else
  camera_config_t c = {};
  c.ledc_channel = LEDC_CHANNEL_0;
  c.ledc_timer   = LEDC_TIMER_0;
  c.pin_d0 = 5;  c.pin_d1 = 18; c.pin_d2 = 19; c.pin_d3 = 21;      // AI-Thinker ESP32-CAM pin map
  c.pin_d4 = 36; c.pin_d5 = 39; c.pin_d6 = 34; c.pin_d7 = 35;
  c.pin_xclk = 0;  c.pin_pclk = 22; c.pin_vsync = 25; c.pin_href = 23;
  c.pin_sscb_sda = 26; c.pin_sscb_scl = 27;
  c.pin_pwdn = 32; c.pin_reset = -1;
  c.xclk_freq_hz = 20000000;
  c.pixel_format = PIXFORMAT_GRAYSCALE;
  c.frame_size   = FRAMESIZE_QVGA;                                   // 320 x 240, cropped and shrunk to 128 x 128
  c.jpeg_quality = 12;
  c.fb_count     = 1;
  c.fb_location  = psramFound() ? CAMERA_FB_IN_PSRAM : CAMERA_FB_IN_DRAM;
  c.grab_mode    = CAMERA_GRAB_LATEST;
  if (esp_camera_init(&c) != ESP_OK) return false;
  for (int i = 0; i < 6; i++) {                                      // let auto-exposure settle
    camera_fb_t* fb = esp_camera_fb_get();
    if (fb) esp_camera_fb_return(fb);
    delay(40);
  }
  return true;
#endif
}

// Fills imgBuf with a 128 x 128 grayscale frame. Returns false if the camera failed.
static bool captureFrame(uint32_t frameId) {
#if USE_TEST_PATTERN
  for (int y = 0; y < pc::N; y++)
    for (int x = 0; x < pc::N; x++) {
      int dx = x - 64, dy = y - 64;
      uint8_t v = (uint8_t)((x * 2 + frameId * 8) & 0xFF);
      if (dx * dx + dy * dy < 30 * 30) v = (uint8_t)(255 - v);
      imgBuf[y * pc::N + x] = v;
    }
  return true;
#else
  (void)frameId;
  if (!cameraOk) return false;
  camera_fb_t* fb = esp_camera_fb_get();            // discard a possibly stale frame
  if (fb) esp_camera_fb_return(fb);
  fb = esp_camera_fb_get();
  if (!fb) return false;
  if (fb->format != PIXFORMAT_GRAYSCALE || fb->width < 16 || fb->height < 16) { esp_camera_fb_return(fb); return false; }
  fr::gray_to_square(fb->buf, fb->width, fb->height, imgBuf, pc::N);
  esp_camera_fb_return(fb);
  return true;
#endif
}

// ---------------------------------------------------------------- ESP-NOW
bool sendPacket(const uint8_t* pkt, size_t len, uint32_t& retries) {
  for (uint8_t a = 0; a < APP_TRIES; a++) {
    sendDone = false;
    if (esp_now_send(PEER_MAC, pkt, len) == ESP_OK) {
      uint32_t t0 = millis();
      while (!sendDone && (millis() - t0) < 100) yield();
      if (sendDone && sendOk) return true;
    }
    retries++;
    delay(2);
  }
  return false;
}

void sendError(uint8_t txn, uint8_t code) {
  uint8_t pkt[3] = {PKT_ERR, txn, code};
  uint32_t r = 0;
  sendPacket(pkt, 3, r);
}

bool sendImage(uint8_t txn, uint32_t frameId, const uint8_t tag[8]) {
  uint8_t pkt[250];
  uint32_t retries = 0;
  const uint32_t len = pc::IMG_BYTES;
  uint16_t numPkts = (len + DATA_PAYLOAD - 1) / DATA_PAYLOAD;
  uint32_t crc = crc32_calc(imgBuf, len);
  uint32_t t0 = millis();

  memset(pkt, 0, 24);
  pkt[0] = PKT_START; pkt[1] = txn;
  put32(pkt + 2, len);
  put32(pkt + 6, crc);
  put16(pkt + 10, numPkts);
  put32(pkt + 12, frameId);
  memcpy(pkt + 16, tag, 8);
  if (!sendPacket(pkt, 24, retries)) {
    Serial.println("[UAV] ABORT: START packet not delivered (base off / wrong MAC / different channel?)");
    return false;
  }
  for (uint16_t seq = 0; seq < numPkts; seq++) {
    uint32_t off = (uint32_t)seq * DATA_PAYLOAD;
    uint32_t left = len - off;
    uint8_t n = left > DATA_PAYLOAD ? DATA_PAYLOAD : (uint8_t)left;
    pkt[0] = PKT_DATA; pkt[1] = txn;
    put16(pkt + 2, seq);
    pkt[4] = n;
    memcpy(pkt + 5, imgBuf + off, n);
    if (!sendPacket(pkt, 5 + n, retries)) {
      Serial.printf("[UAV] ABORT: DATA packet %u/%u failed after %u tries\n", seq, numPkts, APP_TRIES);
      return false;
    }
  }
  uint32_t dt = millis() - t0;
  Serial.printf("[UAV] sent %lu cipher bytes in %u packets, %lu ms (%.1f KiB/s), app retries: %lu\n",
                (unsigned long)len, numPkts, (unsigned long)dt,
                dt ? (len / 1.024f) / dt : 0.0f, (unsigned long)retries);
  return true;
}

void handleSessionInit(const uint8_t* pkt, uint8_t len) {
  if (len < 34) return;
  uint8_t status = ACK_OK;
  if (!pufRootValid) {
    status = ACK_PUF_FAIL;
    sess.valid = false;
    Serial.println("[UAV] session refused: PUF key not available");
  } else {
    uint8_t R[16];
    pufResponse(pkt + 2, R);
    uint32_t t0 = micros();
    pc::session_derive(R, pkt + 18, sess);
    uint32_t dt = micros() - t0;
    haveFrame = false;
    uint8_t h[32];
    pc::sha256(sess.key, 16, h);
    Serial.printf("[UAV] session key derived in %lu us, key fingerprint %02x%02x%02x%02x\n",
                  (unsigned long)dt, h[0], h[1], h[2], h[3]);
  }
  uint8_t ack[3] = {PKT_SESSION_ACK, pkt[1], status};
  uint32_t r = 0;
  sendPacket(ack, 3, r);
}

void handleCapture(const uint8_t* pkt, uint8_t len) {
  if (len < 6) return;
  uint8_t txn = pkt[1];
  uint32_t frameId = get32(pkt + 2);
  if (haveTxn && txn == lastTxn) { Serial.println("[UAV] duplicate capture command ignored"); return; }
  haveTxn = true; lastTxn = txn;

  if (!sess.valid) {
    Serial.println("[UAV] capture requested but no session is active");
    sendError(txn, ERR_NO_SESSION);
    return;
  }
  // A keystream must never be used for two different images: frame ids have to keep increasing.
  if (haveFrame && frameId <= lastFrameId) {
    Serial.printf("[UAV] refused: frame id %lu is not newer than %lu (replayed command?)\n",
                  (unsigned long)frameId, (unsigned long)lastFrameId);
    sendError(txn, ERR_REPLAY);
    return;
  }
  Serial.printf("[UAV] capture command (frame %lu)\n", (unsigned long)frameId);
  digitalWrite(LED_PIN, LOW);
  uint32_t tc = millis();
  if (!captureFrame(frameId)) {
    digitalWrite(LED_PIN, HIGH);
    Serial.println("[UAV] camera capture failed");
    sendError(txn, ERR_CAMERA);
    return;
  }
  lastFrameId = frameId;
  haveFrame = true;
  Serial.printf("[UAV] captured in %lu ms\n", (unsigned long)(millis() - tc));
  printHash("plaintext", imgBuf, pc::IMG_BYTES);

  uint8_t tag[8];
  pc::frame_tag(sess, frameId, imgBuf, tag);                       // keyed check of the plaintext

  uint32_t t0 = micros();
  pc::encrypt(sess, frameId, imgBuf, imgBuf, workBuf, ksBuf);      // in place
  uint32_t te = micros() - t0;
  Serial.printf("[UAV] ENC_TIME_US %lu (frame %lu)\n", (unsigned long)te, (unsigned long)frameId);

  sendImage(txn, frameId, tag);
  digitalWrite(LED_PIN, HIGH);
  ringTail = ringHead;
}

// ---------------------------------------------------------------- startup
static uint8_t* allocBuf(size_t n) {
  uint8_t* p = (uint8_t*)malloc(n);
  if (!p && psramFound()) p = (uint8_t*)ps_malloc(n);
  return p;
}

static void startRadio() {
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.disconnect();
  esp_wifi_set_channel(ESPNOW_CHANNEL, WIFI_SECOND_CHAN_NONE);
  if (esp_now_init() != ESP_OK) {
    while (true) { Serial.println("[UAV] FATAL: esp_now_init failed"); ledBlink(3, 100, 100); delay(1000); }
  }
  esp_now_register_send_cb((esp_now_send_cb_t)onSent);
  esp_now_register_recv_cb((esp_now_recv_cb_t)onRecv);
  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, PEER_MAC, 6);
  peer.channel = 0;
  peer.encrypt = false;
  if (esp_now_add_peer(&peer) != ESP_OK) {
    while (true) { Serial.println("[UAV] FATAL: could not add peer"); ledBlink(3, 100, 100); delay(1000); }
  }
}

static void normalStartup() {
  imgBuf  = allocBuf(pc::IMG_BYTES);
  workBuf = allocBuf(pc::IMG_BYTES);
  ksBuf   = allocBuf(pc::IMG_BYTES);
  if (!imgBuf || !workBuf || !ksBuf) {
    while (true) { Serial.println("[UAV] FATAL: cannot allocate buffers"); ledBlink(3, 100, 100); delay(1000); }
  }
  sess.valid = false;

#if PUF_MODE_REAL
  pufBoot();                       // before Wi-Fi and the camera start, as the PUF research recommends
#else
  emulatedBoot();
#endif

  startRadio();

  cameraOk = initCamera();
  if (!psramFound()) Serial.println("[UAV] WARNING: PSRAM not found. Enable PSRAM in the Arduino Tools menu.");
  Serial.println(cameraOk ? "[UAV] camera ready" : "[UAV] WARNING: camera init failed (check the board is an AI-Thinker ESP32-CAM and has 5 V power)");

  Serial.print("[UAV] my MAC: ");
  Serial.println(WiFi.macAddress());
  Serial.printf("[UAV] cipher: %d Duffing maps, image %dx%d, PUF mode: %s, heap free %lu bytes, sketch size %lu bytes\n",
                pc::NMAPS, pc::N, pc::N, PUF_MODE_REAL ? "REAL" : "EMULATED",
                (unsigned long)ESP.getFreeHeap(), (unsigned long)ESP.getSketchSize());
  Serial.printf("[UAV] ready on channel %d, waiting for session and capture commands\n", ESPNOW_CHANNEL);

  if (pufRootValid && (cameraOk || USE_TEST_PATTERN)) ledBlink(2, 120, 150);      // ready
  else ledBlink(6, 80, 80);                                                       // something is wrong
}

void setup() {
  pufSnapshot();                                   // FIRST: copy the PUF blocks before anything can touch them
  Serial.setRxBufferSize(8192);                    // before begin(); holds a whole helper-data payload
  Serial.begin(SERIAL_BAUD);
  Serial.setTimeout(500);
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, HIGH);
  delay(100);
  Serial.println();
  prefs.begin("puf", false);
  loadHelper();

  Serial.printf("PUFREADY,1,%s,%s,0x%08lx,0x%08lx,%u,%s\n",
                rstName(esp_reset_reason()),
                esp_sleep_get_wakeup_cause() == ESP_SLEEP_WAKEUP_TIMER ? "TIMER" : "NONE",
                (unsigned long)RTC_REGION_ADDR, (unsigned long)addrNoinit(),
                (unsigned)PUF_REGION_BYTES, PUF_MODE_REAL ? "real" : "emulated");

  if (waitMaintenance(MAINT_WINDOW_MS)) {          // host tools ask for maintenance mode
    Serial.println("PUFMAINT,ok");
    maintenanceLoop();
  }
  normalStartup();
}

void loop() {
  int r = pollCommand();
  if (r == CMD_MAINT) maintenanceLoop();
  uint8_t pkt[250];
  uint8_t len;
  if (ringPop(pkt, len)) {
    if (len < 2) return;
    switch (pkt[0]) {
      case PKT_SESSION_INIT: handleSessionInit(pkt, len); break;
      case PKT_CMD:          handleCapture(pkt, len); break;
      default: break;
    }
  }
}
