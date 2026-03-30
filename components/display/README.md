# Display Component

Supports two display families via a shared `display_init()` API:

| Driver | Display | Stack |
|--------|---------|-------|
| OLED (u8g2) | SSD1306, SH1106, SSD1309, SH1107 — 128×64 or 128×32 | u8g2 + I2C/SPI |
| ST7789 TFT | 1.9" IPS 320×170 landscape | esp_lcd + LVGL 9 + esp_lvgl_port |

When the display is disabled (`CONFIG_DISPLAY_ENABLED=n`), only `display_stub.c` is compiled — zero runtime cost.

---

## OLED Display (u8g2)

Shows track title, artist, album, progress bar and playback time. Auto-scrolls long text. Compact two-line layout for 128×32 panels.

### Enabling

```bash
idf.py menuconfig
# AirPlay Receiver → Display Configuration → Enable display
# Select driver: SSD1306 / SH1106 / SSD1309
# Select bus: I2C or SPI
```

### Default Wiring (I2C)

| OLED Pin | ESP32 GPIO |
|----------|------------|
| SDA      | 21         |
| SCL      | 22         |
| VCC      | 3.3V       |
| GND      | GND        |

Default I2C address: `0x3C`. Change in menuconfig if your display uses `0x3D`.

---

## ST7789 TFT Display

Full-colour display showing track metadata on a bitmap background with a progress bar and elapsed/remaining time. Requires ESP32-S3.

### Enabling

```bash
idf.py menuconfig
# AirPlay Receiver → Display Configuration → Enable display
# Select driver: ST7789 TFT (320×170 landscape)
```

Or add to `sdkconfig.defaults.esp32s3`:

```
CONFIG_DISPLAY_ENABLED=y
CONFIG_DISPLAY_DRIVER_ST7789=y
CONFIG_DISPLAY_SPI_CLK=18
CONFIG_DISPLAY_SPI_MOSI=17
CONFIG_DISPLAY_SPI_CS=15
CONFIG_DISPLAY_SPI_DC=16
CONFIG_DISPLAY_SPI_RST=21
CONFIG_DISPLAY_BL_GPIO=38
```

### Wiring (ESP32-S3)

| Display Pin | ESP32-S3 GPIO | Function              |
|-------------|---------------|-----------------------|
| SCL / CLK   | 18            | SPI clock             |
| SDA / MOSI  | 17            | SPI data              |
| CS          | 15            | Chip select           |
| DC / RS     | 16            | Data / command select |
| RES / RST   | 21            | Reset                 |
| BLK / BL    | 38            | Backlight             |
| VCC         | 3.3V          | Power                 |
| GND         | GND           | Ground                |

---

## Background Image

The ST7789 driver renders a full-screen background image stored as a C array in `background.c`. All UI widgets (text, progress bar) are drawn on top of it.

### Replacing the Background

1. Design your image and export as exactly **320×170px PNG**
2. Run the conversion script from the project root:
   ```bash
   python3 components/display/make_background.py <source.png> [brightness]
   ```
   Brightness range: `0.4`–`0.6`. Start at `0.5` — the ST7789 backlight renders
   significantly brighter than a monitor. Adjust to taste.
3. Rebuild — no other files need to change:
   ```bash
   idf.py build && idf.py flash
   ```

### Colour Depth Limitation

The ST7789 runs **RGB565** (16-bit colour):

| Channel | Source | Display |
|---------|--------|---------|
| Red     | 8 bit (256 levels) | 5 bit (32 levels) |
| Green   | 8 bit (256 levels) | 6 bit (64 levels) |
| Blue    | 8 bit (256 levels) | 5 bit (32 levels) |

This causes **visible banding on subtle dark gradients** — a fundamental hardware
limit with no complete software fix. Design backgrounds accordingly:
- Avoid subtle dark-to-dark gradients
- Bold contrast and distinct colour regions render well
- The conversion script applies Floyd-Steinberg dithering, which helps slightly

### Why Not the LVGL Online Converter?

The LVGL v9 online converter (lvgl.io/tools/imageconverter) does not expose a
byte-swap option for RGB565. `make_background.py` gives full control and produces
the correct little-endian output confirmed working on this panel.

---

## Implementation Notes (ST7789 + esp_lvgl_port)

These are non-obvious integration requirements discovered through testing. They
apply to any project using this display with ESP-IDF + LVGL 9 + `esp_lvgl_port`.

### 1. Rotation must be applied AFTER `lvgl_port_add_disp()`

`esp_lvgl_port` resets the ST7789 MADCTL register internally during
`lvgl_port_add_disp()`, wiping any rotation set beforehand. Always apply
`swap_xy`, `mirror`, and `set_gap` **after** that call.

```c
s_lvgl_disp = lvgl_port_add_disp(&disp_cfg);

// Rotation AFTER — not before
ESP_ERROR_CHECK(esp_lcd_panel_swap_xy(panel_handle, true));
ESP_ERROR_CHECK(esp_lcd_panel_mirror(panel_handle, true, false));
ESP_ERROR_CHECK(esp_lcd_panel_set_gap(panel_handle, 0, 35));
```

This applies regardless of ESP32 variant.

### 2. LVGL port task must be pinned to Core 0 (dual-core builds)

The default `task_affinity = -1` allows the LVGL task to migrate to Core 1.
On a dual-core build with audio on Core 1 (priority 7), this causes progressive
audio buffer backpressure — latency climbs from ~1800ms to 10000ms without
recovery, eventually causing stream misalignment.

Do **not** use `ESP_LVGL_PORT_INIT_CONFIG()` — it defaults to `-1`. Set explicitly:

```c
const lvgl_port_cfg_t lvgl_cfg = {
    .task_priority     = 4,
    .task_stack        = 6144,
    .task_affinity     = 0,   // Core 0 — keep Core 1 free for audio
    .task_max_sleep_ms = 500,
    .timer_period_ms   = 5,
};
```

Rule: all display tasks on Core 0, all audio tasks on Core 1.

### 3. Draw buffers must be in DMA-capable internal SRAM

In this version of `esp_lvgl_port`, the flush callback passes the draw buffer
pointer **directly** to `esp_lcd_panel_draw_bitmap` — `trans_size` has no
effect. If the buffer is in PSRAM (`buff_spiram=true`), the SPI master falls
back to allocating a private DMA buffer from internal heap at runtime. Under
memory pressure this fails, causing a flush deadlock and watchdog reset.

**Symptom:** `Failed to allocate priv TX buffer` in the monitor, followed by a
taskLVGL watchdog.

```c
.flags = {
    .buff_dma    = true,   // internal DMA-capable SRAM
    .buff_spiram = false,  // NOT PSRAM
    .swap_bytes  = true,
},
```

Cost at 10 draw lines (double buffer): **12,800 bytes** of internal SRAM.
Set `trans_size = 0` — it is unused in this code path.

---

## Diagnostic: Colour Bar Test

If the background image colours look wrong (washed out, swapped channels,
or psychedelic), run this to confirm byte order before debugging anything else:

```python
from PIL import Image, ImageDraw

bars = [
    (255,255,255), (255,255,0), (0,255,255), (0,255,0),
    (255,0,255),   (255,0,0),   (0,0,255),
]
img = Image.new('RGB', (320, 170))
draw = ImageDraw.Draw(img)
bar_w = 320 // len(bars)
for i, color in enumerate(bars):
    draw.rectangle([i*bar_w, 0, i*bar_w+bar_w, 170], fill=color)
# Convert using make_background.py or the same byte-conversion loop
```

Expected on screen (left to right):
**White → Yellow → Cyan → Green → Magenta → Red → Blue**

If this renders correctly, byte order is confirmed. If channels look wrong, the
problem is in the conversion, not the display driver.

---

## macOS AirPlay Discovery

macOS caches AirPlay device state. If the ESP32 has been crashing on connection
(e.g. the DMA watchdog above), macOS sees the device repeatedly disappear and
becomes conservative — slower to offer or connect to it.

If AirPlay discovery seems slow or stale after a reflash, flush the macOS
mDNS cache as a first diagnostic step:

```bash
sudo dscacheutil -flushcache
```

This rules out macOS holding stale state before assuming the issue is
firmware-side. After stabilising the firmware, connections become near-instant.

---

## Built With Claude

This component was developed collaboratively with [Claude](https://claude.ai) (Anthropic). Claude contributed to the driver implementation, LVGL 9 migration, debugging of the non-obvious integration issues documented above, background image tooling, and this documentation.

All commits made directly by Claude include the following co-author tag:
```
Co-authored-by: Claude (Anthropic) <claude@anthropic.com>
```
