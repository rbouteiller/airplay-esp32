/**
 * USB Audio Class HOST output — native UAC 2.0/1.0 isochronous-OUT streamer.
 *
 * The ESP32-S3 acts as a USB host and streams decoded AirPlay PCM to a
 * connected USB-C headphone/DAC.  Espressif's usb_host_uac component only
 * supports UAC 1.0, but common devices (e.g. Apple USB-C EarPods) are UAC 2.0,
 * so this backend talks to the native ESP-IDF USB Host library directly:
 *
 *   - registers a USB host client
 *   - on device connect: parses the active config descriptor, finds an audio
 *     STREAMING interface alt-setting that is 16-bit stereo on an isochronous
 *     OUT endpoint (works for UAC 1.0 and UAC 2.0 — we don't parse the class
 *     header, just the standard AS interface/format/endpoint descriptors)
 *   - claims that interface+alt (which issues SET_INTERFACE)
 *   - streams PCM via a pool of isochronous OUT transfers, kept continuously
 *     fed from a PCM FIFO that the playback task fills (silence on underrun).
 *
 * The connected device's endpoint is assumed synchronous (no feedback EP); we
 * send the nominal 48 kHz data rate. Sample-rate is the compile-time
 * OUTPUT_RATE (48 kHz); AirPlay audio is resampled to it.
 *
 * FULL-DUPLEX (USB_HOST_FULL_DUPLEX): some headsets — notably the Apple USB-C
 * EarPods (a "Headset" terminal, not "Headphones") — only route USB audio to
 * their speaker while a bidirectional "call" is active. Their playback config
 * (UAC 2.0) has a fixed mixer (bmMixerControls=0) whose USB->speaker crosspoint
 * is connected only in that state. So in addition to the speaker OUT stream we
 * also claim the mic capture interface and submit iso IN transfers (data
 * discarded) to keep the capture stream live and un-gate the speaker. This is
 * best-effort and inert on output-only DACs (which expose no iso IN audio EP).
 */

#include "audio_output.h"

#include "audio_receiver.h"
#include "audio_resample.h"
#include "led.h"
#include "playback_control.h" /* play/pause + volume via DACP */
#include "rtsp_server.h"      /* airplay_get_volume_q15() */
#include "spiram_task.h"      /* task_create_spiram() */

#include "esp_check.h"
#include "esp_err.h"
#include "esp_intr_alloc.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/stream_buffer.h"
#include "freertos/task.h"

#include "driver/gpio.h"
#include "usb/usb_host.h"

#include <stdlib.h>
#include <string.h>

#define TAG           "audio_uac_host"
#define OUTPUT_RATE   CONFIG_OUTPUT_SAMPLE_RATE_HZ /* 48000 */
#define FRAME_SAMPLES 352
#define MAX_RESAMPLE_FRAMES \
  ((size_t)((FRAME_SAMPLES + 2) * ((double)OUTPUT_RATE / 44100) + 16))

#if CONFIG_FREERTOS_UNICORE
#define PLAYBACK_CORE 0
#else
#define PLAYBACK_CORE 1
#endif
#define USB_CORE      0
#define USB_LIB_PRIO  9
#define USB_CLI_PRIO  6
#define PLAYBACK_PRIO 7

/* Isochronous OUT transfer pool. Full-speed: 1 packet per 1 ms frame.
 * 48 kHz 16-bit stereo = 192 bytes/frame. */
#define NUM_URBS        4
#define PACKETS_PER_URB 8 /* 8 ms per URB; 32 ms of transfers in flight */
#define NUM_IN_URBS     2 /* mic-IN capture pool (full-duplex un-gate) */

/* Open the mic-IN stream together with the speaker-OUT stream. Set to 0 to
 * stream output only (plain USB DAC, or to A/B-test the un-gate effect). */
/* Full-duplex (open the mic IN stream alongside the speaker) was an attempt to
 * "un-gate" headsets — disproven: the silence was the missing SET_INTERFACE, not
 * gating. Playback-only is correct; leave at 0. */
#define USB_HOST_FULL_DUPLEX 0

/* PCM FIFO (producer = playback task, consumer = iso OUT callbacks) */
#define FIFO_CAP 16384 /* bytes; ~85 ms at 48 kHz stereo 16-bit */
/* Target FIFO depth (~50 ms). The playback task fills to here then yields, so it
 * paces itself to the iso drain rate instead of busy-spinning. The old loop
 * never delayed while frames were available — it pegged this core at 100% and
 * jittered the shared timing layer into dropping frames as "late" (the
 * play-stop-play-stop stutter). 50 ms keeps a safe margin over the 10 ms tick. */
#define FIFO_TARGET_BYTES ((OUTPUT_RATE / 1000) * 4 * 50)

/* ── USB / streaming state (owned by the USB client task) ────────────────── */
static usb_host_client_handle_t s_client = NULL;
static usb_device_handle_t s_dev = NULL;
static volatile bool s_streaming = false;

static uint8_t s_out_iface = 0;
static uint8_t s_out_alt = 0;
static uint8_t s_out_ep = 0;
static uint16_t s_out_mps = 0;
/* Fractional iso packet sizing so OUTPUT_RATE can match the source (44.1 kHz)
 * with NO resampling — packets carry 44 samples most 1 ms frames, 45 every
 * ~10th, averaging 44.1k. */
static int s_frame_bytes = 4; /* bytes per audio frame (16-bit stereo) */
static int s_pkt_base = 0;    /* floor samples/frame = OUTPUT_RATE/1000 */
static int s_pkt_frac = 0;    /* OUTPUT_RATE % 1000 */
static int s_frac_accum = 0;  /* fractional-sample accumulator */
static uint8_t s_ac_iface = 0; /* AudioControl interface (for class requests) */
static uint8_t s_clock_id = 0; /* UAC2 Clock Source entity ID (0 = none/UAC1) */
static uint8_t s_fu_ids[8];    /* Feature Unit IDs found in the AC interface */
static int s_fu_count = 0;
static uint8_t s_speaker_src = 0; /* entity feeding the speaker output terminal */
static uint8_t s_mixer_id = 0;    /* Mixer Unit ID (0 = none) */
static uint8_t s_mic_fu = 0;      /* feature unit feeding the USB-out (mic) term */
static uint8_t s_clock_ids[4];    /* all UAC2 Clock Source entity IDs */
static int s_clock_count = 0;
static int s_out_subslot = 2;  /* device sample size (bytes): 2=16-bit, 3=24-bit */
static uint8_t s_uac_ver = 0;  /* UAC spec major version: 1 or 2 */

/* Full-duplex capture path (mic IN). Opening it alongside the speaker OUT can
 * un-gate a headset that only routes USB audio during an active bidirectional
 * "call" (e.g. Apple EarPods). Best-effort; absent on output-only DACs. */
static uint8_t s_in_iface = 0xff;
static uint8_t s_in_alt = 0;
static uint8_t s_in_ep = 0;
static uint16_t s_in_mps = 0;
static int s_in_channels = 0;
static int s_in_packet_bytes = 0;
static usb_transfer_t *s_in_urb[NUM_IN_URBS];
static volatile bool s_capturing = false;
static volatile uint32_t s_in_done = 0, s_in_err = 0;

/* HID media-button path: the headset's own play/volume keys arrive as HID
 * interrupt reports; we forward them to the AirPlay source via DACP. */
static uint8_t s_hid_iface = 0xff; /* 0xff = device has no HID interface */
static uint8_t s_hid_alt = 0;
static uint8_t s_hid_ep = 0;
static uint16_t s_hid_mps = 0;
static usb_transfer_t *s_hid_urb = NULL;
static volatile bool s_hid_active = false;
static uint8_t s_hid_prev = 0;              /* previous bitmap (edge detect) */
static QueueHandle_t s_hid_action_q = NULL; /* HID button -> action task */
/* Report byte[1] bitmap bits — verified on Apple EarPods by isolating each key:
 * center/play=0x01, Vol+=0x02, Vol-=0x04. (Edit per device if needed.) */
#define HID_BIT_PLAY_PAUSE 0x01
#define HID_BIT_VOL_UP     0x02
#define HID_BIT_VOL_DOWN   0x04

static usb_transfer_t *s_urb[NUM_URBS];
static SemaphoreHandle_t s_ctrl_sem = NULL; /* signals sync control completion */

/* connect/disconnect handshake from the client callback to the client task */
static volatile bool s_connect_pending = false;
static volatile bool s_disconnect_pending = false;
static volatile uint8_t s_pending_addr = 0;

/* ── PCM queue ─────────────────────────────────────────────────────────────
 * A FreeRTOS stream buffer gives event-driven backpressure: the playback task
 * blocks in xStreamBufferSend until the iso-OUT callbacks drain space, so it
 * paces itself exactly to the device's consumption rate — no busy-poll, no
 * drop-on-full. Sized to FIFO_TARGET_BYTES (~50 ms): it runs near full, keeping
 * the output buffering stable at that depth (see hardware_latency_us). */
static StreamBufferHandle_t s_pcm = NULL;

/* telemetry */
static volatile uint32_t s_xfer_done = 0, s_xfer_err = 0, s_pkt_err = 0;
static volatile uint32_t s_push_bytes = 0;

static int fifo_level(void) {
  return s_pcm ? (int)xStreamBufferBytesAvailable(s_pcm) : 0;
}

static void fifo_reset(void) {
  if (s_pcm)
    xStreamBufferReset(s_pcm);
}

/* Enqueue, blocking (paced by the consumer) until there is room. A long stall
 * (e.g. the device was unplugged) times out and drops the chunk rather than
 * wedging the playback task. */
static void fifo_push(const uint8_t *src, size_t len) {
  if (!s_pcm)
    return;
  s_push_bytes += len;
  xStreamBufferSend(s_pcm, src, len, pdMS_TO_TICKS(100));
}

/* Dequeue up to `len` bytes (non-blocking — runs in the USB callback); pad the
 * remainder with silence on underrun. */
static void fifo_pop_padded(uint8_t *dst, size_t len) {
  size_t got = s_pcm ? xStreamBufferReceive(s_pcm, dst, len, 0) : 0;
  if (got < len)
    memset(dst + got, 0, len - got);
}

/* ── Optional VBUS enable ────────────────────────────────────────────────── */
static void usb_host_vbus_enable(void) {
#if defined(CONFIG_USB_HOST_VBUS_EN_GPIO) && CONFIG_USB_HOST_VBUS_EN_GPIO >= 0
  gpio_config_t io = {
      .pin_bit_mask = 1ULL << CONFIG_USB_HOST_VBUS_EN_GPIO,
      .mode = GPIO_MODE_OUTPUT,
  };
  gpio_config(&io);
  gpio_set_level(CONFIG_USB_HOST_VBUS_EN_GPIO, 1);
  ESP_LOGI(TAG, "VBUS enable GPIO%d -> HIGH", CONFIG_USB_HOST_VBUS_EN_GPIO);
#endif
}

/* ── USB host library daemon ─────────────────────────────────────────────── */
static void usb_lib_task(void *arg) {
  while (true) {
    uint32_t flags = 0;
    usb_host_lib_handle_events(portMAX_DELAY, &flags);
    if (flags & USB_HOST_LIB_EVENT_FLAGS_NO_CLIENTS)
      usb_host_device_free_all();
  }
}

/* ── Descriptor parsing ──────────────────────────────────────────────────── */
/* Walk the (active) config descriptor and find an audio STREAMING interface
 * alt-setting that is PCM 16-bit / 2-channel on an isochronous OUT endpoint.
 * Records iface/alt/endpoint/MPS. Returns true on success. */
static bool find_speaker_altsetting(const usb_config_desc_t *cfg) {
  const uint8_t *p = (const uint8_t *)cfg;
  const uint8_t *end = p + cfg->wTotalLength;
  p += p[0]; /* skip the 9-byte config descriptor */

  int iface = -1, alt = -1;
  bool cur_is_as = false;  /* current alt is an AudioStreaming interface */
  bool cur_is_ac = false;  /* current interface is AudioControl */
  bool cur_is_hid = false; /* current interface is HID (media buttons) */
  int as_channels = 0, as_bits = 0, as_subslot = 0;
  bool found_speaker = false;
  s_ac_iface = 0;
  s_uac_ver = 0;
  s_out_subslot = 2;
  s_clock_id = 0;
  s_clock_count = 0;
  s_fu_count = 0;
  s_speaker_src = 0;
  s_mic_fu = 0;
  s_mixer_id = 0;
  s_in_iface = 0xff;
  s_in_alt = 0;
  s_in_ep = 0;
  s_in_mps = 0;
  s_in_channels = 0;
  s_hid_iface = 0xff;
  s_hid_ep = 0;
  s_hid_mps = 0;

  while (p + 2 <= end) {
    uint8_t len = p[0], type = p[1];
    if (len < 2 || p + len > end)
      break;

    if (type == 0x04) { /* INTERFACE */
      iface = p[2];
      alt = p[3];
      uint8_t cls = p[5], sub = p[6], proto = p[7];
      cur_is_ac = (cls == 0x01 && sub == 0x01); /* AUDIO / AUDIOCONTROL */
      cur_is_as = (cls == 0x01 && sub == 0x02); /* AUDIO / AUDIOSTREAMING */
      cur_is_hid = (cls == 0x03);               /* HID (media buttons) */
      if (cur_is_ac) {
        s_ac_iface = (uint8_t)iface;
        s_uac_ver = (proto == 0x20) ? 2 : 1; /* bInterfaceProtocol 0x20 = UAC2 */
      }
      if (cur_is_hid && s_hid_iface == 0xff) {
        s_hid_iface = (uint8_t)iface;
        s_hid_alt = (uint8_t)alt;
      }
      as_channels = 0;
      as_bits = 0;
      as_subslot = 0;
    } else if (cur_is_ac && type == 0x24) { /* CS_INTERFACE (AudioControl) */
      /* INPUT_TERMINAL (subtype 2): grab the clock feeding the USB-streaming
       * (host->device) terminal. UAC2 layout: wTerminalType @4, bCSourceID @7 */
      if (p[2] == 0x02 && len >= 8) {
        /* INPUT_TERMINAL: clock of the USB-streaming (host->device) terminal */
        uint16_t ttype = (uint16_t)(p[4] | (p[5] << 8));
        if (ttype == 0x0101) /* USB Streaming */
          s_clock_id = p[7];
      } else if (p[2] == 0x03 && len >= 8) {
        /* OUTPUT_TERMINAL: bSourceID @7 feeds this terminal. A non-USB output
         * (speaker/headset) is the physical speaker; a USB-streaming output is
         * the mic->host path, fed by the mic feature unit. */
        uint16_t ttype = (uint16_t)(p[4] | (p[5] << 8));
        if ((ttype >> 8) != 0x01)
          s_speaker_src = p[7];
        else
          s_mic_fu = p[7];
      } else if (p[2] == 0x04 && len >= 5) {
        /* MIXER_UNIT: bUnitID @3 */
        s_mixer_id = p[3];
      } else if (p[2] == 0x06 && len >= 4 && s_fu_count < 8) {
        /* FEATURE_UNIT: bUnitID @3 */
        s_fu_ids[s_fu_count++] = p[3];
      } else if (p[2] == 0x0a && len >= 4 &&
                 s_clock_count < (int)sizeof(s_clock_ids)) {
        /* CLOCK_SOURCE: bClockID @3 — collect so we set every clock's rate */
        s_clock_ids[s_clock_count++] = p[3];
      }
    } else if (cur_is_as && type == 0x24) { /* CS_INTERFACE (AudioStreaming) */
      uint8_t subtype = p[2];
      if (subtype == 0x01) {
        /* AS_GENERAL: UAC2 carries bNrChannels @10 (UAC1 carries it in the
         * FORMAT_TYPE descriptor below). */
        if (s_uac_ver == 2 && len >= 11)
          as_channels = p[10];
      } else if (subtype == 0x02) {
        /* FORMAT_TYPE_I: UAC2 → bSubslotSize@4, bBitResolution@5;
         *                UAC1 → bNrChannels@4, bSubframeSize@5, bBitResolution@6 */
        if (s_uac_ver == 2) {
          if (len >= 6) {
            as_subslot = p[4];
            as_bits = p[5];
          }
        } else if (len >= 7) {
          as_channels = p[4];
          as_subslot = p[5];
          as_bits = p[6];
        }
      }
    } else if (cur_is_as && type == 0x05) { /* ENDPOINT */
      uint8_t ep_addr = p[2], ep_attr = p[3];
      uint16_t mps = (uint16_t)(p[4] | (p[5] << 8));
      bool is_out = !(ep_addr & 0x80);
      bool is_iso = (ep_attr & 0x03) == 0x01;
      /* sync type (bmAttributes[3:2]): 0=none 1=async 2=adaptive 3=sync.
       * usage (bmAttributes[5:4]): 0=data 1=feedback. An async OUT has a
       * separate feedback IN endpoint we'd need to honor to avoid drift. */
      ESP_LOGI(TAG,
               "  AS iface=%d alt=%d: ch=%d bits=%d sub=%d ep=0x%02x iso=%d "
               "out=%d sync=%d use=%d mps=%u",
               iface, alt, as_channels, as_bits, as_subslot, ep_addr, is_iso,
               is_out, (ep_attr >> 2) & 0x03, (ep_attr >> 4) & 0x03, mps);
      if (is_iso && mps > 0) {
        if (is_out && as_channels == 2 && as_subslot >= 2 && as_subslot <= 4) {
          /* Stereo PCM iso OUT = the speaker path. Prefer 16-bit (subslot 2, no
           * conversion); otherwise accept 24-/32-bit (e.g. the UAC1 Bose). */
          bool better =
              !found_speaker || (s_out_subslot != 2 && as_subslot == 2);
          if (better) {
            s_out_iface = (uint8_t)iface;
            s_out_alt = (uint8_t)alt;
            s_out_ep = ep_addr;
            s_out_mps = mps;
            s_out_subslot = as_subslot;
            found_speaker = true;
          }
        } else if (!is_out && as_channels >= 1 && as_subslot == 2 &&
                   s_in_ep == 0) {
          /* 16-bit iso IN = the mic capture path (opened for full-duplex) */
          s_in_iface = (uint8_t)iface;
          s_in_alt = (uint8_t)alt;
          s_in_ep = ep_addr;
          s_in_mps = mps;
          s_in_channels = as_channels;
        }
      }
    } else if (cur_is_hid && type == 0x05) { /* HID interrupt endpoint */
      uint8_t ep_addr = p[2], ep_attr = p[3];
      uint16_t mps = (uint16_t)(p[4] | (p[5] << 8));
      if ((ep_addr & 0x80) && (ep_attr & 0x03) == 0x03 && s_hid_ep == 0) {
        s_hid_ep = ep_addr; /* interrupt IN — media button reports */
        s_hid_mps = mps;
        ESP_LOGI(TAG, "  HID iface=%u ep=0x%02x mps=%u (media buttons)",
                 s_hid_iface, ep_addr, mps);
      }
    }
    p += len;
  }
  return found_speaker;
}

/* ── Isochronous OUT streaming ───────────────────────────────────────────── */
/* Size each iso packet for the (possibly fractional) rate; sets per-packet
 * num_bytes + xfer->num_bytes, returns the urb total. */
static int fill_out_packets(usb_transfer_t *xfer) {
  int total = 0;
  for (int j = 0; j < PACKETS_PER_URB; j++) {
    int samples = s_pkt_base;
    s_frac_accum += s_pkt_frac;
    if (s_frac_accum >= 1000) {
      samples++;
      s_frac_accum -= 1000;
    }
    int bytes = samples * s_frame_bytes;
    xfer->isoc_packet_desc[j].num_bytes = bytes;
    total += bytes;
  }
  xfer->num_bytes = total;
  return total;
}

static void out_xfer_cb(usb_transfer_t *xfer) {
  if (!s_streaming)
    return; /* tearing down — do not resubmit */
  s_xfer_done++;
  if (xfer->status != USB_TRANSFER_STATUS_COMPLETED)
    s_xfer_err++;
  for (int j = 0; j < PACKETS_PER_URB; j++)
    if (xfer->isoc_packet_desc[j].status != USB_TRANSFER_STATUS_COMPLETED)
      s_pkt_err++;

  int total = fill_out_packets(xfer); /* fractional sizing + xfer->num_bytes */
  fifo_pop_padded(xfer->data_buffer, (size_t)total);

  if ((s_xfer_done % 1250) == 0) /* ~ every 10 s (1250 urbs * 8 ms) */
    ESP_LOGI(TAG, "tlm xfers=%lu xerr=%lu pkterr=%lu push=%luB fifo=%d/%d",
             (unsigned long)s_xfer_done, (unsigned long)s_xfer_err,
             (unsigned long)s_pkt_err, (unsigned long)s_push_bytes,
             fifo_level(), FIFO_TARGET_BYTES);

  /* Resubmit regardless of transient status so the iso stream keeps flowing;
   * a real disconnect arrives via the DEV_GONE client event. */
  esp_err_t e = usb_host_transfer_submit(xfer);
  if (e != ESP_OK && (s_xfer_done % 1250) == 0)
    ESP_LOGW(TAG, "resubmit iso OUT: %s", esp_err_to_name(e));
}

static esp_err_t start_streaming(void) {
  /* Match the source rate (no resampling). Fractional packets: e.g. 44.1 kHz =
   * 44 samples/frame, 45 every ~10th. Allocate the worst case (one extra
   * sample/packet), capped at the endpoint MPS. */
  s_frame_bytes = 2 * s_out_subslot; /* 4 = 16-bit, 6 = 24-bit (stereo) */
  s_pkt_base = OUTPUT_RATE / 1000;
  s_pkt_frac = OUTPUT_RATE % 1000;
  s_frac_accum = 0;
  int alloc = (s_pkt_base + 1) * s_frame_bytes * PACKETS_PER_URB;
  if (alloc > (int)s_out_mps * PACKETS_PER_URB)
    alloc = (int)s_out_mps * PACKETS_PER_URB;

  fifo_reset();
  s_streaming = true;
  for (int i = 0; i < NUM_URBS; i++) {
    ESP_RETURN_ON_ERROR(
        usb_host_transfer_alloc(alloc, PACKETS_PER_URB, &s_urb[i]), TAG,
        "transfer_alloc");
    s_urb[i]->device_handle = s_dev;
    s_urb[i]->bEndpointAddress = s_out_ep;
    s_urb[i]->callback = out_xfer_cb;
    s_urb[i]->context = NULL;
    memset(s_urb[i]->data_buffer, 0, alloc); /* prime with silence */
    fill_out_packets(s_urb[i]);              /* sets packet sizes + num_bytes */
    ESP_RETURN_ON_ERROR(usb_host_transfer_submit(s_urb[i]), TAG, "submit");
  }
  ESP_LOGI(TAG, "Streaming: ep=0x%02x rate=%d (%d+frac samp/frame) x %d pkt x %d urbs",
           s_out_ep, OUTPUT_RATE, s_pkt_base, PACKETS_PER_URB, NUM_URBS);
  return ESP_OK;
}

/* ── Isochronous IN capture (full-duplex) ────────────────────────────────── */
/* We don't use the mic audio; resubmitting IN transfers just keeps the capture
 * stream live so a headset treats this as an active call and routes USB->spkr. */
static void in_xfer_cb(usb_transfer_t *xfer) {
  if (!s_capturing)
    return; /* tearing down — do not resubmit */
  s_in_done++;
  if (xfer->status != USB_TRANSFER_STATUS_COMPLETED)
    s_in_err++;
  for (int j = 0; j < PACKETS_PER_URB; j++)
    xfer->isoc_packet_desc[j].num_bytes = s_in_packet_bytes; /* discard data */
  xfer->num_bytes = s_in_packet_bytes * PACKETS_PER_URB;
  if ((s_in_done % 500) == 0)
    ESP_LOGI(TAG, "tlm mic-IN done=%lu err=%lu", (unsigned long)s_in_done,
             (unsigned long)s_in_err);
  usb_host_transfer_submit(xfer);
}

static esp_err_t start_capture(void) {
  s_in_packet_bytes = s_in_channels * 2 * (OUTPUT_RATE / 1000);
  if (s_in_packet_bytes > s_in_mps)
    s_in_packet_bytes = s_in_mps;
  int total = s_in_packet_bytes * PACKETS_PER_URB;
  s_capturing = true;
  for (int i = 0; i < NUM_IN_URBS; i++) {
    if (usb_host_transfer_alloc(total, PACKETS_PER_URB, &s_in_urb[i]) != ESP_OK) {
      s_in_urb[i] = NULL;
      goto fail;
    }
    s_in_urb[i]->device_handle = s_dev;
    s_in_urb[i]->bEndpointAddress = s_in_ep;
    s_in_urb[i]->callback = in_xfer_cb;
    s_in_urb[i]->context = NULL;
    s_in_urb[i]->num_bytes = total;
    for (int j = 0; j < PACKETS_PER_URB; j++)
      s_in_urb[i]->isoc_packet_desc[j].num_bytes = s_in_packet_bytes;
    if (usb_host_transfer_submit(s_in_urb[i]) != ESP_OK)
      goto fail;
  }
  return ESP_OK;
fail:
  s_capturing = false;
  for (int i = 0; i < NUM_IN_URBS; i++)
    if (s_in_urb[i]) {
      usb_host_transfer_free(s_in_urb[i]);
      s_in_urb[i] = NULL;
    }
  return ESP_FAIL;
}

static void ctrl_done_cb(usb_transfer_t *t) {
  (void)t;
  xSemaphoreGive(s_ctrl_sem);
}

/* Blocking control transfer on EP0. MUST be called from a task other than the
 * USB client task (that task dispatches this transfer's completion callback). */
static esp_err_t ctrl_xfer_sync(uint8_t reqtype, uint8_t req, uint16_t val,
                                uint16_t idx, const uint8_t *data,
                                uint16_t len) {
  usb_transfer_t *x = NULL;
  uint16_t buflen = len ? len : 1;
  if (usb_host_transfer_alloc(8 + buflen, 0, &x) != ESP_OK)
    return ESP_ERR_NO_MEM;
  usb_setup_packet_t *s = (usb_setup_packet_t *)x->data_buffer;
  s->bmRequestType = reqtype;
  s->bRequest = req;
  s->wValue = val;
  s->wIndex = idx;
  s->wLength = len;
  if (data && len)
    memcpy(x->data_buffer + 8, data, len);
  x->num_bytes = 8 + len;
  x->device_handle = s_dev;
  x->bEndpointAddress = 0;
  x->callback = ctrl_done_cb;
  x->context = NULL;
  esp_err_t e = usb_host_transfer_submit_control(s_client, x);
  if (e == ESP_OK) {
    if (xSemaphoreTake(s_ctrl_sem, pdMS_TO_TICKS(500)) != pdTRUE)
      e = ESP_ERR_TIMEOUT;
    else
      e = (x->status == USB_TRANSFER_STATUS_COMPLETED) ? ESP_OK : ESP_FAIL;
  }
  usb_host_transfer_free(x);
  return e;
}

/* UAC SET_CUR helpers (class request to the AudioControl interface). */
static esp_err_t uac_set_clock_hz(uint8_t clk_id, uint32_t hz) {
  uint8_t d[4] = {(uint8_t)hz, (uint8_t)(hz >> 8), (uint8_t)(hz >> 16),
                  (uint8_t)(hz >> 24)};
  /* CS_SAM_FREQ_CONTROL (0x01) << 8 */
  return ctrl_xfer_sync(0x21, 0x01, 0x0100,
                        (uint16_t)((clk_id << 8) | s_ac_iface), d, 4);
}
/* UAC1: SAMPLING_FREQ_CONTROL on the streaming ENDPOINT (3-byte rate). The EP
 * exists only after the streaming alt is selected, so call after SET_INTERFACE. */
static esp_err_t uac1_set_ep_rate(uint8_t ep, uint32_t hz) {
  uint8_t d[3] = {(uint8_t)hz, (uint8_t)(hz >> 8), (uint8_t)(hz >> 16)};
  return ctrl_xfer_sync(0x22, 0x01, 0x0100, ep, d, 3);
}
static esp_err_t uac_fu_set_mute(uint8_t fu_id, bool mute) {
  uint8_t d = mute ? 1 : 0; /* MUTE_CONTROL (0x01) << 8, channel 0 (master) */
  return ctrl_xfer_sync(0x21, 0x01, 0x0100,
                        (uint16_t)((fu_id << 8) | s_ac_iface), &d, 1);
}
static esp_err_t uac_fu_set_volume_db(uint8_t fu_id, int16_t db_q8) {
  uint8_t d[2] = {(uint8_t)db_q8, (uint8_t)(db_q8 >> 8)};
  /* VOLUME_CONTROL (0x02) << 8, channel 0 (master) */
  return ctrl_xfer_sync(0x21, 0x01, 0x0200,
                        (uint16_t)((fu_id << 8) | s_ac_iface), d, 2);
}
static esp_err_t uac_mixer_set_db(uint8_t mixer_id, uint8_t in_ch,
                                  uint8_t out_ch, int16_t db_q8) {
  uint8_t d[2] = {(uint8_t)db_q8, (uint8_t)(db_q8 >> 8)};
  /* wValue = (input channel number << 8) | output channel number */
  return ctrl_xfer_sync(0x21, 0x01, (uint16_t)((in_ch << 8) | out_ch),
                        (uint16_t)((mixer_id << 8) | s_ac_iface), d, 2);
}

/* ── HID media buttons (headset play/volume keys) ────────────────────────── */
typedef enum {
  HID_ACT_PLAY_PAUSE,
  HID_ACT_VOL_UP,
  HID_ACT_VOL_DOWN,
} hid_action_t;

/* DACP (play/pause, volume) does mDNS + HTTP, which can block — so the USB
 * callback only enqueues here; this task does the network work. */
static void hid_action_task(void *arg) {
  (void)arg;
  int v;
  while (1) {
    if (xQueueReceive(s_hid_action_q, &v, portMAX_DELAY) != pdTRUE)
      continue;
    switch ((hid_action_t)v) {
    case HID_ACT_PLAY_PAUSE:
      ESP_LOGI(TAG, "HID button -> play/pause");
      playback_control_play_pause();
      break;
    case HID_ACT_VOL_UP:
      ESP_LOGI(TAG, "HID button -> volume up");
      playback_control_volume_up();
      break;
    case HID_ACT_VOL_DOWN:
      ESP_LOGI(TAG, "HID button -> volume down");
      playback_control_volume_down();
      break;
    }
  }
}

static void hid_post(hid_action_t a) {
  int v = (int)a;
  if (s_hid_action_q)
    xQueueSend(s_hid_action_q, &v, 0); /* non-blocking */
}

static void hid_in_cb(usb_transfer_t *xfer) {
  if (!s_hid_active)
    return;
  if (xfer->status == USB_TRANSFER_STATUS_COMPLETED &&
      xfer->actual_num_bytes > 0) {
    const uint8_t *r = xfer->data_buffer;
    int nb = xfer->actual_num_bytes;
    /* Layout (Apple EarPods + similar): byte[0]=report ID, byte[1]=button
     * bitmap. Keep the raw log (only fires on press/release) to support other
     * devices, then dispatch once per new press (0->1 edge). */
    ESP_LOGI(TAG, "HID report (%dB): %02x %02x %02x %02x", nb, r[0],
             nb > 1 ? r[1] : 0, nb > 2 ? r[2] : 0, nb > 3 ? r[3] : 0);
    uint8_t bm = (nb > 1) ? r[1] : 0;
    uint8_t newly = (uint8_t)(bm & ~s_hid_prev);
    s_hid_prev = bm;
    if (newly & HID_BIT_PLAY_PAUSE)
      hid_post(HID_ACT_PLAY_PAUSE);
    if (newly & HID_BIT_VOL_UP)
      hid_post(HID_ACT_VOL_UP);
    if (newly & HID_BIT_VOL_DOWN)
      hid_post(HID_ACT_VOL_DOWN);
  }
  if (s_hid_active)
    usb_host_transfer_submit(xfer);
}

static esp_err_t start_hid(void) {
  if (usb_host_transfer_alloc(s_hid_mps, 0, &s_hid_urb) != ESP_OK)
    return ESP_ERR_NO_MEM;
  s_hid_urb->device_handle = s_dev;
  s_hid_urb->bEndpointAddress = s_hid_ep;
  s_hid_urb->callback = hid_in_cb;
  s_hid_urb->context = NULL;
  s_hid_urb->num_bytes = s_hid_mps;
  s_hid_active = true;
  return usb_host_transfer_submit(s_hid_urb);
}

static void setup_device(uint8_t addr) {
  if (usb_host_device_open(s_client, addr, &s_dev) != ESP_OK) {
    ESP_LOGE(TAG, "device_open(addr=%u) failed", addr);
    s_dev = NULL;
    return;
  }
  const usb_config_desc_t *cfg = NULL;
  if (usb_host_get_active_config_descriptor(s_dev, &cfg) != ESP_OK || !cfg) {
    ESP_LOGE(TAG, "get_active_config_descriptor failed");
    goto fail_close;
  }
  if (!find_speaker_altsetting(cfg)) {
    ESP_LOGE(TAG, "No stereo PCM iso OUT alt-setting found");
    goto fail_close;
  }
  ESP_LOGI(TAG,
           "Speaker iface=%u alt=%u ep=0x%02x mps=%u | Mic iface=%u alt=%u "
           "ep=0x%02x ch=%d | AC iface=%u clocks=%d FUs=%d mic_fu=%u",
           s_out_iface, s_out_alt, s_out_ep, s_out_mps, s_in_iface, s_in_alt,
           s_in_ep, s_in_channels, s_ac_iface, s_clock_count, s_fu_count,
           s_mic_fu);

  /* 1) UAC2: set every clock source's sample rate BEFORE selecting a streaming
   * alt. UAC1 has no clock entities — its rate is set on the endpoint after
   * SET_INTERFACE (below). */
  if (s_uac_ver == 2) {
    for (int i = 0; i < s_clock_count; i++) {
      esp_err_t e = uac_set_clock_hz(s_clock_ids[i], OUTPUT_RATE);
      ESP_LOGI(TAG, "set clock id=%u %d Hz: %s", s_clock_ids[i], OUTPUT_RATE,
               esp_err_to_name(e));
    }
    if (s_clock_count == 0 && s_clock_id)
      uac_set_clock_hz(s_clock_id, OUTPUT_RATE);
  }

  /* 2) Claim the streaming interface+alt. NOTE: usb_host_interface_claim() only
   * configures the HOST-side pipes — it does NOT send SET_INTERFACE to the
   * device. Without the explicit SET_INTERFACE below, the device's streaming
   * endpoint stays on alt 0 (DISABLED) and every iso-OUT packet is silently
   * dropped (the host still reports pkt_err=0 because iso has no handshake). */
  if (usb_host_interface_claim(s_client, s_dev, s_out_iface, s_out_alt) !=
      ESP_OK) {
    ESP_LOGE(TAG, "interface_claim(iface=%u alt=%u) failed", s_out_iface,
             s_out_alt);
    goto fail_close;
  }
  /* THE FIX: switch the DEVICE to the streaming alt (enables its endpoint). */
  esp_err_t si = ctrl_xfer_sync(0x01, 0x0b, s_out_alt, s_out_iface, NULL, 0);
  ESP_LOGI(TAG, "SET_INTERFACE(iface=%u alt=%u): %s", s_out_iface, s_out_alt,
           esp_err_to_name(si));
  /* UAC1: now that the endpoint exists, set its sampling frequency. */
  if (s_uac_ver == 1) {
    esp_err_t er = uac1_set_ep_rate(s_out_ep, OUTPUT_RATE);
    ESP_LOGI(TAG, "UAC1 set ep 0x%02x rate %d Hz: %s", s_out_ep, OUTPUT_RATE,
             esp_err_to_name(er));
  }

  /* 3) Unmute the speaker FU (master) and the mic FU (so the capture stream has
   * signal — part of looking like a live call); mute the rest, e.g. the
   * mic-monitor (sidetone) FU that otherwise loops the mic into the speaker. */
  for (int i = 0; i < s_fu_count; i++) {
    bool master = (s_fu_ids[i] == s_speaker_src); /* feeds the speaker */
    bool mic = (s_fu_ids[i] == s_mic_fu);         /* feeds the USB mic-out */
    bool keep = master || mic;
    esp_err_t em = uac_fu_set_mute(s_fu_ids[i], !keep);
    if (keep)
      uac_fu_set_volume_db(s_fu_ids[i], 0);
    ESP_LOGI(TAG, "FU %u %s mute=%d:%s", s_fu_ids[i],
             master ? "SPK" : (mic ? "MIC" : "off"), !keep, esp_err_to_name(em));
  }

  /* 3b) Route the USB stereo input through the mixer to the speaker (a headset
   * mixer's USB crosspoints default to muted, while the mic pin is unity). */
  if (s_mixer_id) {
    esp_err_t a = uac_mixer_set_db(s_mixer_id, 1, 1, 0); /* USB L -> out L */
    esp_err_t b = uac_mixer_set_db(s_mixer_id, 2, 2, 0); /* USB R -> out R */
    ESP_LOGI(TAG, "mixer %u (1->1):%s (2->2):%s", s_mixer_id, esp_err_to_name(a),
             esp_err_to_name(b));
  }

  /* 3c) Full-duplex: also claim the mic interface and run iso IN transfers, so
   * a headset that only routes USB audio during an active bidirectional call
   * un-gates its speaker. Best-effort — failure falls back to output-only. */
#if USB_HOST_FULL_DUPLEX
  if (s_in_ep) {
    esp_err_t ce =
        usb_host_interface_claim(s_client, s_dev, s_in_iface, s_in_alt);
    if (ce == ESP_OK && start_capture() == ESP_OK) {
      ESP_LOGI(TAG, "Full-duplex: mic IN iface=%u alt=%u ep=0x%02x ch=%d mps=%u",
               s_in_iface, s_in_alt, s_in_ep, s_in_channels, s_in_mps);
    } else {
      ESP_LOGW(TAG, "Full-duplex mic IN open failed (claim=%s) — OUT only",
               esp_err_to_name(ce));
      if (ce == ESP_OK)
        usb_host_interface_release(s_client, s_dev, s_in_iface);
      s_in_ep = 0;
    }
  }
#else
  s_in_ep = 0; /* output-only build: never open capture */
#endif

  /* 4) Start the isochronous OUT stream. */
  audio_resample_init(44100, OUTPUT_RATE, 2);
  audio_resample_reset();
  if (start_streaming() != ESP_OK) {
    ESP_LOGE(TAG, "start_streaming failed");
    s_streaming = false;
    s_capturing = false;
    for (int i = 0; i < NUM_IN_URBS; i++)
      if (s_in_urb[i]) {
        usb_host_transfer_free(s_in_urb[i]);
        s_in_urb[i] = NULL;
      }
    usb_host_interface_release(s_client, s_dev, s_out_iface);
    if (s_in_ep)
      usb_host_interface_release(s_client, s_dev, s_in_iface);
    goto fail_close;
  }
  ESP_LOGI(TAG, "USB audio OUT streaming started");

  /* 5) Headset media buttons: claim the HID interface (if present) and read its
   * interrupt reports. Best-effort — failure just means no button control. */
  if (s_hid_iface != 0xff && s_hid_ep) {
    if (usb_host_interface_claim(s_client, s_dev, s_hid_iface, s_hid_alt) ==
        ESP_OK) {
      ctrl_xfer_sync(0x21, 0x0a, 0x0000, s_hid_iface, NULL, 0); /* SET_IDLE 0 */
      if (start_hid() == ESP_OK) {
        ESP_LOGI(TAG, "HID media buttons active (iface=%u ep=0x%02x)",
                 s_hid_iface, s_hid_ep);
      } else {
        usb_host_interface_release(s_client, s_dev, s_hid_iface);
        s_hid_iface = 0xff;
      }
    } else {
      ESP_LOGW(TAG, "HID claim failed (iface=%u)", s_hid_iface);
      s_hid_iface = 0xff;
    }
  }
  return;

fail_close:
  usb_host_device_close(s_client, s_dev);
  s_dev = NULL;
}

static void teardown_device(void) {
  s_streaming = false;
  s_capturing = false;
  s_hid_active = false;
  vTaskDelay(pdMS_TO_TICKS(5)); /* let in-flight callbacks settle */
  for (int i = 0; i < NUM_URBS; i++) {
    if (s_urb[i]) {
      usb_host_transfer_free(s_urb[i]);
      s_urb[i] = NULL;
    }
  }
  for (int i = 0; i < NUM_IN_URBS; i++) {
    if (s_in_urb[i]) {
      usb_host_transfer_free(s_in_urb[i]);
      s_in_urb[i] = NULL;
    }
  }
  if (s_hid_urb) {
    usb_host_transfer_free(s_hid_urb);
    s_hid_urb = NULL;
  }
  if (s_dev) {
    usb_host_interface_release(s_client, s_dev, s_out_iface);
    if (s_in_ep)
      usb_host_interface_release(s_client, s_dev, s_in_iface);
    if (s_hid_iface != 0xff)
      usb_host_interface_release(s_client, s_dev, s_hid_iface);
    usb_host_device_close(s_client, s_dev);
    s_dev = NULL;
  }
  s_in_ep = 0;
  s_hid_iface = 0xff;
  s_hid_ep = 0;
  ESP_LOGI(TAG, "USB audio device torn down");
}

/* ── USB client (NEW_DEV / DEV_GONE) ─────────────────────────────────────── */
static void client_event_cb(const usb_host_client_event_msg_t *msg, void *arg) {
  if (msg->event == USB_HOST_CLIENT_EVENT_NEW_DEV) {
    if (!s_dev && !s_connect_pending) {
      s_pending_addr = msg->new_dev.address;
      s_connect_pending = true;
    }
  } else if (msg->event == USB_HOST_CLIENT_EVENT_DEV_GONE) {
    s_disconnect_pending = true;
  }
}

static void usb_client_task(void *arg) {
  const usb_host_client_config_t cfg = {
      .is_synchronous = false,
      .max_num_event_msg = 5,
      .async = {.client_event_callback = client_event_cb, .callback_arg = NULL},
  };
  if (usb_host_client_register(&cfg, &s_client) != ESP_OK) {
    ESP_LOGE(TAG, "client_register failed");
    vTaskDelete(NULL);
    return;
  }
  ESP_LOGI(TAG, "USB host client ready; waiting for a USB speaker/headphone");
  /* Pump events continuously: dispatches NEW_DEV / DEV_GONE, the setup task's
   * control-transfer completions, and the iso OUT completions. */
  while (true)
    usb_host_client_handle_events(s_client, portMAX_DELAY);
}

/* Device setup/teardown runs on its own task (not the client task) so the
 * blocking control transfers in setup_device() can wait while the client task
 * keeps dispatching their completion callbacks. */
static void usb_setup_task(void *arg) {
  (void)arg;
  while (true) {
    if (s_disconnect_pending) {
      s_disconnect_pending = false;
      teardown_device();
    }
    if (s_connect_pending && s_client) {
      s_connect_pending = false;
      setup_device(s_pending_addr);
    }
    vTaskDelay(pdMS_TO_TICKS(20));
  }
}

/* ── Volume + playback task ──────────────────────────────────────────────── */
static void apply_volume(int16_t *buf, size_t n) {
#ifndef CONFIG_DAC_CONTROLS_VOLUME
  int32_t vol = airplay_get_volume_q15();
  for (size_t i = 0; i < n; i++)
    buf[i] = (int16_t)(((int32_t)buf[i] * vol) >> 15);
#endif
}

static volatile bool flush_requested = false;
static volatile int source_rate = 44100;
static volatile bool resample_reinit_needed = false;

/* Expand n16 16-bit PCM samples to the device's subslot size, left-justified
 * (e.g. 16-bit -> 24-bit = value << 8). Writes n16 * subslot bytes. */
static int expand_pcm(const int16_t *src, int n16, uint8_t *dst, int subslot) {
  int shift = 8 * (subslot - 2);
  uint8_t *o = dst;
  for (int i = 0; i < n16; i++) {
    int32_t v = (int32_t)src[i] << shift;
    for (int b = 0; b < subslot; b++)
      *o++ = (uint8_t)(v >> (8 * b));
  }
  return n16 * subslot;
}

static void playback_task(void *arg) {
  int16_t *pcm = malloc((size_t)(FRAME_SAMPLES + 1) * 2 * sizeof(int16_t));
  int16_t *silence = calloc((size_t)FRAME_SAMPLES * 2, sizeof(int16_t));
  int16_t *resample_buf = malloc(MAX_RESAMPLE_FRAMES * 2 * sizeof(int16_t));
  /* Device-format scratch for >16-bit sinks (e.g. 24-bit Bose); worst case is
   * MAX_RESAMPLE_FRAMES stereo frames at 4 bytes/sample. */
  uint8_t *conv_buf = malloc((size_t)MAX_RESAMPLE_FRAMES * 2 * 4);
  if (!pcm || !silence || !resample_buf || !conv_buf) {
    ESP_LOGE(TAG, "alloc failed");
    free(pcm);
    free(silence);
    free(resample_buf);
    free(conv_buf);
    vTaskDelete(NULL);
    return;
  }
  while (true) {
    if (resample_reinit_needed) {
      resample_reinit_needed = false;
      audio_resample_init((uint32_t)source_rate, OUTPUT_RATE, 2);
    }
    if (flush_requested) {
      flush_requested = false;
      audio_resample_reset();
      fifo_reset();
    }
    /* No FIFO-level polling here: fifo_push() blocks on the stream buffer until
     * the iso callbacks free space, which paces this loop to the device. */
    size_t samples = audio_receiver_read(pcm, FRAME_SAMPLES + 1);
    if (samples > 0) {
      int16_t *play_buf = pcm;
      size_t play_samples = samples;
      if (audio_resample_is_active()) {
        play_samples = audio_resample_process(pcm, samples, resample_buf,
                                              MAX_RESAMPLE_FRAMES);
        play_buf = resample_buf;
      }
      apply_volume(play_buf, play_samples * 2);
      led_audio_feed(play_buf, play_samples);
      if (s_streaming) {
        if (s_frame_bytes == 4) {
          fifo_push((const uint8_t *)play_buf, play_samples * 4);
        } else {
          int n = expand_pcm(play_buf, (int)play_samples * 2, conv_buf,
                             s_out_subslot);
          fifo_push(conv_buf, (size_t)n);
        }
      } else {
        taskYIELD();
      }
    } else {
      led_audio_feed(silence, FRAME_SAMPLES);
      vTaskDelay(1);
    }
  }
}

/* ── Public API ──────────────────────────────────────────────────────────── */
esp_err_t audio_output_init(void) {
  ESP_LOGI(TAG, "Init USB UAC HOST (native) output, rate=%d", OUTPUT_RATE);
  s_pcm = xStreamBufferCreate(FIFO_TARGET_BYTES, 1);
  s_ctrl_sem = xSemaphoreCreateBinary();
  if (!s_pcm || !s_ctrl_sem)
    return ESP_ERR_NO_MEM;

  /* Task that turns headset HID button presses into DACP commands (off the USB
   * callback, since DACP does blocking mDNS + HTTP). */
  s_hid_action_q = xQueueCreate(8, sizeof(int));
  if (s_hid_action_q)
    task_create_spiram(hid_action_task, "hid_act", 4096, NULL, 5, NULL, NULL);

  usb_host_vbus_enable();
  const usb_host_config_t host_cfg = {
      .skip_phy_setup = false,
      .intr_flags = ESP_INTR_FLAG_LEVEL1,
  };
  ESP_RETURN_ON_ERROR(usb_host_install(&host_cfg), TAG, "usb_host_install");

  xTaskCreatePinnedToCore(usb_lib_task, "usb_lib", 4096, NULL, USB_LIB_PRIO,
                          NULL, USB_CORE);
  xTaskCreatePinnedToCore(usb_client_task, "usb_cli", 5120, NULL, USB_CLI_PRIO,
                          NULL, USB_CORE);
  xTaskCreatePinnedToCore(usb_setup_task, "usb_setup", 5120, NULL, USB_CLI_PRIO,
                          NULL, USB_CORE);

  audio_resample_init(44100, OUTPUT_RATE, 2);
  return ESP_OK;
}

void audio_output_start(void) {
  xTaskCreatePinnedToCore(playback_task, "uac_play", 4096, NULL, PLAYBACK_PRIO,
                          NULL, PLAYBACK_CORE);
}

void audio_output_flush(void) {
  flush_requested = true;
}

void audio_output_set_source_rate(int rate) {
  if (rate > 0 && rate != source_rate) {
    source_rate = rate;
    resample_reinit_needed = true;
  }
}

uint32_t audio_output_get_hardware_latency_us(void) {
  /* The real output buffering the AirPlay timing layer must lead by. The
   * playback task keeps the PCM FIFO near FIFO_TARGET_BYTES, and the iso URB
   * queue holds NUM_URBS x PACKETS_PER_URB ms in flight, so a frame pushed now
   * is not heard until it drains through both. The task pulls frames this far
   * ahead of their acoustic time to keep the pipeline full; if the timing layer
   * thinks the pipeline is only ~4 ms deep (the old hardcoded value), it treats
   * those pulled-ahead frames as "early" and emits silence, the receive buffer
   * backs up and ages, and stale frames then drop as "late" — the oscillation
   * heard as stutter. Reporting the true depth makes them release on time. */
  uint32_t fifo_us = (uint32_t)((uint64_t)FIFO_TARGET_BYTES * 1000000ULL /
                                ((uint32_t)OUTPUT_RATE * s_frame_bytes));
  uint32_t urb_us = (uint32_t)NUM_URBS * PACKETS_PER_URB * 1000;
  return fifo_us + urb_us;
}
