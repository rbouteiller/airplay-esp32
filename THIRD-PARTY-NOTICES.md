# Third-party notices

airplay-esp32 is licensed under GPL-3.0-or-later (see [LICENSE](LICENSE)) with
an additional permission for Espressif binary components (see
[LICENSE-EXCEPTION](LICENSE-EXCEPTION)). That license covers the code written
for this project. The components below are covered by their own licenses, which
continue to apply.

## Bundled in this repository

| Component | Path | License |
| --- | --- | --- |
| [u8g2](https://github.com/olikraus/u8g2) by Oliver Kraus (git submodule) | `components/u8g2` | BSD-2-Clause |
| [u8g2-hal-esp-idf](https://github.com/mkfrey/u8g2-hal-esp-idf) by Neil Kolban and Markus Frey | `components/u8g2-hal-esp-idf` | Apache-2.0 |
| Resampler by David Bryant | `components/audio-resampler` | BSD-3-Clause |
| TinyUSB descriptors by Ha Thach, adapted | `main/usb/usb_descriptors.c` | MIT |
| TinyUSB configuration from Espressif, adapted | `main/usb/tusb_config.h` | Apache-2.0 |

Every other C and header file in `main/` and `components/` carries an SPDX
header identifying it as GPL-3.0-or-later.

## Fetched at build time

These are pulled from the Espressif component registry by the IDF Component
Manager and are not stored in this repository, but they are linked into the
firmware binaries published in GitHub releases.

| Component | License | GPL-3.0 compatible |
| --- | --- | --- |
| ESP-IDF (incl. Wi-Fi, Bluetooth and PHY libraries) | Apache-2.0 | Yes |
| `espressif/esp_audio_codec` (ALAC and AAC decoders, precompiled) | Espressif Modified MIT | **No** — see below |
| `espressif/mdns` | Apache-2.0 | Yes |
| `espressif/libsodium` | ISC | Yes |
| `espressif/tinyusb` | MIT | Yes |
| `espressif/usb_device_uac` | Apache-2.0 | Yes |
| `espressif/led_strip` | Apache-2.0 | Yes |
| `espressif/esp_lvgl_port` | Apache-2.0 | Yes |
| `espressif/cmake_utilities` | Apache-2.0 | Yes |
| `lvgl/lvgl` | MIT | Yes |

### espressif/esp_audio_codec

This component provides the ALAC and AAC decoders and is distributed only as
precompiled archives. Its license permits use "EXCLUSIVELY with Espressif
Systems products" and prohibits redistribution for use with non-Espressif
products. A field-of-use restriction of this kind is a further restriction
within the meaning of section 7 of the GPL, so the component cannot be combined
with GPL-covered code under the GPL alone.

[LICENSE-EXCEPTION](LICENSE-EXCEPTION) grants the additional permission needed
to distribute firmware that links airplay-esp32 against it. Note that the
exception covers airplay-esp32's own code only. If you combine this project
with GPL-licensed code from a third party, that code's copyright holders have
not granted the same permission, and you should satisfy yourself that your
combination is distributable.

## Apple interoperability artifacts

The following are constants required to interoperate with Apple's AirPlay
implementation. They did not originate with this project, are not the copyright
of its contributors, and are not licensed to you by this project under the GPL
or under any other terms. They are widely published across independent AirPlay
receiver implementations and are included here solely to allow the protocol to
be spoken.

| Artifact | Location |
| --- | --- |
| FairPlay handshake response tables | `main/rtsp/rtsp_fairplay.c` |
| AirPlay RSA key | `main/rtsp/rtsp_rsa.c` |

## Protocol references

This project's protocol implementation was informed by the following work. They
are acknowledged as references and documentation:

- [Shairport Sync](https://github.com/mikebrady/shairport-sync) — MIT
- [openairplay/airplay2-receiver](https://github.com/openairplay/airplay2-receiver)
  — no license stated by its authors

## Trademarks

AirPlay, Apple, iPhone, iPad, Mac, HomePod and Siri are trademarks of Apple
Inc. This project is independent and is not affiliated with, endorsed by, or
sponsored by Apple Inc.
