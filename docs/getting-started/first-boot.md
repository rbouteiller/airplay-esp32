# First boot

On its first start the device has no WiFi credentials, so it brings up its own network and
a captive portal for you to configure it.

1. **Power the board** over USB-C.
2. On a phone or laptop, join the WiFi network **`ESP32-AirPlay-Setup`**.
3. A captive portal opens automatically. If it does not, browse to **`192.168.4.1`**.
4. Give the speaker a name, for example "Kitchen Speaker".
5. Select your home WiFi network and enter its password.
6. The device restarts and joins your network.
7. Open any music app, tap the AirPlay icon and pick your speaker.

That's it. Settings are stored in NVS and survive reboots and firmware updates.

!!! tip "If the WiFi connection fails"

    After several failed attempts the device returns to setup mode automatically, so you
    can rejoin `ESP32-AirPlay-Setup` and correct the credentials.

## The web interface

Once the device is on your network you can reach its web interface from a browser. Find
its IP address in your router's list of connected clients, or via the serial monitor.

| Page | Purpose |
| --- | --- |
| `/` | Setup and control panel — device name, WiFi, volume |
| `/logs` | Live log viewer |
| `/bq` | Per-section biquad EQ and crossovers, on TAS5825M boards |

The same interface is used for [OTA firmware updates](../reference/ota.md), so USB is only
needed for the very first flash.

## Something not working?

If the setup network never appears, the portal shows "file not found", or you get silence
after connecting, see [Troubleshooting](../troubleshooting.md).
