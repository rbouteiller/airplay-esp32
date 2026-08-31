# OTA updates

Once the device is on your network you can update its firmware over WiFi without
unplugging anything. USB is only needed for the very first flash.

1. Get the new firmware — either build it (`pio run -e <env>` or `idf.py build`) or
   download a `.bin` from the
   [releases page](https://github.com/rbouteiller/airplay-esp32/releases/latest).
2. Open the device's web interface. Find its IP in your router's list of connected clients.
3. Use the firmware upload page to flash the new version.

The device reboots into the new firmware automatically. Settings stored in NVS — device
name, WiFi credentials, volume, EQ — survive the update.

!!! warning "OTA cannot change the partition table"

    If you are upgrading from a firmware built before the SPIFFS `storage` partition
    existed, the first flash has to happen over serial, because the partition layout
    itself changes. See [SPIFFS filesystem](spiffs.md#flashing-the-image).

## Updating files without reflashing

Web pages, the ST7789 background image and TAS57xx hybrid flow programs live on SPIFFS and
can be replaced individually over HTTP, without touching the firmware:

```bash
curl -X POST "http://<device-ip>/api/fs/upload?path=/spiffs/www/index.html" \
     --data-binary @data/www/index.html
```

See the [file management API](spiffs.md#file-management-api) for the full set of endpoints.
