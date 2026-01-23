set(ALAC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../alac/codec")

idf_component_register(
    SRCS
        "main.c"
        "wifi.c"
        "mdns_airplay.c"
        "rtsp_server.c"
        "plist.c"
        "tlv8.c"
        "hap.c"
        "srp.c"
        "audio_receiver.c"
        "apple_alac.cpp"
        "${ALAC_DIR}/ALACDecoder.cpp"
        "${ALAC_DIR}/ALACBitUtilities.c"
        "${ALAC_DIR}/ag_dec.c"
        "${ALAC_DIR}/dp_dec.c"
        "${ALAC_DIR}/matrix_dec.c"
        "EndianPortable_esp32.c"
    INCLUDE_DIRS "." "${ALAC_DIR}"
    PRIV_REQUIRES
        nvs_flash
        esp_wifi
        esp_netif
        esp_event
        esp_ringbuf
        esp_driver_i2s
)
