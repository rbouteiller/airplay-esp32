set( SRC_FILES
    "main.c"
    "alac_magic_cookie.c"
    "settings.c"
    "audio/audio_receiver.c"
    "audio/audio_stream.c"
    "audio/audio_stream_realtime.c"
    "audio/audio_stream_buffered.c"
    "audio/audio_decoder.c"
    "audio/audio_buffer.c"
    "audio/audio_timing.c"
    "audio/audio_crypto.c"
    "audio/audio_resample.c"
    "rtsp/rtsp_server.c"
    "rtsp/rtsp_conn.c"
    "rtsp/rtsp_message.c"
    "rtsp/rtsp_handlers.c"
    "rtsp/rtsp_fairplay.c"
    "rtsp/rtsp_crypto.c"
    "rtsp/rtsp_rsa.c"
    "rtsp/rtsp_events.c"
    "plist/plist_xml.c"
    "plist/bplist_parser.c"
    "plist/bplist_builder.c"
    "plist/base64.c"
    "hap/hap.c"
    "hap/hap_pair_verify.c"
    "hap/hap_pair_setup.c"
    "hap/hap_crypto.c"
    "hap/srp.c"
    "hap/tlv8.c"
    "network/wifi.c"
    "network/mdns_airplay.c"
    "network/ptp_clock.c"
    "network/ntp_clock.c"
    "network/socket_utils.c"
    "network/web_server.c"
    "network/ota.c"
    "network/dns_server.c"
    "network/log_stream.c"
    "led.c"
    "audio/eq_events.c"
    "buttons.c"
    "playback_control.c"
    "dacp_client.c"
)

# Select audio output implementation at compile time. audio_output_common.c
# carries weak defaults for the optional entry points, so a backend only has
# to implement what it actually supports.
list(APPEND SRC_FILES "audio/audio_output_common.c")
if(CONFIG_AUDIO_OUTPUT_SPDIF)
    list(APPEND SRC_FILES "audio/audio_output_spdif.c")
elseif(CONFIG_AUDIO_OUTPUT_USB)
    list(APPEND SRC_FILES "audio/audio_output_usb.c")
else()
    list(APPEND SRC_FILES "audio/audio_output.c")
endif()

# Bluetooth A2DP sink (only available on ESP32 with Classic BT)
if(CONFIG_BT_A2DP_ENABLE)
    list(APPEND SRC_FILES "audio/a2dp_sink.c")
    list(APPEND SRC_FILES "bt_coex.c")
endif()

# USB Audio Class sink (host -> I2S, chips with USB OTG only)
if(CONFIG_USB_AUDIO_SINK)
    list(APPEND SRC_FILES "audio/usb_audio_sink.c")
endif()

# W5500 SPI Ethernet
if(CONFIG_ETH_W5500_ENABLED)
    list(APPEND SRC_FILES "network/ethernet.c")
endif()

set( INC_DIRS
    "." 
    "audio" 
    "rtsp" 
    "plist" 
    "hap" 
    "network"
    "usb"
)

set( DEPS
    driver
    nvs_flash
    esp_wifi
    esp_netif
    esp_event
    esp_ringbuf
    esp_driver_i2s
    esp_timer
    esp_http_server
    esp_http_client
    app_update
    json
    mbedtls
    esp_driver_ledc
    boards
    dac
    dac_tas58xx
    dac_tas57xx
    display
    audio-resampler
    esp_eth
    spiffs_storage
)

# Bluetooth component only needed when A2DP is enabled
#if(CONFIG_BT_A2DP_ENABLE)
    list(APPEND DEPS bt)
#endif()

# Ethernet component only needed when W5500 is enabled
#if(CONFIG_ETH_W5500_ENABLED)
    list(APPEND DEPS esp_eth)
#endif()

idf_component_register(
    SRCS ${SRC_FILES}
    INCLUDE_DIRS ${INC_DIRS}
    PRIV_REQUIRES ${DEPS}
)

# Enable function wrapping for abort() to intercept panics and mute GPIO
if(CONFIG_BOARD_SQUEEZEAMP_COMMON)
    target_link_libraries(${COMPONENT_LIB} INTERFACE "-Wl,--wrap=abort")
endif()

# Composite UAC + HID device. CONFIG_USB_DEVICE_UAC_AS_PART makes
# usb_device_uac withhold its own descriptors, tusb_config.h and include paths
# so we can add the HID interface; we have to supply all three instead.
if(CONFIG_USB_AUDIO_SINK AND CONFIG_USB_DEVICE_UAC_AS_PART)
    idf_build_get_property(build_components BUILD_COMPONENTS)
    if(tinyusb IN_LIST build_components)
        set(tinyusb_name tinyusb)
    else()
        set(tinyusb_name espressif__tinyusb)
    endif()
    idf_component_get_property(tusb_lib ${tinyusb_name} COMPONENT_LIB)
    idf_component_get_property(uac_dir espressif__usb_device_uac COMPONENT_DIR)
    target_include_directories(${tusb_lib} PUBLIC
        "${COMPONENT_DIR}/usb" "${uac_dir}/tusb_uac")
    # Compiled into TinyUSB rather than main: CFG_TUSB_MCU and the OS include
    # path are set on that target only, and both files include tusb.h.
    # PRIVATE, not PUBLIC: an INTERFACE copy propagates to every dependent and
    # PlatformIO then compiles the sources twice.
    target_sources(${tusb_lib} PRIVATE
        "${COMPONENT_DIR}/usb/usb_descriptors.c"
        "${COMPONENT_DIR}/usb/usb_hid_control.c")
endif()
