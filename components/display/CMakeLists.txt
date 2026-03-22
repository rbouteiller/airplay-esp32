# Display component
# Supports:
#   - OLED displays (SSD1306, SH1106, SSD1309, SH1107) via u8g2
#   - ST7789 TFT via esp_lcd + LVGL 8.3
#
# When disabled, only the stub is compiled.

idf_component_register(
    SRCS "display_stub.c"
    INCLUDE_DIRS "include"
)

if(CONFIG_DISPLAY_ENABLED)
    if(CONFIG_DISPLAY_DRIVER_ST7789)
        target_sources(${COMPONENT_LIB} PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/display_st7789.c")
        target_link_libraries(${COMPONENT_LIB} PRIVATE
            idf::esp_lcd
            idf::driver
            idf::esp_timer
            idf::lvgl__lvgl)
    else()
        target_sources(${COMPONENT_LIB} PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/display.c")
        target_link_libraries(${COMPONENT_LIB} PRIVATE
            idf::u8g2
            idf::u8g2-hal-esp-idf
            idf::esp_timer)
    endif()

    target_include_directories(${COMPONENT_LIB} PRIVATE
        "${PROJECT_DIR}/main/rtsp"
        "${PROJECT_DIR}/main"
    )
endif()