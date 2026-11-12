if(CONFIG_HUSB238A)
    set(srcs "husb238a.c")
else()
    set(srcs "")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "."
    REQUIRES esp_driver_i2c
    PRIV_REQUIRES board_utils
)
