if(CONFIG_DAC_ES8311)
    set(srcs "dac_es8311.c")
else()
    set(srcs "")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "."
    REQUIRES dac
    PRIV_REQUIRES driver esp_driver_i2c board_utils
)
