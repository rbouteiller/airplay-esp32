if(CONFIG_DAC_TAS58XX)
    set(srcs "dac_tas58xx.c" "tas58xx_biquad.c")
else()
    set(srcs "")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "."
    REQUIRES dac
    PRIV_REQUIRES driver esp_driver_i2c board_utils
)
