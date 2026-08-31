if(CONFIG_DAC_TAS57XX)
    set(srcs "dac_tas57xx.c" "tas57xx_cram.c" "tas57xx_hf1.c" "tas57xx_hf3.c")
else()
    set(srcs "")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "."
    REQUIRES dac
    PRIV_REQUIRES driver esp_driver_i2c board_utils
)
