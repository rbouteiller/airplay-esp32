if(CONFIG_DAC_PCM51XX)
    set(srcs "dac_pcm51xx.c")
else()
    set(srcs "")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "."
    REQUIRES dac
    PRIV_REQUIRES esp_driver_gpio esp_driver_i2c board_utils
)
