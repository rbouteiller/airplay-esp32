if(CONFIG_DAC_TAS57XX)
    set(srcs "dac_tas57xx.c")
else()
    set(srcs "")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "."
    REQUIRES dac
    PRIV_REQUIRES driver esp_driver_i2c
)
