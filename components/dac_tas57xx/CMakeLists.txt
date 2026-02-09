idf_component_register(
    SRCS "dac_tas57xx.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES driver esp_driver_i2c
)
