idf_component_register(
    SRCS "board_utils.c"
    INCLUDE_DIRS "."
    REQUIRES esp_driver_i2c
    PRIV_REQUIRES esp_driver_gpio
)
