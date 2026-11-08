file(GLOB_RECURSE SOURCES src/*.c)
idf_component_register(SRCS ${SOURCES}
                       INCLUDE_DIRS "include"
                       REQUIRES esp_driver_gpio esp_driver_i2c esp_driver_spi freertos u8g2)