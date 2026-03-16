idf_component_register(
    SRCS "spiffs_storage.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES spiffs esp_partition
)
