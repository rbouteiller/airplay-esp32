# During component requirements scanning, CONFIG_ vars are not yet available.
# We must declare all possible dependencies upfront.
set(PRIV_REQUIRES driver nvs_flash esp_driver_i2c esp_driver_spi dac dac_tas57xx dac_tas58xx main)

if(CONFIG_BOARD_TARGET_PATH)
    set(boards_dir ${CONFIG_BOARD_TARGET_PATH})
else()
    # Requirements scan phase - register with all dirs so headers are found
    set(boards_dir "squeezeamp")
endif()

idf_component_register(
    SRC_DIRS "${boards_dir}" "."
    INCLUDE_DIRS "${boards_dir}" "."
    PRIV_REQUIRES ${PRIV_REQUIRES}
)
