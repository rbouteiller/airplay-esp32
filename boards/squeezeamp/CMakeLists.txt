# SqueezeAMP board-specific sources and dependencies
#
# This file is included by boards/CMakeLists.txt when BOARD_SQUEEZEAMP is selected

# Add TAS57xx DAC driver
list(APPEND BOARD_SRCS "${CMAKE_SOURCE_DIR}/main/audio/dac_tas57xx.c")

# Add I2C driver dependency for DAC communication
list(APPEND BOARD_DEPS esp_driver_i2c)
