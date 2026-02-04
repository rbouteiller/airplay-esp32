# SqueezeAMP 4MB variant - shares HAL with squeezeamp
#
# This file is included by boards/CMakeLists.txt when BOARD_SQUEEZEAMP_4M is selected

# Use board.c from squeezeamp (same HAL, just different flash size)
list(APPEND BOARD_SRCS "${CMAKE_CURRENT_LIST_DIR}/../squeezeamp/board.c")

# Add TAS57xx DAC driver
list(APPEND BOARD_SRCS "${CMAKE_SOURCE_DIR}/main/audio/dac_tas57xx.c")

# Add I2C driver dependency for DAC communication
list(APPEND BOARD_DEPS esp_driver_i2c)

# Add squeezeamp directory to include path for board.h resolution
list(APPEND BOARD_INCLUDE_DIRS "${CMAKE_CURRENT_LIST_DIR}/../squeezeamp")
