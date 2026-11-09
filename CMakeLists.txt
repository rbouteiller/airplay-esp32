# AirPlay 2 Receiver for ESP32
cmake_minimum_required(VERSION 3.22.1)

# Read firmware version from version.txt, then tag it with the commit it was
# built from (and -dirty if the tree has uncommitted changes) so the version
# shown in the web UI and mDNS TXT record ("fv") identifies the exact build.
# esp_app_format truncates PROJECT_VER to 31 chars + NUL, so this always fits.
file(READ "${CMAKE_SOURCE_DIR}/version.txt" PROJECT_VER)
string(STRIP "${PROJECT_VER}" PROJECT_VER)

# Set by build.yml (-DFIRMWARE_BETA=ON) only for beta.yml's rolling pre-release,
# so a board flashed from it is identifiable as a beta build rather than a
# release or a plain dev build.
option(FIRMWARE_BETA "Tag PROJECT_VER as a beta build" OFF)
if(FIRMWARE_BETA)
    set(PROJECT_VER "${PROJECT_VER}-beta")
endif()

find_package(Git QUIET)
if(GIT_EXECUTABLE)
    # Reconfigure (and thus re-run these commands) whenever HEAD or the index
    # changes, so switching branches/commits or staging a change picks up a
    # fresh hash/dirty state without a full clean build.
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
                 "${CMAKE_SOURCE_DIR}/.git/HEAD" "${CMAKE_SOURCE_DIR}/.git/index")
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE GIT_HASH_RESULT)
    if(GIT_HASH_RESULT EQUAL 0 AND GIT_HASH)
        set(PROJECT_VER "${PROJECT_VER}-g${GIT_HASH}")
        execute_process(
            COMMAND ${GIT_EXECUTABLE} status --porcelain
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE GIT_DIRTY
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET)
        if(GIT_DIRTY)
            set(PROJECT_VER "${PROJECT_VER}-dirty")
        endif()
    endif()
endif()

# Add components directory
set(EXTRA_COMPONENT_DIRS "${CMAKE_SOURCE_DIR}/components")

include($ENV{IDF_PATH}/tools/cmake/version.cmake)
if(IDF_VERSION_MAJOR LESS 5 OR (IDF_VERSION_MAJOR EQUAL 5 AND IDF_VERSION_MINOR LESS 5))
    message(WARNING
        "ESP-IDF ${IDF_VERSION_MAJOR}.${IDF_VERSION_MINOR}.${IDF_VERSION_PATCH} detected. "
        "This project is developed and tested against ESP-IDF >= 5.5. "
        "Older versions may require workarounds (e.g. for hosted-WiFi Kconfig symbols on ESP32-P4). "
        "Please upgrade with: cd $ENV{IDF_PATH} && git fetch && git checkout v5.5.2 && ./install.sh")
endif()

# Board configs live in config/, so ESP-IDF no longer finds sdkconfig.defaults
# by itself — it only auto-detects one at the project root. Without this a bare
# "idf.py build" would silently configure with no defaults at all instead of
# failing, so restore the base layer when the caller has not chosen one.
if(NOT SDKCONFIG_DEFAULTS AND NOT DEFINED ENV{SDKCONFIG_DEFAULTS})
    set(SDKCONFIG_DEFAULTS "${CMAKE_SOURCE_DIR}/config/sdkconfig.defaults")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(airplay2-receiver VERSION ${PROJECT_VER})

include(cmake/fix_usb_device_uac_platformio.cmake)

# Build a SPIFFS image from data/ and flash it alongside the firmware.
# Partition label "storage" matches partitions.csv. Used by:
#   - components/dac_tas57xx/ (HybridFlow DAC firmware)
#   - components/display/     (ST7789 background image)
# Flash firmware + SPIFFS together with: idf.py build flash
#
# data/ is staged through a script that gzips the pages first: raw, the web UI
# alone overflows the 188 KB SPIFFS partition on a 4 MB board.
set(spiffs_image_dir "${CMAKE_BINARY_DIR}/spiffs_image")
set(spiffs_stage_args "")
# Both DAC drivers keep their DSP images in hf/, so each build carries only the
# family it can actually load.
if(NOT CONFIG_DAC_TAS57XX)
  list(APPEND spiffs_stage_args --exclude "hf/base-hf*.bin"
       --exclude "hf/tas57xx_fw*.bin")
endif()
if(NOT CONFIG_DAC_TAS58XX)
  list(APPEND spiffs_stage_args --exclude "hf/tas5825m_fw*.bin")
endif()
add_custom_target(
  spiffs_image_stage ALL
  COMMAND ${PYTHON} "${CMAKE_SOURCE_DIR}/scripts/gen_spiffs_image.py"
          ${spiffs_stage_args} "${CMAKE_SOURCE_DIR}/data" "${spiffs_image_dir}"
  VERBATIM)
spiffs_create_partition_image(storage "${spiffs_image_dir}" FLASH_IN_PROJECT
                              DEPENDS spiffs_image_stage)
