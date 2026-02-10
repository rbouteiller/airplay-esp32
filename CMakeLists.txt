# AirPlay 2 Receiver for ESP32
cmake_minimum_required(VERSION 3.16)

# Add components directory
set(EXTRA_COMPONENT_DIRS "${CMAKE_SOURCE_DIR}/components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(airplay2-receiver)
