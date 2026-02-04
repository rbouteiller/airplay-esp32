# Board auto-discovery and source aggregation
#
# This file finds the selected board and adds its sources/dependencies
# to the build. Include this from main/CMakeLists.txt.

set(BOARD_SRCS "")
set(BOARD_DEPS "")
set(BOARD_INCLUDE_DIRS "${CMAKE_CURRENT_LIST_DIR}")

# List of supported boards (folder names under boards/)
set(SUPPORTED_BOARDS
    squeezeamp
    squeezeamp-4m
    esp32s3-generic
)

foreach(BOARD IN LISTS SUPPORTED_BOARDS)
    # Convert board name to CONFIG variable name
    # e.g., "squeezeamp" -> "SQUEEZEAMP", "esp32s3-generic" -> "ESP32S3_GENERIC"
    string(TOUPPER "${BOARD}" BOARD_UPPER)
    string(REPLACE "-" "_" BOARD_CONFIG "${BOARD_UPPER}")

    if(CONFIG_BOARD_${BOARD_CONFIG})
        message(STATUS "Board selected: ${BOARD}")
        set(BOARD_DIR "${CMAKE_CURRENT_LIST_DIR}/${BOARD}")

        # Add board.c as a source
        if(EXISTS "${BOARD_DIR}/board.c")
            list(APPEND BOARD_SRCS "${BOARD_DIR}/board.c")
        endif()

        # Include board-specific CMakeLists.txt if it exists
        # This allows boards to add extra sources and dependencies
        if(EXISTS "${BOARD_DIR}/CMakeLists.txt")
            include("${BOARD_DIR}/CMakeLists.txt")
        endif()

        # Add board directory to include path
        list(APPEND BOARD_INCLUDE_DIRS "${BOARD_DIR}")
    endif()
endforeach()

# Export variables to parent scope
set(BOARD_SRCS ${BOARD_SRCS} PARENT_SCOPE)
set(BOARD_DEPS ${BOARD_DEPS} PARENT_SCOPE)
set(BOARD_INCLUDE_DIRS ${BOARD_INCLUDE_DIRS} PARENT_SCOPE)
