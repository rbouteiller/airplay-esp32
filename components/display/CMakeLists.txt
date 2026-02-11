# Display component — only compiled when CONFIG_DISPLAY_ENABLED is set.
# When disabled, only the stub is compiled; display.h provides an
# inline no-op display_init().
#
# We always register with a source file (stub) so the component is never
# an INTERFACE library. When enabled, display.c is added and u8g2 linked.

idf_component_register(
    SRCS "display_stub.c"
    INCLUDE_DIRS "include"
)

if(CONFIG_DISPLAY_ENABLED)
    target_sources(${COMPONENT_LIB} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/display.c")
    target_link_libraries(${COMPONENT_LIB} PRIVATE idf::u8g2 idf::u8g2-hal-esp-idf)
    target_include_directories(${COMPONENT_LIB} PRIVATE
        "${PROJECT_DIR}/main/rtsp"
        "${PROJECT_DIR}/main"
    )
endif()
