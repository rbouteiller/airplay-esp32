idf_component_register(
    SRCS "resampler.c"
    INCLUDE_DIRS "."
)

# Optimise for ESP32/Xtensa: single-precision float, fast math, max optimisation
# (GCC-only flags skipped under clang, i.e. the lint build).
target_compile_options(${COMPONENT_LIB} PRIVATE
    $<$<C_COMPILER_ID:GNU>:-Wno-calloc-transposed-args>
    -O3
    -ffast-math
    $<$<C_COMPILER_ID:GNU>:-fsingle-precision-constant>
    -fno-math-errno
)
