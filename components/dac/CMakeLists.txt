# All possible DAC driver dependencies declared upfront (scan-phase safe)
idf_component_register(
    SRCS "dac.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES dac_tas57xx
)
