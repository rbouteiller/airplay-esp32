#!/usr/bin/env python3
"""Run the DAC dispatch layer on the host: output delay and latency sum.

Builds once per plain-DAC preset (CONFIG_DAC_PLAIN_DELAY_*).
Requires Python 3 and a C compiler; no ESP-IDF installation or hardware needed.
Run from any directory with: python3 tests/dac_dispatch/run.py
"""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

SHIMS = ("esp_err.h",)

PRESETS = (
    ("unknown", "#define CONFIG_DAC_PLAIN_DELAY_UNKNOWN 1\n"),
    ("PCM510xA normal", "#define CONFIG_DAC_PLAIN_DELAY_PCM510X_NORMAL 1\n"),
    ("PCM510xA low latency",
     "#define CONFIG_DAC_PLAIN_DELAY_PCM510X_LOW_LATENCY 1\n"),
    ("CS434x", "#define CONFIG_DAC_PLAIN_DELAY_CS434X 1\n"),
    ("custom", "#define CONFIG_DAC_PLAIN_DELAY_CUSTOM 1\n"
               "#define CONFIG_DAC_PLAIN_DELAY_CUSTOM_Q4 100\n"),
)

with tempfile.TemporaryDirectory(prefix="dac-dispatch-tests-") as temporary:
    build = Path(temporary)
    for name in SHIMS:
        shim = build / name
        shim.parent.mkdir(parents=True, exist_ok=True)
        shim.write_text('#include "mocks.h"\n')
    print("DAC dispatch host tests", flush=True)
    for index, (label, config) in enumerate(PRESETS):
        (build / "sdkconfig.h").write_text(config)
        binary = build / f"test-{index}"
        command = shlex.split(os.environ.get("CC", "cc")) + [
            "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g", "-O1",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            "-I", str(build), "-I", str(HERE),
            "-I", str(ROOT / "components/dac/include"),
            "-I", str(ROOT / "main/audio"),
            str(HERE / "test.c"), "-o", str(binary),
        ]
        print(f"-- preset: {label}", flush=True)
        subprocess.run(command, check=True)
        subprocess.run([str(binary)], check=True)
