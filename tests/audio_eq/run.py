#!/usr/bin/env python3
"""Run the software EQ against a double-precision reference on the host.

Requires Python 3 and a C compiler; no ESP-IDF installation or hardware needed.
Run from any directory with: python3 tests/audio_eq/run.py
"""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

# Only ESP-IDF/platform dependencies are replaced. The EQ and the filter
# designer it shares with the TAS58xx driver are compiled from the repo.
SHIMS = (
    "esp_err.h", "esp_heap_caps.h", "esp_log.h", "sdkconfig.h",
    "settings.h", "freertos/FreeRTOS.h", "freertos/semphr.h",
)

with tempfile.TemporaryDirectory(prefix="audio-eq-tests-") as temporary:
    build = Path(temporary)
    for name in SHIMS:
        shim = build / name
        shim.parent.mkdir(parents=True, exist_ok=True)
        shim.write_text('#include "mocks.h"\n')

    command = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g", "-O1",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(build), "-I", str(HERE),
        "-I", str(ROOT / "components/dac_tas58xx"),
        "-I", str(ROOT / "main/audio"),
        str(HERE / "test.c"),
        str(ROOT / "main/audio/audio_eq.c"),
        str(ROOT / "components/dac_tas58xx/tas58xx_biquad.c"),
        "-lm", "-o", str(build / "test"),
    ]
    print("Software EQ host tests", flush=True)
    subprocess.run(command, check=True)
    subprocess.run([str(build / "test")], check=True)
