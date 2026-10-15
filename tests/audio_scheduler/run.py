#!/usr/bin/env python3
"""Run the scheduler's drift trims over a sine tone on the host.

Requires Python 3 and a C compiler; no ESP-IDF installation or hardware needed.
Run from any directory with: python3 tests/audio_scheduler/run.py
"""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

# Only ESP-IDF/platform dependencies are replaced. test.c includes
# audio_scheduler.c itself and stands in for the timeline and clock map.
SHIMS = (
    "esp_err.h", "esp_timer.h", "freertos/FreeRTOS.h",
    "freertos/portmacro.h", "freertos/semphr.h",
)

with tempfile.TemporaryDirectory(prefix="audio-scheduler-tests-") as temporary:
    build = Path(temporary)
    for name in SHIMS:
        shim = build / name
        shim.parent.mkdir(parents=True, exist_ok=True)
        shim.write_text('#include "mocks.h"\n')

    command = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g", "-O1",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        # The timeline mocks ignore most of what they are passed.
        "-Wno-unused-parameter",
        "-I", str(build), "-I", str(HERE),
        "-I", str(ROOT / "main/audio"),
        str(HERE / "test.c"),
        "-lm", "-o", str(build / "test"),
    ]
    print("Audio scheduler host tests", flush=True)
    subprocess.run(command, check=True)
    subprocess.run([str(build / "test")], check=True)
