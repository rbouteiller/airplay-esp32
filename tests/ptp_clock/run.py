#!/usr/bin/env python3
"""Run the PTP offset filter through clock steps and delayed SYNCs on the host.

Requires Python 3 and a C compiler; no ESP-IDF installation or hardware needed.
Run from any directory with: python3 tests/ptp_clock/run.py
"""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

# Only ESP-IDF/platform dependencies are replaced. test.c includes
# ptp_clock.c itself, so it can feed the filter samples directly.
SHIMS = (
    "esp_err.h", "esp_log.h", "esp_timer.h", "freertos/FreeRTOS.h",
    "freertos/task.h", "spiram_task.h",
)

with tempfile.TemporaryDirectory(prefix="ptp-clock-tests-") as temporary:
    build = Path(temporary)
    for name in SHIMS:
        shim = build / name
        shim.parent.mkdir(parents=True, exist_ok=True)
        shim.write_text('#include "mocks.h"\n')

    command = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g", "-O1",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        # The FreeRTOS task entry point never reads its parameter.
        "-Wno-unused-parameter",
        "-I", str(build), "-I", str(HERE),
        "-I", str(ROOT / "main/network"),
        str(HERE / "test.c"),
        "-o", str(build / "test"),
    ]
    print("PTP clock host tests", flush=True)
    subprocess.run(command, check=True)
    subprocess.run([str(build / "test")], check=True)
