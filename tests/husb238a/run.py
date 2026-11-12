#!/usr/bin/env python3
"""Run the real HUSB238A driver against a simulated chip and charger.

Requires Python 3 and a C compiler; no ESP-IDF installation or hardware needed.
Run from any directory with: python3 tests/husb238a/run.py
"""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

# Only ESP-IDF/platform dependencies are replaced; the driver is compiled
# straight from the repo.
SHIMS = (
    "esp_err.h", "esp_log.h", "sdkconfig.h", "board_utils.h",
    "driver/i2c_master.h", "freertos/FreeRTOS.h", "freertos/semphr.h",
    "freertos/task.h",
)

with tempfile.TemporaryDirectory(prefix="husb238a-tests-") as temporary:
    build = Path(temporary)
    for name in SHIMS:
        shim = build / name
        shim.parent.mkdir(parents=True, exist_ok=True)
        shim.write_text('#include "mocks.h"\n')

    command = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=c11", "-Wall", "-Wextra", "-Werror", "-g",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(build), "-I", str(HERE),
        "-I", str(ROOT / "components/husb238a"),
        str(HERE / "test.c"), "-o", str(build / "test"),
    ]
    # The board's limit at its default, and below the charger's top offer.
    for max_volts in (20, 15):
        subprocess.run(command + [f"-DCONFIG_HUSB238A_MAX_VOLTS={max_volts}"],
                       check=True)
        subprocess.run([str(build / "test")], check=True)
