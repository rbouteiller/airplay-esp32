#!/usr/bin/env python3
"""Check the rate a TAS5805M's filters are designed at, on the host.

Requires Python 3, Node.js, and a C compiler; no ESP-IDF or hardware needed.
Run from any directory with: python3 tests/tas5805m_rate/run.py
"""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

with tempfile.TemporaryDirectory(prefix="tas5805m-rate-tests-") as temporary:
    build = Path(temporary)
    for name in (
        "esp_err.h", "esp_log.h", "esp_heap_caps.h", "sdkconfig.h",
        "board_utils.h", "driver/i2c_master.h", "freertos/FreeRTOS.h",
        "freertos/semphr.h", "freertos/task.h",
    ):
        shim = build / name
        shim.parent.mkdir(parents=True, exist_ok=True)
        shim.write_text('#include "mocks.h"\n')

    common = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g", "-O1",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(build), "-I", str(HERE),
        "-I", str(ROOT / "components/dac_tas58xx"),
        "-I", str(ROOT / "components/dac/include"),
    ]
    design = str(ROOT / "components/dac_tas58xx/tas58xx_biquad.c")
    command = common + [
        str(HERE / "test.c"),
        design,
        "-lm", "-o", str(build / "test"),
    ]
    print("TAS5805M filter rate host tests", flush=True)
    subprocess.run(command, check=True)
    subprocess.run([str(build / "test")], check=True)

    driver = str(build / "driver-test")
    subprocess.run(common + [
        "-Wno-sign-compare", str(HERE / "driver_test.c"), design,
        "-lm", "-o", driver,
    ], check=True)
    subprocess.run([driver], check=True)

    for rate in (32000, 44100, 48000, 88200, 96000):
        fixture = subprocess.check_output([driver, "--fixture", str(rate)])
        applied = subprocess.check_output(
            shlex.split(os.environ.get("NODE", "node")) +
            [str(HERE / "ui_test.js")], input=fixture,
        )
        subprocess.run([driver, "--roundtrip", str(rate)], input=applied,
                       check=True)
    print("all driver/UI/driver filter round trips passed", flush=True)
