#!/usr/bin/env python3
"""Run the HomeKit pairing store and /pair-* handlers against a mock NVS.

Requires Python 3 and a C compiler; no ESP-IDF installation or hardware needed.
Run from any directory with: python3 tests/hap_pairings/run.py
"""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

# Only ESP-IDF/platform headers are replaced; the store and handlers are
# compiled straight from the repo.
SHIMS = (
    "esp_err.h", "esp_log.h", "esp_heap_caps.h", "esp_timer.h", "nvs.h",
    "freertos/FreeRTOS.h", "freertos/semphr.h",
)

with tempfile.TemporaryDirectory(prefix="hap-pairings-tests-") as temporary:
    build = Path(temporary)
    for name in SHIMS:
        shim = build / name
        shim.parent.mkdir(parents=True, exist_ok=True)
        shim.write_text('#include "mocks.h"\n')

    command = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(build), "-I", str(HERE), "-I", str(ROOT / "main/hap"),
        str(HERE / "test.c"), "-o", str(build / "test"),
    ]
    print("HomeKit pairing store and pair-add/remove/list tests", flush=True)
    subprocess.run(command, check=True)
    result = subprocess.run([str(build / "test")], check=True,
                            stdout=subprocess.PIPE, text=True)
    print("\n".join(line for line in result.stdout.splitlines()
                    if line.startswith("PASS")))
