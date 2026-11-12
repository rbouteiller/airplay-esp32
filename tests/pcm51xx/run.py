#!/usr/bin/env python3
"""Run the real PCM512x driver and board against fault-injecting host mocks.

Requires Python 3 and a C compiler; no ESP-IDF installation or hardware needed.
Run from any directory with: python3 tests/pcm51xx/run.py
"""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

# Only ESP-IDF/platform dependencies are replaced. The DAC dispatch, driver,
# board, and public board/playback headers are compiled directly from the repo.
SHIMS = (
    "esp_err.h", "esp_check.h", "esp_log.h", "sdkconfig.h", "board_utils.h",
    "settings.h", "driver/gpio.h", "driver/i2c_master.h", "driver/spi_master.h",
    "freertos/FreeRTOS.h", "freertos/semphr.h", "freertos/task.h",
)

with tempfile.TemporaryDirectory(prefix="pcm51xx-tests-") as temporary:
    build = Path(temporary)
    for name in SHIMS:
        shim = build / name
        shim.parent.mkdir(parents=True, exist_ok=True)
        shim.write_text('#include "mocks.h"\n')

    command = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=c11", "-Wall", "-Wextra", "-Werror", "-g",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(build), "-I", str(HERE),
        "-I", str(ROOT / "components/dac/include"),
        "-I", str(ROOT / "components/dac_pcm51xx"),
        "-I", str(ROOT / "components/boards"),
        "-I", str(ROOT / "components/boards/hifi-esp32-plus"),
        "-I", str(ROOT / "main"),
        str(HERE / "test.c"),
        str(ROOT / "components/dac/dac.c"),
        str(ROOT / "components/dac_pcm51xx/dac_pcm51xx.c"),
        str(ROOT / "components/boards/hifi-esp32-plus/board.c"),
        "-lm", "-o", str(build / "test"),
    ]
    for ethernet in (False, True):
        print(f"PCM512x host tests (Ethernet={ethernet})", flush=True)
        flags = ["-DCONFIG_ETH_W5500_ENABLED=1"] if ethernet else []
        subprocess.run(command + flags, check=True)
        subprocess.run([str(build / "test")], check=True)
