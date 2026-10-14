#!/usr/bin/env python3
"""Check the rate a TAS58xx's filters are designed at, on the host.

Requires Python 3 and a C compiler; no ESP-IDF installation or hardware needed.
Run from any directory with: python3 tests/tas58xx_rate/run.py
"""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

with tempfile.TemporaryDirectory(prefix="tas58xx-rate-tests-") as temporary:
    build = Path(temporary)
    (build / "esp_err.h").write_text("typedef int esp_err_t;\n")

    command = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g", "-O1",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(build),
        "-I", str(ROOT / "components/dac_tas58xx"),
        str(HERE / "test.c"),
        str(ROOT / "components/dac_tas58xx/tas58xx_biquad.c"),
        "-lm", "-o", str(build / "test"),
    ]
    print("TAS58xx filter rate host tests", flush=True)
    subprocess.run(command, check=True)
    subprocess.run([str(build / "test")], check=True)
