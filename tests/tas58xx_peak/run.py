#!/usr/bin/env python3
"""Check how far a TAS58xx biquad chain lifts a full-scale tone, on the host.

Requires Python 3 and a C compiler; no ESP-IDF installation or hardware needed.
Run from any directory with: python3 tests/tas58xx_peak/run.py
"""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

with tempfile.TemporaryDirectory(prefix="tas58xx-peak-tests-") as temporary:
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
    print("TAS58xx chain peak host tests", flush=True)
    subprocess.run(command, check=True)
    subprocess.run([str(build / "test")], check=True)
