#!/usr/bin/env python3
"""Check the /bq page draws the filters the TAS58xx firmware designs.

Requires Python 3, a C compiler and Node.js; no ESP-IDF installation or
hardware needed. Run from any directory with: python3 tests/bq_page/run.py
"""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

with tempfile.TemporaryDirectory(prefix="bq-page-tests-") as temporary:
    build = Path(temporary)
    (build / "esp_err.h").write_text("typedef int esp_err_t;\n")

    command = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g", "-O1",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(build),
        "-I", str(ROOT / "components/dac_tas58xx"),
        str(HERE / "designs.c"),
        str(ROOT / "components/dac_tas58xx/tas58xx_biquad.c"),
        "-lm", "-o", str(build / "designs"),
    ]
    print("/bq page curve against the firmware's designs", flush=True)
    subprocess.run(command, check=True)
    designs = subprocess.run([str(build / "designs")], check=True,
                             capture_output=True).stdout
    subprocess.run(["node", str(HERE / "page.js"),
                    str(ROOT / "data/www/bq.html")],
                   input=designs, check=True)
