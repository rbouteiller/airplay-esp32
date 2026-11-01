#!/usr/bin/env python3
"""Run the per-output delay on the host, with 16- and 32-bit output words.

Requires Python 3 and a C compiler; no ESP-IDF installation or hardware needed.
Run from any directory with: python3 tests/audio_delay/run.py
"""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

with tempfile.TemporaryDirectory(prefix="audio-delay-tests-") as temporary:
    build = Path(temporary)
    print("Per-output delay host tests", flush=True)
    for words, define in (("16-bit", None), ("32-bit", "CONFIG_I2S_32BIT_OUTPUT")):
        (build / "sdkconfig.h").write_text(
            f"#define {define} 1\n" if define else "")
        binary = build / f"test-{words}"
        command = shlex.split(os.environ.get("CC", "cc")) + [
            "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g", "-O1",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            "-I", str(build), "-I", str(ROOT / "main/audio"),
            str(HERE / "test.c"), str(ROOT / "main/audio/audio_delay.c"),
            "-o", str(binary),
        ]
        print(f"-- {words} words", flush=True)
        subprocess.run(command, check=True)
        subprocess.run([str(binary)], check=True)
