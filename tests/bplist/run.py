#!/usr/bin/env python3
"""Check real AirPlay /info plists with an independent Unicode decoder.

Requires Python 3 and a C compiler; no ESP-IDF installation or hardware needed.
Run from any directory with: python3 tests/bplist/run.py
"""

import os
from pathlib import Path
import plistlib
import shlex
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

VALID_NAMES = (
    "", "AirPlay ESP32", "A" * 64, "Café", "客厅音箱", "Привет",
    "Room 🎵", "🎵" * 16, "音" * 16,
    "\u007f\u0080\u07ff\u0800\ud7ff\ue000\uffff\U00010000\U0010ffff",
)
INVALID_NAMES = (
    "80", "bf", "c0af", "c1bf", "c2", "c241", "c2ff",
    "e0", "e0a0", "e080af", "e1a041", "eda080", "edbfbf",
    "f0", "f090", "f09080", "f08080af", "f1908041", "f4908080",
    "f5808080", "f888808080", "fe", "ff",
)

with tempfile.TemporaryDirectory(prefix="bplist-tests-") as temporary:
    build = Path(temporary)
    # The unrelated SETUP builder calls this stream-mode classifier. The
    # /info builder itself has no platform dependencies and is compiled intact.
    (build / "audio_stream.h").write_text(
        "#include <stdbool.h>\n"
        "typedef int audio_stream_type_t;\n"
        "static inline bool audio_stream_uses_buffer(audio_stream_type_t type) {\n"
        "  return type == 103;\n"
        "}\n"
    )
    command = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g", "-O1",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(build), "-I", str(ROOT / "main/plist"),
        str(HERE / "test.c"), str(ROOT / "main/plist/bplist_builder.c"),
        "-o", str(build / "test"),
    ]
    print("Binary plist Unicode and capacity tests", flush=True)
    subprocess.run(command, check=True)
    for name in VALID_NAMES:
        result = subprocess.run(
            [str(build / "test"), name.encode("utf-8").hex()],
            check=True, stdout=subprocess.PIPE,
        )
        decoded = plistlib.loads(result.stdout)
        assert decoded["name"] == name, (name, decoded["name"])
        assert decoded["deviceid"] == "12:34:56:78:9A:BC"
    for encoded in INVALID_NAMES:
        result = subprocess.run(
            [str(build / "test"), encoded], capture_output=True,
        )
        assert result.returncode == 2 and not result.stdout, (
            encoded, result.returncode, result.stderr.decode(errors="replace")
        )
    print(
        f"PASS: {len(VALID_NAMES)} Unicode round-trips with every output capacity; "
        f"{len(INVALID_NAMES)} malformed UTF-8 sequences rejected"
    )
