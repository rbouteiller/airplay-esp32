#!/usr/bin/env python3
"""Check the output cursor (main/audio/audio_output_cursor.c) against a model
of ESP-IDF's I2S TX driver: does the depth the scheduler is given put every
frame where the DMA really plays it?

test.c models the driver (esp_driver_i2s/i2s_common.c, v6.1) frame by frame
and runs the playback task's write path through it for the I2S backend (8 x
256-frame descriptors) and the S/PDIF one (22 x 96, preloaded), at 32, 44.1
and 48 kHz: a writer starting 0..N+1 EOFs after the enable, continuous
writing, stalls of 500..3000 frames, task stop/restart after 5..100 ms, a
Bluetooth/USB sink handing the ring back, and EOFs landing in the middle of
cursor updates.  Every frame rendered after the last event must play within
2 frames of where the cursor said.

The same harness is then built against baseline/, the cursor logic the two
backends had before, to show what it catches: that build must fail.

Requires Python 3 and a C compiler; no ESP-IDF installation or hardware.
Run from any directory with: python3 tests/i2s_cursor/run.py
"""

import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CURSOR = ROOT / "main/audio/audio_output_cursor.c"

# Scenarios the old code must get wrong, or the harness has lost its teeth.
MUST_FAIL_OLD = (
    # The ring played ahead of the first write was never counted.
    ("i2s", "start 0..9 EOFs after enable", 44100),
    ("i2s", "continuous writing", 44100),
    ("i2s", "stop, restart after 20 ms", 44100),
    ("spdif", "start 0..23 EOFs after enable", 44100),
    ("spdif", "stall of 3000 frames", 44100),   # dry ring read as empty
)

LINE = re.compile(r"^(i2s|spdif)\s+(.+?)\s+(\d+) Hz: worst \|played - "
                  r"predicted\| =\s+(\d+) frames .* (ok|FAIL)$")


def build(build_dir, name, cursor_source):
    binary = build_dir / name
    command = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g", "-O1",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(ROOT / "main/audio"),
        str(HERE / "test.c"), str(cursor_source), "-o", str(binary),
    ]
    subprocess.run(command, check=True)
    return binary


def run(binary, backend):
    out = subprocess.run([str(binary), backend], capture_output=True,
                         text=True)
    results = {}
    notes = []
    for line in out.stdout.splitlines():
        match = LINE.match(line)
        if match:
            key = (match[1], match[2], int(match[3]))
            results[key] = (int(match[4]), match[5] == "ok")
        elif line.startswith("      ("):
            notes.append(line.strip())
    return out.returncode, results, notes, out.stdout


def main():
    print("I2S output cursor host tests", flush=True)
    ok = True
    with tempfile.TemporaryDirectory(prefix="i2s-cursor-tests-") as tmp:
        build_dir = Path(tmp)
        new = build(build_dir, "new", CURSOR)
        old = {"i2s": build(build_dir, "old_i2s", HERE / "baseline/old_i2s.c"),
               "spdif": build(build_dir, "old_spdif",
                              HERE / "baseline/old_spdif.c")}
        old_results = {}
        for backend in ("i2s", "spdif"):
            code, results, notes, raw = run(new, backend)
            _, before, _, _ = run(old[backend], backend)
            old_results.update(before)
            if not results:
                print(raw)
                ok = False
            print(f"-- {backend}: worst |played - predicted|, "
                  "frames (ms), now vs. before")
            for key, (worst, passed) in results.items():
                rate = key[2]
                was = before.get(key, (None, None))[0]
                was_text = ("" if was is None else
                            f"   before {was:5d} ({was * 1000 / rate:5.2f})")
                print(f"   {key[1]:30s} {rate:5d} Hz: {worst:3d} "
                      f"({worst * 1000 / rate:4.2f}){was_text}"
                      f"{'' if passed else '   FAIL'}")
            for note in notes[-1:]:
                print("  ", note)
            if code != 0 or not all(p for _, p in results.values()):
                ok = False
        for key in MUST_FAIL_OLD:
            if old_results.get(key, (0, True))[1]:
                print(f"the old cursor passed {key}: the harness no longer "
                      "reproduces what it got wrong")
                ok = False
    print("all passed" if ok else "FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
