#!/usr/bin/env python3
"""Compile production audio logic for a host-only transition replay."""
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
HERE = pathlib.Path(__file__).resolve().parent
ARTIFACTS = ROOT / "artifacts" / "audio-transition"
ARTIFACTS.mkdir(parents=True, exist_ok=True)
EXE = ARTIFACTS / "replay"

sources = [
    HERE / "replay.c",
    *(ROOT / "main" / "audio" / name for name in (
        "audio_stream.c", "audio_engine_v2.c", "audio_timeline.c",
        "audio_scheduler.c", "audio_clock_map.c", "audio_epoch.c")),
]
subprocess.run([
    "cc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra",
    "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
    "-I", str(HERE / "shims"), "-I", str(ROOT / "main" / "audio"),
    *map(str, sources), "-lm", "-o", str(EXE),
], check=True)
subprocess.run([str(EXE), str(ARTIFACTS)], check=True)

results = {name: json.loads((ARTIFACTS / f"{name}.json").read_text())
           for name in ("gapless_minus_1088", "same_epoch_plus_2405",
                        "forced_slot_retry",
                        "stale_phase_reanchor", "stale_phase_reanchor_wrap",
                        "flush_all_stale",
                        "flush_after_anchor", "wrap_after_anchor")}
for name, counters in results.items():
    print(f"{name}: {counters}")

assert results["flush_all_stale"]["lower_gate_drops"] == 12
assert results["flush_all_stale"]["upper_gate_drops"] == 1
assert results["flush_all_stale"]["inserted"] == 0
assert results["flush_all_stale"]["recovery_rms"] == 0
assert results["flush_after_anchor"]["inserted"] >= 20
assert results["flush_after_anchor"]["first_usable_rtp"] == 2776599456 + 1024
assert results["flush_after_anchor"]["first_usable_rtp"] > 2776599456
assert results["flush_after_anchor"]["transition_rms"] > 1000
assert results["flush_after_anchor"]["recovery_rms"] > 1000
assert results["gapless_minus_1088"]["old_rms"] > 1000
assert results["gapless_minus_1088"]["recovery_rms"] > 1000
assert results["gapless_minus_1088"]["received"] == 585
assert results["gapless_minus_1088"]["admitted"] == 585
assert results["gapless_minus_1088"]["decoded"] == 585
assert results["gapless_minus_1088"]["inserted"] == 585
assert results["gapless_minus_1088"]["queue_drops"] == 0
assert results["gapless_minus_1088"]["max_pending_jobs"] == 12
assert results["gapless_minus_1088"]["reader_backpressure_guard_encounters"] > 0
assert results["gapless_minus_1088"]["post_start_zero_windows"] == 0, \
    "captured -1088 transition has a silent window after old audio starts"
assert results["gapless_minus_1088"]["transition_zero_run_frames"] <= 352, \
    "captured -1088 transition has more than one I2S quantum of silence"
assert results["forced_slot_retry"]["inserted"] == 2, \
    "producer did not retry after the occupied physical slot was released"
assert results["forced_slot_retry"]["insert_failures"] == 0
phase_2405 = results["same_epoch_plus_2405"]
assert phase_2405["old_rms"] > 1000
assert phase_2405["recovery_rms"] > 1000
assert phase_2405["received"] == phase_2405["admitted"] == 585
assert phase_2405["decoded"] == phase_2405["inserted"] == 585
assert phase_2405["insert_failures"] == 0
assert phase_2405["transition_zero_run_frames"] == 1381, \
    "+2405 synthetic input no longer reports its 1381-sample RTP hole"
wrapped = results["wrap_after_anchor"]
assert wrapped["first_usable_rtp"] == 0
assert wrapped["lower_gate_drops"] == 12
assert wrapped["received"] == 33
assert wrapped["admitted"] == wrapped["decoded"] == wrapped["inserted"] == 20
assert wrapped["recovery_rms"] > 1000
stale = results["stale_phase_reanchor"]
assert stale["first_usable_rtp"] == 1313964994 + 4 * 1024
if not stale["first_new_inserted"]:
    assert stale["received"] == stale["admitted"] == stale["decoded"] == 25
    assert stale["inserted"] == 24
    assert stale["continuation_packets"] == 0
    assert stale["nonzero_output_frames"] == 0
    raise AssertionError(
        "stale-phase reanchor: a valid above-anchor frame decoded but production "
        "timeline retained 24 stale old-phase blocks and rejected PCM after 6 s")
assert stale["continuation_packets"] == 64
assert stale["received"] == stale["admitted"] == stale["decoded"] == 89
assert stale["inserted"] == 89, "corrected stale-phase continuation lost PCM insertion"
assert stale["nonzero_output_frames"] > 0
assert stale["recovery_rms"] > 1000, "corrected stale-phase continuation stayed silent"
assert stale["initial_zero_windows"] <= 23, "recovery exceeded the configured 180 ms preroll"
assert stale["post_start_zero_windows"] == 0, "recovery has a silent window after audio starts"
stale_wrap = results["stale_phase_reanchor_wrap"]
assert stale_wrap["first_usable_rtp"] == 2048
assert stale_wrap["received"] == stale_wrap["admitted"] == stale_wrap["decoded"] == 89
assert stale_wrap["inserted"] == 89
assert stale_wrap["recovery_rms"] > 1000
assert stale_wrap["initial_zero_windows"] <= 23
assert stale_wrap["post_start_zero_windows"] == 0
print("audio transition replay assertions passed")
