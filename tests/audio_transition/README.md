# Host AirPlay transition replay

Run `python3 tests/audio_transition/run.py` from the repository root. The script
compiles production RTP admission, buffered decode handoff, engine, timeline,
scheduler, clock map and epoch for the host. It writes stereo PCM16 WAV and
JSON counters under `artifacts/audio-transition/` and checks insertion,
admission, RTP wrap, phase transitions, and rendered PCM.

The captured RTP step is `-1088` at `1313964994`; the captured pause/flush
anchor is `2776599456`. Packet bytes are unavailable. The decoder uses a
deterministic stereo waveform, and every surrounding packet time is synthetic.

The `gapless_minus_1088` replay starts with 185 old-phase frames and feeds 400
new-phase frames at 1024 samples each. A cooperative TCP reader stops reading
when either the modeled decode queue reaches the production near-full limit of
12 jobs or the production PCM timeline reports nearly full. All 585 packets
are retained, decoded and inserted after the playback floor advances from the
timeline read cursor. The pre-follow-up production path inserted 581/585 and
left 10 fully silent 352-sample windows in this early-wake replay. The corrected
path inserts 585/585 and has no fully silent 352-sample callback. Sample-level
inspection still finds a 288-frame (6.53 ms) zero run where the final old-track
render quantum drains before the blocked new-phase producer resumes. This is a
short modeled boundary concealment, not sample-perfect continuity or evidence
that the physical speaker's longer silence was reproduced. The 400-frame
continuation crosses the 192-slot ring twice. The
`reader_backpressure_guard_encounters` field counts observations of the
near-full guard in this synthetic loop, not elapsed wait windows.

`forced_slot_retry` marks the target ring slot occupied while other ring slots
remain free, then clears that flag and signals the semaphore during the wait.
This checks that `audio_engine_v2_push_pcm_wait()` retries after a failed
reservation instead of dropping the decoded frame. It is a focused retry test;
it does not run a concurrent timeline reader or verify its ownership release.

The `same_epoch_plus_2405` replay keeps the same outgoing content and changes
the next track's first RTP to 2405 samples after the last outgoing start. It
checks that all outgoing and incoming frames insert and both portions render.
That synthetic schedule leaves `2405 - 1024 = 1381` RTP samples (31.3 ms)
between the final outgoing block and the first incoming block; its corresponding
1381-frame zero run is expected from this input.

The `stale_phase_reanchor` replay models a distinct pause/resume without an
immediate flush: 24 old-phase blocks remain in the timeline, a new anchor
places the playout target beyond them, and an above-anchor new-phase packet is
accepted and decoded. Without the correction, production
`audio_timeline_phase_blocked()` keeps the decoded packet waiting because
those 24 blocks still occupy the timeline. The original scheduler preroll did
not trim them at this occupancy. The 6 s decode push timeout then dropped the
packet. This no-flush clock jump is a synthetic hypothesis tied to the
captured 24-block level, not an observed RTP
trace from the physical speaker. The baseline replay stops on that first
failed insertion, so it never repeats a six-second timeout. Once the first
new packet inserts, the same runner feeds 64 more above-anchor frames, renders
through normal preroll, and requires all 89 attempted packets to insert with
nonzero recovery RMS. JSON records which path ran as `first_new_inserted` and
`continuation_packets`. `initial_zero_windows` is bounded by the configured
180 ms preroll (23 render windows at 352 samples), and
`post_start_zero_windows` must be zero for this recovered run.
`stale_phase_reanchor_wrap` repeats this condition with the old blocks before
32-bit RTP wrap and the new phase after it, exercising the same trim path.

The two `flush_*` scenarios model PAUSE, immediate FLUSHBUFFERED, anchor,
stale lower/upper RTP packets, and a passing continuation whose first usable
RTP timestamp is strictly above the anchor (`anchor + 1024`). The passing
WAV begins with three silent 352-sample render windows while the output clock
advances to that frame. `wrap_after_anchor` repeats the passing case across
32-bit RTP wrap, with the first usable timestamp at zero.

`rendered_samples` is the production scheduler's advanced sample count and can
include concealed samples. `nonzero_output_frames`, RMS and zero-output
windows are measured from the emitted WAV. JSON also records the longest
sample-level all-channel zero run for the whole output and transition interval.
Host FreeRTOS/ESP shims provide memory, virtual time, semaphore and logging
behavior; the consumer runs synchronously from the producer's semaphore wait.
No device or playback/control API is called.
