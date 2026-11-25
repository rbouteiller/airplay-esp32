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
        str(ROOT / "main/plist/bplist_parser.c"),
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
        assert decoded["model"] == "airplay-esp32"
        assert decoded["statusFlags"] == 0x404
        assert decoded["pi"] == "1f0b0a39-6a4e-4d1c-9e5a-2b8f3c7d6e10"
        assert decoded["psi"] == "8c2d4e6f-0a1b-4c3d-8e5f-60718293a4b5"
    for encoded in INVALID_NAMES:
        result = subprocess.run(
            [str(build / "test"), encoded], capture_output=True,
        )
        assert result.returncode == 2 and not result.stdout, (
            encoded, result.returncode, result.stderr.decode(errors="replace")
        )

    # POST /configure response, decoded independently.
    result = subprocess.run([str(build / "test"), "configure"], check=True,
                            stdout=subprocess.PIPE)
    assert plistlib.loads(result.stdout) == {
        "Identifier": "1f0b0a39-6a4e-4d1c-9e5a-2b8f3c7d6e10",
        "Enable_HK_Access_Control": True,
        "PublicKey": bytes(range(32)),
        "Device_Name": "Café",
        "Access_Control_Level": 2,
    }

    # POST /configure requests, as the Home app might send them.
    def parse(body):
        result = subprocess.run([str(build / "test"), "parse-configure"],
                                input=body, check=True, stdout=subprocess.PIPE)
        return dict(line.split("=", 1)
                    for line in result.stdout.decode().splitlines())

    binary = plistlib.FMT_BINARY
    request = {"ConfigurationDictionary": {
        "Enable_HK_Access_Control": True, "Access_Control_Level": 1,
        "Device_Name": "Kitchen", "Password": "1234"}}
    assert parse(plistlib.dumps(request, fmt=binary)) == {
        "enable": "1", "level": "1", "password": "1234",
        "toplevel_name": "-"}
    request = {"ConfigurationDictionary": {
        "Enable_HK_Access_Control": False}, "Device_Name": "Top"}
    assert parse(plistlib.dumps(request, fmt=binary)) == {
        "enable": "0", "level": "-", "password": "-", "toplevel_name": "Top"}
    # Flags sent as integers still count.
    request = {"ConfigurationDictionary": {"Enable_HK_Access_Control": 1}}
    assert parse(plistlib.dumps(request, fmt=binary))["enable"] == "1"
    # Keys at the wrong level, wrong types and garbage find nothing.
    request = {"Enable_HK_Access_Control": True, "Access_Control_Level": 2}
    assert parse(plistlib.dumps(request, fmt=binary))["enable"] == "-"
    request = {"ConfigurationDictionary": [1, 2, 3]}
    assert parse(plistlib.dumps(request, fmt=binary))["enable"] == "-"
    request = {"ConfigurationDictionary": {"Access_Control_Level": "2"}}
    assert parse(plistlib.dumps(request, fmt=binary))["level"] == "-"
    garbage = bytearray(plistlib.dumps(
        {"ConfigurationDictionary": {"Access_Control_Level": 1}}, fmt=binary))
    garbage[-9] = 0xFF  # offset table points past the end
    assert parse(bytes(garbage))["level"] == "-"
    assert parse(b"bplist00" + b"\xff" * 40)["level"] == "-"
    print("PASS: /configure response and request parsing, every truncation")

    print(
        f"PASS: {len(VALID_NAMES)} Unicode round-trips with every output capacity; "
        f"{len(INVALID_NAMES)} malformed UTF-8 sequences rejected"
    )

    # AirPlay 2 remote control over the event channel: the NSKeyedArchiver of
    # the group UUID, the MediaRemote command and the volume notification,
    # in the shape Shairport Sync sends (remote/remote.c).
    command[command.index(str(HERE / "test.c"))] = str(HERE / "remote_test.c")
    command[-1] = str(build / "remote_test")
    print("Remote control plist tests", flush=True)
    subprocess.run(command, check=True)

    def remote(*args):
        result = subprocess.run(
            [str(build / "remote_test"), *map(str, args)],
            check=True, stdout=subprocess.PIPE,
        )
        return plistlib.loads(result.stdout)

    GROUP = "343F4AF7-9158-4466-AC59-250A1281FFD6"
    ARCHIVE = {
        "$version": 100000,
        "$archiver": "NSKeyedArchiver",
        "$top": {"root": plistlib.UID(1)},
        "$objects": [
            "$null",
            {"NS.objects": [plistlib.UID(2)], "$class": plistlib.UID(3)},
            GROUP,
            {"$classname": "NSMutableArray",
             "$classes": ["NSMutableArray", "NSArray", "NSObject"]},
        ],
    }
    assert remote("archive", GROUP) == ARCHIVE

    for number in (0, 1, 2, 3, 4, 5):
        decoded = remote("command", number, GROUP)
        params = decoded.pop("params")
        assert decoded == {"type": "sendMediaRemoteCommand",
                           "modernMediaRemoteCommand": str(number)}, decoded
        archive = params.pop("kMRMediaRemoteOptionDestinationDeviceUIDs")
        assert plistlib.loads(archive) == ARCHIVE
        assert params == {
            "kMRMediaRemoteOptionSendOptionsNumber": 0,
            "kMRMediaRemoteOptionCommandID":
                "11111111-2222-4333-8444-555555555555",
            "kMRMediaRemoteOptionIsRedirectingCommand": True,
        }, params

    for volume in (0.0, 0.42, 1.0):
        assert remote("volume", volume) == {
            "type": "sendMediaRemoteCommand", "value": "dvlc",
            "volume": volume, "params": {"volume": volume},
        }

    print("PASS: group archive, 6 MediaRemote commands and 3 volume "
          "notifications decode as expected with every output capacity")
