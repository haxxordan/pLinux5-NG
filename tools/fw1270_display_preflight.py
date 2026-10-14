#!/usr/bin/env python3
"""Check two 12.70 MP3 display offsets in the pinned kernel-text capture.

This reads a workstation file only. It does not connect to a PS5 or establish
that the functions are safe to call after NPT clear.
"""

import argparse
import hashlib
from pathlib import Path


EXPECTED_SIZE = 0xD50000
EXPECTED_SHA256 = "9d79abbbb4dec7e077d5c65031b84b38955306d0772a7007c675d6e27a446c61"
INVOKE_SIGNATURE = bytes.fromhex(
    "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec 48 0a 00 00 48"
)
INIT_PREFIX = bytes.fromhex(
    "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 78 4c 8d 2d"
)


def occurrences(data: bytes, needle: bytes):
    pos = 0
    while (pos := data.find(needle, pos)) != -1:
        yield pos
        pos += 1


def rel32_target(data: bytes, pos: int, displacement_at: int, instruction_len: int):
    disp = int.from_bytes(
        data[pos + displacement_at : pos + displacement_at + 4],
        "little",
        signed=True,
    )
    return pos + instruction_len + disp


def check(data: bytes):
    invoke_hits = list(occurrences(data, INVOKE_SIGNATURE))
    if len(invoke_hits) != 1:
        raise ValueError(f"MP3_INVOKE signature has {len(invoke_hits)} matches")
    invoke = invoke_hits[0]

    # MP3_INVOKE checks its ready byte near entry. The 7-byte cmp includes
    # an immediate of one after the RIP-relative displacement.
    ready_checks = [
        pos
        for pos in occurrences(data[invoke : invoke + 0x80], b"\x80\x3d")
        if pos + 7 <= 0x80 and data[invoke + pos + 6] == 1
    ]
    ready_targets = {
        rel32_target(data, invoke + pos, 2, 7) for pos in ready_checks
    }
    if len(ready_targets) != 1:
        raise ValueError(f"expected one MP3 readiness check, got {ready_targets}")
    ready = ready_targets.pop()

    # A wrapper tail-jumps to the invoke function with a fixed command ID.
    wrappers = []
    for pos in occurrences(data, b"\xe9"):
        if pos < 6 or pos + 5 > len(data):
            continue
        if rel32_target(data, pos, 1, 5) != invoke:
            continue
        if data[pos - 6] != 0xBF or data[pos - 1] != 0x5D:
            raise ValueError(f"unexpected wrapper form at text+0x{pos:x}")
        command = int.from_bytes(data[pos - 5 : pos - 1], "little")
        wrappers.append((pos, command))
    if len(wrappers) != 16 or not {21, 22}.issubset({c for _, c in wrappers}):
        raise ValueError(f"MP3 command wrappers are incomplete: {wrappers}")
    if any(b[0] - a[0] != 0x20 for a, b in zip(wrappers, wrappers[1:])):
        raise ValueError("MP3 wrappers are not the expected 32-byte sequence")

    # The initializer is identified by its long 13.20-derived prologue,
    # followed later by a write of one to the same readiness byte.
    init_hits = list(occurrences(data, INIT_PREFIX))
    ready_writes = [
        pos
        for pos in occurrences(data, b"\xc6\x05")
        if pos + 7 <= len(data)
        and data[pos + 6] == 1
        and rel32_target(data, pos, 2, 7) == ready
    ]
    candidates = [
        init
        for init in init_hits
        if any(0 < write - init < 0x1000 for write in ready_writes)
    ]
    if len(candidates) != 1:
        raise ValueError(f"expected one MP3 initializer, got {candidates}")
    initializer = candidates[0]

    return invoke, initializer, ready, wrappers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="pinned 12.70 kernel-text .bin")
    args = parser.parse_args()
    data = args.image.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != EXPECTED_SIZE or digest != EXPECTED_SHA256:
        parser.error(
            f"capture does not match pinned 12.70 image: size=0x{len(data):x}, "
            f"sha256={digest}"
        )
    try:
        invoke, initializer, ready, wrappers = check(data)
    except ValueError as exc:
        parser.error(str(exc))
    print(f"capture: size=0x{len(data):x} sha256={digest}")
    print(f"FUN_MP3_INVOKE: text+0x{invoke:x} (offline candidate)")
    print(f"FUN_MP3_INITIALIZE: text+0x{initializer:x} (offline candidate)")
    print(f"readiness byte: text+0x{ready:x}")
    print(
        f"command wrappers: {len(wrappers)} at "
        f"text+0x{wrappers[0][0]:x}..0x{wrappers[-1][0]:x}; IDs 21, 22 present"
    )


if __name__ == "__main__":
    main()
