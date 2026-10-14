#!/usr/bin/env python3
"""Check pinned 12.70 kernel and HV captures for handoff control-flow leads.

Offline only: this does not identify a safe patch site or enable a payload.
The console captures are deliberately kept outside this repository.
"""

import argparse
import hashlib
import struct
from pathlib import Path


KERNEL_SIZE = 0xD50000
KERNEL_SHA256 = "9d79abbbb4dec7e077d5c65031b84b38955306d0772a7007c675d6e27a446c61"
HV_BASE = 0x62820000
HV_SIZE = 0x30000
HV_SHA256 = "6b07a3cd4d41c29564c86d5335087de5383c6d24b52a14b53f5369da5c2ad910"

KERNEL_SIGNATURES = {
    "hv_mp_startup_call": (0xC9DFB0, "55 48 89 e5 53 48 89 d3 48 89 f1 b8 0f 00 00 00 89 fa 0f 01 d9 5b 5d c3"),
    "smp_rendezvous": (0xB8FBC0, "55 48 89 e5 49 89 c8 48 89 d1 48 89 f2 48 89 fe 48 8b 3d 51 06 1a 03 5d e9 a3 fd ff ff"),
    "smp_rendezvous_cpus": (0xB8F980, "55 48 89 e5 41 57 41 56 41 55 41 54 53 50"),
    "setup callback": (0xB8FAF7, "41 ff d4"),
    "action callback": (0xB8FB1C, "41 ff d7"),
    "teardown callback": (0xB8FB41, "41 ff d6"),
}

HV_SIGNATURES = {
    "dispatcher entry": (0x62846A00, "55 48 89 e5 41 57 41 56 41 55 41 54 53"),
    "VMCB EXITCODE load": (0x62846A31, "48 8b 4f 08 48 8b 41 70"),
    "RAX 0x17 telemetry bypass": (0x62846A6B, "48 3d 81 00 00 00 75 0a 48 83 b9 f8 05 00 00 17 74 4c"),
    "exit jump table": (0x62846AF2, "48 8d 05 03 47 00 00 48 63 0c 88 48 01 c1 ff e1"),
    "VMMCALL case": (0x62847175, "49 8b 46 08 80 b8 cb 04 00 00 00 0f 84 97 03 00 00"),
    "nested command dispatch": (0x628476B0, "4c 8b 80 f8 05 00 00 4d 8d 68 fc 49 83 fd 1c"),
}


def pinned_image(path: Path, size: int, digest: str) -> bytes:
    data = path.read_bytes()
    actual_digest = hashlib.sha256(data).hexdigest()
    if len(data) != size or actual_digest != digest:
        raise ValueError(
            f"{path}: capture differs from pinned image "
            f"(size=0x{len(data):x}, sha256={actual_digest})"
        )
    return data


def exact(data: bytes, offset: int, signature: str, label: str) -> None:
    expected = bytes.fromhex(signature)
    actual = data[offset : offset + len(expected)]
    if actual != expected:
        raise ValueError(f"{label}: bytes differ at image+0x{offset:x}")


def rel32(data: bytes, instruction: int, disp_at: int, length: int) -> int:
    return instruction + length + struct.unpack_from("<i", data, instruction + disp_at)[0]


def check_kernel(data: bytes) -> None:
    for label, (offset, signature) in KERNEL_SIGNATURES.items():
        exact(data, offset, signature, label)

    rendezvous = 0xB8FBC0
    if rel32(data, rendezvous + 0x10, 3, 7) != 0x3D30228:
        raise ValueError("smp_rendezvous CPU-set reference differs")
    if rel32(data, rendezvous + 0x18, 1, 5) != 0xB8F980:
        raise ValueError("smp_rendezvous tail-call differs")


def check_hv(data: bytes) -> None:
    for label, (address, signature) in HV_SIGNATURES.items():
        exact(data, address - HV_BASE, signature, label)

    # EXITCODE 0x81 indexes the table after subtracting its first code, 0x14.
    table = 0x6284B1FC
    slot = table - HV_BASE + (0x81 - 0x14) * 4
    target = table + struct.unpack_from("<i", data, slot)[0]
    if target != 0x62847175:
        raise ValueError(f"EXITCODE 0x81 target differs: 0x{target:x}")

    bypass = 0x62846A7B - HV_BASE
    if bypass + 2 + struct.unpack_from("<b", data, bypass + 1)[0] != 0x62846AC9 - HV_BASE:
        raise ValueError("guest RAX=0x17 telemetry bypass branch differs")
    case_branch = 0x62847180 - HV_BASE
    if rel32(data, case_branch, 2, 6) != 0x6284751D - HV_BASE:
        raise ValueError("VMMCALL case state branch differs")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel_text", type=Path)
    parser.add_argument("hv_code", type=Path)
    args = parser.parse_args()
    try:
        kernel = pinned_image(args.kernel_text, KERNEL_SIZE, KERNEL_SHA256)
        hv = pinned_image(args.hv_code, HV_SIZE, HV_SHA256)
        check_kernel(kernel)
        check_hv(hv)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    print("PASS pinned 12.70 kernel and HV capture hashes")
    print("PASS kernel: hv_mp_startup_call and smp_rendezvous callback path")
    print("PASS HV: VMCB EXITCODE 0x81 dispatches to PA 0x62847175")
    print("PASS HV: guest RAX=0x17 skips telemetry; VMMCALL case has a state branch")
    print("LIMIT offline control-flow evidence; no safe redirect or return path established")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
