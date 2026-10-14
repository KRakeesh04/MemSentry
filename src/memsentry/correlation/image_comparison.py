"""Conservative PE executable-section comparison, never a whole-image hash verdict.

Accepts an on-disk PE and its RVA-addressed mapped image, supplied read-only by an
adapter. Supports x86 HIGHLOW and x64 DIR64 relocations. Unsupported relocation
forms, truncated images, or unknown acquisition consistency fail explicitly.
IAT ranges and investigator-validated patches are excluded with recorded reasons.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any


class ImageComparisonError(ValueError):
    pass


def compare_pe_images(
    reference: bytes,
    mapped: bytes,
    *,
    loaded_base: int,
    reference_verified: bool,
    acquisition_consistent: bool,
    known_patches: tuple[tuple[int, int, str], ...] = (),
) -> dict[str, Any]:
    def unpack(fmt: str, data: bytes, offset: int) -> tuple[Any, ...]:
        try:
            return struct.unpack_from(fmt, data, offset)
        except (struct.error, ValueError) as exc:
            raise ImageComparisonError("Truncated PE data") from exc

    if reference[:2] != b"MZ" or mapped[:2] != b"MZ":
        raise ImageComparisonError("Both buffers must contain PE headers")
    pe = unpack("<I", reference, 0x3C)[0]
    if reference[pe : pe + 4] != b"PE\0\0":
        raise ImageComparisonError("Invalid PE signature")
    machine, count, stamp = unpack("<HHI", reference, pe + 4)
    if machine not in {0x14C, 0x8664} or not 1 <= count <= 96:
        raise ImageComparisonError("Unsupported PE architecture or section count")
    memory_pe = unpack("<I", mapped, 0x3C)[0]
    if mapped[memory_pe : memory_pe + 4] != b"PE\0\0" or unpack("<HHI", mapped, memory_pe + 4) != (
        machine,
        count,
        stamp,
    ):
        raise ImageComparisonError("Mapped headers do not identify the reference PE")
    optional_size = unpack("<H", reference, pe + 20)[0]
    optional = pe + 24
    magic = unpack("<H", reference, optional)[0]
    if (machine, magic) not in {(0x14C, 0x10B), (0x8664, 0x20B)}:
        raise ImageComparisonError("Unsupported PE optional header")
    x64 = magic == 0x20B
    preferred_base = unpack("<Q" if x64 else "<I", reference, optional + (24 if x64 else 28))[0]
    directory_offset = optional + (112 if x64 else 96)
    directory_count = unpack("<I", reference, optional + (108 if x64 else 92))[0]
    size_image = unpack("<I", reference, optional + 56)[0]
    if len(mapped) < size_image or not reference_verified or not acquisition_consistent:
        raise ImageComparisonError(
            "Complete mapped image, verified reference and consistent acquisition are required"
        )
    if optional_size < (112 if x64 else 96) + min(directory_count, 16) * 8:
        raise ImageComparisonError("Invalid data-directory bounds")
    sections: list[tuple[str, int, int, int, int, int]] = []
    for index in range(count):
        offset = optional + optional_size + 40 * index
        name = reference[offset : offset + 8].rstrip(b"\0").decode("ascii", errors="replace")
        virtual_size, rva, raw_size, raw_offset = unpack("<IIII", reference, offset + 8)
        flags = unpack("<I", reference, offset + 36)[0]
        if raw_offset + raw_size > len(reference) or rva + virtual_size > size_image:
            raise ImageComparisonError("Section exceeds image bounds")
        sections.append((name, rva, virtual_size, raw_offset, raw_size, flags))

    def disk_offset(rva: int, size: int) -> int:
        for _, base, _, raw, raw_size, _ in sections:
            if base <= rva and rva + size <= base + raw_size:
                return raw + rva - base
        raise ImageComparisonError("Directory is not backed by complete reference bytes")

    def directory(index: int) -> tuple[int, int]:
        if index >= directory_count:
            return 0, 0
        values = unpack("<II", reference, directory_offset + index * 8)
        return int(values[0]), int(values[1])

    # Compare a private bytearray copy, leaving both supplied evidence buffers intact.
    expected = bytearray(mapped[:size_image])
    for _, rva, virtual_size, raw, raw_size, _ in sections:
        length = min(virtual_size or raw_size, raw_size)
        expected[rva : rva + length] = reference[raw : raw + length]
    delta = loaded_base - preferred_base
    relocation_rva, relocation_size = directory(5)
    if delta and not relocation_size:
        raise ImageComparisonError("Relocated image has no usable base relocation directory")
    if relocation_size:
        start = disk_offset(relocation_rva, relocation_size)
        end = start + relocation_size
        cursor = start
        while cursor < end:
            page, block_size = unpack("<II", reference, cursor)
            if block_size < 8 or block_size % 2 or cursor + block_size > end:
                raise ImageComparisonError("Invalid relocation block")
            for offset in range(cursor + 8, cursor + block_size, 2):
                entry = unpack("<H", reference, offset)[0]
                kind, rva = entry >> 12, page + (entry & 0xFFF)
                if kind == 0:
                    continue
                width = 8 if kind == 10 and x64 else (4 if kind == 3 and not x64 else 0)
                if not width or rva + width > len(expected):
                    raise ImageComparisonError("Unsupported or out-of-range base relocation")
                original = int.from_bytes(
                    reference[disk_offset(rva, width) : disk_offset(rva, width) + width], "little"
                )
                expected[rva : rva + width] = ((original + delta) % (1 << (width * 8))).to_bytes(
                    width, "little"
                )
            cursor += block_size
    exclusions = list(known_patches)
    iat_rva, iat_size = directory(12)
    if iat_size:
        exclusions.append((iat_rva, iat_size, "PE import address table (loader resolved)"))
    for rva, size, reason in exclusions:
        if rva < 0 or size <= 0 or rva + size > size_image or not reason:
            raise ImageComparisonError("Invalid validated patch/exclusion range")
        expected[rva : rva + size] = mapped[rva : rva + size]
    mismatches: list[dict[str, Any]] = []
    mismatch_count = 0
    compared = 0
    for name, rva, virtual_size, raw, raw_size, flags in sections:
        if not flags & 0x20000000:
            continue
        length = min(virtual_size or raw_size, raw_size)
        compared += length
        for relative in range(length):
            address = rva + relative
            if expected[address] != mapped[address]:
                mismatch_count += 1
                if len(mismatches) < 256:
                    mismatches.append(
                        {
                            "section": name,
                            "rva": address,
                            "file_offset": raw + relative,
                            "virtual_address": loaded_base + address,
                            "expected": expected[address],
                            "observed": mapped[address],
                        }
                    )
    if not compared:
        raise ImageComparisonError("No file-backed executable section bytes available")
    return {
        "comparison_method": "pe_executable_sections_v1",
        "comparison_reliable": True,
        "relocations_accounted": True,
        "loader_changes_accounted": True,
        "unexplained_mismatch_count": mismatch_count,
        "mismatches": mismatches,
        "mismatches_truncated": mismatch_count > len(mismatches),
        "compared_bytes": compared,
        "exclusions": [
            {"rva": rva, "size": size, "reason": reason} for rva, size, reason in exclusions
        ],
        "reference_sha256": hashlib.sha256(reference).hexdigest(),
        "mapped_sha256": hashlib.sha256(mapped).hexdigest(),
        "loaded_base": loaded_base,
        "limitations": [
            "Executable file-backed sections only; unknown legitimate patches can remain unexplained."
        ],
    }
