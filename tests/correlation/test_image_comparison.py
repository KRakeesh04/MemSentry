"""Tiny synthetic PE byte buffers, never executed or loaded as programs."""

from __future__ import annotations

import struct

import pytest

from memsentry.correlation.image_comparison import ImageComparisonError, compare_pe_images


def synthetic_pe():
    disk = bytearray(0x600)
    disk[:2] = b"MZ"
    struct.pack_into("<I", disk, 0x3C, 0x80)
    disk[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHI", disk, 0x84, 0x14C, 2, 12345)
    struct.pack_into("<H", disk, 0x94, 224)
    optional = 0x98
    struct.pack_into("<H", disk, optional, 0x10B)
    struct.pack_into("<I", disk, optional + 28, 0x400000)
    struct.pack_into("<I", disk, optional + 56, 0x3000)
    struct.pack_into("<I", disk, optional + 92, 16)
    table = optional + 224
    for offset, name, rva, raw, flags in [
        (table, b".text", 0x1000, 0x200, 0x60000020),
        (table + 40, b".reloc", 0x2000, 0x400, 0x42000040),
    ]:
        disk[offset : offset + len(name)] = name
        struct.pack_into("<IIII", disk, offset + 8, 0x200, rva, 0x200, raw)
        struct.pack_into("<I", disk, offset + 36, flags)
    disk[0x200:0x400] = bytes([0x41]) * 0x200
    # One x86 relocation at RVA 0x1010, plus ABSOLUTE padding.
    struct.pack_into("<I", disk, 0x210, 0x401234)
    struct.pack_into("<II", disk, optional + 96 + 5 * 8, 0x2000, 12)
    struct.pack_into("<IIHH", disk, 0x400, 0x1000, 12, 0x3010, 0)
    memory = bytearray(0x3000)
    memory[:0x200] = disk[:0x200]
    memory[0x1000:0x1200] = disk[0x200:0x400]
    memory[0x2000:0x2200] = disk[0x400:0x600]
    return bytes(disk), memory


def compare(disk, memory, **options):
    return compare_pe_images(
        disk,
        bytes(memory),
        loaded_base=options.pop("loaded_base", 0x400000),
        reference_verified=True,
        acquisition_consistent=True,
        **options,
    )


def test_identical_and_relocated_code_are_not_mismatches():
    disk, memory = synthetic_pe()
    assert compare(disk, memory)["unexplained_mismatch_count"] == 0
    struct.pack_into("<I", memory, 0x1010, 0x501234)
    result = compare(disk, memory, loaded_base=0x500000)
    assert result["unexplained_mismatch_count"] == 0
    assert result["relocations_accounted"] is True


def test_executable_changes_preserve_offsets_and_buffers():
    disk, memory = synthetic_pe()
    memory[0x1050] = 0x42
    saved = bytes(memory)
    result = compare(disk, memory)
    assert result["unexplained_mismatch_count"] == 1
    assert result["mismatches"][0] == {
        "section": ".text",
        "rva": 0x1050,
        "file_offset": 0x250,
        "virtual_address": 0x401050,
        "expected": 0x41,
        "observed": 0x42,
    }
    assert bytes(memory) == saved
    assert (
        compare(disk, memory, known_patches=((0x1050, 1, "Synthetic validated hotpatch"),))[
            "unexplained_mismatch_count"
        ]
        == 0
    )


def test_import_address_table_loader_changes_are_accounted():
    disk, memory = synthetic_pe()
    reference = bytearray(disk)
    struct.pack_into("<II", reference, 0x98 + 96 + 12 * 8, 0x1080, 4)
    memory[0x1080:0x1084] = b"IAT!"
    result = compare(bytes(reference), memory)
    assert result["unexplained_mismatch_count"] == 0
    assert result["exclusions"][0]["reason"].startswith("PE import")


def test_incomplete_incompatible_or_unsupported_images_are_explicit():
    disk, memory = synthetic_pe()
    with pytest.raises(ImageComparisonError, match="Complete"):
        compare(disk, memory[:500])
    with pytest.raises(ImageComparisonError, match="identify"):
        memory[0x88] = 0xFF
        compare(disk, memory)
    with pytest.raises(ImageComparisonError):
        compare(b"NOT A PE", memory)
    with pytest.raises(ImageComparisonError, match="verified"):
        disk, memory = synthetic_pe()
        compare_pe_images(
            disk,
            bytes(memory),
            loaded_base=0x400000,
            reference_verified=False,
            acquisition_consistent=True,
        )
