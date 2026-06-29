#!/usr/bin/env python3
"""Convert an ELF virtual address to a file offset via PT_LOAD segments.

Usage: va_to_offset.py <elf-binary> <va-hex>

Prints the file offset as a hex string, or exits non-zero if not found.
"""
import sys
import struct


def va_to_file_offset(path: str, va: int) -> int | None:
    with open(path, "rb") as f:
        ident = f.read(16)
        if ident[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        bits = 64 if ident[4] == 2 else 32

        f.seek(0)
        if bits == 64:
            hdr = f.read(64)
            e_phoff     = struct.unpack_from("<Q", hdr, 32)[0]
            e_phentsize = struct.unpack_from("<H", hdr, 54)[0]
            e_phnum     = struct.unpack_from("<H", hdr, 56)[0]
            f.seek(e_phoff)
            for _ in range(e_phnum):
                ph = f.read(e_phentsize)
                p_type   = struct.unpack_from("<I", ph,  0)[0]
                p_offset = struct.unpack_from("<Q", ph,  8)[0]
                p_vaddr  = struct.unpack_from("<Q", ph, 16)[0]
                p_filesz = struct.unpack_from("<Q", ph, 40)[0]
                if p_type == 1 and p_vaddr <= va < p_vaddr + p_filesz:
                    return p_offset + (va - p_vaddr)
        else:
            hdr = f.read(52)
            e_phoff     = struct.unpack_from("<I", hdr, 28)[0]
            e_phentsize = struct.unpack_from("<H", hdr, 42)[0]
            e_phnum     = struct.unpack_from("<H", hdr, 44)[0]
            f.seek(e_phoff)
            for _ in range(e_phnum):
                ph = f.read(e_phentsize)
                p_type   = struct.unpack_from("<I", ph,  0)[0]
                p_offset = struct.unpack_from("<I", ph,  4)[0]
                p_vaddr  = struct.unpack_from("<I", ph,  8)[0]
                p_filesz = struct.unpack_from("<I", ph, 16)[0]
                if p_type == 1 and p_vaddr <= va < p_vaddr + p_filesz:
                    return p_offset + (va - p_vaddr)
    return None


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <elf-binary> <va-hex>", file=sys.stderr)
        sys.exit(1)
    path = sys.argv[1]
    va = int(sys.argv[2], 16)
    off = va_to_file_offset(path, va)
    if off is None:
        print(f"VA 0x{va:x} not found in any PT_LOAD segment", file=sys.stderr)
        sys.exit(1)
    print(hex(off))
