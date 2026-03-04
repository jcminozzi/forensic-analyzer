"""
pe_parser.py — Windows PE (Portable Executable) header analysis
Manual implementation using struct — sem dependência de pefile
"""

import struct
from datetime import datetime
from typing import Optional


MACHINE_TYPES = {
    0x0000: "Unknown",
    0x014C: "x86 (i386)",
    0x0162: "MIPS R3000",
    0x0168: "MIPS R10000",
    0x01C0: "ARM",
    0x01F0: "PowerPC",
    0x0200: "Itanium (IA-64)",
    0x8664: "x64 (AMD64)",
    0xAA64: "ARM64 (AArch64)",
}

SUBSYSTEMS = {
    0:  "Unknown",
    1:  "Native (sem subsistema)",
    2:  "Windows GUI",
    3:  "Windows Console (CUI)",
    5:  "OS/2 Console",
    7:  "POSIX Console",
    9:  "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    13: "EFI ROM Image",
    14: "Xbox",
    16: "Windows Boot Application",
}

# DLL Characteristics flags
DLLCHAR_FLAGS = {
    0x0020: "HIGH_ENTROPY_VA (ASLR 64-bit)",
    0x0040: "DYNAMIC_BASE (ASLR)",
    0x0080: "FORCE_INTEGRITY",
    0x0100: "NX_COMPAT (DEP/NX)",
    0x0200: "NO_ISOLATION",
    0x0400: "NO_SEH",
    0x0800: "NO_BIND",
    0x1000: "APPCONTAINER",
    0x2000: "WDM_DRIVER",
    0x4000: "GUARD_CF (Control Flow Guard)",
    0x8000: "TERMINAL_SERVER_AWARE",
}

# Characteristics flags
CHAR_FLAGS = {
    0x0001: "RELOCS_STRIPPED",
    0x0002: "EXECUTABLE_IMAGE",
    0x0004: "LINE_NUMS_STRIPPED",
    0x0008: "LOCAL_SYMS_STRIPPED",
    0x0200: "DEBUG_STRIPPED (symbols removed)",
    0x1000: "SYSTEM (driver/kernel)",
    0x2000: "DLL",
    0x4000: "UP_SYSTEM_ONLY",
}

SUSPICIOUS_SECTIONS = {".upx0", ".upx1", ".upx2", "upx0", "upx1",
                       ".aspack", ".adata", ".vmp0", ".vmp1", ".themida",
                       ".nsp0", ".nsp1", ".petite", "pebundle"}


def parse(data: bytes) -> Optional[dict]:
    try:
        if data[:2] != b'MZ':
            return None

        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 24 > len(data):
            return None

        sig = data[pe_offset:pe_offset+4]
        if sig != b'PE\x00\x00':
            return None

        # COFF Header
        machine       = struct.unpack_from("<H", data, pe_offset + 4)[0]
        num_sections  = struct.unpack_from("<H", data, pe_offset + 6)[0]
        timestamp_raw = struct.unpack_from("<I", data, pe_offset + 8)[0]
        opt_hdr_size  = struct.unpack_from("<H", data, pe_offset + 20)[0]
        characteristics = struct.unpack_from("<H", data, pe_offset + 22)[0]

        # Optional Header
        opt_off = pe_offset + 24
        magic = struct.unpack_from("<H", data, opt_off)[0] if opt_off + 2 <= len(data) else 0
        is_64 = (magic == 0x20B)

        subsystem  = 0
        dll_chars  = 0
        image_base = 0
        ep_rva     = 0

        if opt_off + 4 <= len(data):
            ep_rva = struct.unpack_from("<I", data, opt_off + 16)[0]

        if is_64:
            if opt_off + 72 <= len(data):
                subsystem = struct.unpack_from("<H", data, opt_off + 68)[0]
                dll_chars = struct.unpack_from("<H", data, opt_off + 70)[0]
            if opt_off + 32 <= len(data):
                image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
        else:
            if opt_off + 72 <= len(data):
                subsystem = struct.unpack_from("<H", data, opt_off + 68)[0]
                dll_chars = struct.unpack_from("<H", data, opt_off + 70)[0]
            if opt_off + 32 <= len(data):
                image_base = struct.unpack_from("<I", data, opt_off + 28)[0]

        # Sections
        sec_table_off = opt_off + opt_hdr_size
        sections = []
        for i in range(min(num_sections, 24)):
            s_off = sec_table_off + i * 40
            if s_off + 40 > len(data):
                break
            name_bytes = data[s_off:s_off+8]
            name = name_bytes.rstrip(b'\x00').decode('latin-1', errors='replace')
            vsize     = struct.unpack_from("<I", data, s_off + 8)[0]
            raw_size  = struct.unpack_from("<I", data, s_off + 16)[0]
            flags     = struct.unpack_from("<I", data, s_off + 36)[0]
            sections.append({
                "name": name,
                "virtual_size": vsize,
                "raw_size": raw_size,
                "exec": bool(flags & 0x20000000),
                "write": bool(flags & 0x80000000),
            })

        # Compiled timestamp
        compiled_at = datetime.utcfromtimestamp(timestamp_raw)
        now = datetime.utcnow()
        ts_future = compiled_at > now
        ts_old    = compiled_at.year < 1995
        ts_epoch  = timestamp_raw == 0

        # Flags breakdown
        char_flags_list = [label for bit, label in CHAR_FLAGS.items() if characteristics & bit]
        dll_flags_list  = [label for bit, label in DLLCHAR_FLAGS.items() if dll_chars & bit]

        # Security mitigations
        has_aslr  = bool(dll_chars & 0x0040)
        has_nx    = bool(dll_chars & 0x0100)
        has_cfg   = bool(dll_chars & 0x4000)
        has_seh   = not bool(dll_chars & 0x0400)
        is_dll    = bool(characteristics & 0x2000)
        is_driver = bool(characteristics & 0x1000)
        is_stripped = bool(characteristics & 0x0200)

        # Suspicious sections
        susp_secs = [s["name"] for s in sections if s["name"].lower() in SUSPICIOUS_SECTIONS]

        # Writable+executable sections (common in injectors)
        wx_secs = [s["name"] for s in sections if s["exec"] and s["write"]]

        return {
            "arch":         MACHINE_TYPES.get(machine, f"0x{machine:04X}"),
            "num_sections": num_sections,
            "timestamp_raw": timestamp_raw,
            "compiled_at":  compiled_at.strftime("%d/%m/%Y %H:%M:%S UTC"),
            "ts_future":    ts_future,
            "ts_old":       ts_old,
            "ts_epoch":     ts_epoch,
            "is_64":        is_64,
            "is_dll":       is_dll,
            "is_driver":    is_driver,
            "is_stripped":  is_stripped,
            "subsystem":    SUBSYSTEMS.get(subsystem, f"0x{subsystem:02X}"),
            "image_base":   f"0x{image_base:016X}" if is_64 else f"0x{image_base:08X}",
            "entry_point":  f"0x{ep_rva:08X}",
            "has_aslr":     has_aslr,
            "has_nx":       has_nx,
            "has_cfg":      has_cfg,
            "has_seh":      has_seh,
            "sections":     sections,
            "susp_sections":susp_secs,
            "wx_sections":  wx_secs,
            "char_flags":   char_flags_list,
            "dll_flags":    dll_flags_list,
        }

    except Exception:
        return None
