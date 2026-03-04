"""
file_info.py — Hashes, magic bytes, file type detection, entropy, timestamps
"""

import hashlib
import math
import os
import struct
from datetime import datetime
from pathlib import Path
from typing import Optional


# ── Magic byte signatures ─────────────────────────────────────────────────────
MAGIC_SIGNATURES = [
    (b'\x25\x50\x44\x46',        "PDF",   "PDF Document",                  "📄"),
    (b'\x50\x4B\x03\x04',        "ZIP",   "ZIP / Office Open XML",         "📦"),
    (b'\x50\x4B\x05\x06',        "ZIP",   "ZIP (empty)",                   "📦"),
    (b'\x4D\x5A',                "PE",    "Windows Executable (PE/MZ)",    "⚙️"),
    (b'\xD0\xCF\x11\xE0',        "OLE",   "Microsoft Office OLE2",         "📊"),
    (b'\x7F\x45\x4C\x46',        "ELF",   "Linux/Unix Executable (ELF)",   "🐧"),
    (b'\xCA\xFE\xBA\xBE',        "JAR",   "Java Class / JAR",              "☕"),
    (b'\x1F\x8B\x08',            "GZ",    "GZIP Archive",                  "🗜️"),
    (b'\x52\x61\x72\x21\x1A\x07',"RAR",   "RAR Archive",                  "🗜️"),
    (b'\xFF\xD8\xFF',            "JPG",   "JPEG Image",                    "🖼️"),
    (b'\x89\x50\x4E\x47',        "PNG",   "PNG Image",                     "🖼️"),
    (b'\x47\x49\x46\x38',        "GIF",   "GIF Image",                     "🖼️"),
    (b'\x25\x21\x50\x53',        "PS",    "PostScript Document",           "📜"),
    (b'\x7B\x5C\x72\x74\x66',    "RTF",   "Rich Text Format",              "📝"),
    (b'\x37\x7A\xBC\xAF\x27\x1C',"7Z",   "7-Zip Archive",                 "🗜️"),
    (b'\x42\x5A\x68',            "BZ2",   "BZip2 Archive",                 "🗜️"),
    (b'\x4F\x67\x67\x53',        "OGG",   "OGG Media",                     "🎵"),
    (b'\x49\x44\x33',            "MP3",   "MP3 Audio",                     "🎵"),
]

EXT_MAP = {
    "pdf":  ("PDF",    "PDF Document",                 "📄"),
    "exe":  ("PE",     "Windows Executable",           "⚙️"),
    "dll":  ("PE",     "Windows DLL",                  "⚙️"),
    "sys":  ("PE",     "Windows Driver",               "⚙️"),
    "doc":  ("OLE",    "Word Document (legado)",        "📝"),
    "xls":  ("OLE",    "Excel Spreadsheet (legado)",   "📊"),
    "ppt":  ("OLE",    "PowerPoint (legado)",          "📊"),
    "docx": ("ZIP",    "Word Document (OOXML)",         "📝"),
    "xlsx": ("ZIP",    "Excel Spreadsheet (OOXML)",    "📊"),
    "pptx": ("ZIP",    "PowerPoint (OOXML)",            "📊"),
    "jar":  ("ZIP",    "Java Archive (JAR)",            "☕"),
    "apk":  ("ZIP",    "Android APK",                  "📱"),
    "zip":  ("ZIP",    "ZIP Archive",                  "📦"),
    "rar":  ("RAR",    "RAR Archive",                  "🗜️"),
    "gz":   ("GZ",     "GZIP Archive",                 "🗜️"),
    "py":   ("TEXT",   "Python Script",                "🐍"),
    "js":   ("SCRIPT", "JavaScript",                   "⚠️"),
    "vbs":  ("SCRIPT", "VBScript",                     "⚠️"),
    "ps1":  ("SCRIPT", "PowerShell Script",            "⚠️"),
    "bat":  ("SCRIPT", "Batch Script",                 "⚠️"),
    "cmd":  ("SCRIPT", "Command Script",               "⚠️"),
    "hta":  ("SCRIPT", "HTML Application",             "⚠️"),
    "wsf":  ("SCRIPT", "Windows Script File",          "⚠️"),
    "scr":  ("PE",     "Windows Screensaver (exec)",   "⚠️"),
}

EXEC_EXTS   = {"exe","bat","cmd","vbs","js","ps1","jar","scr","pif","com","reg","msi","hta","wsf","dll"}
MACRO_EXTS  = {"doc","docm","xls","xlsm","ppt","pptm","xlam","dotm"}


def compute_hashes(data: bytes) -> dict:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    e = 0.0
    n = len(data)
    for f in freq:
        if f:
            p = f / n
            e -= p * math.log2(p)
    return e


def entropy_label(e: float) -> tuple[str, str]:
    """Returns (label, severity)"""
    if e > 7.5:
        return "MUITO ALTA — possível cifrado/packed", "HIGH"
    elif e > 7.0:
        return "ELEVADA — possível compressão/ofuscação", "MED"
    elif e > 5.0:
        return "NORMAL — executável/binário típico", "PASS"
    else:
        return "BAIXA — texto ou dados estruturados", "INFO"


def detect_type(data: bytes, filename: str) -> dict:
    ext = Path(filename).suffix.lstrip(".").lower()

    # Magic bytes first
    for magic, ftype, label, icon in MAGIC_SIGNATURES:
        if data[:len(magic)] == magic:
            ext_mismatch = False
            expected_by_ext = EXT_MAP.get(ext, (None,))[0]
            if expected_by_ext and expected_by_ext != ftype:
                ext_mismatch = True
            return {
                "type": ftype, "label": label, "icon": icon,
                "ext": ext, "detected_by": "magic_bytes",
                "ext_mismatch": ext_mismatch,
                "expected_ext_type": expected_by_ext,
            }

    # Fallback to extension
    if ext in EXT_MAP:
        t, l, i = EXT_MAP[ext]
        return {"type": t, "label": l, "icon": i, "ext": ext, "detected_by": "extension", "ext_mismatch": False}

    return {"type": "UNKNOWN", "label": f"Tipo desconhecido (.{ext or '?'})", "icon": "📁",
            "ext": ext, "detected_by": "unknown", "ext_mismatch": False}


def hex_dump(data: bytes, n: int = 128) -> str:
    data = data[:n]
    lines = []
    for i in range(0, len(data), 16):
        row = data[i:i+16]
        offset = f"{i:04X}"
        hex_part = " ".join(f"{b:02X}" for b in row).ljust(47)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"  {offset}  {hex_part}  {ascii_part}")
    return "\n".join(lines)


def get_file_times(path: str) -> dict:
    stat = os.stat(path)
    times = {
        "modificado": datetime.fromtimestamp(stat.st_mtime).strftime("%d/%m/%Y %H:%M:%S"),
        "acessado":   datetime.fromtimestamp(stat.st_atime).strftime("%d/%m/%Y %H:%M:%S"),
    }
    # ctime = creation on Windows, metadata change on Linux
    try:
        times["criado"] = datetime.fromtimestamp(stat.st_birthtime).strftime("%d/%m/%Y %H:%M:%S")
    except AttributeError:
        times["criado"] = datetime.fromtimestamp(stat.st_ctime).strftime("%d/%m/%Y %H:%M:%S")
    return times


def format_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.2f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.2f} PB"
