"""
zip_parser.py — ZIP/OOXML content listing
strings_extractor.py — IPs, URLs, emails from raw bytes
"""

import struct
import re
from typing import List, Dict


# ── ZIP ─────────────────────────────────────────────────────────────────────

EXEC_EXTS   = {"exe","bat","cmd","vbs","js","ps1","jar","scr","pif","com","reg","msi","hta","wsf","dll"}
MACRO_EXTS  = {"doc","docm","xls","xlsm","ppt","pptm","xlam","dotm"}


def parse_zip(data: bytes) -> List[Dict]:
    """Parse ZIP central directory to list files."""
    files = []
    i = 0
    # Scan for local file headers (PK\x03\x04)
    while i < len(data) - 30:
        if data[i:i+4] == b'PK\x03\x04':
            try:
                compress    = struct.unpack_from("<H", data, i + 8)[0]
                comp_size   = struct.unpack_from("<I", data, i + 18)[0]
                uncomp_size = struct.unpack_from("<I", data, i + 22)[0]
                name_len    = struct.unpack_from("<H", data, i + 26)[0]
                extra_len   = struct.unpack_from("<H", data, i + 28)[0]
                name_bytes  = data[i + 30 : i + 30 + name_len]
                try:
                    name = name_bytes.decode("utf-8", errors="replace")
                except Exception:
                    name = name_bytes.decode("latin-1", errors="replace")
                if name:
                    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
                    files.append({
                        "name":        name,
                        "comp_size":   comp_size,
                        "uncomp_size": uncomp_size,
                        "ext":         ext,
                        "is_exec":     ext in EXEC_EXTS,
                        "is_macro":    ext in MACRO_EXTS,
                        "compress":    compress,
                    })
                i += 30 + name_len + extra_len
                continue
            except Exception:
                pass
        i += 1
    return files


# ── STRINGS ─────────────────────────────────────────────────────────────────

# Regex patterns
IP_RE      = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
URL_RE     = re.compile(r'https?://[^\s"\'<>)\]\x00-\x1f\\,]+')
EMAIL_RE   = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}')
DOMAIN_RE  = re.compile(r'\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|br|io|gov|edu|info|biz|co)\b')

PRIVATE_IP = re.compile(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|255\.)')

SUSPICIOUS_URL_PATTERNS = [
    re.compile(r'bit\.ly', re.I),
    re.compile(r'tinyurl', re.I),
    re.compile(r'goo\.gl', re.I),
    re.compile(r'ow\.ly', re.I),
    re.compile(r'cutt\.ly', re.I),
    re.compile(r'rb\.gy', re.I),
    re.compile(r'is\.gd', re.I),
    re.compile(r'shorturl', re.I),
    re.compile(r'tiny\.cc', re.I),
    re.compile(r'clck\.ru', re.I),
    re.compile(r't\.co/?$', re.I),
]


def extract_strings(data: bytes) -> dict:
    text = data.decode("latin-1", errors="replace")

    all_ips   = list(set(IP_RE.findall(text)))
    all_urls  = list(set(u.rstrip(".,;)") for u in URL_RE.findall(text)))
    all_emails = list(set(EMAIL_RE.findall(text)))

    # Filter IPs
    private_ips = [ip for ip in all_ips if PRIVATE_IP.match(ip)]
    public_ips  = [ip for ip in all_ips if not PRIVATE_IP.match(ip)]

    # Flag suspicious URLs
    susp_urls = [u for u in all_urls if any(p.search(u) for p in SUSPICIOUS_URL_PATTERNS)]

    # Printable ASCII strings (min 6 chars, common malware IOC extraction)
    ascii_strings = _extract_ascii(data, min_len=6)

    return {
        "all_ips":     all_ips,
        "private_ips": private_ips,
        "public_ips":  public_ips,
        "urls":        all_urls[:80],
        "susp_urls":   susp_urls,
        "emails":      all_emails[:40],
        "ascii_strings": ascii_strings[:200],
    }


def _extract_ascii(data: bytes, min_len: int = 6) -> List[str]:
    """Extract printable ASCII strings from binary data."""
    result = []
    current = bytearray()
    for b in data:
        if 32 <= b < 127:
            current.append(b)
        else:
            if len(current) >= min_len:
                s = current.decode("ascii", errors="ignore").strip()
                if s and len(s) >= min_len:
                    result.append(s)
            current = bytearray()
    if len(current) >= min_len:
        result.append(current.decode("ascii", errors="ignore").strip())
    return result
