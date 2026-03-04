"""
pdf_parser.py — PDF deep analysis: metadata, JS, auto-actions, URLs, embedded files
Uses raw byte parsing + pdfplumber for text extraction
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import pdfplumber
    HAS_PDFPLUMBER = True
except ImportError:
    HAS_PDFPLUMBER = False


# Ferramentas/geradores de PDF que são usados em fraudes
SUSPICIOUS_PRODUCERS = [
    r"fpdf", r"tcpdf", r"reportlab", r"ghostscript", r"mupdf",
    r"online.{0,10}pdf", r"pdf.{0,10}online", r"ilovepdf", r"smallpdf",
    r"html2pdf", r"wkhtmltopdf", r"phantomjs", r"weasyprint",
    r"libreoffice.{0,5}writer", r"openoffice", r"pdf24", r"pdfescape",
    r"nitro", r"pdfcreator", r"cutepdf", r"dompdf",
]


def _raw_get(text: str, key: str) -> str:
    """Extract /Key (value) from raw PDF text."""
    pattern = rf'/{key}\s*\(([^){{}}]{{0,400}})\)'
    m = re.search(pattern, text)
    if m:
        return m.group(1).replace("\\", "").strip()
    return ""


def _xmp_get(text: str, tag: str) -> str:
    m = re.search(rf'<(?:\w+:)?{tag}>([^<]{{0,200}})<', text, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def parse_pdf_date(d: str) -> str:
    """Convert PDF date D:YYYYMMDDHHmmSSOHH'mm' to readable string."""
    if not d:
        return ""
    d = re.sub(r'^D:', '', d).strip()
    try:
        yr = d[0:4]   or "????"
        mo = d[4:6]   or "??"
        dy = d[6:8]   or "??"
        hr = d[8:10]  or "00"
        mn = d[10:12] or "00"
        sc = d[12:14] or "00"
        tz = d[14:].replace("'", "").strip() or "UTC"
        if tz == "Z":
            tz = "UTC"
        return f"{dy}/{mo}/{yr} {hr}:{mn}:{sc} TZ={tz}"
    except Exception:
        return d


def analyze(path: str) -> dict:
    result = {
        "ok": False, "error": "",
        "version": "", "linearized": False,
        "title": "", "author": "", "subject": "", "keywords": "",
        "creator": "", "producer": "", "creation_date": "", "mod_date": "",
        "pages": 0,
        "js_count": 0, "aa_count": 0, "embedded_files": 0,
        "form_count": 0, "stream_count": 0, "obj_count": 0,
        "susp_strings": [], "susp_producer": False,
        "urls": [], "text_sample": "", "is_boleto": False, "boleto_code": "",
    }

    try:
        with open(path, "rb") as f:
            raw_bytes = f.read()
    except Exception as e:
        result["error"] = str(e)
        return result

    # Decode a working subset as latin-1 (handles binary safely)
    sample_size = min(len(raw_bytes), 600_000)
    text = raw_bytes[:sample_size].decode("latin-1", errors="replace")

    # PDF version
    vm = re.search(r'%PDF-(\d+\.\d+)', text)
    result["version"] = vm.group(1) if vm else "desconhecida"

    # Linearized
    result["linearized"] = bool(re.search(r'/Linearized', text))

    # Metadata from document catalog
    result["title"]      = _raw_get(text, "Title")    or _xmp_get(text, "title")
    result["author"]     = _raw_get(text, "Author")   or _xmp_get(text, "creator")
    result["subject"]    = _raw_get(text, "Subject")
    result["keywords"]   = _raw_get(text, "Keywords")
    result["creator"]    = _raw_get(text, "Creator")  or _xmp_get(text, "CreatorTool")
    result["producer"]   = _raw_get(text, "Producer")
    result["creation_date"] = parse_pdf_date(
        _raw_get(text, "CreationDate") or _xmp_get(text, "CreateDate")
    )
    result["mod_date"]   = parse_pdf_date(
        _raw_get(text, "ModDate") or _xmp_get(text, "ModifyDate")
    )

    # Suspicious producer
    prod = result["producer"].lower()
    result["susp_producer"] = any(re.search(p, prod) for p in SUSPICIOUS_PRODUCERS)

    # Risk indicators (counted in raw bytes)
    result["js_count"]       = len(re.findall(r'/JavaScript', text))
    result["aa_count"]       = len(re.findall(r'/AA|/OpenAction', text))
    result["embedded_files"] = len(re.findall(r'/EmbeddedFile', text))
    result["form_count"]     = len(re.findall(r'/AcroForm', text))
    result["stream_count"]   = len(re.findall(r'stream[\r\n]', text))
    result["obj_count"]      = len(re.findall(r'\d+ \d+ obj[\r\n ]', text))

    # Suspicious strings
    susp_patterns = [
        (r'/Launch',      "Ação /Launch — pode executar programa externo"),
        (r'/SubmitForm',  "Formulário com SubmitForm — envia dados para URL"),
        (r'/ImportData',  "ImportData — importa dados externos"),
        (r'cmd\.exe',     "Referência a cmd.exe"),
        (r'powershell',   "Referência a PowerShell"),
        (r'eval\(',       "Chamada eval() em JavaScript"),
        (r'unescape\(',   "unescape() — desofuscação JS"),
        (r'/RichMedia',   "RichMedia — pode conter Flash/executável"),
    ]
    for pattern, desc in susp_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            result["susp_strings"].append(desc)

    # URLs in raw text
    url_re = re.compile(r'https?://[^\s"\'<>)\]\x00-\x1f]+')
    result["urls"] = list(set(url_re.findall(text)))[:60]

    # pdfplumber: text extraction for boleto detection
    if HAS_PDFPLUMBER:
        try:
            with pdfplumber.open(path) as pdf:
                result["pages"] = len(pdf.pages)
                page_texts = []
                for page in pdf.pages[:6]:
                    try:
                        t = page.extract_text() or ""
                        page_texts.append(t)
                        # Also get hyperlinks
                        for ann in (page.annots or []):
                            uri = ann.get("uri") or ann.get("URI", "")
                            if uri and uri not in result["urls"]:
                                result["urls"].append(uri)
                    except Exception:
                        pass

                full_text = " ".join(page_texts)
                result["text_sample"] = full_text[:1500]

                boleto_kw = [
                    "boleto", "código de barras", "linha digitável", "vencimento",
                    "beneficiário", "cedente", "sacado", "nosso número",
                    "pagamento", "banco cobrador",
                ]
                result["is_boleto"] = any(kw in full_text.lower() for kw in boleto_kw)

                if result["is_boleto"]:
                    # Try to extract boleto code
                    patterns = [
                        r'\d{5}[.\s]\d{5}\s+\d{5}[.\s]\d{6}\s+\d{5}[.\s]\d{6}\s+\d\s+\d{14}',
                        r'\d{47,48}',
                    ]
                    for p in patterns:
                        m = re.search(p, full_text)
                        if m:
                            result["boleto_code"] = re.sub(r'[\s.]', '', m.group(0))
                            break
        except Exception as e:
            result["error"] = f"pdfplumber: {e}"

    result["ok"] = True
    return result
