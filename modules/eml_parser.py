"""
eml_parser.py — Análise forense de arquivos .eml
Detecta spoofing, verifica SPF/DKIM/DMARC, analisa cadeia de Received,
extrai anexos suspeitos, URLs e indicadores de comprometimento.
"""

import email
import email.policy
import re
import unicodedata
from email import message_from_bytes
from email.header import decode_header, make_header
from email.utils import parseaddr, getaddresses
from pathlib import Path
from typing import Optional
from datetime import datetime


# ── Extensões perigosas em anexos ────────────────────────────────────────────
DANGEROUS_EXTS = {
    "exe","bat","cmd","vbs","js","ps1","jar","scr","pif","com","reg",
    "msi","hta","wsf","dll","lnk","iso","img","docm","xlsm","pptm",
}

SUSPICIOUS_URL_RE = [
    re.compile(r'bit\.ly', re.I), re.compile(r'tinyurl', re.I),
    re.compile(r'goo\.gl', re.I), re.compile(r'cutt\.ly', re.I),
    re.compile(r'rb\.gy', re.I),  re.compile(r'is\.gd', re.I),
    re.compile(r'shorturl', re.I),re.compile(r'clck\.ru', re.I),
]

# Domínios de free email — útil para detectar impersonation corporativo
FREE_EMAIL_PROVIDERS = {
    "gmail.com","yahoo.com","hotmail.com","outlook.com","live.com",
    "icloud.com","protonmail.com","mail.com","aol.com","yandex.com",
    "tempmail.com","guerrillamail.com","mailinator.com","throwam.com",
    "10minutemail.com","trashmail.com","dispostable.com",
}

TEMP_EMAIL_PROVIDERS = {
    "tempmail.com","guerrillamail.com","mailinator.com","throwam.com",
    "10minutemail.com","trashmail.com","dispostable.com","yopmail.com",
    "sharklasers.com","guerrillamailblock.com","grr.la","spam4.me",
}


def _decode_header_str(h) -> str:
    """Decodifica header que pode estar em base64/quoted-printable."""
    if not h:
        return ""
    try:
        return str(make_header(decode_header(h)))
    except Exception:
        return str(h)


def _extract_domain(email_addr: str) -> str:
    _, addr = parseaddr(email_addr)
    if "@" in addr:
        return addr.split("@", 1)[1].lower().strip(">").strip()
    return ""


def _is_homograph(domain: str) -> list:
    """Detecta caracteres Unicode que imitam ASCII (ataques homógrafo)."""
    suspicious = []
    for ch in domain:
        if ord(ch) > 127:
            name = unicodedata.name(ch, "")
            suspicious.append(f"'{ch}' (U+{ord(ch):04X} — {name})")
    return suspicious


def _parse_received_chain(headers: list) -> list:
    """Extrai e ordeia a cadeia de Received headers (mais antigo → mais recente)."""
    chain = []
    ip_re = re.compile(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]')
    for h in reversed(headers):
        entry = {"raw": h, "ips": ip_re.findall(h)}
        # Tenta extrair from/by
        from_m = re.search(r'from\s+(\S+)', h, re.I)
        by_m   = re.search(r'by\s+(\S+)',   h, re.I)
        date_m = re.search(r';\s*(.+)$',    h)
        entry["from"] = from_m.group(1) if from_m else ""
        entry["by"]   = by_m.group(1)   if by_m   else ""
        entry["date"] = date_m.group(1).strip() if date_m else ""
        chain.append(entry)
    return chain


def _parse_auth_results(auth_str: str) -> dict:
    """Parse do header Authentication-Results."""
    result = {"spf": "none", "dkim": "none", "dmarc": "none", "raw": auth_str}
    if not auth_str:
        return result
    low = auth_str.lower()
    for proto in ("spf", "dkim", "dmarc"):
        # spf=pass, dkim=fail, etc.
        m = re.search(rf'{proto}=(\w+)', low)
        if m:
            result[proto] = m.group(1)
    return result


def _parse_spf_header(spf_str: str) -> str:
    """Lê o header Received-SPF."""
    if not spf_str:
        return "none"
    m = re.match(r'^\s*(\w+)', spf_str)
    return m.group(1).lower() if m else "none"


def _extract_urls(text: str) -> list:
    url_re = re.compile(r'https?://[^\s"\'<>)\]\x00-\x1f\\,]+')
    urls = list(set(u.rstrip(".,;)>") for u in url_re.findall(text)))
    return urls


def _get_body(msg) -> str:
    """Extrai texto do corpo do email (plain text preferencial)."""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain":
                try:
                    body += part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", errors="replace"
                    )
                except Exception:
                    pass
            elif ct == "text/html" and not body:
                try:
                    raw_html = part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", errors="replace"
                    )
                    # Strip tags
                    body += re.sub(r'<[^>]+>', ' ', raw_html)
                except Exception:
                    pass
    else:
        try:
            body = msg.get_payload(decode=True).decode(
                msg.get_content_charset() or "utf-8", errors="replace"
            )
        except Exception:
            pass
    return body


def _get_attachments(msg) -> list:
    """Lista todos os anexos com nome e tipo."""
    attachments = []
    for part in msg.walk():
        disp = part.get("Content-Disposition", "")
        if "attachment" in disp.lower() or part.get_filename():
            name = _decode_header_str(part.get_filename()) or "sem_nome"
            ext  = Path(name).suffix.lstrip(".").lower()
            size = 0
            try:
                payload = part.get_payload(decode=True)
                size = len(payload) if payload else 0
            except Exception:
                pass
            attachments.append({
                "name":      name,
                "ext":       ext,
                "size":      size,
                "is_danger": ext in DANGEROUS_EXTS,
                "content_type": part.get_content_type(),
            })
    return attachments


def _f(sev: str, desc: str) -> dict:
    return {"sev": sev, "desc": desc}


def analyze(path: str) -> dict:
    result = {
        "ok": False, "error": "",
        "subject": "", "date": "",
        "from_raw": "", "from_name": "", "from_addr": "", "from_domain": "",
        "reply_to": "", "return_path": "", "envelope_sender": "",
        "to": [], "cc": [],
        "message_id": "", "x_mailer": "", "x_originating_ip": "",
        "received_chain": [],
        "auth_results": {}, "spf": "none", "dkim": "none", "dmarc": "none",
        "received_spf": "none",
        "dkim_signature_present": False,
        "attachments": [], "urls": [], "body_sample": "",
        "findings": [],
    }

    try:
        with open(path, "rb") as f:
            raw = f.read()
    except Exception as e:
        result["error"] = str(e)
        return result

    try:
        msg = message_from_bytes(raw, policy=email.policy.compat32)
    except Exception as e:
        result["error"] = f"Erro ao parsear EML: {e}"
        return result

    # ── Headers básicos ───────────────────────────────────────────────────────
    result["subject"]  = _decode_header_str(msg.get("Subject", ""))
    result["date"]     = msg.get("Date", "")
    result["from_raw"] = msg.get("From", "")
    result["message_id"]   = msg.get("Message-ID", "")
    result["x_mailer"]     = msg.get("X-Mailer", "") or msg.get("User-Agent", "")
    result["x_originating_ip"] = msg.get("X-Originating-IP", "") or msg.get("X-Source-IP", "")

    # From parsing
    from_name, from_addr = parseaddr(_decode_header_str(result["from_raw"]))
    result["from_name"]   = from_name.strip()
    result["from_addr"]   = from_addr.lower().strip()
    result["from_domain"] = _extract_domain(from_addr)

    # Reply-To, Return-Path, Sender
    result["reply_to"]      = msg.get("Reply-To", "")
    result["return_path"]   = msg.get("Return-Path", "")
    result["envelope_sender"] = msg.get("X-Envelope-From", "") or msg.get("Envelope-From", "")

    # To / CC
    to_raw  = msg.get_all("To",  [])
    cc_raw  = msg.get_all("CC",  [])
    result["to"] = [addr for _, addr in getaddresses(to_raw)]
    result["cc"] = [addr for _, addr in getaddresses(cc_raw)]

    # ── Received chain ────────────────────────────────────────────────────────
    received = msg.get_all("Received") or []
    result["received_chain"] = _parse_received_chain(received)

    # ── Authentication ────────────────────────────────────────────────────────
    auth_raw = " ".join(msg.get_all("Authentication-Results") or [])
    result["auth_results"] = _parse_auth_results(auth_raw)
    result["spf"]   = result["auth_results"].get("spf",  "none")
    result["dkim"]  = result["auth_results"].get("dkim", "none")
    result["dmarc"] = result["auth_results"].get("dmarc","none")

    spf_hdr = msg.get("Received-SPF", "")
    result["received_spf"] = _parse_spf_header(spf_hdr)
    if result["spf"] == "none" and result["received_spf"] != "none":
        result["spf"] = result["received_spf"]

    result["dkim_signature_present"] = bool(msg.get("DKIM-Signature"))

    # ── Body & URLs ───────────────────────────────────────────────────────────
    body = _get_body(msg)
    result["body_sample"] = body[:2000]
    result["urls"] = _extract_urls(body)

    # ── Attachments ───────────────────────────────────────────────────────────
    result["attachments"] = _get_attachments(msg)

    # ── FINDINGS ──────────────────────────────────────────────────────────────
    findings = []
    from_domain  = result["from_domain"]
    reply_domain = _extract_domain(result["reply_to"])
    rpath_domain = _extract_domain(result["return_path"])

    # 1. SPF
    spf = result["spf"]
    if spf in ("fail", "hardfail", "softfail"):
        findings.append(_f("CRIT", f"SPF {spf.upper()} — o servidor que enviou NÃO está autorizado a enviar email pelo domínio '{from_domain}'. Forte indicador de spoofing."))
    elif spf == "none":
        findings.append(_f("MED", f"SPF não configurado ou não verificado para '{from_domain}'. Inconclusivo."))
    elif spf in ("pass", "neutral"):
        findings.append(_f("PASS", f"SPF {spf.upper()} — servidor autorizado pelo domínio."))

    # 2. DKIM
    if not result["dkim_signature_present"]:
        findings.append(_f("MED", "Sem assinatura DKIM no email — autenticidade da origem não verificável criptograficamente."))
    else:
        dkim = result["dkim"]
        if dkim in ("fail", "invalid", "permerror"):
            findings.append(_f("CRIT", f"DKIM {dkim.upper()} — assinatura criptográfica inválida. Email foi modificado em trânsito ou assinatura falsificada."))
        elif dkim == "none":
            findings.append(_f("LOW", "DKIM-Signature presente mas resultado não encontrado em Authentication-Results."))
        else:
            findings.append(_f("PASS", f"DKIM {dkim.upper()} — assinatura criptográfica válida."))

    # 3. DMARC
    dmarc = result["dmarc"]
    if dmarc in ("fail", "none"):
        findings.append(_f("HIGH" if dmarc == "fail" else "MED",
            f"DMARC {'FAIL' if dmarc == 'fail' else 'não verificado'} — "
            "política de autenticação não satisfeita. Email pode não ser do remetente declarado."))
    elif dmarc == "pass":
        findings.append(_f("PASS", "DMARC PASS — email alinhado com política do domínio."))

    # 4. From vs Reply-To mismatch
    if reply_domain and reply_domain != from_domain:
        findings.append(_f("HIGH",
            f"Reply-To em domínio diferente do From: "
            f"From='{from_domain}' Reply-To='{reply_domain}'. "
            "Respostas irão para um domínio diferente — técnica comum de phishing."))

    # 5. From vs Return-Path mismatch
    if rpath_domain and rpath_domain != from_domain:
        findings.append(_f("HIGH",
            f"Return-Path em domínio diferente do From: "
            f"From='{from_domain}' Return-Path='{rpath_domain}'. "
            "Envelope sender divergente indica spoofing do header From."))

    # 6. Display name spoofing
    fname = result["from_name"].lower()
    if from_domain:
        domain_root = from_domain.split(".")[-2] if "." in from_domain else from_domain
        trusted = ["banco", "bradesco", "itau", "santander", "caixa", "bb", "nubank",
                   "inter", "paypal", "microsoft", "google", "amazon", "apple",
                   "netflix", "mercadolivre", "ifood", "correios", "receita", "gov"]
        impersonated = [t for t in trusted if t in fname and t not in from_domain]
        if impersonated:
            findings.append(_f("CRIT",
                f"Display name spoofing detectado: nome '{result['from_name']}' "
                f"referencia '{', '.join(impersonated)}' mas o domínio real é '{from_domain}'. "
                "Técnica clássica de phishing."))

    # 7. Homograph attack
    if from_domain:
        homos = _is_homograph(from_domain)
        if homos:
            findings.append(_f("CRIT",
                f"Caracteres Unicode suspeitos no domínio remetente '{from_domain}': "
                + ", ".join(homos) + " — ataque homógrafo para simular domínio legítimo."))

    # 8. Free email masquerando como corporativo
    if from_domain in FREE_EMAIL_PROVIDERS and result["from_name"]:
        name_lower = result["from_name"].lower()
        if any(corp in name_lower for corp in ["suporte","noreply","no-reply","atendimento","financeiro","cobrança","banco","pagamento"]):
            findings.append(_f("HIGH",
                f"Email corporativo falso: remetente '{result['from_name']}' "
                f"usa provedor gratuito '{from_domain}'. Empresas legítimas usam domínio próprio."))

    # 9. Temp/disposable email
    if from_domain in TEMP_EMAIL_PROVIDERS:
        findings.append(_f("CRIT",
            f"Domínio de email temporário/descartável: '{from_domain}' — "
            "fortemente associado a spam, phishing e fraudes."))

    # 10. Sem Message-ID
    if not result["message_id"]:
        findings.append(_f("MED",
            "Sem header Message-ID — emails legítimos sempre possuem identificador único. "
            "Ausência indica geração manual ou ferramenta de spam."))

    # 11. Received chain inconsistency
    chain = result["received_chain"]
    if len(chain) == 0:
        findings.append(_f("MED", "Sem headers Received — email pode ter sido forjado localmente."))
    elif len(chain) == 1:
        findings.append(_f("LOW",
            "Apenas 1 hop no Received — email veio diretamente ou headers foram removidos."))

    # Primeiro IP da cadeia (onde o email entrou)
    first_hop_ips = chain[0]["ips"] if chain else []
    if first_hop_ips:
        findings.append(_f("INFO", f"IP de entrada (primeiro hop): {', '.join(first_hop_ips)}"))

    if result["x_originating_ip"]:
        findings.append(_f("INFO", f"X-Originating-IP: {result['x_originating_ip']}"))

    # 12. Anexos perigosos
    for att in result["attachments"]:
        if att["is_danger"]:
            findings.append(_f("CRIT",
                f"Anexo perigoso: '{att['name']}' (.{att['ext']}) — "
                f"tipo: {att['content_type']}. Extensão executável em anexo de email."))

    # 13. URLs suspeitas no corpo
    susp_urls = [u for u in result["urls"] if any(p.search(u) for p in SUSPICIOUS_URL_RE)]
    if susp_urls:
        findings.append(_f("HIGH",
            f"{len(susp_urls)} URL(s) de encurtador suspeito no corpo: "
            + ", ".join(susp_urls[:3])))

    # 14. URLs com IP direto (sem domínio)
    ip_url_re = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    ip_urls = [u for u in result["urls"] if ip_url_re.match(u)]
    if ip_urls:
        findings.append(_f("HIGH",
            f"URL(s) apontando para IP direto (sem domínio): "
            + ", ".join(ip_urls[:3]) + " — técnica usada para evadir filtros de domínio."))

    result["findings"] = findings
    result["ok"] = True
    return result
