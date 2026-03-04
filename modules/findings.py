"""
findings.py — Engine de geração de findings e score de risco
"""

from modules.file_info import (
    EXEC_EXTS, MACRO_EXTS, shannon_entropy, entropy_label
)
import re

SEV_SCORE = {"CRIT": 45, "HIGH": 25, "MED": 12, "LOW": 4, "INFO": 0, "PASS": 0}

DOUBLE_EXT = re.compile(
    r'\.(jpg|pdf|txt|png|doc|xls|mp3|mp4)\.(exe|bat|cmd|vbs|scr|pif|js|ps1)$',
    re.IGNORECASE
)

SUSPICIOUS_URL_RE = [
    re.compile(r'bit\.ly', re.I), re.compile(r'tinyurl', re.I),
    re.compile(r'goo\.gl', re.I), re.compile(r'cutt\.ly', re.I),
    re.compile(r'rb\.gy', re.I),  re.compile(r'is\.gd', re.I),
    re.compile(r'shorturl', re.I),re.compile(r'clck\.ru', re.I),
]


def _f(sev: str, desc: str) -> dict:
    return {"sev": sev, "desc": desc}


def generate(file_info: dict, file_type: dict, entropy: float,
             strings: dict, pe: dict, zip_files: list,
             pdf_raw: dict, vt: dict) -> list:
    """
    Gera lista de findings com severidade baseada em todos os módulos.
    """
    findings = []

    # ── Extensão ──────────────────────────────────────────────────────────────
    ext = file_type.get("ext", "")

    if file_type.get("ext_mismatch"):
        findings.append(_f("CRIT",
            f"SPOOFING DE EXTENSÃO: extensão .{ext} mas assinatura de bytes indica "
            f"{file_type['type']} ({file_type['label']}). "
            "Técnica clássica para enganar usuários e bypassar filtros."))

    if DOUBLE_EXT.search(file_info.get("name", "")):
        findings.append(_f("CRIT",
            f"DUPLA EXTENSÃO detectada: '{file_info['name']}' — "
            "disfarça executáveis como documentos benignos."))

    if ext in EXEC_EXTS:
        findings.append(_f("HIGH",
            f"Extensão executável de risco: .{ext} — "
            "vetor comum de malware. Nunca execute sem verificar a origem."))

    if ext in MACRO_EXTS:
        findings.append(_f("HIGH",
            f"Formato com suporte a macros VBA: .{ext} — "
            "documentos com macros são vetor recorrente de trojans (Emotet, Qakbot, etc.)"))

    # ── Entropia ──────────────────────────────────────────────────────────────
    label, sev = entropy_label(entropy)
    if sev in ("HIGH", "MED"):
        findings.append(_f(sev,
            f"Entropia elevada: {entropy:.4f} bits — {label}. "
            "Binários legítimos raramente excedem 7.5 sem serem compressores."))

    # ── PE ────────────────────────────────────────────────────────────────────
    if pe:
        if pe.get("ts_future"):
            findings.append(_f("HIGH",
                f"Timestamp de compilação NO FUTURO: {pe['compiled_at']} — "
                "timestamp falsificado é indicativo claro de malware."))
        elif pe.get("ts_old"):
            findings.append(_f("MED",
                f"Timestamp de compilação muito antigo: {pe['compiled_at']} — "
                "pode indicar falsificação de timestamp ou software legado."))
        elif pe.get("ts_epoch"):
            findings.append(_f("MED",
                "Timestamp zero (Unix epoch) — binário compilado com timestamp zerado, "
                "técnica usada para dificultar análise forense."))

        if not pe.get("has_nx"):
            findings.append(_f("MED",
                "DEP/NX não habilitado — binário compilado sem Data Execution Prevention. "
                "Proteção básica ausente."))
        if not pe.get("has_aslr"):
            findings.append(_f("MED",
                "ASLR não habilitado — sem Address Space Layout Randomization, "
                "facilita exploração de memória."))

        for sec in pe.get("susp_sections", []):
            findings.append(_f("HIGH",
                f"Seção suspeita detectada: '{sec}' — "
                "indica uso de packer/protector (UPX, Themida, VMProtect, etc.)"))

        for sec in pe.get("wx_sections", []):
            findings.append(_f("HIGH",
                f"Seção '{sec}' é gravável E executável (W+X) — "
                "padrão comum em shellcode/injeção de código."))

        if pe.get("is_stripped"):
            findings.append(_f("LOW",
                "Símbolos de debug removidos (stripped) — "
                "comum em software legítimo de produção, mas também em malware."))

    # ── ZIP ───────────────────────────────────────────────────────────────────
    if zip_files:
        danger = [f for f in zip_files if f.get("is_exec")]
        macros = [f for f in zip_files if f.get("is_macro")]
        if danger:
            names = ", ".join(f["name"] for f in danger[:5])
            findings.append(_f("HIGH",
                f"{len(danger)} arquivo(s) executável(is) dentro do ZIP: {names}"))
        if macros:
            names = ", ".join(f["name"] for f in macros[:5])
            findings.append(_f("MED",
                f"Documentos com macros dentro do ZIP: {names}"))

    # ── PDF ───────────────────────────────────────────────────────────────────
    if pdf_raw and pdf_raw.get("ok"):
        if pdf_raw.get("js_count", 0) > 0:
            findings.append(_f("CRIT",
                f"JavaScript embutido: {pdf_raw['js_count']} ocorrência(s) — "
                "PDFs com JS podem executar código arbitrário ao abrir. "
                "Principal vetor de exploit via PDF (CVE-2008-2992, etc.)"))

        if pdf_raw.get("aa_count", 0) > 0:
            findings.append(_f("HIGH",
                f"Ação automática (/AA ou /OpenAction): {pdf_raw['aa_count']} — "
                "executa automaticamente ao abrir o documento."))

        if pdf_raw.get("embedded_files", 0) > 0:
            findings.append(_f("HIGH",
                f"{pdf_raw['embedded_files']} arquivo(s) embutido(s) no PDF — "
                "PDFs podem carregar executáveis, scripts ou outros documentos."))

        for s in pdf_raw.get("susp_strings", []):
            findings.append(_f("HIGH", f"String suspeita: {s}"))

        if pdf_raw.get("susp_producer"):
            findings.append(_f("MED",
                f"Gerador suspeito: '{pdf_raw['producer']}' — "
                "ferramenta genérica frequentemente usada em geração de documentos falsos."))

        # Metadados ausentes
        meta_missing = not any([
            pdf_raw.get("creator"), pdf_raw.get("author"), pdf_raw.get("title")
        ])
        if meta_missing:
            findings.append(_f("MED",
                "Metadados ausentes (Creator, Author e Title não definidos) — "
                "documentos legítimos geralmente possuem metadados de criação. "
                "Comum em documentos fraudulentos gerados automaticamente."))

        # Inconsistência Creator vs Producer
        cr = (pdf_raw.get("creator") or "").lower()
        pr = (pdf_raw.get("producer") or "").lower()
        if cr and pr:
            word_match = any(x in cr for x in ["word", "excel", "office"])
            linux_match = any(x in pr for x in ["linux", "ghostscript", "tcpdf", "reportlab"])
            if word_match and linux_match:
                findings.append(_f("MED",
                    f"Inconsistência de metadados: Creator='{pdf_raw['creator']}' "
                    f"vs Producer='{pdf_raw['producer']}' — "
                    "metadados contraditórios indicam documento forjado ou convertido de forma suspeita."))

    # ── Strings suspeitas ─────────────────────────────────────────────────────
    susp_urls = strings.get("susp_urls", [])
    if susp_urls:
        findings.append(_f("HIGH",
            f"{len(susp_urls)} URL(s) de encurtadores suspeitos encontradas: "
            + ", ".join(susp_urls[:3])))

    pub_ips = strings.get("public_ips", [])
    if len(pub_ips) > 5:
        findings.append(_f("MED",
            f"{len(pub_ips)} IPs públicos hardcoded no arquivo: "
            + ", ".join(pub_ips[:5]) + "... — volume elevado pode indicar C2 embutido."))

    # ── VirusTotal ────────────────────────────────────────────────────────────
    if vt and "error" not in vt:
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        tot = vt.get("total", 0)
        if mal >= 10:
            findings.append(_f("CRIT",
                f"VirusTotal: {mal}/{tot} engines detectaram como MALICIOSO. "
                "Arquivo amplamente reconhecido como malware."))
        elif mal >= 3:
            findings.append(_f("HIGH",
                f"VirusTotal: {mal}/{tot} engines detectaram como malicioso."))
        elif mal > 0 or sus > 0:
            findings.append(_f("MED",
                f"VirusTotal: {mal} malicioso(s), {sus} suspeito(s) de {tot} engines."))
        else:
            findings.append(_f("PASS",
                f"VirusTotal: 0/{tot} detecções — arquivo considerado limpo."))

    return findings


def compute_score(findings: list) -> int:
    score = sum(SEV_SCORE.get(f["sev"], 0) for f in findings)
    return min(100, score)


def verdict_from_score(score: int) -> tuple:
    if score == 0:
        return "SAFE",  "✅", "Sem ameaças detectadas"
    elif score < 40:
        return "WARN",  "⚠️", "Suspeito — requer verificação"
    else:
        return "HIGH",  "🚨", "ALTO RISCO — não abrir/executar"
