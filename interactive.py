"""
interactive.py — Modo interativo do Forensic Analyzer
Menu TUI no terminal, sem dependências externas.
"""

import os
import sys
import glob
from pathlib import Path

from modules.output import Fore, Style, c, banner, section, section_end, step, warn_inline, error, ok, dim, finding as print_finding, verdict as print_verdict
from modules.file_info import format_size
from modules.boleto import validate as validate_boleto
from modules.eml_parser import analyze as analyze_eml
from config import get_vt_key, print_env_status


MENU_COLOR   = Fore.CYAN
TITLE_COLOR  = Fore.WHITE + Style.BRIGHT
OPTION_COLOR = Fore.CYAN
INPUT_COLOR  = Fore.YELLOW


def cls():
    os.system("cls" if os.name == "nt" else "clear")


def pause():
    input(f"\n  {c('Pressione ENTER para continuar...', Style.DIM)}")


def header():
    print(f"\n{MENU_COLOR}{'═'*65}{Style.RESET_ALL}")
    print(f"{TITLE_COLOR}  ██████╗  ██████╗  ██████╗{Style.RESET_ALL}")
    print(f"{TITLE_COLOR}  ██╔═══╝ ██╔═══██╗██╔════╝{Style.RESET_ALL}")
    print(f"{TITLE_COLOR}  █████╗  ██║   ██║██║     {Style.RESET_ALL}  {c('FORENSIC ANALYZER v2.0', Fore.CYAN + Style.BRIGHT)}")
    print(f"{TITLE_COLOR}  ██╔══╝  ██║   ██║██║     {Style.RESET_ALL}  {c('SOC Toolkit // Modo Interativo', Style.DIM)}")
    print(f"{TITLE_COLOR}  ██║     ╚██████╔╝╚██████╗{Style.RESET_ALL}")
    print(f"{TITLE_COLOR}  ╚═╝      ╚═════╝  ╚═════╝{Style.RESET_ALL}")
    print(f"{MENU_COLOR}{'═'*65}{Style.RESET_ALL}")


def menu_option(num: str, label: str, desc: str = "", color=OPTION_COLOR):
    num_str  = c(f"  [{num}]", color + Style.BRIGHT)
    lab_str  = c(f" {label}", Fore.WHITE)
    desc_str = c(f"  {desc}", Style.DIM) if desc else ""
    print(f"{num_str}{lab_str}{desc_str}")


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{c(default, Style.DIM)}]" if default else ""
    try:
        val = input(f"\n  {c('▸', INPUT_COLOR)} {prompt}{suffix}: ").strip()
        return val if val else default
    except (KeyboardInterrupt, EOFError):
        return default


def ask_file(prompt: str = "Caminho do arquivo") -> str:
    """Pede um path com tab-completion básico (glob)."""
    path = ask(prompt)
    if not path:
        return ""
    # Expand ~ e variáveis
    path = os.path.expandvars(os.path.expanduser(path))
    # Se não existe mas tem glob, tenta expandir
    if not os.path.exists(path) and "*" in path:
        matches = glob.glob(path)
        if matches:
            path = matches[0]
    return path


def confirm(prompt: str) -> bool:
    ans = ask(f"{prompt} (s/n)", "n")
    return ans.lower() in ("s", "sim", "y", "yes")


def separator():
    print(f"  {c('─' * 61, Style.DIM)}")


# ─────────────────────────────────────────────────────────────────────────────
# SUB-MENUS
# ─────────────────────────────────────────────────────────────────────────────

def menu_analyze_file(vt_key: str):
    """Análise de arquivo — pede o path e chama o analisador principal."""
    cls()
    header()
    print(f"\n  {c('ANÁLISE DE ARQUIVO', Fore.CYAN + Style.BRIGHT)}\n")
    print(f"  {c('Formatos suportados: PDF, EXE, DLL, ZIP, DOCX, XLSM, EML, qualquer binário', Style.DIM)}")

    path = ask_file("Caminho do arquivo (ou arraste aqui)")
    if not path:
        warn_inline("Nenhum arquivo informado.")
        pause()
        return

    if not os.path.isfile(path):
        error(f"Arquivo não encontrado: {path}")
        pause()
        return

    ext = Path(path).suffix.lower()

    # EML vai para analisador específico
    if ext == ".eml":
        _run_eml(path)
        pause()
        return

    # Opções extras
    print()
    do_strings = confirm("Extrair strings, IPs e URLs do binário? (mais lento em arquivos grandes)")
    do_json    = confirm("Salvar relatório em JSON?")
    json_path  = ""
    if do_json:
        base     = Path(path).stem
        json_path = ask("Nome do arquivo JSON", f"relatorio_{base}.json")

    print()
    # Import inline para evitar circular
    from analyzer import analyze_file
    report = analyze_file(path, vt_key, do_strings)

    if do_json and json_path:
        import json
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2, default=str)
            ok(f"JSON salvo: {json_path}")
        except Exception as e:
            error(f"Erro ao salvar JSON: {e}")

    pause()


def menu_analyze_eml(vt_key: str = ""):
    """Análise de arquivo .eml."""
    cls()
    header()
    print(f"\n  {c('ANÁLISE DE EMAIL (.eml)', Fore.CYAN + Style.BRIGHT)}\n")
    print(f"  {c('Detecta spoofing, verifica SPF/DKIM/DMARC, analisa Received chain.', Style.DIM)}")

    path = ask_file("Caminho do arquivo .eml")
    if not path:
        warn_inline("Nenhum arquivo informado.")
        pause()
        return

    if not os.path.isfile(path):
        error(f"Arquivo não encontrado: {path}")
        pause()
        return

    print()
    _run_eml(path)
    pause()


def _run_eml(path: str):
    """Executa e imprime análise EML."""
    step(f"Analisando: {path}")
    result = analyze_eml(path)

    if not result["ok"]:
        error(f"Falha: {result['error']}")
        return

    findings = result.get("findings", [])
    crit_high = [f for f in findings if f["sev"] in ("CRIT", "HIGH")]
    score = min(len(crit_high) * 30, 100)

    from modules.findings import verdict_from_score
    cls_v, icon, label = verdict_from_score(score)
    print_verdict(f"EMAIL: {label}", score, f"{len(findings)} indicador(es)")

    # Cabeçalhos
    section("CABEÇALHOS")
    _kv("Assunto",       result["subject"]  or c("(sem assunto)", Fore.YELLOW))
    _kv("Data",          result["date"]     or c("ausente", Fore.YELLOW))
    _kv("From",          result["from_raw"] or c("ausente", Fore.RED))
    _kv("  → Nome",      result["from_name"]  or c("sem nome amigável", Style.DIM))
    _kv("  → Endereço",  result["from_addr"]  or c("inválido", Fore.RED))
    _kv("  → Domínio",   result["from_domain"] or c("não detectado", Fore.RED))
    if result["reply_to"]:
        rp_domain = result["from_domain"]
        from modules.eml_parser import _extract_domain
        rt_domain = _extract_domain(result["reply_to"])
        mismatch = rt_domain and rt_domain != rp_domain
        _kv("Reply-To", result["reply_to"],
            bad=mismatch, warn=False, ok=not mismatch)
    if result["return_path"]:
        _kv("Return-Path", result["return_path"])
    if result["x_mailer"]:
        _kv("X-Mailer",    result["x_mailer"])
    if result["x_originating_ip"]:
        _kv("X-Orig-IP",   result["x_originating_ip"])
    _kv("Message-ID",    result["message_id"] or c("AUSENTE", Fore.RED),
        bad=not result["message_id"])
    section_end()

    # Autenticação
    section("SPF / DKIM / DMARC")
    _auth_row("SPF",   result["spf"])
    _auth_row("DKIM",  result["dkim"],  result["dkim_signature_present"])
    _auth_row("DMARC", result["dmarc"])
    section_end()

    # Received chain
    chain = result["received_chain"]
    if chain:
        section(f"RECEIVED CHAIN ({len(chain)} hop(s))")
        for i, hop in enumerate(chain):
            hop_label = c(f"  Hop {i+1}", Fore.WHITE + Style.BRIGHT)
            from_s = c(hop['from'], Fore.CYAN) if hop['from'] else c("?", Style.DIM)
            by_s   = c(hop['by'],   Fore.CYAN) if hop['by']   else c("?", Style.DIM)
            ips    = c(", ".join(hop["ips"]), Fore.YELLOW) if hop["ips"] else c("sem IP", Style.DIM)
            print(f"{hop_label}  {Style.DIM}from{Style.RESET_ALL} {from_s} "
                  f"{Style.DIM}by{Style.RESET_ALL} {by_s}  {Style.DIM}[{Style.RESET_ALL}{ips}{Style.DIM}]{Style.RESET_ALL}")
            if hop["date"]:
                print(f"          {c(hop['date'], Style.DIM)}")
        section_end()

    # Anexos
    if result["attachments"]:
        section(f"ANEXOS ({len(result['attachments'])})")
        for att in result["attachments"]:
            danger_tag = c(" [PERIGOSO!]", Fore.RED + Style.BRIGHT) if att["is_danger"] else ""
            size_s = format_size(att["size"]) if att["size"] else "?"
            print(f"  {c(att['name'], Fore.WHITE)}{danger_tag}  "
                  f"{c(att['content_type'], Style.DIM)}  {c(size_s, Style.DIM)}")
        section_end()

    # URLs
    if result["urls"]:
        from modules.zip_strings import SUSPICIOUS_URL_RE as SURLS
        section(f"URLs NO CORPO ({len(result['urls'])})")
        for url in result["urls"][:20]:
            is_susp = any(p.search(url) for p in SURLS)
            prefix  = c("⚠ ", Fore.RED) if is_susp else "  "
            col     = Fore.RED if is_susp else Fore.CYAN
            print(f"{prefix}{c(url, col)}")
        section_end()

    # Findings
    section("INDICADORES / FINDINGS")
    if not findings:
        ok("Nenhum indicador de risco detectado.")
    else:
        for f in findings:
            print_finding(f["sev"], f["desc"])
    section_end()


def _auth_row(proto: str, status: str, sig_present: bool = True):
    status = status or "none"
    if status in ("pass", "neutral"):
        col = Fore.GREEN; icon = "✓"
    elif status in ("fail", "hardfail", "softfail", "invalid", "permerror"):
        col = Fore.RED; icon = "✗"
    else:
        col = Fore.YELLOW; icon = "?"
    sig_note = "" if sig_present else c("  (sem assinatura)", Fore.YELLOW)
    proto_label = c(f"{proto.upper():<8}", Style.BRIGHT)
    print(f"  {proto_label} {c(icon, col)} {c(status.upper(), col + Style.BRIGHT)}{sig_note}")


def _kv(key: str, value, bad=False, warn=False, ok_=False):
    key_s = f"  {Fore.WHITE}{key:<20}{Style.RESET_ALL}"
    if bad:
        val_s = c(str(value), Fore.RED)
    elif warn:
        val_s = c(str(value), Fore.YELLOW)
    elif ok_:
        val_s = c(str(value), Fore.GREEN)
    else:
        val_s = str(value)
    print(f"{key_s}{val_s}")


def menu_boleto():
    """Menu de validação de boleto."""
    cls()
    header()
    print(f"\n  {c('VALIDAÇÃO DE BOLETO', Fore.YELLOW + Style.BRIGHT)}\n")
    print(f"  {c('Suporta: linha digitável (47), código de barras (44), arrecadação (48)', Style.DIM)}")
    print(f"  {c('Cole com ou sem pontos e espaços.', Style.DIM)}")

    code = ask("Linha digitável ou código de barras")
    if not code:
        warn_inline("Nenhum código informado.")
        pause()
        return

    print()
    from analyzer import _print_boleto
    result = validate_boleto(code)
    _print_boleto(result)
    pause()


def menu_config(vt_key_ref: list):
    """Configurações de sessão."""
    cls()
    header()
    print(f"\n  {c('CONFIGURAÇÕES', Fore.CYAN + Style.BRIGHT)}\n")
    print_env_status()
    separator()

    current = vt_key_ref[0]
    if current:
        masked = current[:4] + "*" * max(0, len(current) - 8) + current[-4:]
        print(f"\n  Chave VirusTotal ativa: {c(masked, Fore.GREEN)}")
    else:
        print(f"\n  {c('Sem chave VirusTotal configurada.', Fore.YELLOW)}")

    if confirm("\n  Alterar chave do VirusTotal agora?"):
        new_key = ask("Nova VT_API_KEY (ENTER para manter)")
        if new_key:
            vt_key_ref[0] = new_key
            ok("Chave atualizada para esta sessão.")
            dim("(Para persistir, adicione ao .env)")

    pause()


def menu_about():
    cls()
    header()
    print(f"""
  {c('Forensic Analyzer v2.0', Fore.CYAN + Style.BRIGHT)}
  {c('Desenvolvido por:', Style.DIM)} João Carlos Minozzi
  {c('Contexto:', Style.DIM)} SOC / Cybersecurity enthusiast

  {c('Módulos disponíveis:', Fore.WHITE)}
  • Hashes: MD5, SHA-1, SHA-256, SHA-512
  • Detecção por magic bytes (spoofing de extensão)
  • Entropia de Shannon + hex dump
  • Análise de cabeçalho PE (EXE/DLL) — sem pefile
  • Análise profunda de PDF (pdfplumber + raw bytes)
  • Listagem de conteúdo ZIP/OOXML
  • Extração de strings, IPs, URLs, emails de binários
  • Validação de boletos FEBRABAN (bancário + arrecadação)
    ↳ Módulo 10 e 11, campo livre por banco, fator de vencimento
  • Análise de email .eml
    ↳ SPF / DKIM / DMARC, spoofing, Received chain,
      display name fraud, homógrafos, anexos perigosos
  • VirusTotal API (hash only — arquivo nunca enviado)
  • Relatório JSON exportável

  {c('Aviso legal:', Fore.YELLOW)} Uso educacional e de SOC.
  {c('Nenhum arquivo é enviado a servidores externos.', Style.DIM)}
    """)
    pause()


# ─────────────────────────────────────────────────────────────────────────────
# FOLDER SCAN
# ─────────────────────────────────────────────────────────────────────────────

# Extensões que a ferramenta sabe analisar em profundidade
KNOWN_EXTS = {
    # Executáveis
    ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".hta", ".wsf", ".pif", ".com", ".msi", ".reg",
    # Documentos
    ".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm",
    ".ppt", ".pptx", ".pptm", ".rtf",
    # Arquivos compactados
    ".zip", ".rar", ".7z", ".gz", ".tar",
    # Email
    ".eml", ".msg",
    # Outros binários comuns
    ".jar", ".apk", ".iso", ".img", ".lnk",
}

# Pastas que devem ser ignoradas por padrão
SKIP_DIRS = {
    "__pycache__", ".git", ".svn", ".hg", "node_modules",
    ".venv", "venv", "env", ".env", "dist", "build",
    "Windows", "System32", "SysWOW64", "Program Files",
    "Program Files (x86)",
}

MAX_FILE_SIZE_MB = 200  # Arquivos maiores que isso são pulados


def _iter_files(folder: str, recursive: bool, exts_filter: set) -> list:
    """Retorna lista de (path, tamanho) dos arquivos a analisar."""
    found = []
    folder_path = Path(folder)

    def _should_skip_dir(d: Path) -> bool:
        return d.name in SKIP_DIRS or d.name.startswith(".")

    if recursive:
        for root, dirs, files in os.walk(folder_path):
            # Filtra pastas ignoradas in-place
            dirs[:] = [d for d in dirs if not _should_skip_dir(Path(root) / d)]
            for fname in files:
                fpath = Path(root) / fname
                if not exts_filter or fpath.suffix.lower() in exts_filter:
                    try:
                        size = fpath.stat().st_size
                        found.append((str(fpath), size))
                    except Exception:
                        pass
    else:
        for fpath in folder_path.iterdir():
            if fpath.is_file():
                if not exts_filter or fpath.suffix.lower() in exts_filter:
                    try:
                        size = fpath.stat().st_size
                        found.append((str(fpath), size))
                    except Exception:
                        pass

    return sorted(found, key=lambda x: x[0])


def menu_analyze_folder(vt_key: str):
    cls()
    header()
    print(f"\n  {c('ANÁLISE DE PASTA / DIRETÓRIO', Fore.CYAN + Style.BRIGHT)}\n")

    print(f"  {c('Exemplos de caminhos:', Style.DIM)}")
    print(f"  {c('  Windows:', Style.DIM)} {c('C:\\\\Users\\\\joao\\\\Downloads', Fore.YELLOW)}")
    print(f"  {c('  Linux:',   Style.DIM)} {c('/home/joao/downloads', Fore.YELLOW)}")
    print(f"  {c('  Mac:',     Style.DIM)} {c('~/Downloads', Fore.YELLOW)}")
    print(f"  {c('  Relativo:', Style.DIM)} {c('./amostras   ou   ../suspeitos', Fore.YELLOW)}")
    print()

    folder = ask_file("Caminho da pasta")
    if not folder:
        warn_inline("Nenhuma pasta informada.")
        pause()
        return

    folder = os.path.expandvars(os.path.expanduser(folder))

    if not os.path.isdir(folder):
        error(f"Pasta não encontrada: {folder}")
        pause()
        return

    # Opções
    print()
    recursive  = confirm("Varrer subpastas recursivamente?")
    filter_ext = confirm("Filtrar apenas extensões conhecidas (pdf, exe, eml, zip...)?")
    ext_filter = KNOWN_EXTS if filter_ext else set()

    skip_large = confirm(f"Pular arquivos maiores que {MAX_FILE_SIZE_MB}MB?")
    do_strings = confirm("Extrair strings/IPs/URLs de binários? (lento em muitos arquivos)")

    print()
    step(f"Mapeando arquivos em: {folder}")
    files = _iter_files(folder, recursive, ext_filter)

    if not files:
        warn_inline("Nenhum arquivo encontrado com os critérios selecionados.")
        pause()
        return

    # Estatísticas antes de começar
    total_size = sum(s for _, s in files)
    print(f"\n  {c(f'{len(files)} arquivo(s) encontrado(s)', Fore.WHITE + Style.BRIGHT)}"
          f"  {c(f'({format_size(total_size)} total)', Style.DIM)}")

    # Mostra preview
    print()
    for fpath, fsize in files[:12]:
        rel = os.path.relpath(fpath, folder)
        ext = Path(fpath).suffix.lower()
        ext_color = Fore.RED if ext in {".exe",".dll",".bat",".ps1",".vbs",".js",".cmd"} \
                   else Fore.YELLOW if ext in {".pdf",".docm",".xlsm"} \
                   else Fore.CYAN
        print(f"  {c(rel, ext_color)}  {c(format_size(fsize), Style.DIM)}")
    if len(files) > 12:
        print(f"  {c(f'... e mais {len(files)-12} arquivo(s)', Style.DIM)}")

    print()
    if not confirm(f"Iniciar análise de {len(files)} arquivo(s)?"):
        return

    # ── Scan loop ──────────────────────────────────────────────────────────────
    from analyzer import analyze_file
    from modules.findings import compute_score, verdict_from_score

    results_summary = []
    skipped = []
    errors_  = []

    print()
    separator()

    for i, (fpath, fsize) in enumerate(files, 1):
        rel   = os.path.relpath(fpath, folder)
        fname = Path(fpath).name
        ext   = Path(fpath).suffix.lower()

        prefix = f"  [{i:>3}/{len(files)}]"

        # Pula arquivos muito grandes
        if skip_large and fsize > MAX_FILE_SIZE_MB * 1024 * 1024:
            print(f"{c(prefix, Style.DIM)} {c('PULADO', Fore.YELLOW)}  {c(rel, Style.DIM)}"
                  f"  {c(f'({format_size(fsize)} > {MAX_FILE_SIZE_MB}MB)', Style.DIM)}")
            skipped.append({"path": fpath, "reason": f"Tamanho {format_size(fsize)}"})
            continue

        # EML
        if ext == ".eml":
            try:
                r = analyze_eml(fpath)
                findings = r.get("findings", [])
                crits = [f for f in findings if f["sev"] in ("CRIT","HIGH")]
                score = min(len(crits) * 30, 100)
                _, _, vlabel = verdict_from_score(score)
                score_col = Fore.RED if score >= 40 else Fore.YELLOW if score > 0 else Fore.GREEN
                print(f"{c(prefix, Style.DIM)} {c(f'{score:>3}/100', score_col)}  {c(rel, Fore.CYAN)}")
                results_summary.append({
                    "path": fpath, "type": "EML", "score": score,
                    "verdict": vlabel, "findings_count": len(findings)
                })
            except Exception as e:
                print(f"{c(prefix, Style.DIM)} {c('ERRO', Fore.RED)}   {c(rel, Style.DIM)}  {e}")
                errors_.append({"path": fpath, "error": str(e)})
            continue

        # Arquivo genérico
        try:
            # Análise silenciosa (sem print do analyze_file)
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                report = analyze_file(fpath, vt_key, do_strings)

            score    = report.get("score", 0)
            findings = report.get("findings", [])
            _, _, vlabel = verdict_from_score(score)
            score_col = Fore.RED if score >= 40 else Fore.YELLOW if score > 0 else Fore.GREEN
            ftype = report.get("file_type", {}).get("type", "?")
            print(f"{c(prefix, Style.DIM)} {c(f'{score:>3}/100', score_col)}  "
                  f"{c(ftype, Style.DIM):<6}  {c(rel, Fore.CYAN)}")
            results_summary.append({
                "path": fpath, "type": ftype, "score": score,
                "verdict": vlabel, "findings_count": len(findings),
                "md5": report.get("hashes", {}).get("md5",""),
                "sha256": report.get("hashes", {}).get("sha256",""),
            })
        except Exception as e:
            print(f"{c(prefix, Style.DIM)} {c('ERRO', Fore.RED)}   {c(rel, Style.DIM)}  {e}")
            errors_.append({"path": fpath, "error": str(e)})

    # ── Sumário final ──────────────────────────────────────────────────────────
    separator()
    print(f"\n  {c('SUMÁRIO DA VARREDURA', Fore.WHITE + Style.BRIGHT)}\n")

    total    = len(files)
    ok_count = len([r for r in results_summary if r["score"] == 0])
    warn_c   = len([r for r in results_summary if 0 < r["score"] < 40])
    high_c   = len([r for r in results_summary if r["score"] >= 40])
    skip_c   = len(skipped)
    err_c    = len(errors_)

    print(f"  {c('Total analisado:', Style.DIM)}  {c(total,    Fore.WHITE + Style.BRIGHT)}")
    print(f"  {c('✅ Sem risco:',     Style.DIM)}  {c(ok_count, Fore.GREEN)}")
    print(f"  {c('⚠  Suspeitos:',    Style.DIM)}  {c(warn_c,   Fore.YELLOW)}")
    print(f"  {c('🚨 Alto risco:',    Style.DIM)}  {c(high_c,   Fore.RED + Style.BRIGHT)}")
    print(f"  {c('⏭  Pulados:',      Style.DIM)}  {c(skip_c,   Style.DIM)}")
    print(f"  {c('✗  Erros:',        Style.DIM)}  {c(err_c,    Fore.RED)}")

    # Destaca os mais suspeitos
    risky = sorted([r for r in results_summary if r["score"] > 0],
                   key=lambda x: x["score"], reverse=True)
    if risky:
        print(f"\n  {c('ARQUIVOS COM MAIOR RISCO:', Fore.RED + Style.BRIGHT)}\n")
        for r in risky[:10]:
            rel   = os.path.relpath(r["path"], folder)
            score = r["score"]
            col   = Fore.RED if score >= 40 else Fore.YELLOW
            fc    = r['findings_count']
            print(f"  {c(f'{score:>3}/100', col)}  {c(rel, Fore.WHITE)}  "
                  + c(f"({fc} findings)", Style.DIM))

    # Salvar JSON do sumário?
    print()
    if confirm("Salvar sumário em JSON?"):
        import json
        out_path = ask("Nome do arquivo", f"scan_{Path(folder).name}.json")
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump({
                    "folder": folder,
                    "recursive": recursive,
                    "total": total,
                    "results": results_summary,
                    "skipped": skipped,
                    "errors": errors_,
                }, f, ensure_ascii=False, indent=2, default=str)
            ok(f"Salvo: {out_path}")
        except Exception as e:
            error(f"Erro ao salvar: {e}")

    pause()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN LOOP
# ─────────────────────────────────────────────────────────────────────────────

def run():
    # VT key em lista para ser mutável por referência
    vt_key_ref = [get_vt_key()]

    while True:
        cls()
        header()

        # Status da chave VT
        if vt_key_ref[0]:
            masked = vt_key_ref[0][:4] + "****" + vt_key_ref[0][-4:]
            vt_status = c(f"VT: {masked}", Fore.GREEN)
        else:
            vt_status = c("VT: sem chave", Fore.YELLOW)
        print(f"\n  {vt_status}\n")

        separator()
        menu_option("1", "Analisar Arquivo",
                    "PDF, EXE, DLL, ZIP, DOCX, EML...")
        menu_option("2", "Analisar Pasta / Diretório",
                    "Varre todos os arquivos recursivamente")
        menu_option("3", "Analisar Email (.eml)",
                    "Spoofing, SPF/DKIM/DMARC, Received chain")
        menu_option("4", "Validar Boleto",
                    "Linha digitável ou código de barras FEBRABAN")
        menu_option("5", "Configurações",
                    "Alterar chave VirusTotal, ver status do .env")
        menu_option("6", "Sobre",
                    "Módulos, informações da ferramenta")
        separator()
        menu_option("0", "Sair", color=Fore.RED)
        print()

        choice = ask("Opção")

        if choice == "1":
            menu_analyze_file(vt_key_ref[0])
        elif choice == "2":
            menu_analyze_folder(vt_key_ref[0])
        elif choice == "3":
            menu_analyze_eml(vt_key_ref[0])
        elif choice == "4":
            menu_boleto()
        elif choice == "5":
            menu_config(vt_key_ref)
        elif choice == "6":
            menu_about()
        elif choice in ("0", "q", "exit", "sair"):
            cls()
            print(f"\n  {c('Encerrando Forensic Analyzer. Até mais!', Fore.CYAN)}\n")
            sys.exit(0)
        else:
            warn_inline(f"Opção inválida: '{choice}'")
            import time; time.sleep(0.8)
