#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           FORENSIC ANALYZER — SOC File & Boleto Tool            ║
║           Análise forense de arquivos e validação de boletos     ║
╚══════════════════════════════════════════════════════════════════╝

Uso:
  python analyzer.py arquivo.pdf
  python analyzer.py arquivo.exe --vt-key SUA_CHAVE_VT
  python analyzer.py --boleto "34191.09008 61207.727308 71444.640003 8 92690000010000"
  python analyzer.py arquivo.pdf --boleto --vt-key SUA_CHAVE_VT
  python analyzer.py arquivo.pdf --json relatorio.json
  python analyzer.py arquivo.pdf --no-strings   (pula extração de strings — mais rápido)

Aviso: esta ferramenta é para uso educacional e de SOC.
O arquivo analisado NUNCA é enviado a servidores externos.
Somente o hash SHA-256 é consultado no VirusTotal (se a chave for fornecida).

Desenvolvido por: João Carlos Minozzi
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

# ── Adiciona o diretório raiz ao path ─────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

from config import get_vt_key, get_vt_timeout, get_auto_save_json, get_output_dir, print_env_status
from modules import output as out
from modules.file_info import (
    compute_hashes, shannon_entropy, detect_type,
    get_file_times, hex_dump, format_size, entropy_label,
)
from modules.pe_parser    import parse as parse_pe
from modules.pdf_parser   import analyze as analyze_pdf
from modules.zip_strings  import parse_zip, extract_strings
from modules.boleto       import validate as validate_boleto
from modules.findings     import generate as gen_findings, compute_score, verdict_from_score
from modules.virustotal   import query_hash as vt_query
from modules.output       import Fore, Style


VERSION = "2.0.0"
DISCLAIMER = (
    "⚠  AVISO: Esta ferramenta realiza análise heurística local. Resultados são indicativos.\n"
    "   Nenhum arquivo é transmitido a servidores externos.\n"
    "   Apenas o hash SHA-256 é consultado no VirusTotal (se a chave for fornecida).\n"
    "   Para boletos: DVs corretos NÃO garantem autenticidade.\n"
    "   Sempre confirme o beneficiário no internet banking antes de pagar."
)


# ─────────────────────────────────────────────────────────────────────────────
# FILE ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

def analyze_file(path: str, vt_key: str = "", do_strings: bool = True) -> dict:
    report = {}

    if not os.path.isfile(path):
        out.error(f"Arquivo não encontrado: {path}")
        sys.exit(1)

    t_start = time.time()

    # ── Load ──────────────────────────────────────────────────────────────────
    out.step(f"Carregando arquivo: {path}")
    with open(path, "rb") as f:
        data = f.read()

    file_size = len(data)
    file_name = os.path.basename(path)
    report["file"] = {
        "path":  path,
        "name":  file_name,
        "size":  file_size,
        "size_human": format_size(file_size),
    }
    report["file"].update(get_file_times(path))

    # ── Hashes ────────────────────────────────────────────────────────────────
    out.step("Calculando hashes (MD5 / SHA-1 / SHA-256 / SHA-512)...")
    hashes = compute_hashes(data)
    report["hashes"] = hashes

    # ── Type ──────────────────────────────────────────────────────────────────
    out.step("Identificando tipo pelo magic bytes...")
    file_type = detect_type(data, file_name)
    report["file_type"] = file_type

    # ── Entropy ───────────────────────────────────────────────────────────────
    out.step("Calculando entropia de Shannon...")
    entropy = shannon_entropy(data)
    report["entropy"] = entropy
    report["entropy_label"], _ = entropy_label(entropy)

    # ── Strings ───────────────────────────────────────────────────────────────
    strings = {}
    if do_strings:
        out.step("Extraindo strings, IPs, URLs, emails...")
        strings = extract_strings(data)
        report["strings"] = {
            k: v for k, v in strings.items() if k != "ascii_strings"
        }
        report["ascii_strings_count"] = len(strings.get("ascii_strings", []))

    # ── PE ────────────────────────────────────────────────────────────────────
    pe = None
    if file_type["type"] == "PE":
        out.step("Analisando cabeçalho PE...")
        pe = parse_pe(data)
        report["pe"] = pe

    # ── ZIP ───────────────────────────────────────────────────────────────────
    zip_files = []
    if file_type["type"] == "ZIP":
        out.step("Listando arquivos no ZIP...")
        zip_files = parse_zip(data)
        report["zip_files"] = zip_files

    # ── PDF ───────────────────────────────────────────────────────────────────
    pdf_raw = {}
    if file_type["type"] == "PDF":
        out.step("Analisando PDF (metadados + estrutura)...")
        pdf_raw = analyze_pdf(path)
        report["pdf"] = pdf_raw

    # ── VirusTotal ────────────────────────────────────────────────────────────
    vt = {}
    if vt_key:
        out.step("Consultando VirusTotal (hash SHA-256)...")
        vt = vt_query(hashes["sha256"], vt_key)
        report["virustotal"] = vt
    else:
        report["virustotal"] = {"skipped": True}

    # ── Findings ──────────────────────────────────────────────────────────────
    out.step("Gerando findings e score de risco...")
    findings = gen_findings(
        {"name": file_name}, file_type, entropy,
        strings, pe or {}, zip_files, pdf_raw, vt
    )
    score = compute_score(findings)
    cls, icon, label = verdict_from_score(score)
    report["score"]    = score
    report["verdict"]  = label
    report["findings"] = findings

    elapsed = time.time() - t_start

    # ── PRINT RESULTS ─────────────────────────────────────────────────────────
    _print_file_results(
        file_name, file_size, hashes, file_type, entropy,
        strings, pe, zip_files, pdf_raw, vt, findings, score,
        cls, icon, label, elapsed
    )

    return report


def _print_file_results(
        file_name, file_size, hashes, file_type, entropy,
        strings, pe, zip_files, pdf_raw, vt, findings, score,
        cls, icon, label, elapsed):

    # Verdict
    out.banner(f"RESULTADO — {file_name}", Fore.WHITE)
    color_map = {"SAFE": Fore.GREEN, "WARN": Fore.YELLOW, "HIGH": Fore.RED}
    out.verdict(label, score, f"{len(findings)} indicador(es) · {elapsed:.2f}s")

    # File Info
    out.section("INFORMAÇÕES DO ARQUIVO")
    out.kv("Nome",          file_name)
    out.kv("Tamanho",       f"{format_size(file_size)} ({file_size:,} bytes)")
    out.kv("Tipo detectado",f"{file_type['icon']} {file_type['label']}")
    out.kv("Detectado por", file_type["detected_by"])
    if file_type.get("ext_mismatch"):
        out.kv("Extensão ."+file_type["ext"],
               f"MISMATCH! Esperado: {file_type['expected_ext_type']}",
               bad=True)

    # Timestamps
    out.kv("Criado em",   hashes.get("created",  "—"))
    out.kv("Modificado",  hashes.get("modificado","—"))
    out.section_end()

    # Hashes
    out.section("HASHES CRIPTOGRÁFICOS")
    out.kv("MD5",    hashes["md5"])
    out.kv("SHA-1",  hashes["sha1"])
    out.kv("SHA-256",hashes["sha256"])
    out.kv("SHA-512",hashes["sha512"][:64] + "…")
    out.section_end()

    # Entropy
    out.section("ENTROPIA")
    label_e, sev_e = entropy_label(entropy)
    is_bad  = sev_e in ("HIGH", "MED")
    out.kv("Shannon entropy", f"{entropy:.4f} bits — {label_e}",
           bad=sev_e=="HIGH", warn=sev_e=="MED", ok=sev_e not in ("HIGH","MED"))

    # Entropy bar
    bar_len = 40
    filled  = int(entropy / 8 * bar_len)
    color   = Fore.RED if sev_e == "HIGH" else Fore.YELLOW if sev_e == "MED" else Fore.GREEN
    bar     = color + "█" * filled + Style.DIM + "░" * (bar_len - filled) + Style.RESET_ALL
    print(f"  [{bar}]")
    out.section_end()

    # Hex dump
    out.section("HEX DUMP (primeiros 128 bytes)")
    print(out.c(hex_dump(open(__import__('sys').argv[1], 'rb').read() if len(__import__('sys').argv) > 1 else b'', 128),
                Fore.CYAN + Style.DIM))
    out.section_end()

    # PE header
    if pe:
        out.section("CABEÇALHO PE (EXECUTÁVEL WINDOWS)")
        out.kv("Arquitetura",    pe["arch"])
        out.kv("Compilado em",   pe["compiled_at"],
               bad=pe.get("ts_future") or pe.get("ts_old"))
        if pe.get("ts_future"):
            out.warn_inline("Timestamp no FUTURO — fortemente suspeito!")
        out.kv("Tipo",           "DLL" if pe["is_dll"] else "Driver" if pe["is_driver"] else "Executável (.exe)")
        out.kv("Subsistema",     pe["subsystem"])
        out.kv("Image Base",     pe["image_base"])
        out.kv("Entry Point",    pe["entry_point"])
        out.kv("Seções",         ", ".join(s["name"] for s in pe["sections"]))
        out.kv("ASLR",           "✓ Habilitado" if pe["has_aslr"] else "✗ Desabilitado", ok=pe["has_aslr"], bad=not pe["has_aslr"])
        out.kv("DEP/NX",         "✓ Habilitado" if pe["has_nx"]   else "✗ Desabilitado", ok=pe["has_nx"],   bad=not pe["has_nx"])
        out.kv("CFG",            "✓ Habilitado" if pe["has_cfg"]  else "✗ Desabilitado", ok=pe["has_cfg"],  warn=not pe["has_cfg"])
        out.kv("Símbolos",       "Removidos (stripped)" if pe["is_stripped"] else "Presentes")
        if pe.get("susp_sections"):
            out.kv("Seções suspeitas", ", ".join(pe["susp_sections"]), bad=True)
        if pe.get("wx_sections"):
            out.kv("Seções W+X (perig.)", ", ".join(pe["wx_sections"]), bad=True)
        out.section_end()

    # ZIP
    if zip_files:
        out.section(f"CONTEÚDO DO ZIP ({len(zip_files)} arquivo(s))")
        for zf in zip_files[:40]:
            flag = ""
            if zf["is_exec"]:
                flag = out.c(" [EXECUTÁVEL]", Fore.RED + Style.BRIGHT)
            elif zf["is_macro"]:
                flag = out.c(" [MACRO]", Fore.YELLOW)
            size_str = f"  {format_size(zf['uncomp_size'])}"
            print(f"  {out.c(zf['name'], Fore.CYAN)}{flag}{out.c(size_str, Style.DIM)}")
        if len(zip_files) > 40:
            out.dim(f"... e mais {len(zip_files)-40} arquivo(s)")
        out.section_end()

    # PDF
    if pdf_raw and pdf_raw.get("ok"):
        out.section("METADADOS PDF")
        out.kv("Versão PDF",   pdf_raw.get("version", "?"))
        out.kv("Título",       pdf_raw.get("title") or out.c("AUSENTE", Fore.YELLOW))
        out.kv("Autor",        pdf_raw.get("author") or out.c("AUSENTE", Fore.YELLOW))
        out.kv("Criado por",   pdf_raw.get("creator") or out.c("AUSENTE", Fore.RED))
        out.kv("Gerado por",   pdf_raw.get("producer") or out.c("AUSENTE", Fore.RED),
               warn=pdf_raw.get("susp_producer", False))
        out.kv("Data criação", pdf_raw.get("creation_date") or out.c("AUSENTE", Fore.RED))
        out.kv("Modificação",  pdf_raw.get("mod_date") or out.c("AUSENTE", Fore.YELLOW))
        out.kv("Páginas",      pdf_raw.get("pages", "?"))
        out.kv("Objetos",      pdf_raw.get("obj_count", 0))
        out.kv("Streams",      pdf_raw.get("stream_count", 0))
        out.kv("JavaScript",   str(pdf_raw.get("js_count", 0)) + (" ⚠" if pdf_raw.get("js_count", 0) else " ✓"),
               bad=bool(pdf_raw.get("js_count", 0)), ok=not pdf_raw.get("js_count", 0))
        out.kv("AutoActions",  str(pdf_raw.get("aa_count", 0)) + (" ⚠" if pdf_raw.get("aa_count", 0) else " ✓"),
               bad=bool(pdf_raw.get("aa_count", 0)), ok=not pdf_raw.get("aa_count", 0))
        out.kv("Arquivos emb.",str(pdf_raw.get("embedded_files", 0)) + (" ⚠" if pdf_raw.get("embedded_files", 0) else " ✓"),
               bad=bool(pdf_raw.get("embedded_files", 0)))
        out.section_end()

        # URLs do PDF
        if pdf_raw.get("urls"):
            from modules.zip_strings import SUSPICIOUS_URL_RE as SURLS
            out.section(f"URLs NO PDF ({len(pdf_raw['urls'])})")
            for url in pdf_raw["urls"][:30]:
                is_susp = any(p.search(url) for p in SURLS)
                prefix  = out.c("⚠ ", Fore.RED) if is_susp else "  "
                color   = Fore.RED if is_susp else Fore.CYAN
                print(f"{prefix}{out.c(url, color)}")
            out.section_end()

        # Boleto no PDF
        if pdf_raw.get("is_boleto"):
            print(f"\n  {out.c('📄 Boleto detectado no PDF', Fore.YELLOW + Style.BRIGHT)}")
            if pdf_raw.get("boleto_code"):
                print(f"  Linha extraída: {out.c(pdf_raw['boleto_code'], Fore.YELLOW)}")
                print()
                _print_boleto(validate_boleto(pdf_raw["boleto_code"]))
            else:
                out.warn_inline("Palavras-chave de boleto detectadas mas código não pôde ser extraído.")

    # Strings
    if strings.get("public_ips"):
        out.section(f"IPs PÚBLICOS ENCONTRADOS ({len(strings['public_ips'])})")
        for ip in strings["public_ips"][:20]:
            print(f"  {out.c(ip, Fore.YELLOW)}")
        out.section_end()

    if strings.get("emails"):
        out.section(f"EMAILS ENCONTRADOS ({len(strings['emails'])})")
        for em in strings["emails"][:20]:
            print(f"  {out.c(em, Fore.CYAN)}")
        out.section_end()

    # VT
    out.section("VIRUSTOTAL")
    if not vt:
        out.dim("Chave não fornecida. Use --vt-key para habilitar.")
    elif "error" in vt:
        out.warn_inline(f"VT: {vt['error']}")
    elif "skipped" in vt:
        out.dim("Consulta pulada (sem chave).")
    else:
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        tot = vt.get("total", 0)
        harm = vt.get("harmless", 0)
        undet = vt.get("undetected", 0)
        mal_c  = Fore.RED if mal > 0 else Fore.GREEN
        sus_c  = Fore.YELLOW if sus > 0 else Fore.GREEN
        print(f"  {out.c('MALICIOSO:',  Style.DIM)} {out.c(mal,  mal_c+Style.BRIGHT)}   "
              f"{out.c('SUSPEITO:',    Style.DIM)} {out.c(sus,  sus_c)}   "
              f"{out.c('LIMPO:',       Style.DIM)} {out.c(harm, Fore.GREEN)}   "
              f"{out.c('NÃO DETECT.:', Style.DIM)} {out.c(undet, Style.DIM)}   "
              f"{out.c('TOTAL:',       Style.DIM)} {tot}")
        if vt.get("names"):
            out.kv("Nomes conhecidos", ", ".join(vt["names"]))
        if vt.get("tags"):
            out.kv("Tags VT",          ", ".join(vt["tags"]))
        if vt.get("first_seen"):
            from datetime import datetime
            try:
                fs = datetime.utcfromtimestamp(vt["first_seen"]).strftime("%d/%m/%Y %H:%M UTC")
                out.kv("Visto pela 1ª vez", fs)
            except Exception:
                pass
    out.section_end()

    # Findings
    out.section("INDICADORES / FINDINGS")
    if not findings:
        out.ok("Nenhum indicador de risco detectado.")
    else:
        for f in findings:
            out.finding(f["sev"], f["desc"])
    out.section_end()


# ─────────────────────────────────────────────────────────────────────────────
# BOLETO PRINT
# ─────────────────────────────────────────────────────────────────────────────

def _print_boleto(result: dict):
    if "error" in result:
        out.error(result["error"])
        return

    # Verdict
    findings = result.get("findings", [])
    crit_high = [f for f in findings if f["sev"] in ("CRIT", "HIGH")]
    score = len(crit_high) * 40
    cls, icon, label = verdict_from_score(min(score, 100))
    detail = f"{len(crit_high)} indicador(es) crítico(s) — {result.get('type', '')}"
    out.verdict(f"BOLETO: {label}", min(score, 100), detail)

    out.section("DADOS DO BOLETO")
    if result.get("bank_code"):
        out.kv("Banco",   f"{result['bank_code']} — {result.get('bank_name','?')}")
    if result.get("currency"):
        ok_cur = result["currency"] == "9"
        out.kv("Moeda",   f"{result['currency']} — {'BRL (Real) ✓' if ok_cur else 'INVÁLIDO ⚠'}",
               ok=ok_cur, bad=not ok_cur)
    if result.get("due_date"):
        out.kv("Vencimento",  result["due_date"],
               warn="VENCIDO" in result["due_date"])
    if result.get("amount"):
        out.kv("Valor",       result["amount"])
    if result.get("seg_name"):
        out.kv("Segmento",    f"{result.get('segment')} — {result['seg_name']}")
    if result.get("val_type_s"):
        out.kv("Tipo de valor", result["val_type_s"])
    if result.get("company"):
        out.kv("Empresa/convênio", result["company"])
    out.section_end()

    # Blocks
    blocks = result.get("blocks", {})
    if blocks:
        out.section("DÍGITOS VERIFICADORES")
        for name, blk in blocks.items():
            dv     = blk.get("dv",  "?")
            exp    = blk.get("dv_exp", "?")
            ok_dv  = blk.get("ok", False)
            digits = blk.get("digits", "")
            label  = out.c(f"[{'✓' if ok_dv else '✗'}]", Fore.GREEN if ok_dv else Fore.RED + Style.BRIGHT)
            prefix = name.upper().replace("_", " ")
            print(f"  {out.c(prefix, Style.BRIGHT):<20} {label} DV={dv}  esperado={exp}  [{digits}]")
        out.section_end()

    # Campo livre
    if result.get("campo_livre"):
        out.section("CAMPO LIVRE")
        print(f"  {out.c(result['campo_livre'], Fore.YELLOW)}")
        if result.get("campo_livre_decoded"):
            print(f"  {out.c(result['campo_livre_decoded'], Fore.CYAN + Style.DIM)}")
        out.section_end()

    # Barcode
    if result.get("barcode"):
        out.section("CÓDIGO DE BARRAS RECONSTITUÍDO")
        print(f"  {out.c(result['barcode'], Fore.YELLOW + Style.BRIGHT)}")
        out.section_end()

    # Findings
    out.section("VALIDAÇÕES DETALHADAS")
    for f in findings:
        out.finding(f["sev"], f["desc"])
    out.section_end()

    print(f"\n  {out.c('⚠  ATENÇÃO:', Fore.YELLOW + Style.BRIGHT)} DVs corretos NÃO garantem autenticidade.")
    print(f"  {out.c('   Boletos clonados podem ter DVs válidos com conta beneficiária alterada.', Style.DIM)}")
    print(f"  {out.c('   SEMPRE confirme CNPJ/CPF e nome do beneficiário no internet banking.', Style.DIM)}")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="analyzer",
        description="Forensic Analyzer — Análise forense de arquivos e boletos (SOC Tool)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument("file",        nargs="?", help="Arquivo para análise")
    parser.add_argument("--boleto",    nargs="?", const="__from_pdf__",
                        metavar="CODIGO",
                        help="Validar linha digitável/código de barras de boleto")
    parser.add_argument("--vt-key",    default="", metavar="API_KEY",
                        help="Chave de API do VirusTotal")
    parser.add_argument("--no-strings", action="store_true",
                        help="Pular extração de strings (mais rápido)")
    parser.add_argument("--json",      metavar="OUTPUT.json",
                        help="Salvar relatório completo em JSON")
    parser.add_argument("--hex-only",  action="store_true",
                        help="Mostrar apenas hex dump e hashes")
    parser.add_argument("--version",   action="version",
                        version=f"forensic-analyzer {VERSION}")

    args = parser.parse_args()

    # ── Header ────────────────────────────────────────────────────────────────
    print(f"\n{Fore.CYAN}{'═'*65}")
    print(f"  FORENSIC ANALYZER v{VERSION}  //  SOC Toolkit")
    print(f"{'═'*65}{Style.RESET_ALL}")
    print(f"  {out.c(DISCLAIMER, Style.DIM)}\n")

    # ── Resolve VT key (CLI > sistema > .env) ────────────────────────────────
    vt_key = get_vt_key(args.vt_key)
    print_env_status()
    print()

    report = {}

    # ── Boleto mode ───────────────────────────────────────────────────────────
    if args.boleto and args.boleto != "__from_pdf__":
        out.banner("VALIDAÇÃO DE BOLETO", Fore.YELLOW)
        result = validate_boleto(args.boleto)
        _print_boleto(result)
        report["boleto"] = result

    # ── File mode ─────────────────────────────────────────────────────────────
    if args.file:
        report = analyze_file(args.file, vt_key, not args.no_strings)

    if not args.file and not args.boleto:
        parser.print_help()
        sys.exit(0)

    # ── JSON output (manual ou auto-save) ─────────────────────────────────────
    json_path = args.json
    if not json_path and get_auto_save_json() and args.file:
        base = os.path.splitext(os.path.basename(args.file))[0]
        out_dir = get_output_dir()
        os.makedirs(out_dir, exist_ok=True)
        json_path = os.path.join(out_dir, f"relatorio_{base}.json")

    if json_path and report:
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2, default=str)
            out.ok(f"Relatório JSON salvo em: {json_path}")
        except Exception as e:
            out.error(f"Erro ao salvar JSON: {e}")

    print(f"\n{out.c('─'*65, Style.DIM)}\n")


if __name__ == "__main__":
    main()
