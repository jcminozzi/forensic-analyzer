"""
boleto.py — Validação completa de boletos bancários e de arrecadação (FEBRABAN)

Suporta:
- Linha digitável bancária (47 dígitos)
- Código de barras bancário (44 dígitos)
- Boleto de arrecadação/concessionária (48 dígitos, início em 8)
"""

import re
from datetime import datetime, timedelta


# ── Base de bancos ────────────────────────────────────────────────────────────
BANKS = {
    "001": "Banco do Brasil",
    "033": "Santander",
    "037": "Banpará",
    "041": "Banrisul",
    "070": "BRB — Banco de Brasília",
    "077": "Banco Inter",
    "094": "Banco Finaxis",
    "097": "Credisis",
    "099": "Uniprime",
    "104": "Caixa Econômica Federal",
    "133": "Cresol",
    "136": "Unicred",
    "197": "Stone Pagamentos",
    "208": "BTG Pactual",
    "212": "Banco Original",
    "218": "Banco BS2",
    "237": "Bradesco",
    "246": "ABC Brasil",
    "260": "Nubank",
    "290": "Pagseguro",
    "318": "Banco BMG",
    "336": "C6 Bank",
    "341": "Itaú Unibanco",
    "380": "PicPay",
    "389": "Banco Mercantil",
    "422": "Banco Safra",
    "623": "Banco Pan",
    "633": "Banco Rendimento",
    "643": "Banco Pine",
    "707": "Daycoval",
    "739": "Banco Cetelem",
    "745": "Citibank",
    "748": "Sicredi",
    "756": "Sicoob/Bancoob",
    "757": "KEB Hana",
}

SEGMENTS = {
    "1": "Prefeituras",
    "2": "Saneamento",
    "3": "Energia Elétrica / Gás",
    "4": "Telecomunicações",
    "5": "Órgãos Governamentais / Tributos Federais",
    "6": "Carnês e Assemelhados",
    "7": "Multas de Trânsito",
    "9": "Uso Exclusivo do Banco / ISPB",
}

VALUE_TYPES = {
    "6": "Valor real em Reais",
    "7": "Quantidade em moeda variável",
    "8": "Valor real em Reais (convênio)",
    "9": "Referência (sem valor fixo)",
}


# ── Dígito verificador Módulo 10 ──────────────────────────────────────────────
def mod10(num: str) -> int:
    total = 0
    alt = False
    for ch in reversed(num):
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    rem = total % 10
    return 0 if rem == 0 else 10 - rem


# ── Dígito verificador Módulo 11 FEBRABAN ────────────────────────────────────
def mod11_febraban(num: str) -> int:
    """Módulo 11 com pesos 2-9. Resto 0 ou 1 → DV = 1."""
    total = 0
    weight = 2
    for ch in reversed(num):
        total += int(ch) * weight
        weight = 2 if weight == 9 else weight + 1
    rem = total % 11
    return 1 if rem in (0, 1) else 11 - rem


# ── Fator de vencimento → data ────────────────────────────────────────────────
BASE_DATE = datetime(1997, 10, 7)

def factor_to_date(factor: int) -> str:
    if factor == 0:
        return "ISENTO / SEM VENCIMENTO"
    if factor < 1000 or factor > 9999:
        return f"INVÁLIDO (fator={factor})"
    d = BASE_DATE + timedelta(days=factor)
    expired = d < datetime.now()
    label = " ⚠ VENCIDO" if expired else ""
    return d.strftime("%d/%m/%Y") + label


# ── Decode campo livre por banco ──────────────────────────────────────────────
def decode_campo_livre(bank: str, cl: str) -> str:
    """Tenta decodificar o campo livre de 25 dígitos para o banco informado."""
    try:
        if bank == "001":  # Banco do Brasil
            return (f"Convênio: {cl[0:7]} | Conta benef.: {cl[7:19]} | "
                    f"Carteira: {cl[19:21]} | Tipo: {cl[21:23]} | Seq: {cl[23:]}")
        elif bank == "237":  # Bradesco
            return (f"Carteira: {cl[0:2]} | Nosso número: {cl[2:9]} | "
                    f"Conta: {cl[9:16]} | DV: {cl[16]} | Resto: {cl[17:]}")
        elif bank == "341":  # Itaú
            return (f"Carteira: {cl[0:3]} | Nosso número: {cl[3:11]} | "
                    f"DV: {cl[11]} | Agência: {cl[12:16]} | Conta: {cl[16:21]} | "
                    f"DV2: {cl[21]}")
        elif bank == "104":  # CEF
            return (f"Código produto/operação: {cl[0:15]} | "
                    f"Parâmetro: {cl[15]} | DV: {cl[16]} | Seq: {cl[17:]}")
        elif bank == "033":  # Santander
            return f"Código do documento: {cl[0:13]} | IOF: {cl[13]} | Sequencial: {cl[14:]}"
        elif bank == "260":  # Nubank
            return f"Campo livre (Nubank): {cl}"
        elif bank == "077":  # Inter
            return f"Campo livre (Inter): {cl}"
        elif bank == "748":  # Sicredi
            return f"PA: {cl[0:4]} | Cooperativa: {cl[4:7]} | Modalidade: {cl[7]} | Nosso nº: {cl[8:18]} | Tipo: {cl[18]} | Zeros: {cl[19:]}"
        elif bank == "756":  # Sicoob
            return f"Modalidade: {cl[0:2]} | Conta/cooperativa: {cl[2:12]} | Nosso nº: {cl[12:21]} | Parcela: {cl[21:24]} | Tipo: {cl[24:]}"
        else:
            return f"Campo livre (25 dígitos): {cl} — decode específico não disponível para banco {bank}"
    except IndexError:
        return f"Campo livre: {cl} (tamanho insuficiente para decode)"


# ── Finding helper ─────────────────────────────────────────────────────────────
def _finding(sev: str, desc: str) -> dict:
    return {"sev": sev, "desc": desc}


# ── BANCÁRIO 47 dígitos ───────────────────────────────────────────────────────
def validate_bancario_47(raw: str) -> dict:
    c1 = raw[0:10]
    c2 = raw[10:21]
    c3 = raw[21:32]
    c4 = raw[32]
    c5 = raw[33:47]

    bank_code = c1[0:3]
    currency  = c1[3]
    factor    = c5[0:4]
    amount    = c5[4:14]

    campo_livre = c1[4:9] + c2[0:10] + c3[0:10]
    barcode     = bank_code + currency + c4 + factor + amount + campo_livre

    # DV calculations
    dv1_exp = mod10(c1[:9]);   dv1_ok = dv1_exp == int(c1[9])
    dv2_exp = mod10(c2[:10]);  dv2_ok = dv2_exp == int(c2[10])
    dv3_exp = mod10(c3[:10]);  dv3_ok = dv3_exp == int(c3[10])
    dv_g_exp = mod11_febraban(bank_code + currency + factor + amount + campo_livre)
    dv_g_ok  = dv_g_exp == int(c4)

    findings = []
    for label, ok, exp, found in [
        ("Campo 1", dv1_ok, dv1_exp, int(c1[9])),
        ("Campo 2", dv2_ok, dv2_exp, int(c2[10])),
        ("Campo 3", dv3_ok, dv3_exp, int(c3[10])),
    ]:
        if ok:
            findings.append(_finding("PASS", f"{label}: dígito verificador ✓ válido (módulo 10) — DV={found}"))
        else:
            findings.append(_finding("CRIT", f"{label}: DV INVÁLIDO — esperado {exp}, encontrado {found} (módulo 10). Adulteração provável."))

    if dv_g_ok:
        findings.append(_finding("PASS", f"DV geral: ✓ válido (módulo 11 FEBRABAN) — DV={c4}"))
    else:
        findings.append(_finding("CRIT", f"DV GERAL INVÁLIDO — esperado {dv_g_exp}, encontrado {c4} (módulo 11). Máxima suspeita de fraude."))

    bank_name = BANKS.get(bank_code, "BANCO NÃO IDENTIFICADO")
    if bank_code not in BANKS:
        findings.append(_finding("HIGH", f"Código de banco {bank_code} não encontrado na base. Verifique se o banco é legítimo."))
    else:
        findings.append(_finding("INFO", f"Banco identificado: {bank_code} — {bank_name}"))

    if currency != "9":
        findings.append(_finding("HIGH", f"Código de moeda inválido: '{currency}'. Boletos BRL usam obrigatoriamente '9'."))
    else:
        findings.append(_finding("PASS", "Código de moeda: 9 (BRL — Real Brasileiro) ✓"))

    due_str = factor_to_date(int(factor))
    if "VENCIDO" in due_str:
        findings.append(_finding("MED", f"Boleto vencido: {due_str}. Confirme com o beneficiário se ainda pode ser pago."))
    elif "INVÁLIDO" in due_str:
        findings.append(_finding("HIGH", f"Fator de vencimento inválido: {factor}"))
    elif "ISENTO" in due_str:
        findings.append(_finding("INFO", "Sem data de vencimento (fator 0000 — isento / a vista)"))
    else:
        findings.append(_finding("INFO", f"Vencimento: {due_str}"))

    amount_val = int(amount) / 100
    if amount_val == 0:
        findings.append(_finding("INFO", "Valor zero — boleto de instrução sem valor fixo."))
    else:
        findings.append(_finding("INFO", f"Valor: R$ {amount_val:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")))

    return {
        "type":       "Boleto Bancário — Linha Digitável (47 dígitos)",
        "bank_code":  bank_code,
        "bank_name":  bank_name,
        "currency":   currency,
        "factor":     factor,
        "due_date":   due_str,
        "amount":     f"R$ {amount_val:,.2f}".replace(",","X").replace(".",",").replace("X","."),
        "campo_livre": campo_livre,
        "campo_livre_decoded": decode_campo_livre(bank_code, campo_livre),
        "barcode":    barcode,
        "blocks": {
            "c1": {"digits": c1[:9], "dv": c1[9], "dv_exp": dv1_exp, "ok": dv1_ok},
            "c2": {"digits": c2[:10],"dv": c2[10],"dv_exp": dv2_exp, "ok": dv2_ok},
            "c3": {"digits": c3[:10],"dv": c3[10],"dv_exp": dv3_exp, "ok": dv3_ok},
            "dv_geral": {"value": c4, "expected": dv_g_exp, "ok": dv_g_ok},
        },
        "findings":   findings,
    }


# ── BANCÁRIO 44 dígitos ───────────────────────────────────────────────────────
def validate_bancario_44(raw: str) -> dict:
    bank_code   = raw[0:3]
    currency    = raw[3]
    dv_geral    = raw[4]
    factor      = raw[5:9]
    amount      = raw[9:19]
    campo_livre = raw[19:44]

    dv_g_exp = mod11_febraban(raw[:4] + raw[5:])
    dv_g_ok  = dv_g_exp == int(dv_geral)

    bank_name = BANKS.get(bank_code, "Banco não identificado")
    amount_val = int(amount) / 100
    due_str = factor_to_date(int(factor))

    findings = []
    if dv_g_ok:
        findings.append(_finding("PASS", f"DV geral: ✓ válido (módulo 11) — DV={dv_geral}"))
    else:
        findings.append(_finding("CRIT", f"DV GERAL INVÁLIDO — esperado {dv_g_exp}, encontrado {dv_geral}."))
    if bank_code not in BANKS:
        findings.append(_finding("HIGH", f"Banco {bank_code} não identificado."))
    else:
        findings.append(_finding("INFO", f"Banco: {bank_code} — {bank_name}"))
    if currency != "9":
        findings.append(_finding("HIGH", f"Código de moeda inválido: '{currency}'."))
    if "VENCIDO" in due_str:
        findings.append(_finding("MED", f"Boleto vencido: {due_str}."))
    else:
        findings.append(_finding("INFO", f"Vencimento: {due_str}"))
    findings.append(_finding("INFO", f"Valor: R$ {amount_val:,.2f}".replace(",","X").replace(".",",").replace("X",".")))

    return {
        "type":       "Boleto Bancário — Código de Barras (44 dígitos)",
        "bank_code":  bank_code,
        "bank_name":  bank_name,
        "currency":   currency,
        "factor":     factor,
        "due_date":   due_str,
        "amount":     f"R$ {amount_val:,.2f}".replace(",","X").replace(".",",").replace("X","."),
        "campo_livre": campo_livre,
        "campo_livre_decoded": decode_campo_livre(bank_code, campo_livre),
        "barcode":    raw,
        "blocks": {
            "dv_geral": {"value": dv_geral, "expected": dv_g_exp, "ok": dv_g_ok},
        },
        "findings":   findings,
    }


# ── ARRECADAÇÃO 48 dígitos ────────────────────────────────────────────────────
def validate_arrecadacao_48(raw: str) -> dict:
    product     = raw[0]   # sempre '8'
    segment     = raw[1]
    value_type  = raw[2]
    dv_geral    = raw[3]
    value_field = raw[4:15]  # 11 dígitos
    company     = raw[15:19] # 4 dígitos (ISPB truncado)
    campo_livre = raw[19:]   # 29 dígitos

    # Blocos de 12 para validação
    b1, b2, b3, b4 = raw[0:12], raw[12:24], raw[24:36], raw[36:48]

    dv1_exp = mod10(b1[:11]); dv1_ok = dv1_exp == int(b1[11])
    dv2_exp = mod10(b2[:11]); dv2_ok = dv2_exp == int(b2[11])
    dv3_exp = mod10(b3[:11]); dv3_ok = dv3_exp == int(b3[11])
    dv4_exp = mod10(b4[:11]); dv4_ok = dv4_exp == int(b4[11])

    seg_name   = SEGMENTS.get(segment, f"Segmento {segment} (desconhecido)")
    val_type_s = VALUE_TYPES.get(value_type, f"Tipo {value_type} (desconhecido)")

    # Valor
    if value_type in ("6", "8"):
        amount_val = int(value_field) / 100
        amount_str = f"R$ {amount_val:,.2f}".replace(",","X").replace(".",",").replace("X",".")
    else:
        amount_str = f"Referência: {value_field}"

    findings = []
    for label, ok, exp, found in [
        ("Bloco 1", dv1_ok, dv1_exp, int(b1[11])),
        ("Bloco 2", dv2_ok, dv2_exp, int(b2[11])),
        ("Bloco 3", dv3_ok, dv3_exp, int(b3[11])),
        ("Bloco 4", dv4_ok, dv4_exp, int(b4[11])),
    ]:
        if ok:
            findings.append(_finding("PASS", f"{label}: DV ✓ válido (módulo 10) — DV={found}"))
        else:
            findings.append(_finding("CRIT", f"{label}: DV INVÁLIDO — esperado {exp}, encontrado {found}."))

    findings.append(_finding("INFO", f"Produto: {product} (arrecadação)"))
    findings.append(_finding("INFO", f"Segmento: {segment} — {seg_name}"))
    findings.append(_finding("INFO", f"Tipo de valor: {value_type} — {val_type_s}"))
    findings.append(_finding("INFO", f"Empresa/convênio: {company}"))

    return {
        "type":       "Boleto de Arrecadação / Concessionária (48 dígitos)",
        "product":    product,
        "segment":    segment,
        "seg_name":   seg_name,
        "value_type": value_type,
        "val_type_s": val_type_s,
        "company":    company,
        "amount":     amount_str,
        "campo_livre": campo_livre,
        "blocks": {
            "b1": {"digits": b1[:11], "dv": b1[11], "dv_exp": dv1_exp, "ok": dv1_ok},
            "b2": {"digits": b2[:11], "dv": b2[11], "dv_exp": dv2_exp, "ok": dv2_ok},
            "b3": {"digits": b3[:11], "dv": b3[11], "dv_exp": dv3_exp, "ok": dv3_ok},
            "b4": {"digits": b4[:11], "dv": b4[11], "dv_exp": dv4_exp, "ok": dv4_ok},
        },
        "findings":   findings,
    }


# ── ENTRY POINT ───────────────────────────────────────────────────────────────
def validate(raw_input: str) -> dict:
    """Main entry: clean input and route to the correct validator."""
    raw = re.sub(r'[\s.\-]', '', raw_input.strip())

    if not raw.isdigit():
        return {"error": f"Código deve conter apenas números. Encontrado: '{raw[:20]}...'"}

    length = len(raw)

    if length == 47:
        return validate_bancario_47(raw)
    elif length == 44:
        return validate_bancario_44(raw)
    elif length == 48 and raw[0] == "8":
        return validate_arrecadacao_48(raw)
    elif length == 48:
        # Some banks use 48-digit typed line — try as bancario
        return validate_bancario_47(raw[:47])
    else:
        return {"error": f"Tamanho inválido: {length} dígitos. Esperado: 44 (cód. barras), 47 (linha digitável bancária) ou 48 (arrecadação)."}
