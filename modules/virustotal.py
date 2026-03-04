"""
virustotal.py — VirusTotal API v3 integration com timeout e tratamento de erros
"""

import requests
from typing import Optional

VT_URL = "https://www.virustotal.com/api/v3/files/{}"
try:
    from config import get_vt_timeout
    TIMEOUT = get_vt_timeout()
except ImportError:
    TIMEOUT = 10  # fallback


def query_hash(sha256: str, api_key: str) -> dict:
    """
    Consulta o hash SHA-256 na API do VirusTotal.
    Retorna dict com stats ou {'error': 'motivo'}.
    """
    if not api_key or not sha256:
        return {"error": "API key ou hash não fornecidos"}

    try:
        resp = requests.get(
            VT_URL.format(sha256),
            headers={"x-apikey": api_key},
            timeout=TIMEOUT,
        )

        if resp.status_code == 404:
            return {"error": "Hash não encontrado na base do VirusTotal (arquivo nunca submetido)"}
        if resp.status_code == 401:
            return {"error": "Chave de API inválida ou sem autenticação"}
        if resp.status_code == 403:
            return {"error": "Sem permissão — verifique sua chave de API"}
        if resp.status_code == 429:
            return {"error": "Rate limit atingido — aguarde 1 minuto antes de tentar novamente"}
        if resp.status_code != 200:
            return {"error": f"Erro HTTP {resp.status_code}"}

        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        meta  = data.get("data", {}).get("attributes", {})

        return {
            "stats":        stats,
            "malicious":    stats.get("malicious", 0),
            "suspicious":   stats.get("suspicious", 0),
            "harmless":     stats.get("harmless", 0),
            "undetected":   stats.get("undetected", 0),
            "total":        sum(stats.values()),
            "first_seen":   meta.get("first_submission_date", ""),
            "last_seen":    meta.get("last_analysis_date", ""),
            "type_desc":    meta.get("type_description", ""),
            "names":        meta.get("names", [])[:5],
            "tags":         meta.get("tags", [])[:10],
        }

    except requests.Timeout:
        return {"error": f"Timeout após {TIMEOUT}s — VirusTotal não respondeu"}
    except requests.ConnectionError:
        return {"error": "Falha de conexão — sem acesso à internet ou VT fora do ar"}
    except Exception as e:
        return {"error": f"Erro inesperado: {e}"}
