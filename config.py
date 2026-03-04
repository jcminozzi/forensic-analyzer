"""
config.py — Carrega variáveis de ambiente do arquivo .env

Prioridade:
  1. Argumento explícito na CLI (--vt-key)
  2. Variável de ambiente do sistema (export VT_API_KEY=...)
  3. Arquivo .env na raiz do projeto
"""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    # Procura o .env a partir do diretório do script, subindo até a raiz
    _env_path = Path(__file__).parent / ".env"
    load_dotenv(dotenv_path=_env_path, override=False)
    _DOTENV_LOADED = _env_path.exists()
except ImportError:
    _DOTENV_LOADED = False


def get_vt_key(cli_override: str = "") -> str:
    """
    Retorna a chave do VirusTotal.
    Prioridade: CLI > sistema > .env
    """
    if cli_override and cli_override.strip():
        return cli_override.strip()
    return os.getenv("VT_API_KEY", "").strip()


def get_vt_timeout() -> int:
    try:
        return int(os.getenv("VT_TIMEOUT", "10"))
    except ValueError:
        return 10


def get_auto_save_json() -> bool:
    return os.getenv("AUTO_SAVE_JSON", "false").lower() in ("true", "1", "yes")


def get_output_dir() -> str:
    return os.getenv("OUTPUT_DIR", ".").strip()


def print_env_status():
    """Mostra de onde as configurações estão sendo lidas (debug)."""
    from modules.output import Fore, Style, c
    if _DOTENV_LOADED:
        print(f"  {c('✓ .env carregado', Fore.GREEN)}")
    else:
        print(f"  {c('⚠  .env não encontrado — usando variáveis do sistema ou padrões.', Fore.YELLOW)}")
        print(f"  {Style.DIM}  Crie um a partir do .env.example: cp .env.example .env{Style.RESET_ALL}")

    key = get_vt_key()
    if key:
        masked = key[:4] + "*" * (len(key) - 8) + key[-4:]
        print(f"  {c('VT_API_KEY:', Style.DIM)} {c(masked, Fore.GREEN)}")
    else:
        print(f"  {c('VT_API_KEY:', Style.DIM)} {c('não configurada', Fore.YELLOW)}")
