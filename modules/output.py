"""
output.py — Terminal output helpers (colorama-based)
"""

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class _Dummy:
        def __getattr__(self, _): return ""
    Fore = Back = Style = _Dummy()

import shutil

TERM_WIDTH = shutil.get_terminal_size((100, 24)).columns


# ── Severity colors ──────────────────────────────────────────────────────────
SEV_COLOR = {
    "CRIT": Fore.RED + Style.BRIGHT,
    "HIGH": Fore.YELLOW + Style.BRIGHT,
    "MED":  Fore.YELLOW,
    "LOW":  Fore.CYAN,
    "INFO": Fore.BLUE,
    "PASS": Fore.GREEN,
}

VERDICT_COLOR = {
    "SAFE":  Fore.GREEN + Style.BRIGHT,
    "WARN":  Fore.YELLOW + Style.BRIGHT,
    "HIGH":  Fore.RED + Style.BRIGHT,
}


def c(text, *codes):
    return "".join(codes) + str(text) + Style.RESET_ALL


def banner(title: str, color=Fore.CYAN):
    line = "─" * min(TERM_WIDTH - 2, 80)
    print(f"\n{color}{line}{Style.RESET_ALL}")
    print(f"{color}  {title.upper()}{Style.RESET_ALL}")
    print(f"{color}{line}{Style.RESET_ALL}")


def section(title: str, color=Fore.CYAN):
    pad = max(0, 60 - len(title))
    print(f"\n{color}┌─ {title} {'─' * pad}┐{Style.RESET_ALL}")


def section_end(color=Fore.CYAN):
    print(f"{color}└{'─' * 62}┘{Style.RESET_ALL}")


def kv(key: str, value, ok: bool = None, warn: bool = None, bad: bool = None):
    """Print a key-value row with optional coloring."""
    key_str = f"  {Fore.WHITE}{key:<28}{Style.RESET_ALL}"
    if bad:
        val_str = c(value, Fore.RED)
    elif warn:
        val_str = c(value, Fore.YELLOW)
    elif ok:
        val_str = c(value, Fore.GREEN)
    else:
        val_str = str(value)
    print(f"{key_str}{val_str}")


def finding(sev: str, desc: str):
    color = SEV_COLOR.get(sev, "")
    sev_label = f"{color}[{sev:<4}]{Style.RESET_ALL}"
    # Word-wrap desc
    max_w = TERM_WIDTH - 10
    words = desc.split()
    line, lines = [], []
    for w in words:
        if len(" ".join(line + [w])) > max_w:
            lines.append(" ".join(line))
            line = [w]
        else:
            line.append(w)
    if line:
        lines.append(" ".join(line))
    for i, l in enumerate(lines):
        prefix = f"  {sev_label} " if i == 0 else "           "
        print(f"{prefix}{l}")


def verdict(label: str, score: int, detail: str = ""):
    cls = "SAFE" if score == 0 else "WARN" if score < 40 else "HIGH"
    color = VERDICT_COLOR[cls]
    icon = {"SAFE": "✅", "WARN": "⚠️ ", "HIGH": "🚨"}.get(cls, "?")
    print(f"\n  {icon}  {color}{label}{Style.RESET_ALL}")
    if detail:
        print(f"     {Fore.WHITE}{detail}{Style.RESET_ALL}")
    bar_len = 40
    filled = int(score / 100 * bar_len)
    bar_color = Fore.GREEN if score == 0 else Fore.YELLOW if score < 40 else Fore.RED
    bar = bar_color + "█" * filled + Style.DIM + "░" * (bar_len - filled) + Style.RESET_ALL
    print(f"     [{bar}] {bar_color}{score}/100{Style.RESET_ALL}")


def step(msg: str):
    print(f"  {Fore.CYAN}►{Style.RESET_ALL} {msg}")


def warn_inline(msg: str):
    print(f"  {Fore.YELLOW}⚠  {msg}{Style.RESET_ALL}")


def error(msg: str):
    print(f"  {Fore.RED}✗  {msg}{Style.RESET_ALL}")


def ok(msg: str):
    print(f"  {Fore.GREEN}✓  {msg}{Style.RESET_ALL}")


def dim(msg: str):
    print(f"  {Style.DIM}{msg}{Style.RESET_ALL}")
