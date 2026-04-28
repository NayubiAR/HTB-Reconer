"""
core/logger.py
Simple colored logger. Tidak pakai library eksternal biar zero-dependency.
"""
from datetime import datetime


class Color:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"


def _timestamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def info(msg: str):
    print(f"{Color.BLUE}[{_timestamp()}] [*]{Color.RESET} {msg}")


def success(msg: str):
    print(f"{Color.GREEN}[{_timestamp()}] [+]{Color.RESET} {msg}")


def warn(msg: str):
    print(f"{Color.YELLOW}[{_timestamp()}] [!]{Color.RESET} {msg}")


def error(msg: str):
    print(f"{Color.RED}[{_timestamp()}] [-]{Color.RESET} {msg}")


def banner(msg: str):
    line = "=" * 60
    print(f"\n{Color.CYAN}{Color.BOLD}{line}\n>> {msg}\n{line}{Color.RESET}")