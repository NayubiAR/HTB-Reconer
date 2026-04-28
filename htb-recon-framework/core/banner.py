"""
core/banner.py
Welcome banner & interactive prompt untuk framework.
"""

import re
from core import logger
from core.logger import Color


# ASCII art banner. Pakai raw string agar backslash tidak di-escape.
BANNER = r"""
 _   _ _____ ____       ____                                    
| | | |_   _| __ )     |  _ \ ___  ___ ___  _ __   ___ _ __    
| |_| | | | |  _ \ ___ | |_) / _ \/ __/ _ \| '_ \ / _ \ '__|   
|  _  | | | | |_) |___||  _ <  __/ (_| (_) | | | |  __/ |      
|_| |_| |_| |____/     |_| \_\___|\___\___/|_| |_|\___|_|      
"""

TAGLINE = "Automated Reconnaissance Framework for HackTheBox & CTF Labs"
VERSION = "v1.0"
AUTHOR = "Built with Python | Modular | Parallel"


def show_banner():
    """Tampilkan welcome banner berwarna."""
    # Pakai cyan untuk banner agar kontras dengan output normal
    print(f"{Color.CYAN}{Color.BOLD}{BANNER}{Color.RESET}")

    # Tagline & version - center alignment manual
    print(f"{Color.YELLOW}    {TAGLINE}{Color.RESET}")
    print(f"{Color.GREEN}    {VERSION}  |  {AUTHOR}{Color.RESET}")
    print(f"{Color.CYAN}{'=' * 64}{Color.RESET}\n")


def prompt_target() -> str:
    """
    Minta input target IP/hostname dari user dengan validasi loop.
    Return target string yang sudah valid.
    """
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    host_pattern = r"^[a-zA-Z0-9.\-]+$"

    while True:
        try:
            target = input(
                f"{Color.BOLD}[?]{Color.RESET} "
                f"Masukkan target IP/hostname "
                f"{Color.CYAN}(contoh: 10.10.11.100){Color.RESET}: "
            ).strip()

            if not target:
                logger.warn("Target tidak boleh kosong")
                continue

            if target.lower() in ("exit", "quit", "q"):
                logger.info("Dibatalkan oleh user")
                exit(0)

            # Validasi format
            if re.match(ip_pattern, target) or re.match(host_pattern, target):
                return target

            logger.error(
                f"Format tidak valid: '{target}'. Gunakan IP (10.10.11.100) atau hostname"
            )

        except (KeyboardInterrupt, EOFError):
            print()  # newline biar rapi
            logger.info("Dibatalkan oleh user")
            exit(130)


def prompt_profile() -> str:
    """
    Tanya user mau pakai profile scan apa.
    Return: 'quick' | 'default' | 'large'
    """
    print(f"\n{Color.BOLD}[?]{Color.RESET} Pilih profile scan:")
    print(
        f"  {Color.GREEN}1){Color.RESET} Quick    - Wordlist kecil (~5k entries), <1 menit"
    )
    print(
        f"  {Color.YELLOW}2){Color.RESET} Default  - Wordlist standard (~30k entries), ~5 menit  {Color.CYAN}[recommended]{Color.RESET}"
    )
    print(
        f"  {Color.RED}3){Color.RESET} Large    - Wordlist comprehensive (220k+), 20+ menit"
    )

    profile_map = {
        "1": "quick",
        "2": "default",
        "3": "default",
        "": "default",
        "4": "large",
    }
    # Map juga agar user bisa ketik nama langsung
    name_map = {"quick": "quick", "default": "default", "large": "large"}

    while True:
        try:
            choice = (
                input(
                    f"{Color.BOLD}[?]{Color.RESET} "
                    f"Pilihan {Color.CYAN}[1/2/3]{Color.RESET} "
                    f"(default: 2): "
                )
                .strip()
                .lower()
            )

            if not choice or choice == "2":
                return "default"
            if choice == "1":
                return "quick"
            if choice == "3":
                return "large"
            if choice in name_map:
                return name_map[choice]

            logger.error("Pilihan tidak valid. Ketik 1, 2, atau 3")

        except (KeyboardInterrupt, EOFError):
            print()
            return "default"


def prompt_yes_no(question: str, default: bool = True) -> bool:
    """
    Generic yes/no prompt.
    Return True kalau yes, False kalau no.
    """
    default_str = "Y/n" if default else "y/N"

    while True:
        try:
            answer = (
                input(
                    f"{Color.BOLD}[?]{Color.RESET} {question} "
                    f"{Color.CYAN}[{default_str}]{Color.RESET}: "
                )
                .strip()
                .lower()
            )

            if not answer:
                return default
            if answer in ("y", "yes", "ya"):
                return True
            if answer in ("n", "no", "tidak"):
                return False

            logger.error("Jawab y atau n")

        except (KeyboardInterrupt, EOFError):
            print()
            return default


def show_scan_summary(target: str, profile: str, full_scan: bool, output_dir: str):
    """Tampilkan ringkasan setting sebelum mulai scan."""
    print(f"\n{Color.CYAN}{'=' * 64}{Color.RESET}")
    print(f"{Color.BOLD}SCAN CONFIGURATION{Color.RESET}")
    print(f"{Color.CYAN}{'=' * 64}{Color.RESET}")
    print(
        f"  {Color.BOLD}Target       :{Color.RESET} {Color.GREEN}{target}{Color.RESET}"
    )
    print(f"  {Color.BOLD}Profile      :{Color.RESET} {profile}")
    print(
        f"  {Color.BOLD}Full scan    :{Color.RESET} {'enabled' if full_scan else 'disabled'}"
    )
    print(f"  {Color.BOLD}Output dir   :{Color.RESET} {output_dir}")
    print(f"{Color.CYAN}{'=' * 64}{Color.RESET}\n")
