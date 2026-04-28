"""
core/utils.py
Helper functions yang dipakai di seluruh framework.
"""

import shutil
import os
import re
from datetime import datetime
from pathlib import Path


def is_tool_installed(tool_name: str) -> bool:
    """
    Cek apakah sebuah CLI tool tersedia di PATH.
    Memakai shutil.which() yang equivalent dengan `which <tool>` di bash.
    """
    return shutil.which(tool_name) is not None


def validate_target(target: str) -> bool:
    """
    Validasi sederhana: IP v4 atau hostname.
    Ini mencegah command injection di subprocess.
    """
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    host_pattern = r"^[a-zA-Z0-9.\-]+$"
    return bool(re.match(ip_pattern, target) or re.match(host_pattern, target))


def create_output_dir(
    target: str,
    base_dir: str = "results",
    use_timestamp: bool = True,
) -> Path:
    """
    Buat folder output terorganisir berdasarkan target.

    Args:
        target: IP atau hostname (jadi nama folder utama).
        base_dir: Root folder results.
        use_timestamp: Jika True, buat subfolder dengan timestamp agar
                       scan sebelumnya tidak ter-overwrite.

    Struktur hasil:
        use_timestamp=True  → results/10.10.11.100/20260418_153012/
        use_timestamp=False → results/10.10.11.100/

    Return: Path object ke folder paling spesifik (tempat file disimpan).
    """
    target_dir = Path(base_dir) / target
    target_dir.mkdir(parents=True, exist_ok=True)

    if not use_timestamp:
        return target_dir

    # Format: YYYYMMDD_HHMMSS (sortable secara alfabetis)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = target_dir / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)

    # Buat/update symlink "latest" yang selalu menunjuk ke scan terbaru
    # Memudahkan akses: cd results/10.10.11.100/latest
    latest_link = target_dir / "latest"
    try:
        if latest_link.is_symlink() or latest_link.exists():
            latest_link.unlink()
        latest_link.symlink_to(timestamp, target_is_directory=True)
    except OSError:
        # Symlink mungkin gagal di beberapa filesystem (misal FAT32 via USB)
        # Ini non-critical, jadi skip aja tanpa error
        pass

    return run_dir


def get_default_wordlist() -> str:
    """
    Cari wordlist default untuk directory bruteforce.
    Mencoba urutan dari "balanced" → "fallback" → "minimal".

    Strategi: pilih yang punya coverage bagus tapi tidak terlalu lambat.
    raft-medium adalah sweet spot untuk HTB (~30k entries).
    """
    return _find_first_existing(WORDLISTS["dir_default"])


# ============================================================================
# WORDLIST PRESETS
# ============================================================================
# Dictionary terpusat untuk semua wordlist yang dipakai framework.
# Setiap key punya list path - akan dicari urut, yang pertama ada → dipakai.
# Ini pattern "fallback chain" - kalau wordlist favorit tidak ada, pakai
# alternatif terdekat tanpa error.
#
# Cara nambah wordlist: tinggal edit list ini, tidak perlu sentuh kode lain.
# ============================================================================

WORDLISTS = {
    # === DIRECTORY BRUTEFORCE ===
    "dir_quick": [
        # ~4.6k entries, scan selesai <1 menit. Untuk recon awal.
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ],
    "dir_default": [
        # ~30k entries, ~5 menit. Sweet spot untuk HTB.
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirb/common.txt",  # fallback minimal
    ],
    "dir_large": [
        # ~220k+ entries, 20-30 menit. Last resort kalau buntu.
        "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-large.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    ],
    # === FILE BRUTEFORCE (cari file specific, bukan direktori) ===
    "files_default": [
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt",
    ],
    # === API ENDPOINTS ===
    "api": [
        "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
        "/usr/share/seclists/Discovery/Web-Content/api/objects.txt",
    ],
    # === CMS-SPECIFIC ===
    "wordpress": [
        "/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
        "/usr/share/seclists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt",
    ],
    "joomla": [
        "/usr/share/seclists/Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt",
    ],
    "drupal": [
        "/usr/share/seclists/Discovery/Web-Content/CMS/Drupal.txt",
    ],
    # === SUBDOMAIN BRUTEFORCE (untuk Gobuster dns mode) ===
    "subdomain_quick": [
        # 5k entries, cukup untuk HTB
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt",
    ],
    "subdomain_default": [
        # 20k entries, balance speed
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    ],
    "subdomain_large": [
        # 110k entries, comprehensive
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
        "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
    ],
    # === VHOST DISCOVERY ===
    "vhost": [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/seclists/Discovery/DNS/namelist.txt",
    ],
    # === USERNAMES (untuk SSH/SMB/login spray) ===
    "username_common": [
        "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
        "/usr/share/seclists/Usernames/Names/names.txt",
    ],
    "username_xato": [
        # Xato collection - kombinasi terbaik dari berbagai breach
        "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt",
        "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
    ],
    # === PASSWORDS ===
    "password_common": [
        "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
    ],
    "password_default": [
        "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100000.txt",
    ],
    "password_rockyou": [
        # The legend - 14 juta password dari breach RockYou
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
    ],
    # === DEFAULT CREDENTIALS (router/IoT/admin panel) ===
    "default_creds": [
        "/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/best1050.txt",
    ],
    # === SNMP COMMUNITY STRINGS ===
    "snmp": [
        "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt",
        "/usr/share/seclists/Miscellaneous/wireless/common-snmp-community-strings-onesixtyone.txt",
    ],
    # === FILE EXTENSIONS UMUM ===
    "extensions_web": [
        "/usr/share/seclists/Discovery/Web-Content/web-extensions.txt",
    ],
}


def _find_first_existing(paths: list) -> str:
    """
    Helper internal: dari list of paths, return yang pertama exists.
    Kalau semua tidak ada, return None.
    """
    for path in paths:
        if path and os.path.isfile(path):
            return path
    return None


def get_wordlist(category: str) -> str:
    """
    Ambil wordlist berdasarkan kategori dari WORDLISTS dictionary.

    Usage:
        wl = get_wordlist("dir_default")     # untuk gobuster dir
        wl = get_wordlist("subdomain_quick") # untuk gobuster dns
        wl = get_wordlist("wordpress")       # untuk WP-specific scan

    Returns:
        Path wordlist (str) atau None jika tidak ada satupun yang exists.
    """
    if category not in WORDLISTS:
        return None
    return _find_first_existing(WORDLISTS[category])


def list_available_wordlists() -> dict:
    """
    Scan semua wordlist preset, return yang tersedia di system.
    Berguna untuk debugging: "wordlist apa saja yang ada di Kali saya?"

    Returns:
        dict {category: path} hanya untuk yang exists.
    """
    available = {}
    for category, paths in WORDLISTS.items():
        found = _find_first_existing(paths)
        if found:
            available[category] = found
    return available


def get_wordlist_info(path: str) -> dict:
    """
    Ambil metadata wordlist (jumlah baris, ukuran file).
    Berguna untuk estimasi durasi scan.
    """
    if not path or not os.path.isfile(path):
        return {"exists": False}

    try:
        size = os.path.getsize(path)
        # Hitung baris efisien tanpa load semua ke RAM
        with open(path, "rb") as f:
            line_count = sum(1 for _ in f)

        return {
            "exists": True,
            "path": path,
            "size_mb": round(size / (1024 * 1024), 2),
            "lines": line_count,
        }
    except Exception:
        return {"exists": False}
