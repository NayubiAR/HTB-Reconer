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
    Cari wordlist default di Kali Linux.
    Fallback berurutan dari yang paling umum.
    """
    candidates = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ]
    for wl in candidates:
        if os.path.isfile(wl):
            return wl
    return None