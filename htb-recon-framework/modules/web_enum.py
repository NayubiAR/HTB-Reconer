"""
modules/web_enum.py
Stage 2a: Web directory enumeration via Gobuster.

CATATAN SINTAKS GOBUSTER MODERN (v3.6+):
  ✅ BENAR   : gobuster dir -u <url> -w <wordlist> -o <output>
  ❌ SALAH   : gobuster -d <domain>  (flag -d sudah DEPRECATED, itu untuk DNS mode lama)
  ❌ SALAH   : gobuster -r           (flag -r juga sudah tidak dipakai seperti dulu)

Gobuster modern pakai "mode" sebagai positional argument:
  - dir   : directory/file bruteforce
  - dns   : subdomain bruteforce  
  - vhost : virtual host discovery
  - s3    : bucket enumeration
"""
from pathlib import Path
from modules.base_module import BaseModule
from core.runner import run_command
from core.utils import get_default_wordlist
from core import logger


class WebEnumModule(BaseModule):
    tool_name = "gobuster"
    module_name = "Web Directory Enumeration (Gobuster)"
    
<<<<<<< HEAD
    def run(
        self,
        port: int = 80,
        wordlist: str = None,
        profile: str = "default",
        **kwargs,
    ) -> bool:
        """
        Args:
            port: Target port (80, 443, 8080, dll).
            wordlist: Path eksplisit. Jika ada, override profile.
            profile: "quick" | "default" | "large".
                     - quick: ~4.6k entries, <1 menit
                     - default: ~30k entries, ~5 menit (recommended)
                     - large: ~220k+ entries, 20-30 menit
        """
        if not self.check_prerequisites():
            return False
        
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{self.target}:{port}"
        
        # === Resolve wordlist ===
        # Priority: explicit wordlist > profile preset
        if not wordlist:
            profile_map = {
                "quick": "dir_quick",
                "default": "dir_default",
                "large": "dir_large",
            }
            category = profile_map.get(profile, "dir_default")
            wordlist = get_wordlist(category)
=======
    def run(self, port: int = 80, wordlist: str = None, **kwargs) -> bool:
        if not self.check_prerequisites():
            return False
        
        # Tentukan scheme berdasarkan port
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{self.target}:{port}"
        
        # Resolve wordlist: argumen eksplisit > default Kali
        if not wordlist:
            wordlist = get_default_wordlist()
>>>>>>> f447ff96d9158e39a3275b4657dc25263e45d5c3
        
        if not wordlist or not Path(wordlist).exists():
            logger.error("Wordlist tidak ditemukan. Install seclists: sudo apt install seclists")
            return False
        
<<<<<<< HEAD
        # Tampilkan info wordlist (size, line count) agar user tahu durasi expected
        info = get_wordlist_info(wordlist)
        
        logger.banner(f"{self.module_name} on {url}")
        logger.info(f"Wordlist: {wordlist}")
        if info.get("exists"):
            logger.info(f"  Lines: {info['lines']:,} | Size: {info['size_mb']} MB")
        
        output_file = self.output_dir / f"gobuster_{port}.md"
        
=======
        logger.banner(f"{self.module_name} on {url}")
        logger.info(f"Wordlist: {wordlist}")
        
        output_file = self.output_dir / f"gobuster_{port}.md"
        
        # === SINTAKS GOBUSTER MODERN ===
        # dir                : mode (positional, wajib di awal)
        # -u <url>           : target URL
        # -w <wordlist>      : path ke wordlist
        # -o <file>          : output ke file
        # -t 50              : threads (default 10, naik ke 50 untuk HTB lab)
        # -x php,html,txt    : file extensions yang di-probe
        # -k                 : skip TLS verification (untuk self-signed HTB)
        # --no-error         : sembunyikan connection errors di output
        # -q                 : quiet mode (bersihkan banner)
>>>>>>> f447ff96d9158e39a3275b4657dc25263e45d5c3
        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-o", str(output_file),
            "-t", "50",
            "-x", "php,html,txt,bak",
            "--no-error",
            "-q",
        ]
        
        if scheme == "https":
            cmd.append("-k")
        
<<<<<<< HEAD
        # Timeout dinamis berdasarkan profile
        timeout_map = {"quick": 300, "default": 1800, "large": 3600}
        timeout = timeout_map.get(profile, 1800)
        
        success, _ = run_command(cmd, timeout=timeout)
=======
        success, _ = run_command(cmd, timeout=1800)
>>>>>>> f447ff96d9158e39a3275b4657dc25263e45d5c3
        
        if success:
            logger.success(f"Gobuster selesai untuk port {port}. Output: {output_file}")
        return success