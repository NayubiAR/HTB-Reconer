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
    
    def run(self, port: int = 80, wordlist: str = None, **kwargs) -> bool:
        if not self.check_prerequisites():
            return False
        
        # Tentukan scheme berdasarkan port
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{self.target}:{port}"
        
        # Resolve wordlist: argumen eksplisit > default Kali
        if not wordlist:
            wordlist = get_default_wordlist()
        
        if not wordlist or not Path(wordlist).exists():
            logger.error("Wordlist tidak ditemukan. Install seclists: sudo apt install seclists")
            return False
        
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
        
        success, _ = run_command(cmd, timeout=1800)
        
        if success:
            logger.success(f"Gobuster selesai untuk port {port}. Output: {output_file}")
        return success