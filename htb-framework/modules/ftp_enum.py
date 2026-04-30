"""
modules/ftp_enum.py
FTP Enumeration untuk port 21.

Strategy:
1. Banner grab via netcat / nmap script
2. Test anonymous login (user: anonymous, password: anonymous@domain.com)
3. Kalau bisa anonymous, list direktori secara recursive
"""
from pathlib import Path
from modules.base_module import BaseModule
from core.runner import run_command
from core.utils import is_tool_installed
from core import logger


class FtpEnumModule(BaseModule):
    tool_name = "ftp"  # FTP client biasanya pre-installed di Kali
    module_name = "FTP Enumeration"
    
    def run(self, port: int = 21, **kwargs) -> bool:
        logger.banner(f"{self.module_name} on {self.target}:{port}")
        
        ran_something = False
        
        # === Langkah 1: Banner grab + anon login check via Nmap NSE ===
        # Nmap punya script khusus FTP yang sangat informatif
        if is_tool_installed("nmap"):
            logger.info("Banner grab + anon check via Nmap NSE script...")
            output_file = self.output_dir / "ftp_nmap.md"
            cmd = [
                "nmap",
                "-sV",
                "-p", str(port),
                "--script", "ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor",
                self.target,
            ]
            run_command(cmd, output_file=output_file, timeout=180)
            ran_something = True
        
        # === Langkah 2: Test anonymous login dengan FTP client ===
        # Kalau berhasil, sekalian list direktori
        if is_tool_installed("ftp"):
            logger.info("Testing anonymous FTP login...")
            output_file = self.output_dir / "ftp_anon_attempt.md"
            
            # Pakai expect-style approach: pipe command ke ftp client
            # Ini lebih reliable daripada interactive
            ftp_commands = (
                "user anonymous anonymous@test.com\n"
                "ls -la\n"
                "ls -la /\n"
                "bye\n"
            )
            
            # Pakai bash dengan heredoc untuk feed perintah ke ftp
            cmd = [
                "bash", "-c",
                f"echo -e '{ftp_commands}' | ftp -nv {self.target} {port}"
            ]
            run_command(cmd, output_file=output_file, timeout=60)
            ran_something = True
        
        # === Langkah 3: Recursive listing dengan wget (kalau anon bekerja) ===
        # wget punya mode FTP yang otomatis fetch struktur direktori
        if is_tool_installed("wget"):
            logger.info("Attempting recursive directory listing...")
            output_file = self.output_dir / "ftp_recursive.md"
            
            # --no-verbose: minimize output noise
            # --spider: jangan download file, hanya list
            # -r: recursive
            # -l 2: max 2 level kedalaman (hindari trap)
            cmd = [
                "wget",
                "--no-verbose",
                "--spider",
                "-r",
                "-l", "2",
                f"ftp://anonymous:anonymous@{self.target}:{port}/",
            ]
            run_command(cmd, output_file=output_file, timeout=120, show_output=False)
            ran_something = True
        
        if not ran_something:
            logger.error(
                "Tidak ada FTP tool tersedia. Install: "
                "sudo apt install ftp wget nmap"
            )
            return False
        
        logger.success(f"FTP enum selesai untuk port {port}")
        return True
