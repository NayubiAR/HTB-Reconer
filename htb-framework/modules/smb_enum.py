"""
modules/smb_enum.py
Stage 2b: SMB enumeration untuk port 445.
Strategy: coba enum4linux-ng dulu (lebih modern), fallback ke smbclient.
"""
from pathlib import Path
from modules.base_module import BaseModule
from core.runner import run_command
from core.utils import is_tool_installed
from core import logger


class SmbEnumModule(BaseModule):
    tool_name = "smbclient"  # Minimal requirement
    module_name = "SMB Enumeration"
    
    def run(self, **kwargs) -> bool:
        logger.banner(f"{self.module_name} on {self.target}")
        
        ran_something = False
        
        # 1. enum4linux-ng (rewrite modern dari enum4linux)
        if is_tool_installed("enum4linux-ng"):
            logger.info("Running enum4linux-ng (comprehensive)...")
            output_file = self.output_dir / "enum4linux.md"
            cmd = ["enum4linux-ng", "-A", self.target]
            run_command(cmd, output_file=output_file, timeout=600)
            ran_something = True
        elif is_tool_installed("enum4linux"):
            logger.info("Running enum4linux (legacy)...")
            output_file = self.output_dir / "enum4linux.md"
            cmd = ["enum4linux", "-a", self.target]
            run_command(cmd, output_file=output_file, timeout=600)
            ran_something = True
        else:
            logger.warn("enum4linux tidak ditemukan, skip ke smbclient")
        
        # 2. smbclient -L untuk list shares (null session)
        if is_tool_installed("smbclient"):
            logger.info("Listing SMB shares via null session...")
            output_file = self.output_dir / "smbclient_shares.md"
            cmd = ["smbclient", "-L", f"//{self.target}/", "-N"]
            run_command(cmd, output_file=output_file, timeout=60)
            ran_something = True
        
        if not ran_something:
            logger.error("Tidak ada SMB tool tersedia. Install: sudo apt install smbclient enum4linux-ng")
            return False
        
        return True
