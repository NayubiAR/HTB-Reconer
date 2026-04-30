"""
modules/nmap_scan.py
Stage 1: Nmap fast scan.
Strategy: scan top 1000 ports dulu dengan service detection.
Output XML untuk parsing, juga .txt untuk manual review.
"""
from pathlib import Path
from modules.base_module import BaseModule
from core.runner import run_command
from core import logger


class NmapModule(BaseModule):
    tool_name = "nmap"
    module_name = "Nmap Fast Scan"
    
    def run(self, **kwargs) -> bool:
        if not self.check_prerequisites():
            return False
        
        logger.banner(f"{self.module_name} on {self.target}")
        
        xml_output = self.output_dir / "nmap_fast.xml"
        txt_output = self.output_dir / "nmap_fast.txt"
        
        # -sV: service/version detection
        # -T4: aggressive timing (safe for HTB labs)
        # --top-ports 1000: default, cukup untuk fase awal
        # -oA: output semua format (xml, nmap, gnmap) dengan base name
        # -Pn: skip host discovery (HTB biasanya block ICMP)
        cmd = [
            "nmap",
            "-sV",
            "-T4",
            "-Pn",
            "--top-ports", "1000",
            "-oX", str(xml_output),
            "-oN", str(txt_output),
            self.target,
        ]
        
        success, _ = run_command(cmd, timeout=900)
        
        if success:
            logger.success(f"Nmap scan selesai. Output: {xml_output}")
        return success
    
    def get_xml_path(self) -> Path:
        """Expose path XML untuk di-parse oleh orchestrator."""
        return self.output_dir / "nmap_fast.xml"
