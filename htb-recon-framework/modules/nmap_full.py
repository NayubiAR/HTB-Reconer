"""
modules/nmap_full.py
Full port scan dengan -p- (semua 65535 ports).
Didesain untuk jalan di BACKGROUND sambil modul lain proses hasil fast scan.

Strategi 2-tahap:
  1. Fast scan (top-1000) → kasih insight cepat → trigger modul awal
  2. Full scan (-p-)      → background → catch port aneh (2222, 8888, dll)
                                       → trigger modul tambahan kalau perlu
"""
from pathlib import Path
from modules.base_module import BaseModule
from core.runner import run_command
from core import logger


class NmapFullModule(BaseModule):
    tool_name = "nmap"
    module_name = "Nmap Full Port Scan"
    
    def run(self, **kwargs) -> bool:
        if not self.check_prerequisites():
            return False
        
        logger.info(f"[BG] Full port scan started untuk {self.target}")
        
        xml_output = self.output_dir / "nmap_full.xml"
        txt_output = self.output_dir / "nmap_full.txt"
        
        # -p-          : semua port 1-65535
        # --min-rate   : kirim minimal 1000 paket/detik (HTB lab tahan ini)
        # -T4          : aggressive timing
        # -Pn          : skip ping
        # --open       : hanya tampilkan port open di output
        # CATATAN: tidak pakai -sV di sini biar cepat, version detection
        # nanti bisa di-trigger lagi untuk port-port spesifik kalau perlu
        cmd = [
            "nmap",
            "-p-",
            "--min-rate", "1000",
            "-T4",
            "-Pn",
            "--open",
            "-oX", str(xml_output),
            "-oN", str(txt_output),
            self.target,
        ]
        
        # Timeout lebih panjang karena full scan bisa makan waktu lama
        # Tidak show_output supaya tidak ganggu modul lain di terminal
        success, _ = run_command(cmd, timeout=1800, show_output=False)
        
        if success:
            logger.success(f"[BG] Full port scan SELESAI: {xml_output}")
        return success
    
    def get_xml_path(self) -> Path:
        return self.output_dir / "nmap_full.xml"
