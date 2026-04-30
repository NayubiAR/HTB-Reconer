"""
modules/base_module.py
Abstract base class. Setiap modul tool harus inherit dari sini.
Ini enforces interface yang konsisten: semua modul punya .run() method.
"""
from abc import ABC, abstractmethod
from pathlib import Path
from core import logger
from core.utils import is_tool_installed


class BaseModule(ABC):
    tool_name: str = ""     # Override di subclass, contoh: "gobuster"
    module_name: str = ""   # Nama display, contoh: "Web Enumeration"
    
    def __init__(self, target: str, output_dir: Path):
        self.target = target
        self.output_dir = output_dir
    
    def check_prerequisites(self) -> bool:
        """Validasi tool sudah terinstal sebelum run."""
        if not is_tool_installed(self.tool_name):
            logger.error(
                f"{self.tool_name} tidak ditemukan. "
                f"Install dengan: sudo apt install {self.tool_name}"
            )
            return False
        return True
    
    @abstractmethod
    def run(self, **kwargs) -> bool:
        """Execute modul. Harus di-override di subclass."""
        pass
