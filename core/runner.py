"""
core/runner.py
Wrapper subprocess. Penting: kita PAKAI subprocess.run() dengan list args,
BUKAN shell=True, untuk mencegah command injection.
"""
import subprocess
from pathlib import Path
from core import logger


def run_command(
    cmd: list,
    output_file: Path = None,
    timeout: int = 600,
    show_output: bool = True,
) -> tuple[bool, str]:
    """
    Jalankan command sebagai list of args.
    
    Args:
        cmd: List argumen, contoh: ["nmap", "-sV", "10.10.10.10"]
        output_file: Path untuk simpan stdout. Jika None, tidak disimpan.
        timeout: Maksimum waktu eksekusi (detik).
        show_output: Tampilkan output real-time ke terminal.
    
    Returns:
        (success: bool, output: str)
    """
    logger.info(f"Executing: {' '.join(cmd)}")
    
    try:
        # capture_output=True menangkap stdout+stderr
        # text=True otomatis decode bytes -> string
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,  # Jangan raise exception di non-zero exit
        )
        
        combined_output = result.stdout + result.stderr
        
        if show_output and result.stdout:
            print(result.stdout)
        
        # Simpan ke file jika diminta
        if output_file:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(f"# Command: {' '.join(cmd)}\n\n")
                f.write(combined_output)
            logger.success(f"Output saved: {output_file}")
        
        # Exit code 0 = success di sebagian besar tools
        if result.returncode == 0:
            return True, combined_output
        else:
            logger.warn(f"Command exited with code {result.returncode}")
            return False, combined_output
            
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout}s")
        return False, ""
    except FileNotFoundError:
        logger.error(f"Tool not found: {cmd[0]}")
        return False, ""
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return False, ""