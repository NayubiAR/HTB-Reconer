#!/usr/bin/env python3
"""
main.py
HTB Recon Framework - Entry Point

Usage:
    python3 main.py -t 10.10.11.100
    python3 main.py -t 10.10.11.100 -w /path/to/wordlist.txt
"""
import argparse
import sys
from pathlib import Path

from core import logger
from core.utils import validate_target, create_output_dir
from core.parser import parse_nmap_xml
from modules.nmap_scan import NmapModule
from modules.web_enum import WebEnumModule
from modules.smb_enum import SmbEnumModule


# Mapping port -> modul yang akan dijalankan
# Mudah di-extend: tambah entry baru di sini untuk service lain
PORT_MODULE_MAP = {
    80:   ("web",  WebEnumModule),
    443:  ("web",  WebEnumModule),
    8080: ("web",  WebEnumModule),
    8443: ("web",  WebEnumModule),
    445:  ("smb",  SmbEnumModule),
    139:  ("smb",  SmbEnumModule),
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="HTB Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t", "--target", required=True, help="IP address or hostname target")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist untuk gobuster")
    parser.add_argument("-o", "--output", default="results", help="Base output directory")
    parser.add_argument("--skip-nmap", action="store_true", help="Skip Nmap, pakai XML existing")
    parser.add_argument(
        "--no-timestamp",
        action="store_true",
        help="Disable timestamp subfolder (WARNING: akan overwrite scan sebelumnya)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    
    # === Validasi input ===
    if not validate_target(args.target):
        logger.error(f"Target tidak valid: {args.target}")
        sys.exit(1)
    
    # === Setup output directory ===
    output_dir = create_output_dir(
        args.target,
        args.output,
        use_timestamp=not args.no_timestamp,
    )
    logger.success(f"Output directory: {output_dir}")
    
    # === STAGE 1: Nmap Scan ===
    nmap = NmapModule(args.target, output_dir)
    
    if not args.skip_nmap:
        if not nmap.run():
            logger.error("Nmap scan gagal. Exiting.")
            sys.exit(1)
    
    # === STAGE 2: Parse hasil & chaining ===
    open_ports = parse_nmap_xml(nmap.get_xml_path())
    
    if not open_ports:
        logger.warn("Tidak ada port terbuka ditemukan. Mungkin target down atau di-firewall.")
        sys.exit(0)
    
    # Print ringkasan
    logger.banner("OPEN PORTS SUMMARY")
    for p in open_ports:
        logger.success(f"  Port {p['port']}/{p['protocol']:3} - {p['service']} {p['product']}")
    
    # Hindari menjalankan modul yang sama berkali-kali
    # (misal port 80 dan 443 sama-sama trigger WebEnumModule)
    executed_modules = set()
    
    for p in open_ports:
        port_num = p["port"]
        if port_num not in PORT_MODULE_MAP:
            continue
        
        category, ModuleClass = PORT_MODULE_MAP[port_num]
        
        # Untuk web, jalankan per-port (karena URL-nya beda)
        # Untuk SMB, cukup sekali karena target-nya sama
        dedup_key = f"{category}_{port_num}" if category == "web" else category
        if dedup_key in executed_modules:
            continue
        executed_modules.add(dedup_key)
        
        module = ModuleClass(args.target, output_dir)
        
        # Pass argumen spesifik per-modul
        if category == "web":
            module.run(port=port_num, wordlist=args.wordlist)
        else:
            module.run()
    
    logger.banner("RECON SELESAI")
    logger.success(f"Semua hasil tersimpan di: {output_dir}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warn("\nInterrupted by user. Exiting...")
        sys.exit(130)