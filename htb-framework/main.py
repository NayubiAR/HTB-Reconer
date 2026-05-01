#!/usr/bin/env python3
"""
main.py
HTB Recon Framework - Parallel Edition

Workflow paralel:

    [Nmap Fast Scan]
          |
          +--> [Nmap Full Scan -p-] (background, jalan paralel)
          |
          +--> Parse fast XML
                  |
                  v
              [Stage 2 Modules: PARALEL]
                - Gobuster:80
                - Gobuster:443
                - SMB enum
                - FTP enum
                  |
                  v
              [Wait full scan, trigger modul untuk port baru]
                  |
                  v
              [Recon Selesai]
"""
import argparse
import sys
from pathlib import Path

from core import logger
from core.banner import (
    show_banner,
    prompt_target,
    prompt_profile,
    prompt_yes_no,
    show_scan_summary,
)
from core.utils import (
    validate_target,
    create_output_dir,
    list_available_wordlists,
    get_wordlist_info,
)
from core.parser import parse_nmap_xml
from core.executor import ParallelExecutor
from modules.nmap_scan import NmapModule
from modules.nmap_full import NmapFullModule
from modules.web_enum import WebEnumModule
from modules.web_discovery import WebDiscoveryModule
from modules.smb_enum import SmbEnumModule
from modules.ftp_enum import FtpEnumModule


PORT_MODULE_MAP = {
    21:   ("ftp",  FtpEnumModule),
    80:   ("web",  WebEnumModule),
    443:  ("web",  WebEnumModule),
    8080: ("web",  WebEnumModule),
    8443: ("web",  WebEnumModule),
    445:  ("smb",  SmbEnumModule),
    139:  ("smb",  SmbEnumModule),
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="HTB Reconnaissance Framework (Parallel Edition)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t", "--target", help="IP address or hostname target")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist untuk gobuster (override profile)")
    parser.add_argument(
        "-p", "--profile",
        choices=["quick", "default", "large"],
        default="default",
        help="Wordlist profile: quick (<1m), default (~5m), large (20m+)",
    )
    parser.add_argument("-o", "--output", default="results", help="Base output directory")
    parser.add_argument("--skip-nmap", action="store_true", help="Skip Nmap, pakai XML existing")
    parser.add_argument(
        "--no-timestamp",
        action="store_true",
        help="Disable timestamp subfolder (WARNING: akan overwrite scan sebelumnya)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=5,
        help="Max concurrent modules (default: 5)",
    )
    parser.add_argument(
        "--no-full-scan",
        action="store_true",
        help="Skip background full port scan",
    )
    parser.add_argument(
        "--list-wordlists",
        action="store_true",
        help="Tampilkan semua wordlist yang tersedia di system, lalu exit",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip welcome banner",
    )
    parser.add_argument(
        "--no-interactive",
        action="store_true",
        help="Disable interactive prompt (untuk automation/scripting)",
    )
    parser.add_argument(
        "--advanced-web",
        action="store_true",
        help="Pakai web discovery advanced (ffuf + auto-detect tech + filter)",
    )
    parser.add_argument(
        "--web-modes",
        default="dir",
        help="Web discovery modes (comma-separated): dir,subdomain,vhost (default: dir)",
    )
    parser.add_argument(
        "--domain",
        help="Domain target (untuk subdomain/vhost mode, contoh: htb.local)",
    )
    return parser.parse_args()


def schedule_stage2_modules(
    target, output_dir, open_ports, wordlist, workers,
    profile="default", advanced_web=False, web_modes=None, domain=None,
):
    """
    Stage 2: jadwalkan modul enumerasi berdasarkan port terbuka.
    Semua modul jalan paralel.
    
    Args:
        advanced_web: True = pakai WebDiscoveryModule (ffuf + auto-detect)
                      False = pakai WebEnumModule basic (gobuster only)
        web_modes: List mode web discovery ['dir', 'subdomain', 'vhost']
        domain: Domain untuk subdomain/vhost mode
    """
    executor = ParallelExecutor(max_workers=workers)
    executed_keys = set()
    web_modes = web_modes or ["dir"]
    
    # Pilih modul web berdasarkan flag advanced
    WebClass = WebDiscoveryModule if advanced_web else WebEnumModule
    
    for p in open_ports:
        port_num = p["port"]
        if port_num not in PORT_MODULE_MAP:
            continue
        
        category, DefaultModuleClass = PORT_MODULE_MAP[port_num]
        # Override class web jika advanced
        ModuleClass = WebClass if category == "web" else DefaultModuleClass
        
        dedup_key = f"{category}_{port_num}" if category == "web" else category
        if dedup_key in executed_keys:
            continue
        executed_keys.add(dedup_key)
        
        module = ModuleClass(target, output_dir)
        
        if category == "web":
            task_kwargs = {
                "port": port_num,
                "wordlist": wordlist,
                "profile": profile,
            }
            # Hanya pass modes & domain jika pakai advanced module
            if advanced_web:
                task_kwargs["modes"] = web_modes
                task_kwargs["domain"] = domain
            
            executor.add_task(
                name=f"{category}_{port_num}",
                func=module.run,
                **task_kwargs,
            )
        else:
            executor.add_task(
                name=category,
                func=module.run,
                port=port_num,
            )
    
    if not executor.tasks:
        logger.warn("Tidak ada modul Stage 2 yang cocok")
        return {}
    
    return executor.run_all()


def find_new_ports(initial_ports, full_ports):
    """Return port yang HANYA ada di full scan (tidak di fast scan)."""
    initial_set = {p["port"] for p in initial_ports}
    return [p for p in full_ports if p["port"] not in initial_set]


def main():
    args = parse_args()
    
    # === Show banner (default ON, kecuali --no-banner) ===
    if not args.no_banner:
        show_banner()
    
    # === Handler --list-wordlists (jalan tanpa target) ===
    if args.list_wordlists:
        logger.banner("WORDLIST AVAILABILITY CHECK")
        available = list_available_wordlists()
        
        if not available:
            logger.error("Tidak ada wordlist yang ditemukan!")
            logger.info("Install: sudo apt install seclists wordlists")
            sys.exit(1)
        
        logger.success(f"Ditemukan {len(available)} wordlist preset:\n")
        for category, path in sorted(available.items()):
            info = get_wordlist_info(path)
            lines = info.get("lines", 0)
            print(f"  [{category:20s}] {lines:>10,} lines  {path}")
        
        from core.utils import WORDLISTS
        missing = set(WORDLISTS.keys()) - set(available.keys())
        if missing:
            logger.warn(f"\nTidak ditemukan: {', '.join(sorted(missing))}")
            logger.info("Install lebih banyak: sudo apt install seclists")
        sys.exit(0)
    
    # === INTERACTIVE MODE ===
    # Aktif jika: tidak ada --target DAN tidak ada --no-interactive
    is_interactive = not args.target and not args.no_interactive
    
    if is_interactive:
        # Prompt interaktif: target wajib, profile opsional
        args.target = prompt_target()
        args.profile = prompt_profile()
        
        # Tanya full scan (default Yes)
        args.no_full_scan = not prompt_yes_no(
            "Aktifkan background full port scan (-p-)?",
            default=True,
        )
        
        # Tanya advanced web discovery (BARU)
        args.advanced_web = prompt_yes_no(
            "Pakai Advanced Web Discovery? (ffuf + auto-detect tech + smart filter)",
            default=True,
        )
    
    # === Validasi target ===
    if not args.target:
        logger.error("Argument -t/--target wajib diisi (kecuali pakai --list-wordlists)")
        logger.info("Atau jalankan tanpa argumen untuk interactive mode")
        sys.exit(1)
    
    if not validate_target(args.target):
        logger.error(f"Target tidak valid: {args.target}")
        sys.exit(1)
    
    output_dir = create_output_dir(
        args.target,
        args.output,
        use_timestamp=not args.no_timestamp,
    )
    
    # === Show scan summary & konfirmasi (interactive only) ===
    if is_interactive:
        show_scan_summary(
            target=args.target,
            profile=args.profile,
            full_scan=not args.no_full_scan,
            output_dir=str(output_dir),
        )
        if not prompt_yes_no("Lanjutkan scan?", default=True):
            logger.info("Dibatalkan oleh user")
            sys.exit(0)
    
    logger.success(f"Output directory: {output_dir}")
    
    # === STAGE 1A: Fast Scan (foreground) ===
    nmap_fast = NmapModule(args.target, output_dir)
    if not args.skip_nmap:
        if not nmap_fast.run():
            logger.error("Nmap fast scan gagal. Exiting.")
            sys.exit(1)
    
    # === STAGE 1B: Full Scan (background) ===
    full_scan_future = None
    bg_executor = None
    if not args.no_full_scan and not args.skip_nmap:
        nmap_full = NmapFullModule(args.target, output_dir)
        bg_executor = ParallelExecutor()
        full_scan_future = bg_executor.run_background("nmap_full_scan", nmap_full.run)
    
    # === Parse Stage 1A ===
    open_ports = parse_nmap_xml(nmap_fast.get_xml_path())
    if not open_ports:
        logger.warn("Tidak ada port terbuka.")
        sys.exit(0)
    
    logger.banner("OPEN PORTS (Fast Scan)")
    for p in open_ports:
        logger.success(f"  {p['port']}/{p['protocol']:3} - {p['service']} {p['product']}")
    
    # === STAGE 2: Parallel Modules ===
    logger.banner("STAGE 2: PARALLEL ENUMERATION")
    web_modes_list = [m.strip() for m in args.web_modes.split(",")] if args.web_modes else ["dir"]
    schedule_stage2_modules(
        args.target, output_dir, open_ports,
        args.wordlist, args.workers, args.profile,
        advanced_web=args.advanced_web,
        web_modes=web_modes_list,
        domain=args.domain,
    )
    
    # === STAGE 3: Wait Full Scan + Trigger Module Baru ===
    if full_scan_future:
        logger.banner("STAGE 3: WAITING FULL PORT SCAN")
        logger.info("Menunggu full port scan selesai...")
        
        try:
            full_scan_success = full_scan_future.result(timeout=1800)
            
            if full_scan_success:
                full_xml = output_dir / "nmap_full.xml"
                full_ports = parse_nmap_xml(full_xml)
                new_ports = find_new_ports(open_ports, full_ports)
                
                if new_ports:
                    logger.banner(f"PORT BARU DITEMUKAN: {len(new_ports)}")
                    for p in new_ports:
                        logger.success(f"  {p['port']}/{p['protocol']} - {p['service']}")
                    
                    logger.info("Menjalankan modul untuk port baru...")
                    schedule_stage2_modules(
                        args.target, output_dir, new_ports,
                        args.wordlist, args.workers, args.profile,
                        advanced_web=args.advanced_web,
                        web_modes=web_modes_list,
                        domain=args.domain,
                    )
                else:
                    logger.success("Tidak ada port baru di full scan")
        except Exception as e:
            logger.error(f"Full scan error: {e}")
        finally:
            if hasattr(full_scan_future, "_executor"):
                full_scan_future._executor.shutdown(wait=False)
    
    logger.banner("RECON SELESAI")
    logger.success(f"Semua hasil tersimpan di: {output_dir}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warn("\nInterrupted by user. Exiting...")
        sys.exit(130)