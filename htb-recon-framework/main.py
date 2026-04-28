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
from core.utils import validate_target, create_output_dir
from core.parser import parse_nmap_xml
from core.executor import ParallelExecutor
from modules.nmap_scan import NmapModule
from modules.nmap_full import NmapFullModule
from modules.web_enum import WebEnumModule
from modules.smb_enum import SmbEnumModule


PORT_MODULE_MAP = {
    80: ("web", WebEnumModule),
    443: ("web", WebEnumModule),
    8080: ("web", WebEnumModule),
    8443: ("web", WebEnumModule),
    445: ("smb", SmbEnumModule),
    139: ("smb", SmbEnumModule),
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="HTB Reconnaissance Framework (Parallel Edition)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-t", "--target", required=True, help="IP address or hostname target"
    )
    parser.add_argument("-w", "--wordlist", help="Custom wordlist untuk gobuster")
    parser.add_argument(
        "-o", "--output", default="results", help="Base output directory"
    )
    parser.add_argument(
        "--skip-nmap", action="store_true", help="Skip Nmap, pakai XML existing"
    )
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
    return parser.parse_args()


def schedule_stage2_modules(target, output_dir, open_ports, wordlist, workers):
    """
    Stage 2: jadwalkan modul enumerasi berdasarkan port terbuka.
    Semua modul jalan paralel.
    """
    executor = ParallelExecutor(max_workers=workers)
    executed_keys = set()

    for p in open_ports:
        port_num = p["port"]
        if port_num not in PORT_MODULE_MAP:
            continue

        category, ModuleClass = PORT_MODULE_MAP[port_num]
        dedup_key = f"{category}_{port_num}" if category == "web" else category
        if dedup_key in executed_keys:
            continue
        executed_keys.add(dedup_key)

        module = ModuleClass(target, output_dir)

        if category == "web":
            executor.add_task(
                name=f"{category}_{port_num}",
                func=module.run,
                port=port_num,
                wordlist=wordlist,
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

    if not validate_target(args.target):
        logger.error(f"Target tidak valid: {args.target}")
        sys.exit(1)

    output_dir = create_output_dir(
        args.target,
        args.output,
        use_timestamp=not args.no_timestamp,
    )
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
        logger.success(
            f"  {p['port']}/{p['protocol']:3} - {p['service']} {p['product']}"
        )

    # === STAGE 2: Parallel Modules ===
    logger.banner("STAGE 2: PARALLEL ENUMERATION")
    schedule_stage2_modules(
        args.target,
        output_dir,
        open_ports,
        args.wordlist,
        args.workers,
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
                        logger.success(
                            f"  {p['port']}/{p['protocol']} - {p['service']}"
                        )

                    logger.info("Menjalankan modul untuk port baru...")
                    schedule_stage2_modules(
                        args.target,
                        output_dir,
                        new_ports,
                        args.wordlist,
                        args.workers,
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
