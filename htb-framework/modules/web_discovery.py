"""
modules/web_discovery.py
Web Directory & Subdomain Discovery Wrapper.

Multi-tool integration: ffuf, gobuster, dirsearch.
Setiap tool dipakai untuk task yang sesuai kekuatannya:
- gobuster:   directory bruteforce (cepat, output bersih)
- ffuf:       subdomain/vhost discovery + advanced filtering
- dirsearch:  recursive scan dengan smart extension handling

Features:
1. Auto-Wordlist: pilih wordlist berdasarkan tech yang terdeteksi
2. Auto-Filter: hilangkan false positives via baseline calibration
3. Multi-Mode: dir | subdomain | vhost (bisa kombinasi)
"""
from pathlib import Path
from modules.base_module import BaseModule
from core.runner import run_command
from core.utils import get_wordlist, is_tool_installed, get_wordlist_info
from core.web_detector import detect_technologies
from core import logger


class WebDiscoveryModule(BaseModule):
    """
    Modul advanced web discovery yang menggabungkan 3 tool.
    
    Berbeda dengan web_enum.py (basic gobuster), modul ini:
    - Auto-detect tech sebelum scan
    - Pilih wordlist & extensions secara otomatis
    - Filter false positives dengan baseline calibration
    - Support subdomain & vhost discovery
    """
    
    tool_name = "ffuf"  # Primary tool, fallback ke gobuster
    module_name = "Advanced Web Discovery"
    
    def run(
        self,
        port: int = 80,
        wordlist: str = None,
        profile: str = "default",
        modes: list = None,        # ["dir", "subdomain", "vhost"]
        domain: str = None,         # untuk subdomain/vhost
        **kwargs,
    ) -> bool:
        """
        Args:
            port: Target port.
            wordlist: Override wordlist eksplisit.
            profile: 'quick' | 'default' | 'large'.
            modes: List mode yang dijalankan. Default ['dir'].
            domain: Domain untuk subdomain/vhost mode.
        """
        if modes is None:
            modes = ["dir"]
        
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{self.target}:{port}"
        
        logger.banner(f"{self.module_name} on {url}")
        
        # === STEP 1: Tech Detection ===
        tech_info = detect_technologies(url)
        
        # === STEP 2: Smart Wordlist Selection ===
        wordlist_path = self._select_wordlist(wordlist, profile, tech_info)
        if not wordlist_path:
            logger.error("Tidak ada wordlist yang tersedia")
            return False
        
        # === STEP 3: Smart Extensions ===
        extensions = self._select_extensions(tech_info)
        
        # === STEP 4: Run modes ===
        success_count = 0
        
        for mode in modes:
            if mode == "dir":
                if self._run_dir_discovery(url, wordlist_path, extensions, port):
                    success_count += 1
            elif mode == "subdomain":
                if self._run_subdomain_discovery(domain or self.target, profile):
                    success_count += 1
            elif mode == "vhost":
                if self._run_vhost_discovery(url, domain or self.target, profile):
                    success_count += 1
            else:
                logger.warn(f"Mode tidak dikenal: {mode}")
        
        return success_count > 0
    
    # ========================================================================
    # WORDLIST & EXTENSION SELECTION (Auto-Wordlist Feature)
    # ========================================================================
    
    def _select_wordlist(self, explicit_wl, profile, tech_info) -> str:
        """
        Smart wordlist selection.
        
        Priority:
        1. Explicit wordlist dari user (override semua)
        2. CMS-specific kalau detected (wordpress, joomla, drupal)
        3. Profile default berdasarkan profile flag
        """
        # Priority 1: explicit
        if explicit_wl and Path(explicit_wl).exists():
            logger.info(f"Pakai wordlist eksplisit: {explicit_wl}")
            return explicit_wl
        
        # Priority 2: CMS-specific
        cms_category = tech_info.get("wordlist_category")
        if cms_category:
            cms_wl = get_wordlist(cms_category)
            if cms_wl:
                logger.success(f"Auto-pilih wordlist {cms_category}: {cms_wl}")
                return cms_wl
            logger.warn(f"Wordlist {cms_category} tidak ada, fallback ke default")
        
        # Priority 3: profile default
        profile_map = {
            "quick": "dir_quick",
            "default": "dir_default",
            "large": "dir_large",
        }
        category = profile_map.get(profile, "dir_default")
        wl = get_wordlist(category)
        
        if wl:
            info = get_wordlist_info(wl)
            logger.info(
                f"Pakai wordlist {category}: {wl} "
                f"({info.get('lines', 0):,} entries)"
            )
        return wl
    
    def _select_extensions(self, tech_info) -> list:
        """
        Pilih extensions berdasarkan tech yang terdeteksi.
        Default fallback: extensions umum web.
        """
        detected_ext = tech_info.get("extensions", [])
        
        if detected_ext:
            logger.success(f"Auto-pilih extensions: {','.join(detected_ext)}")
            return detected_ext
        
        # Default fallback - ekstensi paling umum
        default_ext = ["php", "html", "txt", "bak", "old"]
        logger.info(f"Pakai extensions default: {','.join(default_ext)}")
        return default_ext
    
    # ========================================================================
    # DIRECTORY DISCOVERY (with auto-filter)
    # ========================================================================
    
    def _run_dir_discovery(self, url, wordlist, extensions, port) -> bool:
        """
        Directory bruteforce dengan auto-filter.
        Pakai ffuf (preferred) atau gobuster sebagai fallback.
        """
        # === BASELINE CALIBRATION (Auto-Filter Feature) ===
        # Cari size response untuk URL yang pasti tidak ada (random string)
        # Kalau Gobuster nemu hasil dengan size sama persis, itu false positive
        baseline = self._calibrate_baseline(url)
        
        if is_tool_installed("ffuf"):
            return self._run_ffuf_dir(url, wordlist, extensions, baseline, port)
        elif is_tool_installed("gobuster"):
            logger.warn("ffuf tidak terinstal, fallback ke gobuster")
            return self._run_gobuster_dir(url, wordlist, extensions, port)
        else:
            logger.error("Tidak ada tool web discovery (ffuf/gobuster). Install dulu!")
            return False
    
    def _calibrate_baseline(self, url) -> dict:
        """
        Baseline calibration untuk auto-filter false positives.
        
        Cara kerjanya: request URL yang PASTI tidak ada (random gibberish).
        Response size & status itu jadi "baseline" untuk filter.
        Hasil scan yang match baseline = pasti false positive.
        
        Ini penting karena banyak server return status 200 dengan halaman
        custom 404, bukan status 404 beneran.
        """
        from core.web_detector import fetch_http_response
        
        logger.info("Calibrating baseline (deteksi false positive)...")
        
        # Random string yang HAMPIR pasti tidak ada
        fake_path = "ZZZZZZZZ_nonexistent_path_for_calibration_xyz123"
        baseline_url = f"{url.rstrip('/')}/{fake_path}"
        
        headers, body = fetch_http_response(baseline_url, timeout=5)
        
        baseline = {
            "size": len(body) if body else 0,
            "status_pattern": None,  # akan diisi ffuf dengan -ac flag
        }
        
        if baseline["size"] > 0:
            logger.info(f"Baseline size: {baseline['size']} bytes (akan di-filter)")
        
        return baseline
    
    def _run_ffuf_dir(self, url, wordlist, extensions, baseline, port) -> bool:
        """
        ffuf untuk directory discovery dengan filter advanced.
        
        Sintaks ffuf modern:
        - FUZZ keyword di URL = posisi yang di-fuzz
        - -mc all = match semua status (kita filter manual)
        - -fc 404 = filter status 404
        - -fs <size> = filter ukuran response yang sama dengan baseline
        - -ac = auto-calibrate (ffuf otomatis cari baseline sendiri)
        """
        output_file = self.output_dir / f"ffuf_dir_{port}.json"
        readable_file = self.output_dir / f"ffuf_dir_{port}.md"
        
        ext_str = "," + ",".join(extensions) if extensions else ""
        
        cmd = [
            "ffuf",
            "-u", f"{url}/FUZZ",
            "-w", wordlist,
            "-e", ext_str,                    # Extensions yang dicoba
            "-mc", "200,204,301,302,307,401,403,405",  # Match codes (HILANGKAN 404)
            "-fc", "404",                     # Explicit filter 404
            "-ac",                            # Auto-calibration (smart baseline)
            "-acc", "200",                    # Calibrate spesifik untuk status 200
            "-t", "50",                       # Threads
            "-o", str(output_file),
            "-of", "json",                    # Format JSON untuk parsing
            "-s",                             # Silent mode (clean output)
        ]
        
        # Filter explicit baseline size kalau ada
        if baseline.get("size", 0) > 0:
            cmd.extend(["-fs", str(baseline["size"])])
        
        # Skip TLS verify untuk HTTPS self-signed
        if url.startswith("https://"):
            cmd.extend(["-k"])
        
        logger.info(f"Running ffuf with auto-filter (404 + baseline size)...")
        success, output = run_command(cmd, timeout=1800, show_output=False)
        
        # Convert JSON ke Markdown yang readable
        if success:
            self._convert_ffuf_to_markdown(output_file, readable_file, url)
            logger.success(f"ffuf selesai. Hasil: {readable_file}")
        
        return success
    
    def _run_gobuster_dir(self, url, wordlist, extensions, port) -> bool:
        """Fallback ke gobuster kalau ffuf tidak ada."""
        output_file = self.output_dir / f"gobuster_dir_{port}.md"
        
        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-o", str(output_file),
            "-t", "50",
            "-x", ",".join(extensions),
            "-b", "404,403",                  # blacklist status codes
            "--no-error",
            "-q",
        ]
        
        if url.startswith("https://"):
            cmd.append("-k")
        
        success, _ = run_command(cmd, timeout=1800)
        if success:
            logger.success(f"gobuster selesai: {output_file}")
        return success
    
    def _convert_ffuf_to_markdown(self, json_file: Path, md_file: Path, url: str):
        """
        Convert ffuf JSON output ke markdown human-readable.
        Sortir berdasarkan status code, group by interesting findings.
        """
        import json
        
        try:
            with open(json_file) as f:
                data = json.load(f)
        except Exception as e:
            logger.warn(f"Gagal parse JSON ffuf: {e}")
            return
        
        results = data.get("results", [])
        if not results:
            md_file.write_text("# ffuf Results\n\nTidak ada hasil ditemukan.\n")
            return
        
        # Group by status code
        by_status = {}
        for r in results:
            status = r.get("status", 0)
            by_status.setdefault(status, []).append(r)
        
        # Write markdown
        lines = [f"# ffuf Discovery Results - {url}\n"]
        lines.append(f"Total findings: {len(results)}\n")
        
        # Sortir status: 200 dulu (paling menarik), lalu redirect, lalu auth
        for status in sorted(by_status.keys()):
            entries = by_status[status]
            
            label = {
                200: "✓ OK (Accessible)",
                301: "→ Moved Permanently",
                302: "→ Found (Redirect)",
                401: "🔒 Unauthorized",
                403: "🚫 Forbidden",
                500: "⚠ Server Error",
            }.get(status, f"Status {status}")
            
            lines.append(f"\n## [{status}] {label} - {len(entries)} entries\n")
            for r in sorted(entries, key=lambda x: x.get("url", "")):
                url_path = r.get("url", "")
                size = r.get("length", 0)
                lines.append(f"- `{url_path}` (size: {size})")
        
        md_file.write_text("\n".join(lines) + "\n")
    
    # ========================================================================
    # SUBDOMAIN DISCOVERY (ffuf dengan Host header fuzzing)
    # ========================================================================
    
    def _run_subdomain_discovery(self, domain, profile) -> bool:
        """
        Subdomain bruteforce via DNS query.
        Pakai gobuster dns mode (sintaks modern: dns subcommand).
        """
        if not is_tool_installed("gobuster"):
            logger.error("gobuster diperlukan untuk subdomain discovery")
            return False
        
        # Pilih wordlist subdomain sesuai profile
        wl_map = {
            "quick": "subdomain_quick",
            "default": "subdomain_default",
            "large": "subdomain_large",
        }
        wordlist = get_wordlist(wl_map.get(profile, "subdomain_default"))
        if not wordlist:
            logger.error("Wordlist subdomain tidak tersedia")
            return False
        
        output_file = self.output_dir / "subdomains.md"
        
        # Sintaks gobuster modern untuk DNS:
        # gobuster dns -d <domain> -w <wordlist>
        cmd = [
            "gobuster", "dns",
            "-d", domain,
            "-w", wordlist,
            "-o", str(output_file),
            "-t", "50",
            "-q",
        ]
        
        logger.info(f"Subdomain discovery untuk {domain}...")
        success, _ = run_command(cmd, timeout=900)
        if success:
            logger.success(f"Subdomain discovery selesai: {output_file}")
        return success
    
    # ========================================================================
    # VHOST DISCOVERY (ffuf - virtual host bruteforce)
    # ========================================================================
    
    def _run_vhost_discovery(self, url, domain, profile) -> bool:
        """
        Virtual host discovery: cari hostname yang di-host di IP yang sama.
        Berbeda dengan subdomain — vhost tidak butuh DNS resolution.
        
        Teknik: kirim request dengan Host header berbeda-beda,
        cari yang return content berbeda dari baseline.
        """
        if not is_tool_installed("ffuf"):
            logger.warn("ffuf diperlukan untuk vhost discovery, skip")
            return False
        
        wl_map = {
            "quick": "subdomain_quick",
            "default": "vhost",
            "large": "subdomain_large",
        }
        wordlist = get_wordlist(wl_map.get(profile, "vhost"))
        if not wordlist:
            return False
        
        output_file = self.output_dir / "vhosts.json"
        readable_file = self.output_dir / "vhosts.md"
        
        # ffuf dengan -H untuk fuzz Host header
        cmd = [
            "ffuf",
            "-u", url,
            "-H", f"Host: FUZZ.{domain}",
            "-w", wordlist,
            "-mc", "200,301,302,401,403",
            "-ac",                            # Auto-calibrate
            "-t", "50",
            "-o", str(output_file),
            "-of", "json",
            "-s",
        ]
        
        if url.startswith("https://"):
            cmd.extend(["-k"])
        
        logger.info(f"Vhost discovery untuk {domain}...")
        success, _ = run_command(cmd, timeout=900, show_output=False)
        if success:
            self._convert_ffuf_to_markdown(output_file, readable_file, f"vhosts on {url}")
            logger.success(f"Vhost discovery selesai: {readable_file}")
        return success