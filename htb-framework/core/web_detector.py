"""
core/web_detector.py
Web Technology Fingerprinting.

Deteksi teknologi yang dipakai target:
- Web Server (Apache, Nginx, IIS)
- Backend Language (PHP, ASP.NET, Java, Python)
- CMS (WordPress, Joomla, Drupal)
- Framework (Laravel, Django, Express)

Hasil deteksi dipakai untuk pilih wordlist yang relevan.
Contoh: kalau detect Apache + PHP, pakai wordlist PHP.
"""
import re
import urllib.request
import urllib.error
import ssl
from core import logger


# Patterns untuk detect teknologi dari HTTP response
# Order matters: yang lebih spesifik di atas (misal WordPress > PHP)
TECH_PATTERNS = {
    # === CMS (paling spesifik dulu) ===
    "wordpress": {
        "headers": [r"x-powered-by:.*wordpress"],
        "body": [r"/wp-content/", r"/wp-includes/", r"wp-json"],
        "wordlist_category": "wordpress",
        "extensions": ["php"],
    },
    "joomla": {
        "headers": [],
        "body": [r"/components/com_", r"Joomla!", r"/templates/system/"],
        "wordlist_category": "joomla",
        "extensions": ["php"],
    },
    "drupal": {
        "headers": [r"x-generator:.*drupal"],
        "body": [r"/sites/default/files/", r"Drupal\.settings"],
        "wordlist_category": "drupal",
        "extensions": ["php"],
    },
    
    # === Backend Language ===
    "php": {
        "headers": [r"x-powered-by:.*php", r"set-cookie:.*phpsessid"],
        "body": [r"\.php\"", r"\.php\?"],
        "wordlist_category": None,  # pakai dir_default tapi extensions PHP
        "extensions": ["php", "phtml", "php3", "php5", "phps"],
    },
    "aspnet": {
        "headers": [r"x-powered-by:.*asp\.net", r"x-aspnet-version", r"set-cookie:.*asp\.net_sessionid"],
        "body": [r"__VIEWSTATE", r"\.aspx\""],
        "wordlist_category": None,
        "extensions": ["aspx", "asp", "ashx", "asmx"],
    },
    "java": {
        "headers": [r"x-powered-by:.*(jsp|servlet|tomcat)", r"set-cookie:.*jsessionid"],
        "body": [r"\.jsp\"", r"\.do\""],
        "wordlist_category": None,
        "extensions": ["jsp", "do", "action"],
    },
    "python": {
        "headers": [r"server:.*(python|werkzeug|gunicorn)"],
        "body": [r"django", r"flask"],
        "wordlist_category": None,
        "extensions": ["py"],
    },
    "nodejs": {
        "headers": [r"x-powered-by:.*express"],
        "body": [],
        "wordlist_category": None,
        "extensions": ["js"],
    },
    
    # === Web Server ===
    "apache": {
        "headers": [r"server:.*apache"],
        "body": [],
        "wordlist_category": None,
        "extensions": [],
    },
    "nginx": {
        "headers": [r"server:.*nginx"],
        "body": [],
        "wordlist_category": None,
        "extensions": [],
    },
    "iis": {
        "headers": [r"server:.*microsoft-iis"],
        "body": [],
        "wordlist_category": None,
        "extensions": ["asp", "aspx"],
    },
}


def fetch_http_response(url: str, timeout: int = 10) -> tuple[dict, str]:
    """
    Fetch HTTP response (headers + body) dari URL.
    
    Pakai urllib bawaan Python (zero dependency).
    Return: (headers_dict, body_string)
    """
    try:
        # Bypass SSL verify untuk self-signed cert (umum di HTB)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # Custom User-Agent biar tidak di-block oleh server
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) HTBRecon/1.0"},
        )
        
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            # Headers dict (case-insensitive lookup)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            # Body, limit 50KB agar tidak download halaman besar
            body = resp.read(50000).decode("utf-8", errors="ignore")
            return headers, body
            
    except urllib.error.HTTPError as e:
        # Error 404/500 dll tetap berguna - kita masih dapat headers
        headers = {k.lower(): v for k, v in e.headers.items()}
        try:
            body = e.read(50000).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return headers, body
    except Exception as e:
        logger.warn(f"Gagal fetch {url}: {e}")
        return {}, ""


def detect_technologies(url: str) -> dict:
    """
    Deteksi teknologi web dari URL target.
    
    Returns:
        {
            "detected": ["wordpress", "php", "apache"],
            "extensions": ["php", "phtml"],
            "cms": "wordpress",        # atau None
            "wordlist_category": "wordpress",  # atau None
            "raw_server": "Apache/2.4.41",
        }
    """
    logger.info(f"Detecting web technologies on {url}...")
    
    headers, body = fetch_http_response(url)
    
    if not headers and not body:
        logger.warn("Tidak bisa fetch response dari target")
        return {"detected": [], "extensions": [], "cms": None, "wordlist_category": None}
    
    # Gabungkan headers jadi single string untuk regex matching
    # Format: "key: value\nkey: value\n..."
    headers_str = "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()
    
    detected = []
    all_extensions = set()
    cms = None
    wordlist_category = None
    
    for tech_name, patterns in TECH_PATTERNS.items():
        # Cek di headers
        header_match = any(
            re.search(p, headers_str, re.IGNORECASE)
            for p in patterns["headers"]
        )
        # Cek di body
        body_match = any(
            re.search(p, body, re.IGNORECASE)
            for p in patterns["body"]
        )
        
        if header_match or body_match:
            detected.append(tech_name)
            all_extensions.update(patterns["extensions"])
            
            # Set CMS kalau detected (priority: yang ditemukan pertama)
            if patterns["wordlist_category"] and not cms:
                cms = tech_name
                wordlist_category = patterns["wordlist_category"]
    
    result = {
        "detected": detected,
        "extensions": sorted(all_extensions),
        "cms": cms,
        "wordlist_category": wordlist_category,
        "raw_server": headers.get("server", "unknown"),
    }
    
    # Log hasil
    if detected:
        logger.success(f"Detected: {', '.join(detected)}")
        if all_extensions:
            logger.info(f"Suggested extensions: {', '.join(sorted(all_extensions))}")
        if cms:
            logger.success(f"CMS detected: {cms} → akan pakai wordlist '{wordlist_category}'")
    else:
        logger.warn("Tidak ada teknologi spesifik yang terdeteksi")
    
    return result