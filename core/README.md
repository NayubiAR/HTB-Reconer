# HTB Recon Framework

Modular reconnaissance automation untuk HackTheBox / lab CTF.

## Install Dependencies (Kali Linux)

```bash
sudo apt update
sudo apt install -y nmap gobuster smbclient enum4linux-ng seclists
```

Framework ini **zero-dependency** di sisi Python (hanya pakai stdlib).

## Usage

```bash
# Basic scan
python3 main.py -t 10.10.11.100

# Custom wordlist
python3 main.py -t 10.10.11.100 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Skip Nmap jika sudah pernah scan
python3 main.py -t 10.10.11.100 --skip-nmap
```

## Workflow

1. **Stage 1** — Nmap fast scan (top 1000 ports, -sV, -Pn)
2. **Stage 2** — Parse XML, trigger modul berdasarkan port terbuka:
   - Port 80/443/8080/8443 → Gobuster (dir mode)
   - Port 139/445 → enum4linux-ng + smbclient

## Struktur Output

```
results/
└── 10.10.11.100/
    ├── nmap_fast.xml         # Parseable
    ├── nmap_fast.txt         # Human-readable
    ├── gobuster_80.md
    ├── enum4linux.md
    └── smbclient_shares.md
```

## Extending Framework

Tambah modul baru dengan inherit `BaseModule`:

```python
# modules/ftp_enum.py
from modules.base_module import BaseModule

class FtpEnumModule(BaseModule):
    tool_name = "ftp"
    module_name = "FTP Enumeration"
    
    def run(self, **kwargs) -> bool:
        if not self.check_prerequisites():
            return False
        # ... logic here
```

Lalu register di `main.py` → `PORT_MODULE_MAP`.