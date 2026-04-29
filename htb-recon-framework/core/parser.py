"""
core/parser.py
Parse hasil Nmap XML (flag -oX). Lebih reliable daripada regex ke text output.
"""
import xml.etree.ElementTree as ET
from pathlib import Path
from core import logger


def parse_nmap_xml(xml_file: Path) -> list[dict]:
    """
    Parse file Nmap XML, return list of open ports.
    
    Struktur return:
    [
        {"port": 80, "protocol": "tcp", "service": "http", "product": "nginx"},
        {"port": 445, "protocol": "tcp", "service": "microsoft-ds", "product": ""},
    ]
    """
    if not xml_file.exists():
        logger.error(f"Nmap XML file not found: {xml_file}")
        return []
    
    open_ports = []
    
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        # Traverse: nmaprun -> host -> ports -> port
        for port in root.iter("port"):
            state_elem = port.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue
            
            service_elem = port.find("service")
            service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
            product = service_elem.get("product", "") if service_elem is not None else ""
            
            open_ports.append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "service": service_name,
                "product": product,
            })
        
        logger.success(f"Parsed {len(open_ports)} open ports from Nmap XML")
        return open_ports
        
    except ET.ParseError as e:
        logger.error(f"Failed to parse XML: {e}")
        return []
