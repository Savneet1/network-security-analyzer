"""
Configuration file for Network Security Analyzer
Author: Savneet Singh
GitHub: https://github.com/Savneet1/network-security-analyzer
"""

import os
from pathlib import Path

# Project paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "output_reports"

# Ensure directories exist
REPORTS_DIR.mkdir(exist_ok=True)

# Scanning configuration
DEFAULT_TIMEOUT = 1.0  # Socket timeout in seconds
MAX_THREADS = 100  # Maximum concurrent threads for scanning
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443
]

# OS Detection signatures (TTL-based + TCP window)
OS_SIGNATURES = {
    'Linux': {'ttl': 64, 'window': [5840, 32120, 29200], 'df': True},
    'Windows': {'ttl': 128, 'window': [64240, 65535, 8192], 'df': True},
    'Cisco': {'ttl': 255, 'window': [4128], 'df': False},
    'FreeBSD': {'ttl': 64, 'window': [65535], 'df': True},
    'OpenBSD': {'ttl': 64, 'window': [16384], 'df': False},
    'Solaris': {'ttl': 255, 'window': [24820], 'df': True}
}

# Service signatures for banner matching
SERVICE_SIGNATURES = {
    'SSH': [b'SSH-', b'OpenSSH'],
    'HTTP': [b'HTTP/', b'Server:', b'Apache', b'nginx', b'Microsoft-IIS'],
    'FTP': [b'220', b'FTP', b'vsFTPd', b'ProFTPD'],
    'SMTP': [b'220', b'SMTP', b'ESMTP', b'Postfix', b'Exim'],
    'MySQL': [b'mysql', b'MariaDB'],
    'PostgreSQL': [b'PostgreSQL'],
    'RDP': [b'\x03\x00\x00'],
    'SMB': [b'SMB', b'\xffSMB'],
    'Telnet': [b'Telnet', b'login:'],
    'DNS': [b'BIND', b'dnsmasq']
}

# NVD API configuration
NVD_API_KEY = os.getenv('NVD_API_KEY', None)  # Optional: export NVD_API_KEY="your-key"
NVD_DELAY = 0.6 if NVD_API_KEY else 6.0  # Seconds between API requests

# Firewall detection
FIREWALL_INDICATORS = {
    'filtered': 'Port appears filtered (no response/ICMP unreachable)',
    'closed': 'Port explicitly closed (RST received)',
    'open': 'Port open (SYN-ACK received)',
    'stealth': 'Stealth filtering detected (no response to SYN)'
}

# Output colors
COLORS = {
    'HEADER': '\033[95m',
    'BLUE': '\033[94m',
    'CYAN': '\033[96m',
    'GREEN': '\033[92m',
    'WARNING': '\033[93m',
    'FAIL': '\033[91m',
    'ENDC': '\033[0m',
    'BOLD': '\033[1m',
    'UNDERLINE': '\033[4m'
}
