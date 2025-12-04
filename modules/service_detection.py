"""
Service Detection and Banner Grabbing
Identifies services running on open ports via banner analysis
"""

import socket
from typing import Dict, Optional
from config import SERVICE_SIGNATURES, DEFAULT_TIMEOUT


class ServiceDetector:
    def __init__(self, target: str, timeout: float = DEFAULT_TIMEOUT):
        self.target = target
        self.timeout = timeout
    
    def grab_banner(self, port: int) -> Optional[str]:
        """
        Attempt to grab banner from a port
        Returns: Banner string or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            
            # Try sending HTTP request for web servers
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n")
            
            banner = sock.recv(1024)
            sock.close()
            
            return banner.decode('utf-8', errors='ignore').strip()
        except:
            return None
    
    def identify_service(self, port: int, banner: Optional[str] = None) -> Dict:
        """
        Identify service on a port using banner matching and common port knowledge
        Returns: Dictionary with service information
        """
        if banner is None:
            banner = self.grab_banner(port)
        
        service_info = {
            'port': port,
            'service': 'unknown',
            'version': 'unknown',
            'banner': banner if banner else 'No banner'
        }
        
        # Banner-based identification
        if banner:
            banner_bytes = banner.encode()
            for service_name, signatures in SERVICE_SIGNATURES.items():
                if any(sig in banner_bytes for sig in signatures):
                    service_info['service'] = service_name
                    service_info['version'] = self._extract_version(banner)
                    return service_info
        
        # Fallback to common port-service mapping
        common_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-ALT'
        }
        
        if port in common_services:
            service_info['service'] = common_services[port]
        
        return service_info
    
    def _extract_version(self, banner: str) -> str:
        """Extract version information from banner"""
        import re
        
        # Common version patterns
        patterns = [
            r'(\d+\.\d+\.\d+)',  # X.Y.Z
            r'(\d+\.\d+)',       # X.Y
            r'[vV]ersion[\s:]+(\S+)',
            r'[/\s](\d+\.\d+\S*)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner)
            if match:
                return match.group(1)
        
        return 'unknown'
    
    def detect_services(self, open_ports: list[int]) -> Dict[int, Dict]:
        """
        Detect services on all open ports
        Returns: Dictionary mapping port -> service info
        """
        services = {}
        print(f"[*] Detecting services on {len(open_ports)} open ports...")
        
        for port in open_ports:
            services[port] = self.identify_service(port)
            print(f"    Port {port}: {services[port]['service']}")
        
        return services
