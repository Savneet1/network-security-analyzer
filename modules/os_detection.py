"""
OS Detection via TCP/IP Stack Fingerprinting
Uses Scapy for packet crafting and TTL/Window analysis
"""

try:
    from scapy.all import IP, TCP, sr1, conf
    conf.verb = 0  # Suppress Scapy output
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from typing import Dict, Optional
from config import OS_SIGNATURES


class OSDetector:
    def __init__(self, target: str):
        self.target = target
        self.os_info = {
            'detected_os': 'Unknown',
            'confidence': 'Low',
            'ttl': None,
            'window_size': None,
            'df_flag': None,
            'details': []
        }
    
    def detect_os(self) -> Dict:
        """
        Perform OS detection using TCP/IP fingerprinting
        Returns: Dictionary with OS detection results
        """
        if not SCAPY_AVAILABLE:
            self.os_info['details'].append('Scapy not available - OS detection disabled')
            return self.os_info
        
        try:
            # Send SYN packet to port 80 (or 443 if 80 fails)
            ports_to_try = [80, 443, 22]
            response = None
            
            for port in ports_to_try:
                print(f"[*] Probing {self.target}:{port} for OS detection...")
                packet = IP(dst=self.target)/TCP(dport=port, flags='S')
                response = sr1(packet, timeout=2, verbose=0)
                if response:
                    break
            
            if not response or not response.haslayer(TCP):
                self.os_info['details'].append('No response received for OS detection')
                return self.os_info
            
            # Extract fingerprint values
            ttl = response.getlayer(IP).ttl
            window = response.getlayer(TCP).window
            df_flag = bool(response.getlayer(IP).flags & 0x02)  # DF bit check
            
            self.os_info['ttl'] = ttl
            self.os_info['window_size'] = window
            self.os_info['df_flag'] = df_flag
            
            # Match against signatures
            detected = self._match_signature(ttl, window, df_flag)
            
            if detected:
                self.os_info['detected_os'] = detected
                self.os_info['confidence'] = 'High' if detected != 'Unix-like' else 'Medium'
                self.os_info['details'].append(f'TTL: {ttl}, Window: {window}, DF: {df_flag}')
            else:
                self.os_info['detected_os'] = 'Unknown OS'
                self.os_info['confidence'] = 'Low'
                self.os_info['details'].append(f'Uncommon signature - TTL: {ttl}, Window: {window}')
            
        except Exception as e:
            self.os_info['details'].append(f'OS detection error: {str(e)}')
        
        return self.os_info
    
    def _match_signature(self, ttl: int, window: int, df: bool) -> Optional[str]:
        """
        Match fingerprint against known OS signatures
        """
        # Normalize TTL (account for router hops - typical initial TTLs: 64, 128, 255)
        if ttl <= 64:
            normalized_ttl = 64
        elif ttl <= 128:
            normalized_ttl = 128
        else:
            normalized_ttl = 255
        
        best_match = None
        
        for os_name, sig in OS_SIGNATURES.items():
            if sig['ttl'] == normalized_ttl:
                # Check window size match
                if window in sig['window'] or any(abs(window - w) < 1000 for w in sig['window']):
                    if sig['df'] == df:
                        return os_name
                    elif not best_match:
                        best_match = os_name
        
        # Fallback heuristics
        if normalized_ttl == 64:
            return best_match or 'Linux/Unix'
        elif normalized_ttl == 128:
            return best_match or 'Windows'
        elif normalized_ttl == 255:
            return best_match or 'Cisco/Network Device'
        
        return None
