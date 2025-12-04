"""
Firewall and Filtering Detection
Analyzes port responses to infer firewall behavior
"""

try:
    from scapy.all import IP, TCP, ICMP, sr1, conf
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from typing import Dict, List
from config import FIREWALL_INDICATORS


class FirewallDetector:
    def __init__(self, target: str):
        self.target = target
        self.firewall_info = {
            'firewall_detected': False,
            'filtering_behavior': [],
            'details': []
        }
    
    def analyze_filtering(self, port_results: Dict) -> Dict:
        """
        Analyze port scan results to detect firewall behavior
        """
        open_ports = port_results.get('open_ports', [])
        closed_ports = port_results.get('closed_ports', [])
        filtered_ports = port_results.get('filtered_ports', [])
        
        total_ports = len(open_ports) + len(closed_ports) + len(filtered_ports)
        
        if not total_ports:
            return self.firewall_info
        
        filtered_ratio = len(filtered_ports) / total_ports
        
        # High filtered ratio suggests firewall
        if filtered_ratio > 0.3:
            self.firewall_info['firewall_detected'] = True
            self.firewall_info['details'].append(
                f'High filtering rate: {filtered_ratio:.1%} of ports filtered'
            )
        
        # Check for stealth patterns
        if filtered_ports and not closed_ports:
            self.firewall_info['filtering_behavior'].append('Stealth filtering (all non-open ports filtered)')
        
        # Check for common firewall ports open
        firewall_ports = [80, 443, 22, 3389]
        if any(p in open_ports for p in firewall_ports) and len(open_ports) < 5:
            self.firewall_info['details'].append('Minimal open ports - likely firewall protected')
        
        return self.firewall_info
    
    def advanced_firewall_scan(self, ports: List[int]) -> Dict:
        """
        Perform advanced firewall detection using multiple scan techniques
        Requires Scapy and root privileges
        """
        if not SCAPY_AVAILABLE:
            self.firewall_info['details'].append('Scapy not available - advanced detection disabled')
            return self.firewall_info
        
        try:
            print(f"[*] Performing advanced firewall detection on {self.target}...")
            
            # Test different TCP flag combinations
            test_results = {}
            
            for port in ports[:5]:  # Test first 5 ports only to save time
                # SYN scan
                syn_resp = sr1(IP(dst=self.target)/TCP(dport=port, flags='S'), timeout=1, verbose=0)
                
                # FIN scan
                fin_resp = sr1(IP(dst=self.target)/TCP(dport=port, flags='F'), timeout=1, verbose=0)
                
                # NULL scan
                null_resp = sr1(IP(dst=self.target)/TCP(dport=port, flags=''), timeout=1, verbose=0)
                
                test_results[port] = {
                    'syn': self._analyze_response(syn_resp),
                    'fin': self._analyze_response(fin_resp),
                    'null': self._analyze_response(null_resp)
                }
            
            # Analyze patterns
            self._analyze_scan_patterns(test_results)
            
        except Exception as e:
            self.firewall_info['details'].append(f'Advanced scan error: {str(e)}')
        
        return self.firewall_info
    
    def _analyze_response(self, response) -> str:
        """Analyze packet response type"""
        if not response:
            return 'filtered'
        elif response.haslayer(TCP):
            flags = response.getlayer(TCP).flags
            if flags & 0x12:  # SYN-ACK
                return 'open'
            elif flags & 0x14:  # RST-ACK
                return 'closed'
        elif response.haslayer(ICMP):
            return 'filtered_icmp'
        return 'unknown'
    
    def _analyze_scan_patterns(self, results: Dict):
        """Analyze scan results for firewall patterns"""
        # Check for stateful firewall (SYN works, others don't)
        stateful_indicators = 0
        
        for port, scans in results.items():
            if scans['syn'] in ['open', 'closed'] and scans['fin'] == 'filtered':
                stateful_indicators += 1
        
        if stateful_indicators >= len(results) * 0.5:
            self.firewall_info['firewall_detected'] = True
            self.firewall_info['filtering_behavior'].append('Stateful firewall detected')
            self.firewall_info['details'].append('SYN packets pass, stealth scans blocked')
