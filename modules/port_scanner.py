"""
Multi-threaded TCP Port Scanner
Uses socket for fast scanning with concurrent.futures ThreadPoolExecutor
"""

import socket
import concurrent.futures
from typing import List, Dict, Tuple
from config import DEFAULT_TIMEOUT, MAX_THREADS


class PortScanner:
    def __init__(self, target: str, timeout: float = DEFAULT_TIMEOUT):
        self.target = target
        self.timeout = timeout
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        
    def scan_port(self, port: int) -> Tuple[int, str]:
        """
        Scan a single TCP port using socket
        Returns: (port, status) where status is 'open', 'closed', or 'filtered'
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                return (port, 'open')
            else:
                return (port, 'closed')
        except socket.timeout:
            return (port, 'filtered')
        except socket.error:
            return (port, 'filtered')
        except Exception:
            return (port, 'error')
    
    def scan_ports(self, ports: List[int], max_threads: int = MAX_THREADS) -> Dict:
        """
        Scan multiple ports concurrently
        Returns: Dictionary with scan results
        """
        print(f"[*] Scanning {len(ports)} ports on {self.target}...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            try:
                future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
                
                for future in concurrent.futures.as_completed(future_to_port):
                    try:
                        port, status = future.result(timeout=2)
                        if status == 'open':
                            self.open_ports.append(port)
                        elif status == 'closed':
                            self.closed_ports.append(port)
                        elif status == 'filtered':
                            self.filtered_ports.append(port)
                    except concurrent.futures.TimeoutError:
                        pass
                    except KeyboardInterrupt:
                        print(f"\n[!] Cancelling remaining scans...")
                        executor.shutdown(wait=False, cancel_futures=True)
                        raise
            except KeyboardInterrupt:
                print(f"[*] Cleaning up threads...")
                raise
        
        return {
            'target': self.target,
            'open_ports': sorted(self.open_ports),
            'closed_ports': sorted(self.closed_ports),
            'filtered_ports': sorted(self.filtered_ports),
            'total_scanned': len(ports)
        }
    
    def quick_scan(self) -> Dict:
        """Scan common ports only"""
        from config import COMMON_PORTS
        return self.scan_ports(COMMON_PORTS)
    
    def full_scan(self) -> Dict:
        """Scan all 65535 ports (takes time!)"""
        return self.scan_ports(range(1, 65536))
    
    def custom_scan(self, port_range: str) -> Dict:
        """
        Scan custom port range
        Format: "80" or "1-1000" or "22,80,443"
        """
        ports = []
        
        if ',' in port_range:
            ports = [int(p.strip()) for p in port_range.split(',')]
        elif '-' in port_range:
            start, end = port_range.split('-')
            ports = list(range(int(start), int(end) + 1))
        else:
            ports = [int(port_range)]
        
        return self.scan_ports(ports)

