"""
Network Topology Mapper
Basic network topology discovery using traceroute-style probing
"""

try:
    from scapy.all import IP, ICMP, TCP, sr1, conf
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import socket
from typing import Dict, List


class TopologyMapper:
    def __init__(self, target: str):
        self.target = target
        self.topology = {
            'target': target,
            'hops': [],
            'gateway_info': {},
            'network_path': []
        }
    
    def trace_route(self, max_hops: int = 30) -> Dict:
        """
        Perform traceroute to map network path
        """
        if not SCAPY_AVAILABLE:
            self.topology['hops'].append({'note': 'Scapy not available - topology mapping disabled'})
            return self.topology
        
        print(f"[*] Tracing route to {self.target} (max {max_hops} hops)...")
        
        try:
            for ttl in range(1, max_hops + 1):
                try:
                    # Send ICMP packet with increasing TTL
                    packet = IP(dst=self.target, ttl=ttl)/ICMP()
                    response = sr1(packet, timeout=2, verbose=0)
                    
                    if response is None:
                        self.topology['hops'].append({
                            'hop': ttl,
                            'ip': '*',
                            'hostname': 'No response',
                            'rtt': None
                        })
                        continue
                    
                    # Extract source IP - multiple fallback methods
                    hop_ip = None
                    try:
                        # Method 1: Direct attribute
                        if hasattr(response, 'src'):
                            hop_ip = str(response.src)
                    except:
                        pass
                    
                    if not hop_ip:
                        try:
                            # Method 2: IP layer
                            if response.haslayer(IP):
                                hop_ip = str(response[IP].src)
                        except:
                            pass
                    
                    if not hop_ip:
                        try:
                            # Method 3: Get layer by index
                            hop_ip = str(response.payload.src)
                        except:
                            pass
                    
                    if not hop_ip or hop_ip == 'None':
                        self.topology['hops'].append({
                            'hop': ttl,
                            'ip': '*',
                            'hostname': 'No response',
                            'rtt': None
                        })
                        continue
                    
                    # Try reverse DNS lookup
                    hostname = hop_ip
                    try:
                        hostname = socket.gethostbyaddr(hop_ip)[0]
                    except:
                        pass
                    
                    # Calculate RTT if available
                    rtt = 'N/A'
                    try:
                        if hasattr(response, 'time'):
                            rtt = f'{response.time * 1000:.2f}ms'
                    except:
                        pass
                    
                    hop_info = {
                        'hop': ttl,
                        'ip': hop_ip,
                        'hostname': hostname,
                        'rtt': rtt
                    }
                    
                    self.topology['hops'].append(hop_info)
                    self.topology['network_path'].append(hop_ip)
                    
                    print(f"    Hop {ttl}: {hop_ip} ({hostname}) - {rtt}")
                    
                    # Check if we reached target
                    if hop_ip == self.target:
                        print(f"[+] Reached target at hop {ttl}")
                        break
                
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    # Skip problematic hop and continue
                    self.topology['hops'].append({
                        'hop': ttl,
                        'ip': '*',
                        'hostname': f'Error: {str(e)[:30]}',
                        'rtt': None
                    })
                    continue
                    
        except KeyboardInterrupt:
            print(f"\n[!] Traceroute interrupted")
            raise
        except Exception as e:
            self.topology['hops'].append({'error': f'Traceroute error: {str(e)}'})
            print(f"[!] Topology mapping error: {str(e)}")
        
        return self.topology
    
    def identify_gateway(self) -> Dict:
        """
        Identify default gateway/first hop
        """
        if self.topology['hops']:
            first_hop = next((h for h in self.topology['hops'] if h.get('ip', '*') != '*'), None)
            if first_hop:
                self.topology['gateway_info'] = {
                    'ip': first_hop.get('ip', 'unknown'),
                    'hostname': first_hop.get('hostname', 'unknown'),
                    'note': 'Likely default gateway or first router'
                }
        
        return self.topology['gateway_info']
    
    def analyze_path(self) -> Dict:
        """
        Analyze network path for interesting hops
        """
        analysis = {
            'total_hops': len([h for h in self.topology['hops'] if h.get('ip', '*') != '*']),
            'unresponsive_hops': len([h for h in self.topology['hops'] if h.get('ip', '*') == '*']),
            'path_summary': []
        }
        
        # Check for cloud providers, ISPs, etc. in hostnames
        interesting_patterns = ['cloudflare', 'akamai', 'amazon', 'google', 'microsoft', 'isp']
        
        for hop in self.topology['hops']:
            if 'error' in hop or hop.get('ip', '*') == '*':
                continue
            hostname = hop.get('hostname', '').lower()
            if any(pattern in hostname for pattern in interesting_patterns):
                matching_patterns = [p for p in interesting_patterns if p in hostname]
                if matching_patterns:
                    analysis['path_summary'].append({
                        'hop': hop.get('hop', 0),
                        'ip': hop.get('ip', 'unknown'),
                        'note': f"Possible {matching_patterns[0]} infrastructure"
                    })
        
        return analysis

