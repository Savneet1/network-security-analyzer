#!/usr/bin/env python3
"""
Network Security Analyzer
A comprehensive network scanning and security assessment tool

Author: Savneet Singh
GitHub: https://github.com/Savneet1/network-security-analyzer
License: MIT

Features:
- Multi-threaded port scanning
- Service detection and fingerprinting
- OS detection via TCP/IP fingerprinting
- Firewall detection and analysis
- Network topology mapping
- CVE vulnerability correlation
- JSON/HTML report generation

Usage:
    sudo python3 scanner.py <target> [options]
    
Examples:
    sudo python3 scanner.py 192.168.1.1 --quick
    sudo python3 scanner.py example.com --ports 1-1000 --vuln
    sudo python3 scanner.py 10.0.0.1 --full --topology
"""

import sys
import argparse
import socket
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

import signal
import os

# Global flag for interrupt
_interrupted = False

# Signal handler for clean Ctrl+C
def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global _interrupted
    if _interrupted:
        # Force exit on second Ctrl+C
        print(f"\n{Fore.RED}[!!] Force quit{Style.RESET_ALL}")
        os._exit(1)
    
    _interrupted = True
    print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Shutting down gracefully... (Press Ctrl+C again to force quit){Style.RESET_ALL}")
    raise KeyboardInterrupt

# Register signal handler
signal.signal(signal.SIGINT, signal_handler)


# Import project modules
from config import COMMON_PORTS
from modules.port_scanner import PortScanner
from modules.service_detection import ServiceDetector
from modules.os_detection import OSDetector
from modules.firewall_detection import FirewallDetector
from modules.topology_mapper import TopologyMapper
from modules.vuln_correlator import VulnerabilityCorrelator
from reports.json_reporter import JSONReporter
from reports.html_reporter import HTMLReporter


class NetworkSecurityAnalyzer:
    def __init__(self, target: str, args):
        self.target = self._resolve_target(target)
        self.args = args
        self.scan_results = {
            'target': self.target,
            'port_scan': {},
            'services': {},
            'os_detection': {},
            'firewall_detection': {},
            'topology': {},
            'vulnerabilities': {}
        }
    
    def _resolve_target(self, target: str) -> str:
        """Resolve hostname to IP address"""
        try:
            ip = socket.gethostbyname(target)
            if ip != target:
                print(f"{Fore.CYAN}[*] Resolved {target} to {ip}")
            return ip
        except socket.gaierror:
            print(f"{Fore.RED}[!] Error: Cannot resolve hostname {target}")
            sys.exit(1)
    
    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║        Network Security Analyzer v1.0.0                ║
║        Comprehensive Network Scanning Tool             ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}Target: {self.target}
Started: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
{Style.RESET_ALL}
"""
        print(banner)
    
    def run_port_scan(self):
        """Execute port scanning"""
        print(f"\n{Fore.GREEN}[+] Phase 1: Port Scanning{Style.RESET_ALL}")
        print("=" * 60)
        
        scanner = PortScanner(self.target, timeout=self.args.timeout)
        
        if self.args.quick:
            results = scanner.quick_scan()
        elif self.args.full:
            print(f"{Fore.YELLOW}[!] Full scan of 65535 ports - this will take time!")
            results = scanner.full_scan()
        elif self.args.ports:
            results = scanner.custom_scan(self.args.ports)
        else:
            results = scanner.quick_scan()
        
        self.scan_results['port_scan'] = results
        
        print(f"\n{Fore.GREEN}[✓] Port scan complete!")
        print(f"    Open ports: {len(results['open_ports'])}")
        print(f"    Filtered ports: {len(results['filtered_ports'])}")
        
        if results['open_ports']:
            print(f"\n{Fore.CYAN}Open ports: {', '.join(map(str, results['open_ports']))}")
    
    def run_service_detection(self):
        """Execute service detection on open ports"""
        open_ports = self.scan_results['port_scan'].get('open_ports', [])
        
        if not open_ports:
            print(f"\n{Fore.YELLOW}[!] No open ports found - skipping service detection")
            return
        
        print(f"\n{Fore.GREEN}[+] Phase 2: Service Detection{Style.RESET_ALL}")
        print("=" * 60)
        
        detector = ServiceDetector(self.target, timeout=self.args.timeout)
        services = detector.detect_services(open_ports)
        
        self.scan_results['services'] = services
        
        print(f"\n{Fore.GREEN}[✓] Service detection complete!")
    
    def run_os_detection(self):
        """Execute OS detection"""
        print(f"\n{Fore.GREEN}[+] Phase 3: OS Detection{Style.RESET_ALL}")
        print("=" * 60)
        
        detector = OSDetector(self.target)
        os_info = detector.detect_os()
        
        self.scan_results['os_detection'] = os_info
        
        if os_info['detected_os'] != 'Unknown':
            print(f"\n{Fore.GREEN}[✓] OS Detection: {os_info['detected_os']} " 
                  f"(Confidence: {os_info['confidence']})")
        else:
            print(f"\n{Fore.YELLOW}[!] OS detection inconclusive")
    
    def run_firewall_detection(self):
        """Execute firewall detection"""
        print(f"\n{Fore.GREEN}[+] Phase 4: Firewall Detection{Style.RESET_ALL}")
        print("=" * 60)
        
        detector = FirewallDetector(self.target)
        fw_info = detector.analyze_filtering(self.scan_results['port_scan'])
        
        if self.args.advanced and self.scan_results['port_scan'].get('open_ports'):
            fw_info = detector.advanced_firewall_scan(
                self.scan_results['port_scan']['open_ports'][:5]
            )
        
        self.scan_results['firewall_detection'] = fw_info
        
        if fw_info['firewall_detected']:
            print(f"\n{Fore.RED}[!] Firewall detected!")
            for detail in fw_info['details']:
                print(f"    - {detail}")
        else:
            print(f"\n{Fore.GREEN}[✓] No obvious firewall detected")
    
    def run_topology_mapping(self):
        """Execute network topology mapping"""
        if not self.args.topology:
            return
        
        print(f"\n{Fore.GREEN}[+] Phase 5: Network Topology Mapping{Style.RESET_ALL}")
        print("=" * 60)
        
        mapper = TopologyMapper(self.target)
        topology = mapper.trace_route(max_hops=self.args.max_hops)
        
        self.scan_results['topology'] = topology
        
        gateway = mapper.identify_gateway()
        if gateway:
            print(f"\n{Fore.GREEN}[✓] Gateway identified: {gateway['ip']}")
    
    def run_vulnerability_correlation(self):
        """Execute vulnerability correlation with NVD"""
        if not self.args.vuln or not self.scan_results['services']:
            return
        
        print(f"\n{Fore.GREEN}[+] Phase 6: Vulnerability Correlation{Style.RESET_ALL}")
        print("=" * 60)
        
        correlator = VulnerabilityCorrelator()
        vulns = correlator.correlate_all_services(self.scan_results['services'])
        
        self.scan_results['vulnerabilities'] = vulns
        
        critical_vulns = correlator.get_critical_vulns()
        if critical_vulns:
            print(f"\n{Fore.RED}[!] Found {len(critical_vulns)} critical/high severity vulnerabilities!")
        else:
            print(f"\n{Fore.GREEN}[✓] No critical vulnerabilities found in NVD")
    
    def generate_reports(self):
        """Generate JSON and HTML reports"""
        print(f"\n{Fore.GREEN}[+] Generating Reports{Style.RESET_ALL}")
        print("=" * 60)
        
        # JSON Report
        json_reporter = JSONReporter(self.scan_results)
        json_path = json_reporter.generate()
        
        # HTML Report
        html_reporter = HTMLReporter(self.scan_results)
        html_path = html_reporter.generate()
        
        print(f"\n{Fore.GREEN}[✓] Reports generated successfully!")
    
    def run(self):
        """Main execution flow"""
        try:
            self.print_banner()
            
            # Execute scan phases
            self.run_port_scan()
            self.run_service_detection()
            self.run_os_detection()
            self.run_firewall_detection()
            self.run_topology_mapping()
            self.run_vulnerability_correlation()
            
            # Generate reports
            self.generate_reports()
            
            print(f"\n{Fore.CYAN}{'=' * 60}")
            print(f"{Fore.GREEN}[✓] Scan complete!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'=' * 60}\n")
            
        except KeyboardInterrupt:
            # Signal handler will catch this
            pass
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
            if self.args.debug:
                raise
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Network Security Analyzer - Comprehensive network scanning tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 scanner.py 192.168.1.1 --quick
  sudo python3 scanner.py example.com --ports 1-1000 --vuln
  sudo python3 scanner.py 10.0.0.1 --full --topology --advanced
  
Note: Requires root/sudo for advanced features (OS detection, topology)
        """
    )
    
    # Required arguments
    parser.add_argument('target', help="Target IP address or hostname")
    
    # Scanning options
    parser.add_argument('--quick', action='store_true', 
                       help="Quick scan of common ports (default)")
    parser.add_argument('--full', action='store_true',
                       help="Full scan of all 65535 ports (slow!)")
    parser.add_argument('--ports', type=str,
                       help="Custom port range (e.g., '80' or '1-1000' or '22,80,443')")
    
    # Feature flags
    parser.add_argument('--vuln', action='store_true',
                       help="Enable vulnerability correlation with NVD (requires internet)")
    parser.add_argument('--topology', action='store_true',
                       help="Enable network topology mapping (requires root)")
    parser.add_argument('--advanced', action='store_true',
                       help="Enable advanced firewall detection (requires root)")
    
    # Configuration
    parser.add_argument('--timeout', type=float, default=1.0,
                       help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument('--max-hops', type=int, default=30,
                       help="Maximum hops for topology mapping (default: 30)")
    parser.add_argument('--debug', action='store_true',
                       help="Enable debug mode (show stack traces)")
    
    args = parser.parse_args()
    
    # Check for root if advanced features requested
    if (args.topology or args.advanced) and os.geteuid() != 0:
        print(f"{Fore.RED}[!] Error: Advanced features require root privileges")
        print(f"{Fore.YELLOW}[*] Run with: sudo python3 scanner.py {' '.join(sys.argv[1:])}")
        sys.exit(1)
    
    # Create and run analyzer
    analyzer = NetworkSecurityAnalyzer(args.target, args)
    analyzer.run()


if __name__ == "__main__":
    import os
    main()
