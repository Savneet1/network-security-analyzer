"""
Vulnerability Correlator
Correlates discovered services with CVE data from NVD database
"""

import time
from typing import Dict, List
from config import NVD_API_KEY, NVD_DELAY

try:
    import nvdlib
    NVDLIB_AVAILABLE = True
except ImportError:
    NVDLIB_AVAILABLE = False


class VulnerabilityCorrelator:
    def __init__(self, api_key: str = NVD_API_KEY):
        self.api_key = api_key
        self.vulnerabilities = {}
        self.delay = NVD_DELAY
    
    def correlate_service(self, service_info: Dict) -> List[Dict]:
        """
        Search NVD for vulnerabilities related to a service
        """
        if not NVDLIB_AVAILABLE:
            return [{'error': 'nvdlib not available - install with: pip install nvdlib'}]
        
        service_name = service_info.get('service', 'unknown')
        version = service_info.get('version', '')
        
        if service_name == 'unknown':
            return []
        
        print(f"[*] Searching CVEs for {service_name} {version}...")
        
        try:
            # Build search query
            search_term = service_name
            if version and version != 'unknown':
                search_term = f"{service_name} {version}"
            
            # Search NVD (with rate limiting)
            cves = nvdlib.searchCVE(
                keywordSearch=search_term,
                limit=10,  # Limit results to keep memory low
                key=self.api_key
            )
            
            vulnerabilities = []
            for cve in cves:
                vuln_info = {
                    'cve_id': cve.id,
                    'description': cve.descriptions[0].value if cve.descriptions else 'No description',
                    'severity': getattr(cve, 'v31severity', 'N/A'),
                    'score': getattr(cve, 'v31score', 'N/A'),
                    'published': str(getattr(cve, 'published', 'N/A')),
                    'references': [ref.url for ref in cve.references[:3]] if cve.references else []
                }
                vulnerabilities.append(vuln_info)
            
            # Rate limiting
            time.sleep(self.delay)
            
            return vulnerabilities
            
        except Exception as e:
            return [{'error': f'NVD query failed: {str(e)}'}]
    
    def correlate_all_services(self, services: Dict[int, Dict]) -> Dict[int, List]:
        """
        Correlate all discovered services with CVE data
        """
        print(f"\n[*] Correlating {len(services)} services with NVD database...")
        print(f"[!] This may take a while due to API rate limiting...\n")
        
        for port, service_info in services.items():
            vulns = self.correlate_service(service_info)
            self.vulnerabilities[port] = vulns
            
            if vulns and 'error' not in vulns[0]:
                print(f"    Port {port} ({service_info['service']}): Found {len(vulns)} CVEs")
        
        return self.vulnerabilities
    
    def get_critical_vulns(self) -> List[Dict]:
        """
        Extract only critical/high severity vulnerabilities
        """
        critical = []
        
        for port, vulns in self.vulnerabilities.items():
            for vuln in vulns:
                if isinstance(vuln, dict) and vuln.get('severity') in ['CRITICAL', 'HIGH']:
                    critical.append({
                        'port': port,
                        **vuln
                    })
        
        return critical
