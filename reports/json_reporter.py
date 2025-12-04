"""
JSON Report Generator
Exports scan results to structured JSON format
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict
from config import REPORTS_DIR


class JSONReporter:
    def __init__(self, scan_data: Dict):
        self.scan_data = scan_data
        self.report_path = None
    
    def generate(self, filename: str = None) -> Path:
        """
        Generate JSON report
        Returns: Path to generated report
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target = self.scan_data.get('target', 'unknown')
            filename = f"scan_{target}_{timestamp}.json"
        
        self.report_path = REPORTS_DIR / filename
        
        # Add metadata
        report_data = {
            'metadata': {
                'scan_time': datetime.now().isoformat(),
                'tool': 'Network Security Analyzer',
                'version': '1.0.0'
            },
            **self.scan_data
        }
        
        with open(self.report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n[+] JSON report saved: {self.report_path}")
        return self.report_path
