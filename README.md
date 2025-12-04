# Network Security Analyzer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![RAM <150MB](https://img.shields.io/badge/RAM-%3C150MB-green.svg)]()

A fast, lightweight network security scanner for penetration testing and security audits.

**Features**: Port scanning • Service detection • OS fingerprinting • Firewall detection • CVE vulnerability checking • Network topology mapping

## ⚡ Quick Start

### 1. Install

git clone https://github.com/Savneet1/network-security-analyzer.git
cd network-security-analyzer
chmod +x setup.sh
sudo ./setup.sh
source venv/bin/activate

text

### 2. Scan

Quick scan (common ports)
sudo python3 scanner.py scanme.nmap.org --quick

Scan specific ports
sudo python3 scanner.py example.com --ports 22,80,443

Full scan with vulnerabilities
sudo python3 scanner.py 192.168.1.1 --quick --vuln

text

### 3. View Results

Open HTML report
xdg-open output_reports/scan_*.html

View JSON data
cat output_reports/scan_*.json | jq '.'

text

## 📖 Usage Examples

| Command | Purpose |
|---------|---------|
| `sudo python3 scanner.py target --quick` | Scan 21 common ports |
| `sudo python3 scanner.py target --ports 80,443` | Scan specific ports |
| `sudo python3 scanner.py target --ports 1-1000` | Scan port range |
| `sudo python3 scanner.py target --full` | Scan all 65535 ports (slow!) |
| `sudo python3 scanner.py target --vuln` | Add CVE vulnerability check |
| `sudo python3 scanner.py target --topology` | Map network path to target |
| `sudo python3 scanner.py target --quick --advanced` | Advanced firewall detection |

## 🔧 Options

positional arguments:
target Target IP or hostname

scanning:
--quick Quick scan (default) - 21 common ports
--full Full scan - all 65535 ports
--ports PORT_RANGE Custom: '80' or '1-1000' or '22,80,443'

features:
--vuln Check CVE vulnerabilities (requires internet)
--topology Map network path (requires sudo)
--advanced Advanced firewall detection (requires sudo)

config:
--timeout SECONDS Socket timeout (default: 1.0)
--max-hops NUM Max traceroute hops (default: 30)
--debug Show error details

text

## 📁 Project Structure

network-security-analyzer/
├── scanner.py # Main program
├── config.py # Configuration
├── requirements.txt # Dependencies
├── setup.sh # Auto setup
├── README.md # This file
├── LICENSE # MIT License
├── modules/ # Core modules
│ ├── port_scanner.py
│ ├── service_detection.py
│ ├── os_detection.py
│ ├── firewall_detection.py
│ ├── topology_mapper.py
│ └── vuln_correlator.py
├── reports/ # Report generators
└── output_reports/ # Generated reports (auto)

text

## 📊 What You Get

### Port Scan Results
- Open ports list
- Service names (SSH, HTTP, etc.)
- Service versions

### OS Detection
- Detected operating system
- Confidence level
- TCP/IP fingerprint analysis

### Vulnerability Check
- CVE IDs from NVD database
- Severity levels (Critical, High, Medium, Low)
- Descriptions and scores

### Network Topology
- Hop-by-hop path to target
- Gateway/router IPs
- Hostnames (if available)

### Reports
- **JSON**: Machine-readable data for automation
- **HTML**: Professional visual report

## 🔑 NVD API Key (Optional)

For faster CVE lookups (10x speed improvement):

1. Get free key: https://nvd.nist.gov/developers/request-an-api-key
2. Set environment variable:
export NVD_API_KEY="your-key-here"

3. Run scan:
sudo -E python3 scanner.py target --vuln

text

Without key: Works fine (slower - 6s per service)  
With key: 10x faster (0.6s per service)

## 🛡️ Legal & Security

### ⚠️ FOR AUTHORIZED USE ONLY

This tool is **only for**:
- ✅ Systems you own
- ✅ Systems with written permission
- ✅ Educational labs (TryHackMe, HackTheBox)
- ✅ Authorized penetration tests

This tool is **NOT for**:
- ❌ Unauthorized scanning
- ❌ Systems you don't control
- ❌ Systems without permission

**Unauthorized scanning is illegal and may result in criminal charges.**

## ❓ Troubleshooting

| Issue | Solution |
|-------|----------|
| "Permission denied" | Use `sudo`: `sudo python3 scanner.py ...` |
| "Cannot resolve hostname" | Use IP instead: `sudo python3 scanner.py 1.2.3.4` |
| Scapy import error | Run: `pip install --upgrade scapy` |
| Slow VPN scan | Increase timeout: `--timeout 3.0` |
| OS detection not working | Target may block ICMP - try different ports |

## 🚀 Common Workflows

### Penetration Testing Recon
sudo python3 scanner.py target --quick --topology

Then review HTML report
xdg-open output_reports/scan_*.html

text

### Security Audit
sudo python3 scanner.py internal-server --quick --vuln

Check for critical vulnerabilities in report
text

### Network Discovery
sudo python3 scanner.py gateway --topology --max-hops 20

See network path and infrastructure
text

## 📊 Stats

- **1,370+ lines** of production Python code
- **6 core features** (scanning, detection, topology, vulns, reports, firewall)
- **2 report formats** (JSON, HTML)
- **<150MB RAM** usage
- **100 concurrent threads** for speed

## 📚 Learn More

- [Nmap Guide](https://nmap.org/book/)
- [NVD Database](https://nvd.nist.gov/)
- [Scapy Docs](https://scapy.readthedocs.io/)
- [OWASP Testing](https://owasp.org/www-project-web-security-testing-guide/)

## 🤝 Contributing

Issues, PRs, and suggestions welcome!

1. Fork repo
2. Create feature branch: `git checkout -b feature/name`
3. Commit: `git commit -m 'Add feature'`
4. Push: `git push origin feature/name`
5. Open Pull Request

## 📄 License

MIT License - You can use, modify, and distribute freely. See [LICENSE](LICENSE) file.

## 👨‍💻 Author

Savneet Singh - [@Savneet1](https://github.com/Savneet1)

## ⭐ If This Helped You

Please star this repo! ⭐

Test it:
sudo python3 scanner.py scanme.nmap.org --quick

text

<div align="center">

**For authorized security testing only** 🔒

**Educational & ethical hacking** ✅

</div>
