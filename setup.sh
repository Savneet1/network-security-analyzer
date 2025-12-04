#!/bin/bash
# Network Security Analyzer - Setup Script

echo "========================================="
echo "Network Security Analyzer - Setup"
echo "========================================="
echo ""

# Check if running as root for system packages
if [ "$EUID" -ne 0 ]; then 
    echo "[!] Some features require root privileges"
    echo "[*] Run 'sudo ./setup.sh' for full setup"
    echo ""
fi

# Update system
echo "[*] Updating system packages..."
sudo apt update

# Install Python3 and pip
echo "[*] Installing Python3 dependencies..."
sudo apt install -y python3 python3-pip python3-venv

# Create virtual environment
echo "[*] Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python packages
echo "[*] Installing Python packages..."
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
echo "[*] Creating project directories..."
mkdir -p output_reports data

# Make scanner executable
chmod +x scanner.py

echo ""
echo "========================================="
echo "[✓] Setup complete!"
echo "========================================="
echo ""
echo "Usage:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Run scanner: sudo python3 scanner.py <target> [options]"
echo ""
echo "Examples:"
echo "  sudo python3 scanner.py 192.168.1.1 --quick"
echo "  sudo python3 scanner.py example.com --vuln --topology"
echo ""
