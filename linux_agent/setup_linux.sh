#!/bin/bash
set -e

echo "=== EcoBPF Linux Setup ==="
echo "This script prepares your Linux machine to run the eBPF energy profiler."

echo "1. Installing requirements..."
# Update package lists
sudo apt-get update

# Install BCC (eBPF Python bindings), Linux kernel headers, and Python pip
# (This assumes a Debian/Ubuntu-based system)
sudo apt-get install -y bpfcc-tools linux-headers-$(uname -r) python3-pip python3-bpfcc python3-yaml python3-fastapi python3-uvicorn python3-websockets

# Optionally use pip if system packages are missing
# pip3 install -r requirements.txt

echo ""
echo "2. Network Information..."
IP_ADDR=$(hostname -I | awk '{print $1}')
echo "=> Your LAN IP is likely: $IP_ADDR"

echo ""
echo "3. Opening firewall for port 8000..."
if command -v ufw >/dev/null 2>&1; then
    sudo ufw allow 8000/tcp || echo "UFW command failed, but that might be fine."
elif command -v iptables >/dev/null 2>&1; then
    sudo iptables -A INPUT -p tcp --dport 8000 -j ACCEPT || echo "iptables command failed."
else
    echo "No standard firewall manager found (ufw/iptables). Skipping firewall rule."
fi

echo ""
echo "=== SETUP COMPLETE ==="
echo "To start the collector, you MUST run as root (for uprobes and RAPL):"
echo "  sudo python3 ecobpf.py -c config.yaml"
echo ""
echo "Once running, go to your Mac, open the dashboard.html, and enter:"
echo "IP: $IP_ADDR"
echo "Port: 8000"
