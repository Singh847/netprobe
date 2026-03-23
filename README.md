# NETPROBE v2.0 — Network & Web Scanner

A Python-based network reconnaissance tool built on Kali Linux.
Replicates Nmap NSE (Nmap Scripting Engine) script functionality
across three scan modes from a single command-line interface.

## Features

### Host Scan
- Ping status and response time
- TTL-based OS fingerprinting
- Port scanning (23 common ports)
- Service banner grabbing
- Date, time and timezone info

### Network Scan
- ARP broadcast subnet discovery
- MAC address collection
- Hostname resolution per device
- OS estimation per device
- Requires sudo/root

### Web Scan
- Page title and meta description
- Domain, IP and server info
- SSL certificate details
- WHOIS domain registration data
- Technology detection
- HTTP security header analysis

## Tech Stack

- Python 3
- Scapy
- Requests
- BeautifulSoup4
- python-whois
- Colorama
- Kali Linux

## Installation
```bash
git clone https://github.com/YOUR-USERNAME/netprobe.git
cd netprobe
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage
```bash
# Host scan
python3 netprobe.py -m host -t 192.168.1.1 --save

# Network scan (requires sudo)
sudo python3 netprobe.py -m network -t 192.168.1.0/24 --save

# Web scan
python3 netprobe.py -m web -t https://example.com --save
```

## Project Structure
```
netprobe/
├── netprobe.py
├── modules/
│   ├── host_scanner.py
│   ├── network_scanner.py
│   └── web_scanner.py
├── utils/
│   ├── colors.py
│   └── helpers.py
└── requirements.txt
```

## Legal Notice

For authorized and educational use only.
Only scan networks and systems you own or
have explicit permission to test.

## Author

Sumeer Singh Rana
