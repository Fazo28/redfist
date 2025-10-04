# 🔥 REDFIST - Red Team Framework

![REDFIST](https://img.shields.io/badge/REDFIST-v1.0-red)
![Python](https://img.shields.io/badge/Python-3.6+-blue)
![License](https://img.shields.io/badge/License-MIT-green)

A comprehensive red teaming framework for authorized security testing and educational purposes.

## ⚠️ LEGAL DISCLAIMER

This tool is provided for **educational and authorized testing purposes only**. Unauthorized use against systems you don't own or have explicit permission to test is illegal. The developers are not responsible for any misuse.


A comprehensive red teaming framework designed for authorized security testing, penetration testing, and educational purposes. REDFIST provides a suite of powerful tools for infrastructure security assessment.
 

· 🚫 Illegal Use: Unauthorized use against systems you don't own or lack explicit permission to test is strictly prohibited and may violate laws
· ✅ Authorized Use: Only use in environments you own or have written permission to test
· 🔒 Responsibility: Users are solely responsible for ensuring their activities comply with applicable laws
· 📜 Ethics: Always follow responsible disclosure practices and ethical guidelines

The developers are not responsible for any misuse or damage caused by this tool.

🎯 Features

Module Description Status
🔍 Port Scanner Multi-threaded TCP port scanning with service detection ✅ Stable
🌐 Subdomain Enumerator Discover hidden subdomains using wordlists ✅ Stable
🔐 Password Sprayer SSH credential testing with rate limiting ✅ Stable
📡 Network Sniffer Packet capture and protocol analysis ✅ Stable
🎣 Phishing Server Credential harvesting simulation ✅ Stable
💻 Payload Generator Reverse shell payload creation ✅ Stable
🖥️ C2 Server Command and control server simulation ✅ Stable

📦 Installation

Prerequisites

· Python 3.6 or higher
· pip (Python package manager)
· Root/Administrator privileges (for some modules)

Quick Install

```bash
# Clone the repository
git clone https://github.com/Fazo28/redfist.git
cd redfist

# Install dependencies
pip install -r requirements.txt

# Make executable (Linux/macOS)
chmod +x redfist.py
```

Manual Installation

```bash
# Install Python dependencies individually
pip install requests scapy paramiko

# Or using the setup script (if available)
python setup.py install
```

Docker Installation

```dockerfile
# Build from Dockerfile
docker build -t redfist .

# Run container
docker run -it --net=host redfist
```

🛠️ Usage

Basic Command Structure

```bash
python redfist.py [COMMAND] [OPTIONS] [TARGET]
```

🔍 Port Scanning

```bash
# Basic port scan
python redfist.py scan 192.168.1.1

# Custom port range with increased threads
python redfist.py scan 192.168.1.1 -p 1-1000 -t 200

# Specific ports only
python redfist.py scan example.com -p 22,80,443,8080,8443

# Aggressive scanning
python redfist.py scan 10.0.0.1 -p 1-65535 -t 500
```

🌐 Subdomain Enumeration

```bash
# Using built-in wordlist
python redfist.py subdomains example.com

# With custom wordlist
python redfist.py subdomains target.com -w custom_wordlist.txt

# Save results to file
python redfist.py subdomains example.com | tee subdomains.txt
```

🔐 Password Spraying

```bash
# Basic password spray
python redfist.py spray 192.168.1.100 -u users.txt -p "Password123"

# Custom SSH port
python redfist.py spray target.com -u employees.txt -p "Company2024!" --port 2222

# With delay between attempts
# (Rate limiting is built-in to avoid account lockouts)
```

📡 Network Sniffing

```bash
# Basic packet capture
python redfist.py sniff -c 100

# Specific interface
python redfist.py sniff -i eth0 -c 500

# Monitor network traffic
python redfist.py sniff -i wlan0 -c 1000
```

🎣 Phishing Server

```bash
# Start basic phishing server
python redfist.py phish -p 8080

# Custom port with redirect
python redfist.py phish -p 80 -r "https://legitimate-site.com"

# Background execution (Linux/macOS)
nohup python redfist.py phish -p 8080 &
```

💻 Payload Generation

```bash
# Generate reverse shell payload
python redfist.py payload 192.168.1.100 4444

# Different payload types (future implementation)
python redfist.py payload 10.0.0.5 1337 -t meterpreter
```

🖥️ C2 Server

```bash
# Start command and control server
python redfist.py c2 -p 4444

# Custom port
python redfist.py c2 -p 9999

# Background execution
nohup python redfist.py c2 -p 4444 > c2.log &
```
