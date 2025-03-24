import ipaddress
import socket
import ssl
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.l2 import ARP, Ether
from colorama import Fore, Style
from scanner.nmap import NmapScanner
from concurrent.futures import ThreadPoolExecutor

class NetworkScanner:
    def __init__(self):
        self.nmap = NmapScanner()
        self.port_states = {
            'open': Fore.GREEN + 'OPEN' + Style.RESET_ALL,
            'closed': Fore.RED + 'CLOSED' + Style.RESET_ALL,
            'filtered': Fore.YELLOW + 'FILTERED' + Style.RESET_ALL
        }
        conf.verb = 0  # Disable Scapy warnings

    def run_scan(self, target, scan_type='quick', custom_ports=''):
        """Main scan controller"""
        try:
            if scan_type == 'quick':
                self._quick_scan(target)
            elif scan_type == 'ports':
                ports = self._parse_ports(custom_ports)
                self._port_scan(target, ports)
            elif scan_type == 'full':
                self._full_scan(target)
            elif scan_type == 'vuln':
                self._vulnerability_scan(target)
        except Exception as e:
            print(f"{Fore.RED}Error: {str(e)}")

    def _full_scan(self, target):
        """Complete scanning workflow"""
        print(f"\n{Fore.BLUE}=== Running Full Scan ===")
        
        # 1. Target Information
        target_info = self._get_target_info(target)
        print(f"\n{Fore.MAGENTA}=== Target Details ===")
        print(f"{Fore.CYAN}IP: {Fore.WHITE}{target_info['ip']}")
        print(f"{Fore.CYAN}Type: {Fore.WHITE}{target_info['type']}")
        print(f"{Fore.CYAN}Scope: {Fore.WHITE}{target_info['scope']}")

        # 2. Host Discovery
        print(f"\n{Fore.MAGENTA}=== Host Discovery ===")
        live_hosts = self._icmp_sweep(target)
        
        if live_hosts:
            for host in live_hosts:
                print(f"{Fore.GREEN}Host Alive: {Fore.WHITE}{host['ip']}")
            
            if target_info['scope'] == 'Private':
                self._arp_scan(target)
            self._dns_scan(live_hosts)
        else:
            print(f"{Fore.YELLOW}No hosts discovered via ICMP/TCP")

        # 3. Port Scanning
        print(f"\n{Fore.MAGENTA}=== Port Scanning ===")
        common_ports = [21,22,23,25,53,80,110,143,443,445,993,995,3389,8080,8443]
        syn_results = self._syn_scan(target, common_ports)
        service_results = self._service_detection(target, syn_results['open_ports'])
        self._display_results(service_results, "ports")

        # 4. OS Detection
        print(f"\n{Fore.MAGENTA}=== OS Fingerprinting ===")
        os_info = self.nmap.os_detection(target)
        if os_info:
            if isinstance(os_info, list):  # Handle list case
                for info in os_info:
                    print(f"{Fore.CYAN}Detected OS: {Fore.WHITE}{info.get('os', 'Unknown')}")
                    print(f"{Fore.CYAN}Accuracy: {Fore.WHITE}{info.get('accuracy', 'N/A')}%")
            elif isinstance(os_info, dict):  # Handle dict case
                print(f"{Fore.CYAN}Detected OS: {Fore.WHITE}{os_info.get('os', 'Unknown')}")
                print(f"{Fore.CYAN}Accuracy: {Fore.WHITE}{os_info.get('accuracy', 'N/A')}%")
            else:
                print(f"{Fore.YELLOW}Unexpected OS info format: {type(os_info)}")

    print(f"\n{Fore.GREEN}=== Full Scan Completed ===")

    def _vulnerability_scan(self, target):
        """Enhanced vulnerability assessment"""
        print(f"\n{Fore.BLUE}=== Running Vulnerability Scan ===")
        
        # First perform full discovery
        self._full_scan(target)
        
        # Then run Nmap vulnerability checks
        print(f"\n{Fore.MAGENTA}=== Vulnerability Assessment ===")
        vulns = self.nmap.vulnerability_scan(target)
        
        if vulns:
            for port, info in vulns.items():
                print(f"\n{Fore.RED}Vulnerabilities on Port {port} ({info['service']}):")
                for vuln in info['vulns']:
                    print(f"{Fore.YELLOW}[!] {vuln['name']}:")
                    print(f"{Fore.WHITE}{vuln['output']}")
                    print("-" * 50)
        else:
            print(f"{Fore.GREEN}No high-risk vulnerabilities detected (CVSS >= 5.0)")

        print(f"\n{Fore.GREEN}=== Vulnerability Scan Completed ===")

    def _icmp_sweep(self, target):
        """Enhanced host discovery with TCP fallback"""
        live_hosts = []
        try:
            if '/' in target:  # Network range
                network = ipaddress.ip_network(target, strict=False)
                if network.is_private:
                    ans, unans = sr(IP(dst=target)/ICMP(), timeout=2, verbose=0)
                    live_hosts = [{'ip': recv.src, 'mac': 'unknown'} for snd,recv in ans]
                else:
                    live_hosts = self._tcp_ping_sweep(target)
            else:  # Single target
                ans, unans = sr(IP(dst=target)/ICMP(), timeout=2, verbose=0)
                if ans:
                    live_hosts = [{'ip': target, 'mac': 'unknown'}]
                else:
                    live_hosts = self._tcp_ping_sweep(target)
        except Exception as e:
            print(f"{Fore.RED}Discovery Error: {str(e)}")
        return live_hosts

    def _tcp_ping_sweep(self, target):
        """TCP-based host discovery"""
        live_hosts = []
        common_ports = [80, 443, 22]
        try:
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for port in common_ports:
                    futures.append(executor.submit(
                        self._test_tcp_port, 
                        target, 
                        port
                    ))
                for future in futures:
                    result = future.result()
                    if result:
                        live_hosts.append(result)
        except Exception as e:
            print(f"{Fore.RED}TCP Ping Error: {str(e)}")
        return live_hosts

    def _test_tcp_port(self, target, port):
        """Test single TCP port for host discovery"""
        try:
            ans, unans = sr(IP(dst=target)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
            if ans:
                send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=0)
                return {'ip': target, 'mac': 'unknown'}
        except:
            return None

    def _arp_scan(self, target):
        """ARP scan for local networks"""
        print(f"{Fore.BLUE}=== ARP Scan ===")
        try:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target), timeout=2, verbose=0)
            for sent, received in ans:
                print(f"{Fore.CYAN}IP: {Fore.WHITE}{received.psrc} {Fore.CYAN}MAC: {Fore.WHITE}{received.hwsrc}")
        except Exception as e:
            print(f"{Fore.RED}ARP Error: {str(e)}")

    def _dns_scan(self, hosts):
        """DNS reverse lookup"""
        print(f"{Fore.BLUE}=== DNS Lookup ===")
        for host in hosts:
            try:
                hostname = socket.getfqdn(host['ip'])
                print(f"{Fore.CYAN}IP: {Fore.WHITE}{host['ip']} {Fore.CYAN}Hostname: {Fore.WHITE}{hostname}")
            except Exception as e:
                print(f"{Fore.RED}DNS Error for {host['ip']}: {str(e)}")

    def _get_target_info(self, target):
        """Get detailed target information"""
        try:
            ip = socket.gethostbyname(target)
            ip_obj = ipaddress.ip_address(ip)
            
            return {
                'ip': ip,
                'type': 'IPv4' if ip_obj.version == 4 else 'IPv6',
                'scope': 'Private' if ip_obj.is_private else 'Public',
                'multicast': ip_obj.is_multicast,
                'loopback': ip_obj.is_loopback,
                'reserved': ip_obj.is_reserved
            }
        except:
            return {'ip': target, 'type': 'Unknown', 'scope': 'Unknown'}

    def _parse_ports(self, port_input):
        """Parse custom port ranges"""
        if not port_input.strip():
            return [21,22,23,80,443,3389,8080]
        
        ports = []
        for part in port_input.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end+1))
            else:
                ports.append(int(part))
        return ports

    def _quick_scan(self, target):
        """Basic host discovery"""
        print(f"\n{Fore.BLUE}=== Running Quick Scan ===")
        live_hosts = self._icmp_sweep(target)
        if live_hosts:
            self._dns_scan(live_hosts)
        else:
            print(f"{Fore.YELLOW}No hosts discovered")

    def _port_scan(self, target, ports):
        """Port scanning with service detection"""
        print(f"\n{Fore.BLUE}=== Running Port Scan ===")
        syn_results = self._syn_scan(target, ports)
        service_results = self._service_detection(target, syn_results['open_ports'])
        self._display_results(service_results, "ports")

    def _syn_scan(self, target, ports):
        """TCP SYN scan implementation"""
        open_ports = []
        for port in ports:
            pkt = IP(dst=target)/TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=1, verbose=0)
            
            if resp and resp.haslayer(TCP):
                if resp[TCP].flags == 0x12:  # SYN-ACK
                    open_ports.append(port)
                    send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=0)
        return {'target': target, 'open_ports': open_ports}

    def _service_detection(self, target, ports):
        """Service and version detection"""
        service_info = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    s.connect((target, port))
                    
                    if port == 80:  # HTTP
                        s.send(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % target.encode())
                        banner = s.recv(4096).decode('utf-8', 'ignore').strip()
                    elif port == 443:  # HTTPS
                        banner = self._ssl_scan(target, port)
                    elif port == 22:  # SSH
                        banner = s.recv(1024).decode('utf-8', 'ignore').strip()
                    else:
                        s.send(b"\r\n\r\n")
                        banner = s.recv(1024).decode('utf-8', 'ignore').strip()
                    
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    
                    service_info.append({
                        'port': port,
                        'state': 'open',
                        'service': service,
                        'banner': banner[:500]  # Limit banner length
                    })
            except Exception as e:
                continue
        return service_info

    def _ssl_scan(self, target, port=443):
        """SSL/TLS certificate inspection"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, port)) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    return f"SSL/TLS Service\nVersion: {ssock.version()}\nCipher: {ssock.cipher()}\nCert Issuer: {cert['issuer']}"
        except Exception as e:
            return f"SSL Error: {str(e)}"

    def _display_results(self, results, scan_type):
        """Display scan results"""
        if scan_type == "hosts":
            print(f"\n{Fore.MAGENTA}=== Live Hosts ===")
            for host in results:
                print(f"{Fore.CYAN}IP: {Fore.WHITE}{host['ip']}")
                print(f"{Fore.CYAN}MAC: {Fore.WHITE}{host.get('mac', 'unknown')}")
                print("-" * 40)
        
        elif scan_type == "ports":
            print(f"\n{Fore.MAGENTA}=== Port Scan Results ===")
            for port_info in results:
                print(f"\n{Fore.CYAN}Port: {Fore.WHITE}{port_info['port']}")
                print(f"{Fore.CYAN}State: {self.port_states[port_info['state']]}")
                print(f"{Fore.CYAN}Service: {Fore.WHITE}{port_info.get('service', 'unknown')}")
                if port_info.get('banner'):
                    print(f"{Fore.CYAN}Banner:\n{Fore.WHITE}{port_info['banner']}")
        
        print(f"\n{Fore.GREEN}Scan completed with {len(results)} results found!")