from scapy.all import *
import ipaddress
import socket
import time

class ScapyScanner:
    def ping_sweep(self, network):
        live_hosts = []
        network = ipaddress.ip_network(network, strict=False)
        
        for ip in network.hosts():
            ip = str(ip)
            packet = IP(dst=ip)/ICMP()
            response = sr1(packet, timeout=1, verbose=0)
            
            if response:
                live_hosts.append({
                    'ip': ip,
                    'mac': response.src if hasattr(response, 'src') else 'unknown'
                })
                time.sleep(0.2)
        
        return live_hosts

    def syn_scan(self, target, ports):
        open_ports = []
        
        for port in ports:
            packet = IP(dst=target)/TCP(dport=port, flags="S")
            response = sr1(packet, timeout=2, verbose=0)
            
            if response and response.haslayer(TCP):
                if response[TCP].flags == 0x12:  # SYN-ACK
                    open_ports.append(port)
                    send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=0)
        
        return {'open_ports': open_ports}