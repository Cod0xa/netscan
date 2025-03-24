#!/usr/bin/python3
import pyfiglet
import os
import platform
from colorama import init, Fore, Style
from scanner.core import NetworkScanner

# Initialize colorama
init(autoreset=True)

# Color definitions
COLOR = {
    'banner': Fore.CYAN,
    'title': Fore.YELLOW + Style.BRIGHT,
    'prompt': Fore.GREEN,
    'error': Fore.RED,
    'success': Fore.GREEN,
    'info': Fore.BLUE,
    'result': Fore.MAGENTA,
    'highlight': Fore.WHITE + Style.BRIGHT,
    'warning': Fore.YELLOW
}

def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def show_banner():
    """Display program banner"""
    banner = pyfiglet.figlet_format("NetScan", font="slant")
    print(COLOR['banner'] + banner)
    print(COLOR['title'] + "⚡ Advanced Network Reconnaissance Toolkit ⚡")
    print(Fore.YELLOW + "-" * 70)

def main():
    clear_screen()
    show_banner()
    scanner = NetworkScanner()
    
    while True:
        try:
            cmd = input(COLOR['prompt'] + ">> ").strip().lower()
            
            if cmd in ('exit', 'quit'):
                print(COLOR['info'] + "Shutting down scanner...")
                break
                
            elif cmd == 'scan':
                target = input(COLOR['prompt'] + "Enter target (IP/CIDR/hostname): ")
                scan_type = input(COLOR['prompt'] + "Scan type (quick/ports/full/vuln): ").lower()
                if scan_type == 'ports':
                    custom_ports = input(COLOR['prompt'] + "Custom ports (comma separated, leave blank for default): ")
                    scanner.run_scan(target, scan_type, custom_ports)
                else:
                    scanner.run_scan(target, scan_type)
                
            elif cmd == 'clear':
                clear_screen()
                show_banner()
                
            elif cmd == 'help':
                print(COLOR['info'] + "\nAvailable Commands:")
                print(COLOR['highlight'] + "scan   " + COLOR['info'] + "- Start advanced network scan")
                print(COLOR['highlight'] + "clear  " + COLOR['info'] + "- Clear terminal")
                print(COLOR['highlight'] + "help   " + COLOR['info'] + "- Show help")
                print(COLOR['highlight'] + "exit   " + COLOR['info'] + "- Quit program")
                print(COLOR['info'] + "\nScan Types:")
                print(COLOR['highlight'] + "quick  " + COLOR['info'] + "- Host discovery + basic info")
                print(COLOR['highlight'] + "ports  " + COLOR['info'] + "- Port scanning with service detection")
                print(COLOR['highlight'] + "full   " + COLOR['info'] + "- Comprehensive scan with OS fingerprinting")
                print(COLOR['highlight'] + "vuln   " + COLOR['info'] + "- Vulnerability assessment\n")
                
            else:
                print(COLOR['error'] + f"Unknown command: {cmd}")
                
        except KeyboardInterrupt:
            print(COLOR['error'] + "\nExiting...")
            break

if __name__ == "__main__":
    main()
