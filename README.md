```markdown
# NetScan Network Scanner

A Python network scanning tool combining Scapy and Nmap functionality with a command-line interface.

## Features
- Host discovery (ICMP ping)
- Port scanning (TCP SYN)
- Full network scans with OS detection
- Color-coded console output
- Supports both Scapy and Nmap engines

## Installation
1. Install requirements:
```bash
pip install rich pyfiglet scapy python-nmap ipaddress
```

2. Clone repository:
```bash
git clone https://github.com/yourusername/netrecon.git
cd netrecon
```

3. Install package:
```bash
pip install -e .
```

## Usage
Run the interactive shell:
```bash
python -m netscan
```

### Available commands
| Command | Description |
|---------|-------------|
| `scan <target> [type]` | Perform network scan<br>Types: `quick` (host discovery), `ports` (port scan), `full` (complete scan) |
| `help` | Show available commands |
| `exit` | Quit program |

### Example commands
```bash
scan 192.168.1.0/24
scan 10.0.0.5 ports
scan 172.16.1.1 full
```

## Project Structure
```
netscan/
├── app.py          # Main application
├── cli.py          # Command interface
└── scanner/
    ├── core.py     # Main scanner logic
    ├── scapy.py    # Scapy implementations
    └── nmap.py     # Nmap implementations
```

## Requirements
- Python 3.8+
- scapy >= 2.4.5
- python-nmap >= 0.7.1
- rich >= 12.0.0

## Disclaimer
Only use on networks you have permission to scan.  
Unauthorized scanning may violate laws and network policies.
