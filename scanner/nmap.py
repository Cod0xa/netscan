import nmap
from colorama import Fore

class NmapScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def os_detection(self, target):
        """Enhanced OS fingerprinting with accuracy reporting"""
        try:
            self.nm.scan(target, arguments='-O --osscan-limit')
            if target in self.nm.all_hosts():
                osmatch = self.nm[target].get('osmatch', [])
                if osmatch:
                    best_match = max(osmatch, key=lambda x: x['accuracy'])
                    return {
                        'os': best_match['name'],
                        'accuracy': best_match['accuracy'],
                        'type': best_match.get('osclass', {}).get('type', 'Unknown')
                    }
        except Exception as e:
            print(f"{Fore.RED}OS Detection Error: {str(e)}")
        return None

    def vulnerability_scan(self, target):
        """Comprehensive vulnerability assessment using NSE scripts"""
        try:
            print(f"{Fore.BLUE}Running Nmap vulnerability scripts...")
            self.nm.scan(target, arguments='--script vuln,vulners -sV --script-args mincvss=5.0')
            
            vulns = {}
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    for port in self.nm[host][proto]:
                        service = self.nm[host][proto][port]['name']
                        scripts = self.nm[host][proto][port].get('script', {})
                        
                        if scripts:
                            vulns[port] = {
                                'service': service,
                                'vulns': []
                            }
                            for script_name, output in scripts.items():
                                if 'vuln' in script_name.lower():
                                    vulns[port]['vulns'].append({
                                        'name': script_name,
                                        'output': output
                                    })
            return vulns
        except Exception as e:
            print(f"{Fore.RED}Vulnerability Scan Error: {str(e)}")
            return None

    def comprehensive_scan(self, target):
        """Legacy method for backward compatibility"""
        return self.os_detection(target)