# NZRX Network Scanner with CVE Detection - Enhanced Edition

import argparse
import ipaddress
import nmap
import requests
import socket
import subprocess
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from termcolor import colored

# Constants
CVE_API = "https://cve.circl.lu/api/search/"
MAX_THREADS = 30

# Banner
BANNER = r'''
888b    |  ~~~~d88P 888~-_   Y88b    /                               ,8P~ ,8P~      ~Y8, ~Y8, 
|Y88b   |     d88P  888   \   Y88b  /                                88   88          88   88 
| Y88b  |    d88P   888    |   Y88b/                                 88   88          88   88 
|  Y88b |   d88P    888   /    /Y88b                                 88   88          88   88 
|   Y88b|  d88P     888_-~    /  Y88b                                88   88   d88b   88   88 
|    Y888 d88P____  888 ~-_  /    Y88b                               88   88   Y88P   88   88 
                                                                     "8b_ "8b_      _d8" _d8" 
,d88~~\  e88~-_       e      888b    | 888b    | 888~~  888~-_               | | | |          
8888    d888   \     d8b     |Y88b   | |Y88b   | 888___ 888   \              | | | |          
`Y88b   8888        /Y88b    | Y88b  | | Y88b  | 888    888    |             | | | |          
 `Y88b, 8888       /  Y88b   |  Y88b | |  Y88b | 888    888   /              | | | |          
   8888 Y888   /  /____Y88b  |   Y88b| |   Y88b| 888    888_-~               | | | |          
\__88P'  "88_-~  /      Y88b |    Y888 |    Y888 888___ 888 ~-_              | | | |          
                                                                             | | | |                                                          
    NZRX Network Scanner with CVE Detection v1.1
'''

def print_banner():
    print(colored(BANNER, 'cyan'))

# Check root privileges
def check_root():
    if os.geteuid() != 0:
        print(colored("[!] This script requires root privileges.", 'red'))
        exit(1)

# Get local network CIDR
def get_local_network():
    try:
        ip_data = subprocess.check_output("ip -o -f inet addr show | awk '{print $4}'", shell=True).decode().splitlines()
        for cidr in ip_data:
            if not cidr.startswith("127"):
                return cidr
    except:
        return "192.168.1.0/24"

# Basic host discovery
def discover_hosts(network):
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    return [h for h in nm.all_hosts() if nm[h].state() == 'up']

# Deep port + service scan
def scan_host(host):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=host, arguments='-T4 -sV -p- --version-intensity 5')
        results = []
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                info = nm[host][proto][port]
                if info['state'] == 'open':
                    results.append({
                        'port': port,
                        'service': info.get('name', ''),
                        'product': info.get('product', ''),
                        'version': info.get('version', '')
                    })
        return {'host': host, 'ports': results}
    except:
        return {'host': host, 'ports': []}

# CVE lookup using CIRCL
def check_cves(product, version):
    try:
        if not product or not version:
            return []
        q = f"{product} {version}".strip().replace(' ', '%20')
        response = requests.get(f"{CVE_API}{q}", timeout=10)
        if response.status_code == 200:
            json_data = response.json()
            return [i['id'] for i in json_data.get('results', [])][:10]
        return []
    except:
        return []

# Full scanner logic
def full_scan(detailed):
    network = get_local_network()
    print(colored(f"[*] Scanning network: {network}", 'yellow'))
    hosts = discover_hosts(network)
    print(colored(f"[+] Active hosts found: {len(hosts)}", 'green'))

    host_results = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(scan_host, host): host for host in hosts}
        for future in as_completed(futures):
            result = future.result()
            if result:
                host_results.append(result)

    # Enrich with CVE data
    for host in host_results:
        for port in host['ports']:
            port['cves'] = check_cves(port['product'], port['version'])

    print_report(host_results, detailed)

# Output function
def print_report(results, detailed):
    vuln_count = 0
    for host in results:
        print(colored(f"\n[+] Host: {host['host']}", 'blue'))
        for port in host['ports']:
            print(f"  Port {port['port']}/{port['service']} - {port['product']} {port['version']}")
            if port['cves']:
                vuln_count += len(port['cves'])
                for cve in port['cves']:
                    print(colored(f"    CVE: {cve}", 'red'))
            elif detailed:
                print("    No known CVEs")

    print(colored(f"\n[=] Total Vulnerabilities Found: {vuln_count}", 'magenta'))

# Main
if __name__ == '__main__':
    check_root()
    print_banner()

    parser = argparse.ArgumentParser(description='NZRX Ultimate Pentest Scanner')
    parser.add_argument('-d', '--detailed', action='store_true', help='Show detailed CVE data')
    args = parser.parse_args()

    start = datetime.now()
    full_scan(args.detailed)
    print(colored(f"\nScan completed in {datetime.now() - start}", 'cyan'))
