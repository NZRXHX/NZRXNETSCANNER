#!/usr/bin/env python3
import argparse
import ipaddress
import nmap
import requests
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
# NZRXHX scanner
# Banner
def print_banner():
    banner = """
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
    NZRX Network Scanner with CVE Detection v1.0
    """
    print(banner)

# Check if script is run as root
def check_root():
    if subprocess.check_output(['id', '-u']).decode().strip() != '0':
        print("This script requires root privileges. Please run with sudo.")
        exit(1)

# Get local network range
def get_local_network():
    try:
        # Get default gateway IP
        gw_ip = subprocess.check_output(['ip', 'route', 'show', 'default']).decode().split()[2]
        
        # Get local IP and netmask
        ip_info = subprocess.check_output(['ip', '-o', '-4', 'addr', 'show']).decode()
        for line in ip_info.splitlines():
            if gw_ip in line:
                parts = line.split()
                ip_with_mask = parts[3]
                ip = ip_with_mask.split('/')[0]
                netmask = ip_with_mask.split('/')[1]
                break
        
        # Calculate network address
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(network)
    
    except Exception as e:
        print(f"Error determining local network: {e}")
        return "192.168.1.0/24"  # Fallback to common default

# Scan network for active hosts
def scan_network(network):
    print(f"[*] Scanning network {network} for active hosts...")
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    
    active_hosts = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            active_hosts.append(host)
    
    return active_hosts

# Scan ports and versions for a single host
def scan_host_ports(host):
    nm = nmap.PortScanner()
    try:
        # First scan for open ports quickly
        nm.scan(hosts=host, arguments='-T4 --min-rate 1000 -p- --open')
        
        if host not in nm.all_hosts():
            return None
        
        open_ports = []
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                if nm[host][proto][port]['state'] == 'open':
                    open_ports.append(port)
        
        if not open_ports:
            return {'host': host, 'ports': []}
        
        # Now perform service/version detection on open ports
        port_str = ','.join(map(str, open_ports))
        nm.scan(hosts=host, arguments=f'-sV -T4 -p {port_str} --version-intensity 7')
        
        port_info = []
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                if nm[host][proto][port]['state'] == 'open':
                    service = nm[host][proto][port]['name']
                    product = nm[host][proto][port].get('product', '')
                    version = nm[host][proto][port].get('version', '')
                    port_info.append({
                        'port': port,
                        'service': service,
                        'product': product,
                        'version': version
                    })
        
        return {'host': host, 'ports': port_info}
    
    except Exception as e:
        print(f"Error scanning host {host}: {e}")
        return {'host': host, 'ports': []}

# Check for CVEs using a simple API (this is a simplified approach)
def check_cves(product, version):
    if not product or not version:
        return []
    
    try:
        # Using a simple CVE search API (this is just an example)
        # In a real-world scenario, you'd want to use a proper vulnerability database
        query = f"{product} {version}"
        url = f"https://cve.circl.lu/api/search/{query}"
        response = requests.get(url)
        
        if response.status_code == 200:
            data = response.json()
            if data and 'results' in data:
                return [cve['id'] for cve in data['results']]
        
        return []
    
    except Exception as e:
        print(f"Error checking CVEs for {product} {version}: {e}")
        return []

# Main scanning function
def perform_scan(detailed=False):
    network = get_local_network()
    active_hosts = scan_network(network)
    
    if not active_hosts:
        print("No active hosts found in the network.")
        return
    
    print(f"\n[*] Found {len(active_hosts)} active hosts. Scanning for open ports and versions...")
    
    # Scan all hosts with ThreadPoolExecutor for parallel scanning
    hosts_with_ports = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(scan_host_ports, active_hosts)
        hosts_with_ports = [result for result in results if result is not None]
    
    # Check for CVEs
    vulnerable_hosts = []
    for host_info in hosts_with_ports:
        vulnerable_ports = []
        for port_info in host_info['ports']:
            cves = check_cves(port_info['product'], port_info['version'])
            if cves:
                vulnerable_ports.append({
                    'port': port_info['port'],
                    'service': port_info['service'],
                    'product': port_info['product'],
                    'version': port_info['version'],
                    'cves': cves
                })
        
        if vulnerable_ports:
            vulnerable_hosts.append({
                'host': host_info['host'],
                'vulnerable_ports': vulnerable_ports
            })
    
    # Print results based on detail level
    if detailed:
        print_detailed_results(active_hosts, hosts_with_ports, vulnerable_hosts)
    else:
        print_simple_results(active_hosts, hosts_with_ports, vulnerable_hosts)

# Print detailed results
def print_detailed_results(active_hosts, hosts_with_ports, vulnerable_hosts):
    print("\n[+] Detailed Scan Results:")
    print(f"\nTotal devices found in network: {len(active_hosts)}")
    print("IP addresses:")
    for host in active_hosts:
        print(f"  - {host}")
    
    hosts_with_open_ports = [h for h in hosts_with_ports if h['ports']]
    print(f"\nDevices with open ports: {len(hosts_with_open_ports)}")
    print("IP addresses and open ports:")
    for host in hosts_with_open_ports:
        print(f"\nHost: {host['host']}")
        for port in host['ports']:
            print(f"  - Port: {port['port']}/{port['service']}")
            print(f"    Service: {port['product']} {port['version']}")
    
    print(f"\nVulnerable devices: {len(vulnerable_hosts)}")
    print("Vulnerabilities found:")
    for host in vulnerable_hosts:
        print(f"\nHost: {host['host']}")
        for port in host['vulnerable_ports']:
            print(f"  - Port: {port['port']}/{port['service']}")
            print(f"    Service: {port['product']} {port['version']}")
            print("    CVEs:")
            for cve in port['cves']:
                print(f"      - {cve}")

# Print simple results
def print_simple_results(active_hosts, hosts_with_ports, vulnerable_hosts):
    print("\n[+] Simple Scan Results:")
    print(f"Total devices found in network: {len(active_hosts)}")
    
    hosts_with_open_ports = [h for h in hosts_with_ports if h['ports']]
    print(f"Devices with open ports: {len(hosts_with_open_ports)}")
    
    print(f"Vulnerable devices: {len(vulnerable_hosts)}")
    if vulnerable_hosts:
        print("\nVulnerabilities found:")
        for host in vulnerable_hosts:
            print(f"\nHost: {host['host']}")
            for port in host['vulnerable_ports']:
                print(f"  - Port: {port['port']}/{port['service']}")
                print(f"    Service: {port['product']} {port['version']}")
                print("    CVEs:")
                for cve in port['cves']:
                    print(f"      - {cve}")

if __name__ == "__main__":
    check_root()
    print_banner()
    
    parser = argparse.ArgumentParser(description="NZRX Network Scanner with CVE Detection")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--detailed', action='store_true', help="Detailed scan results")
    group.add_argument('-s', '--simple', action='store_true', help="Simple scan results")
    args = parser.parse_args()
    
    start_time = datetime.now()
    perform_scan(detailed=args.detailed)
    end_time = datetime.now()
    
    print(f"\nScan completed in {end_time - start_time}")
