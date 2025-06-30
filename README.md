# NZRX Network Scanner — CVE-Aware Toolkit

### Features

- **Full subnet discovery** using system-level interface inspection
- **High-speed multithreaded port scanning** (`-p-`, `-sV`, `--version-intensity 5`)
- **Automatic service fingerprinting** with `nmap`
- **Live CVE checking** via CIRCL CVE API

---

### Usage

## 1. Install Requirements

```bash
pip3 install -r requirements.txt
```
    Ensure nmap is installed on your system.
```bash
sudo apt install nmap -y
```
2. Run the Scanner
```bash
sudo python3 scanner.py -s    # Simple output
sudo python3 scanner.py -d    # Detailed output with all open ports and CVEs
```
3. Example Output
```bash
[+] Host: 192.168.1.5
  Port 80/http - Apache httpd 2.4.49
    CVE: CVE-2021-41773
  Port 22/ssh - OpenSSH 7.2p2
```
Notes

    Must be run as root to use advanced scanning.

    Works best in Linux environments with full interface access.
