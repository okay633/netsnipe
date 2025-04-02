import socket
import json
import time
import random
import sys
import os
from threading import Thread

# Paths
VULN_DB_FILE = 'vuln_db.json'

# Load vulnerability database
def load_vuln_db():
    if not os.path.exists(VULN_DB_FILE):
        print(f"Error: {VULN_DB_FILE} not found. Run with --update-db first.")
        sys.exit(1)
    with open(VULN_DB_FILE, 'r') as f:
        return json.load(f)

# Scan a single port
def scan_port(target, port, stealth=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    if stealth:
        time.sleep(random.uniform(0.1, 0.5))  # Random delay for stealth
    try:
        result = sock.connect_ex((target, port))
        return port if result == 0 else None
    except:
        return None
    finally:
        sock.close()

# Get service banner
def get_banner(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n" if port in [80, 443] else b"\n")
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        return banner
    except:
        return None

# Check for vulnerabilities
def check_vuln(service, version, vuln_db):
    for entry in vuln_db:
        if entry['service'].lower() in service.lower() and entry['version'] == version:
            return {'vulnerable': True, 'cve': entry['cve'], 'desc': entry['description']}
    return {'vulnerable': False, 'cve': None, 'desc': None}

# Main scan function
def scan_target(target, ports, stealth=False, vuln_db=None):
    open_ports = []
    results = {'target': target, 'ports': {}}
    
    threads = []
    for port in ports:
        t = Thread(target=lambda p=port: open_ports.append(scan_port(target, p, stealth)))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    
    open_ports = [p for p in open_ports if p]
    for port in open_ports:
        banner = get_banner(target, port)
        service = banner.split()[0] if banner else "Unknown"
        version = banner.split()[1] if banner and len(banner.split()) > 1 else "Unknown"
        vuln_info = check_vuln(service, version, vuln_db)
        results['ports'][port] = {
            'service': service,
            'version': version,
            'vulnerable': vuln_info['vulnerable'],
            'cve': vuln_info['cve'],
            'description': vuln_info['desc']
        }
        vuln_str = f"[VULNERABLE] CVE: {vuln_info['cve']} - {vuln_info['desc']}" if vuln_info['vulnerable'] else ""
        print(f"Port {port}: {service} {version} {vuln_str}")
    
    return results

# Command-line interface
def main():
    if len(sys.argv) < 2:
        print("Usage: netsnipe <target> [-p ports] [-s] [-o output.json] [--update-db]")
        sys.exit(1)

    target = sys.argv[1]
    ports = range(1, 1025)  # Default: common ports
    stealth = '-s' in sys.argv
    output_file = sys.argv[sys.argv.index('-o') + 1] if '-o' in sys.argv else None
    update_db = '--update-db' in sys.argv

    if '-p' in sys.argv:
        port_arg = sys.argv[sys.argv.index('-p') + 1]
        ports = [int(p) for p in port_arg.split(',')]

    if update_db:
        print("Database update not implemented yet. Use a pre-populated vuln_db.json.")
        sys.exit(0)

    vuln_db = load_vuln_db()
    print(f"Scanning {target} {'(stealth mode)' if stealth else ''}...")
    results = scan_target(target, ports, stealth, vuln_db)

    if output_file:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {output_file}")

if __name__ == '__main__':
    main()
