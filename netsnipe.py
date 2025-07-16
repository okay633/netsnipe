import socket
import json
import time
import random
import sys
import os
import asyncio
import aiohttp
import subprocess
import re
from threading import Thread
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import argparse
import ipaddress
from pathlib import Path

# Paths
VULN_DB_FILE = 'vuln_db.json'
CONFIG_FILE = 'config.json'
SCAN_HISTORY_FILE = 'scan_history.json'

# Enhanced vulnerability database with more comprehensive data
EXTENDED_VULN_DB = [
    {
        "service": "Apache",
        "version": "2.4.49",
        "cve": "CVE-2021-41773",
        "description": "Path traversal and file disclosure vulnerability.",
        "severity": "High",
        "exploitable": True,
        "exploit_complexity": "Low"
    },
    {
        "service": "Apache",
        "version": "2.4.50",
        "cve": "CVE-2021-42013",
        "description": "Path traversal fix bypass.",
        "severity": "High",
        "exploitable": True,
        "exploit_complexity": "Low"
    },
    {
        "service": "OpenSSH",
        "version": "7.6p1",
        "cve": "CVE-2018-15473",
        "description": "User enumeration vulnerability.",
        "severity": "Medium",
        "exploitable": True,
        "exploit_complexity": "Medium"
    },
    {
        "service": "OpenSSH",
        "version": "8.0p1",
        "cve": "CVE-2019-6111",
        "description": "Improper validation of SCP arguments.",
        "severity": "Medium",
        "exploitable": False,
        "exploit_complexity": "High"
    },
    {
        "service": "nginx",
        "version": "1.14.0",
        "cve": "CVE-2019-9516",
        "description": "HTTP/2 denial of service (0-RTT).",
        "severity": "Medium",
        "exploitable": True,
        "exploit_complexity": "Medium"
    },
    {
        "service": "MySQL",
        "version": "5.7.33",
        "cve": "CVE-2021-2154",
        "description": "Privilege escalation vulnerability.",
        "severity": "High",
        "exploitable": True,
        "exploit_complexity": "Medium"
    },
    {
        "service": "PostgreSQL",
        "version": "12.6",
        "cve": "CVE-2021-32027",
        "description": "Buffer overflow in ALTER TABLE.",
        "severity": "High",
        "exploitable": True,
        "exploit_complexity": "Low"
    },
    {
        "service": "Redis",
        "version": "6.0.10",
        "cve": "CVE-2021-32625",
        "description": "Integer overflow in STRALGO command.",
        "severity": "High",
        "exploitable": True,
        "exploit_complexity": "Low"
    }
]

# Common ports organized by service type
SERVICE_PORTS = {
    'web': [80, 443, 8080, 8443, 8000, 8888, 9000, 3000, 5000],
    'ssh': [22, 2222],
    'ftp': [21, 990],
    'telnet': [23],
    'smtp': [25, 587, 465],
    'dns': [53],
    'dhcp': [67, 68],
    'pop3': [110, 995],
    'imap': [143, 993],
    'snmp': [161, 162],
    'ldap': [389, 636],
    'smb': [139, 445],
    'database': [1433, 1521, 3306, 5432, 6379, 27017],
    'rdp': [3389],
    'vnc': [5900, 5901, 5902]
}

# OS fingerprinting signatures
OS_SIGNATURES = {
    'Linux': ['Linux', 'Ubuntu', 'CentOS', 'RedHat', 'Debian'],
    'Windows': ['Windows', 'Microsoft', 'IIS'],
    'Unix': ['Unix', 'AIX', 'Solaris', 'HP-UX'],
    'macOS': ['Darwin', 'Mac OS X', 'macOS'],
    'FreeBSD': ['FreeBSD'],
    'OpenBSD': ['OpenBSD'],
    'NetBSD': ['NetBSD']
}

# Load configuration
def load_config():
    default_config = {
        'timeout': 1,
        'max_threads': 100,
        'stealth_delay': (0.1, 0.5),
        'report_format': 'json',
        'auto_update_db': False,
        'scan_history_limit': 100
    }
    
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        # Merge with defaults
        for key, value in default_config.items():
            if key not in config:
                config[key] = value
        return config
    else:
        # Create default config
        with open(CONFIG_FILE, 'w') as f:
            json.dump(default_config, f, indent=2)
        return default_config

# Enhanced vulnerability database loading
def load_vuln_db():
    if os.path.exists(VULN_DB_FILE):
        with open(VULN_DB_FILE, 'r') as f:
            db = json.load(f)
        # Merge with extended database
        for entry in EXTENDED_VULN_DB:
            if not any(e['service'] == entry['service'] and e['version'] == entry['version'] for e in db):
                db.append(entry)
        return db
    else:
        print(f"Warning: {VULN_DB_FILE} not found. Using built-in database.")
        return EXTENDED_VULN_DB

# Enhanced port scanning with different techniques
def scan_port_advanced(target, port, scan_type='tcp', stealth=False, timeout=1):
    """Enhanced port scanning with multiple techniques"""
    if stealth:
        time.sleep(random.uniform(0.1, 0.5))
    
    if scan_type == 'tcp':
        return scan_tcp_port(target, port, timeout)
    elif scan_type == 'syn':
        return scan_syn_port(target, port, timeout)
    elif scan_type == 'udp':
        return scan_udp_port(target, port, timeout)
    
def scan_tcp_port(target, port, timeout):
    """Traditional TCP connect scan"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target, port))
        return port if result == 0 else None
    except:
        return None
    finally:
        sock.close()

def scan_syn_port(target, port, timeout):
    """SYN scan (requires raw sockets, fallback to TCP)"""
    # For now, fallback to TCP scan (SYN scan requires root privileges)
    return scan_tcp_port(target, port, timeout)

def scan_udp_port(target, port, timeout):
    """UDP port scan"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b'', (target, port))
        sock.recvfrom(1024)
        return port
    except socket.timeout:
        return port  # Port likely open (no response)
    except:
        return None
    finally:
        sock.close()

# Enhanced banner grabbing with multiple protocols
def get_enhanced_banner(target, port):
    """Enhanced banner grabbing with protocol-specific probes"""
    banners = {}
    
    # HTTP/HTTPS banner
    if port in [80, 443, 8080, 8443]:
        banners['http'] = get_http_banner(target, port)
    
    # SSH banner
    if port in [22, 2222]:
        banners['ssh'] = get_ssh_banner(target, port)
    
    # FTP banner
    if port == 21:
        banners['ftp'] = get_ftp_banner(target, port)
    
    # SMTP banner
    if port in [25, 587]:
        banners['smtp'] = get_smtp_banner(target, port)
    
    # Generic banner
    banners['generic'] = get_generic_banner(target, port)
    
    return banners

def get_http_banner(target, port):
    """Get HTTP server banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))
        sock.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
        banner = sock.recv(1024).decode(errors='ignore')
        sock.close()
        return banner
    except:
        return None

def get_ssh_banner(target, port):
    """Get SSH banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))
        banner = sock.recv(1024).decode(errors='ignore')
        sock.close()
        return banner
    except:
        return None

def get_ftp_banner(target, port):
    """Get FTP banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))
        banner = sock.recv(1024).decode(errors='ignore')
        sock.close()
        return banner
    except:
        return None

def get_smtp_banner(target, port):
    """Get SMTP banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))
        banner = sock.recv(1024).decode(errors='ignore')
        sock.close()
        return banner
    except:
        return None

def get_generic_banner(target, port):
    """Get generic banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, port))
        sock.send(b"\n")
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        return banner
    except:
        return None

# OS fingerprinting
def fingerprint_os(target, banners):
    """Attempt to fingerprint the operating system"""
    os_hints = []
    
    # Check banners for OS hints
    for banner_type, banner in banners.items():
        if banner:
            for os_name, signatures in OS_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in banner.lower():
                        os_hints.append(os_name)
    
    # TTL-based fingerprinting
    try:
        result = subprocess.run(['ping', '-c', '1', target], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            ttl_match = re.search(r'ttl=(\d+)', result.stdout.lower())
            if ttl_match:
                ttl = int(ttl_match.group(1))
                if ttl <= 64:
                    os_hints.append('Linux/Unix')
                elif ttl <= 128:
                    os_hints.append('Windows')
                elif ttl <= 255:
                    os_hints.append('Network Device')
    except:
        pass
    
    # Return most common OS hint
    if os_hints:
        return max(set(os_hints), key=os_hints.count)
    return "Unknown"

# Network discovery
def discover_hosts(network):
    """Discover active hosts in a network"""
    try:
        net = ipaddress.ip_network(network, strict=False)
        active_hosts = []
        
        def ping_host(ip):
            try:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)], 
                                      capture_output=True, timeout=3)
                if result.returncode == 0:
                    active_hosts.append(str(ip))
            except:
                pass
        
        threads = []
        for ip in net.hosts():
            t = Thread(target=ping_host, args=(ip,))
            t.start()
            threads.append(t)
            
            # Limit concurrent threads
            if len(threads) >= 50:
                for t in threads:
                    t.join()
                threads = []
        
        # Wait for remaining threads
        for t in threads:
            t.join()
        
        return active_hosts
    except:
        return []

# Enhanced vulnerability checking
def check_vuln_enhanced(service, version, banners, vuln_db):
    """Enhanced vulnerability checking with banner analysis"""
    vulnerabilities = []
    
    # Check against database
    for entry in vuln_db:
        if entry['service'].lower() in service.lower():
            if 'version' in entry and entry['version'] == version:
                vulnerabilities.append(entry)
            elif 'version_range' in entry:
                # Check version ranges (if implemented)
                pass
    
    # Check banners for known vulnerable signatures
    for banner_type, banner in banners.items():
        if banner:
            for entry in vuln_db:
                if 'signature' in entry and entry['signature'].lower() in banner.lower():
                    vulnerabilities.append(entry)
    
    return vulnerabilities

# Enhanced scanning with async support
async def scan_target_enhanced(target, ports, scan_type='tcp', stealth=False, config=None, vuln_db=None):
    """Enhanced target scanning with async support"""
    print(f"Starting enhanced scan of {target}...")
    
    # Discover additional hosts if target is a network
    if '/' in target:
        print("Network range detected. Discovering hosts...")
        hosts = discover_hosts(target)
        print(f"Found {len(hosts)} active hosts: {hosts}")
        
        # For network scans, scan first few hosts
        targets = hosts[:5]  # Limit to first 5 hosts
    else:
        targets = [target]
    
    all_results = {}
    
    for current_target in targets:
        print(f"\nScanning {current_target}...")
        
        # Port scanning
        open_ports = []
        with ThreadPoolExecutor(max_workers=config.get('max_threads', 100)) as executor:
            futures = []
            for port in ports:
                future = executor.submit(scan_port_advanced, current_target, port, 
                                       scan_type, stealth, config.get('timeout', 1))
                futures.append(future)
            
            for future in futures:
                result = future.result()
                if result:
                    open_ports.append(result)
        
        # Service detection and vulnerability checking
        results = {
            'target': current_target,
            'scan_time': datetime.now().isoformat(),
            'scan_type': scan_type,
            'os_fingerprint': None,
            'ports': {}
        }
        
        for port in open_ports:
            print(f"Analyzing port {port}...")
            banners = get_enhanced_banner(current_target, port)
            
            # Extract service and version info
            service = "Unknown"
            version = "Unknown"
            
            if banners.get('http'):
                server_match = re.search(r'Server: ([^\r\n]+)', banners['http'])
                if server_match:
                    service_info = server_match.group(1).split('/')
                    service = service_info[0]
                    version = service_info[1] if len(service_info) > 1 else "Unknown"
            
            elif banners.get('ssh'):
                ssh_match = re.search(r'SSH-[\d.]+-([^\s]+)', banners['ssh'])
                if ssh_match:
                    service = "OpenSSH"
                    version = ssh_match.group(1)
            
            elif banners.get('ftp'):
                if banners['ftp']:
                    parts = banners['ftp'].split()
                    if len(parts) >= 2:
                        service = parts[0]
                        version = parts[1]
            
            # Check for vulnerabilities
            vulnerabilities = check_vuln_enhanced(service, version, banners, vuln_db)
            
            results['ports'][port] = {
                'service': service,
                'version': version,
                'banners': banners,
                'vulnerabilities': vulnerabilities,
                'vulnerable': len(vulnerabilities) > 0
            }
            
            # Print results
            vuln_str = ""
            if vulnerabilities:
                vuln_str = f"[VULNERABLE] {len(vulnerabilities)} vulnerabilities found"
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', 'Unknown')
                    cve = vuln.get('cve', 'N/A')
                    print(f"  - {cve} ({severity}): {vuln['description']}")
            
            print(f"Port {port}: {service} {version} {vuln_str}")
        
        # OS fingerprinting
        if open_ports:
            all_banners = {}
            for port_info in results['ports'].values():
                all_banners.update(port_info['banners'])
            results['os_fingerprint'] = fingerprint_os(current_target, all_banners)
            print(f"OS Fingerprint: {results['os_fingerprint']}")
        
        all_results[current_target] = results
    
    return all_results

# Traceroute functionality
def traceroute(target, max_hops=30):
    """Perform traceroute to target"""
    try:
        result = subprocess.run(['traceroute', '-m', str(max_hops), target], 
                              capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return result.stdout.split('\n')
        else:
            # Try with tracert on Windows-like systems
            result = subprocess.run(['tracert', '-h', str(max_hops), target], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                return result.stdout.split('\n')
    except:
        pass
    return []

# DNS enumeration
def dns_enumeration(target):
    """Perform DNS enumeration"""
    dns_info = {}
    
    # Common DNS record types
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    
    for record_type in record_types:
        try:
            result = subprocess.run(['dig', '+short', target, record_type], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                dns_info[record_type] = result.stdout.strip().split('\n')
        except:
            pass
    
    return dns_info

# Scan history management
def save_scan_history(results, config):
    """Save scan results to history"""
    history = []
    if os.path.exists(SCAN_HISTORY_FILE):
        with open(SCAN_HISTORY_FILE, 'r') as f:
            history = json.load(f)
    
    # Add new scan
    history.append({
        'timestamp': datetime.now().isoformat(),
        'results': results
    })
    
    # Limit history size
    limit = config.get('scan_history_limit', 100)
    if len(history) > limit:
        history = history[-limit:]
    
    with open(SCAN_HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

# Generate comprehensive reports
def generate_report(results, format_type='json', output_file=None):
    """Generate comprehensive reports in various formats"""
    if format_type == 'json':
        report = json.dumps(results, indent=2)
    elif format_type == 'html':
        report = generate_html_report(results)
    elif format_type == 'csv':
        report = generate_csv_report(results)
    else:
        report = json.dumps(results, indent=2)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(report)
        print(f"Report saved to {output_file}")
    else:
        print(report)

def generate_html_report(results):
    """Generate HTML report"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>NetSnipe Scan Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .header { background: #333; color: white; padding: 20px; }
            .target { margin: 20px 0; border: 1px solid #ddd; padding: 15px; }
            .vulnerable { background: #ffebee; }
            .safe { background: #e8f5e8; }
            .port { margin: 10px 0; padding: 10px; border-left: 4px solid #2196F3; }
            .vulnerability { background: #fff3cd; padding: 10px; margin: 5px 0; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background: #f2f2f2; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>NetSnipe Scan Report</h1>
            <p>Generated on: {}</p>
        </div>
    """.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    
    for target, data in results.items():
        html += f"""
        <div class="target">
            <h2>Target: {target}</h2>
            <p><strong>Scan Time:</strong> {data.get('scan_time', 'N/A')}</p>
            <p><strong>OS Fingerprint:</strong> {data.get('os_fingerprint', 'Unknown')}</p>
            <p><strong>Open Ports:</strong> {len(data.get('ports', {}))}</p>
            
            <h3>Port Details</h3>
        """
        
        for port, port_data in data.get('ports', {}).items():
            vuln_class = 'vulnerable' if port_data.get('vulnerable') else 'safe'
            html += f"""
            <div class="port {vuln_class}">
                <h4>Port {port}</h4>
                <p><strong>Service:</strong> {port_data.get('service', 'Unknown')}</p>
                <p><strong>Version:</strong> {port_data.get('version', 'Unknown')}</p>
            """
            
            if port_data.get('vulnerabilities'):
                html += "<h5>Vulnerabilities:</h5>"
                for vuln in port_data['vulnerabilities']:
                    html += f"""
                    <div class="vulnerability">
                        <strong>{vuln.get('cve', 'N/A')} ({vuln.get('severity', 'Unknown')})</strong><br>
                        {vuln.get('description', 'No description available')}
                    </div>
                    """
            
            html += "</div>"
        
        html += "</div>"
    
    html += """
    </body>
    </html>
    """
    
    return html

def generate_csv_report(results):
    """Generate CSV report"""
    csv_lines = ["Target,Port,Service,Version,Vulnerable,CVE,Severity,Description"]
    
    for target, data in results.items():
        for port, port_data in data.get('ports', {}).items():
            if port_data.get('vulnerabilities'):
                for vuln in port_data['vulnerabilities']:
                    csv_lines.append(f"{target},{port},{port_data.get('service', 'Unknown')},"
                                   f"{port_data.get('version', 'Unknown')},Yes,"
                                   f"{vuln.get('cve', 'N/A')},{vuln.get('severity', 'Unknown')},"
                                   f"\"{vuln.get('description', 'No description available')}\"")
            else:
                csv_lines.append(f"{target},{port},{port_data.get('service', 'Unknown')},"
                               f"{port_data.get('version', 'Unknown')},No,N/A,N/A,N/A")
    
    return '\n'.join(csv_lines)

# Main function with argument parsing
def main():
    parser = argparse.ArgumentParser(description='NetSnipe - Advanced Network Scanner')
    parser.add_argument('target', help='Target IP, hostname, or network range (e.g., 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', help='Ports to scan (e.g., 22,80,443 or 1-1000)', default='common')
    parser.add_argument('-t', '--scan-type', choices=['tcp', 'syn', 'udp'], default='tcp', help='Scan type')
    parser.add_argument('-s', '--stealth', action='store_true', help='Enable stealth mode')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-f', '--format', choices=['json', 'html', 'csv'], default='json', help='Output format')
    parser.add_argument('--discover', action='store_true', help='Discover hosts in network range')
    parser.add_argument('--traceroute', action='store_true', help='Perform traceroute')
    parser.add_argument('--dns-enum', action='store_true', help='Perform DNS enumeration')
    parser.add_argument('--update-db', action='store_true', help='Update vulnerability database')
    parser.add_argument('--show-history', action='store_true', help='Show scan history')
    parser.add_argument('--service-type', choices=list(SERVICE_PORTS.keys()), help='Scan specific service type')
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config()
    
    # Show scan history
    if args.show_history:
        if os.path.exists(SCAN_HISTORY_FILE):
            with open(SCAN_HISTORY_FILE, 'r') as f:
                history = json.load(f)
            print(f"Scan History ({len(history)} entries):")
            for i, entry in enumerate(history[-10:]):  # Show last 10
                print(f"{i+1}. {entry['timestamp']} - {list(entry['results'].keys())}")
        else:
            print("No scan history found.")
        return
    
    # Update vulnerability database
    if args.update_db:
        print("Updating vulnerability database...")
        with open(VULN_DB_FILE, 'w') as f:
            json.dump(EXTENDED_VULN_DB, f, indent=2)
        print("Database updated successfully.")
        return
    
    # DNS enumeration
    if args.dns_enum:
        print(f"Performing DNS enumeration on {args.target}...")
        dns_info = dns_enumeration(args.target)
        print(json.dumps(dns_info, indent=2))
        return
    
    # Traceroute
    if args.traceroute:
        print(f"Performing traceroute to {args.target}...")
        trace_results = traceroute(args.target)
        for line in trace_results:
            print(line)
        return
    
    # Determine ports to scan
    if args.ports == 'common':
        ports = list(range(1, 1025))  # Common ports
    elif args.service_type:
        ports = SERVICE_PORTS.get(args.service_type, [])
    elif '-' in args.ports:
        start, end = map(int, args.ports.split('-'))
        ports = list(range(start, end + 1))
    else:
        ports = [int(p) for p in args.ports.split(',')]
    
    # Load vulnerability database
    vuln_db = load_vuln_db()
    
    # Perform scan
    print(f"Starting {args.scan_type.upper()} scan on {args.target}...")
    results = asyncio.run(scan_target_enhanced(
        args.target, ports, args.scan_type, args.stealth, config, vuln_db
    ))
    
    # Save to history
    save_scan_history(results, config)
    
    # Generate report
    generate_report(results, args.format, args.output)

if __name__ == '__main__':
    main()
