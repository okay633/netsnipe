#!/usr/bin/env python3
"""
NetSnipe Utilities - Advanced features for NetSnipe
Provides additional functionality like vulnerability database updates,
network monitoring, reporting, and more.
"""

import json
import requests
import os
import time
import sys
import argparse
import sqlite3
from datetime import datetime, timedelta
import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import schedule
import logging
from pathlib import Path

# Configuration
CONFIG_FILE = 'config.json'
VULN_DB_FILE = 'vuln_db.json'
SCAN_HISTORY_FILE = 'scan_history.json'
MONITORING_DB = 'monitoring.db'
LOG_FILE = 'netsnipe.log'

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class VulnDBUpdater:
    """Handles vulnerability database updates from various sources"""
    
    def __init__(self):
        self.nvd_api_key = os.getenv('NVD_API_KEY')
        
    def update_from_nvd(self):
        """Update vulnerability database from NVD API"""
        logger.info("Updating vulnerability database from NVD...")
        
        # NVD API endpoint
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        try:
            # Get recent CVEs (last 30 days)
            end_date = datetime.now()
            start_date = end_date - timedelta(days=30)
            
            params = {
                'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
                'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
            }
            
            headers = {}
            if self.nvd_api_key:
                headers['apiKey'] = self.nvd_api_key
            
            response = requests.get(base_url, params=params, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            new_entries = []
            
            for cve in data.get('vulnerabilities', []):
                cve_data = cve.get('cve', {})
                cve_id = cve_data.get('id')
                descriptions = cve_data.get('descriptions', [])
                
                if descriptions:
                    description = descriptions[0].get('value', '')
                    
                    # Extract service information from description
                    service = self._extract_service_from_description(description)
                    
                    if service:
                        # Get CVSS score
                        cvss_score = self._extract_cvss_score(cve_data)
                        
                        entry = {
                            'service': service,
                            'version': 'Unknown',
                            'cve': cve_id,
                            'description': description,
                            'severity': self._cvss_to_severity(cvss_score),
                            'cvss_score': cvss_score,
                            'exploitable': self._is_exploitable(cve_data),
                            'exploit_complexity': self._get_exploit_complexity(cve_data),
                            'signature': service.lower()
                        }
                        new_entries.append(entry)
            
            # Merge with existing database
            existing_db = []
            if os.path.exists(VULN_DB_FILE):
                with open(VULN_DB_FILE, 'r') as f:
                    existing_db = json.load(f)
            
            # Add new entries
            for entry in new_entries:
                if not any(e['cve'] == entry['cve'] for e in existing_db):
                    existing_db.append(entry)
            
            # Save updated database
            with open(VULN_DB_FILE, 'w') as f:
                json.dump(existing_db, f, indent=2)
            
            logger.info(f"Added {len(new_entries)} new vulnerabilities to database")
            
        except Exception as e:
            logger.error(f"Error updating from NVD: {e}")
    
    def _extract_service_from_description(self, description):
        """Extract service name from CVE description"""
        services = ['Apache', 'nginx', 'OpenSSH', 'MySQL', 'PostgreSQL', 'Redis', 
                   'IIS', 'Samba', 'Postfix', 'Dovecot', 'Elasticsearch', 'MongoDB']
        
        for service in services:
            if service.lower() in description.lower():
                return service
        return None
    
    def _extract_cvss_score(self, cve_data):
        """Extract CVSS score from CVE data"""
        metrics = cve_data.get('metrics', {})
        if 'cvssMetricV31' in metrics:
            return metrics['cvssMetricV31'][0]['cvssData']['baseScore']
        elif 'cvssMetricV30' in metrics:
            return metrics['cvssMetricV30'][0]['cvssData']['baseScore']
        elif 'cvssMetricV2' in metrics:
            return metrics['cvssMetricV2'][0]['cvssData']['baseScore']
        return 0.0
    
    def _cvss_to_severity(self, score):
        """Convert CVSS score to severity"""
        if score >= 9.0:
            return 'Critical'
        elif score >= 7.0:
            return 'High'
        elif score >= 4.0:
            return 'Medium'
        else:
            return 'Low'
    
    def _is_exploitable(self, cve_data):
        """Determine if vulnerability is exploitable"""
        # Simplified logic - in real implementation, would check exploit databases
        return True
    
    def _get_exploit_complexity(self, cve_data):
        """Get exploit complexity"""
        metrics = cve_data.get('metrics', {})
        if 'cvssMetricV31' in metrics:
            complexity = metrics['cvssMetricV31'][0]['cvssData']['attackComplexity']
            return complexity.title()
        return 'Unknown'

class NetworkMonitor:
    """Continuous network monitoring capabilities"""
    
    def __init__(self):
        self.monitoring = False
        self.monitored_hosts = []
        self.init_database()
    
    def init_database(self):
        """Initialize monitoring database"""
        conn = sqlite3.connect(MONITORING_DB)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitoring_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                host TEXT,
                port INTEGER,
                service TEXT,
                status TEXT,
                response_time REAL,
                vulnerability_count INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                host TEXT,
                alert_type TEXT,
                message TEXT,
                severity TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_host(self, host, ports=None):
        """Add host to monitoring"""
        if ports is None:
            ports = [22, 80, 443, 21, 25, 53]
        
        self.monitored_hosts.append({
            'host': host,
            'ports': ports,
            'last_scan': None,
            'baseline': None
        })
        
        logger.info(f"Added {host} to monitoring")
    
    def start_monitoring(self, interval=300):
        """Start continuous monitoring"""
        self.monitoring = True
        logger.info(f"Starting network monitoring with {interval}s interval")
        
        def monitor_loop():
            while self.monitoring:
                for host_info in self.monitored_hosts:
                    self.scan_host(host_info)
                time.sleep(interval)
        
        monitor_thread = threading.Thread(target=monitor_loop)
        monitor_thread.daemon = True
        monitor_thread.start()
    
    def scan_host(self, host_info):
        """Scan a monitored host"""
        host = host_info['host']
        ports = host_info['ports']
        
        logger.info(f"Scanning monitored host: {host}")
        
        # Run NetSnipe scan
        cmd = ['python3', 'netsnipe.py', host, '-p', ','.join(map(str, ports)), '-f', 'json']
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                # Parse results and store in database
                self.store_monitoring_result(host, result.stdout)
                
                # Check for changes from baseline
                if host_info['baseline']:
                    self.compare_with_baseline(host_info, result.stdout)
                else:
                    host_info['baseline'] = result.stdout
                
                host_info['last_scan'] = datetime.now()
                
        except subprocess.TimeoutExpired:
            logger.error(f"Scan timeout for {host}")
        except Exception as e:
            logger.error(f"Error scanning {host}: {e}")
    
    def store_monitoring_result(self, host, scan_result):
        """Store monitoring result in database"""
        conn = sqlite3.connect(MONITORING_DB)
        cursor = conn.cursor()
        
        try:
            # Parse scan result
            data = json.loads(scan_result)
            
            for host_data in data.values():
                for port, port_data in host_data.get('ports', {}).items():
                    cursor.execute('''
                        INSERT INTO monitoring_results 
                        (timestamp, host, port, service, status, response_time, vulnerability_count)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        datetime.now().isoformat(),
                        host,
                        port,
                        port_data.get('service', 'Unknown'),
                        'open',
                        0.0,  # Would need to implement response time tracking
                        len(port_data.get('vulnerabilities', []))
                    ))
            
            conn.commit()
            
        except Exception as e:
            logger.error(f"Error storing monitoring result: {e}")
        finally:
            conn.close()
    
    def compare_with_baseline(self, host_info, current_result):
        """Compare current scan with baseline"""
        try:
            baseline_data = json.loads(host_info['baseline'])
            current_data = json.loads(current_result)
            
            # Check for new open ports
            baseline_ports = set()
            current_ports = set()
            
            for host_data in baseline_data.values():
                baseline_ports.update(host_data.get('ports', {}).keys())
            
            for host_data in current_data.values():
                current_ports.update(host_data.get('ports', {}).keys())
            
            new_ports = current_ports - baseline_ports
            closed_ports = baseline_ports - current_ports
            
            if new_ports:
                self.create_alert(host_info['host'], 'new_port', 
                                f"New open ports detected: {list(new_ports)}", 'Medium')
            
            if closed_ports:
                self.create_alert(host_info['host'], 'closed_port', 
                                f"Ports closed: {list(closed_ports)}", 'Low')
            
        except Exception as e:
            logger.error(f"Error comparing with baseline: {e}")
    
    def create_alert(self, host, alert_type, message, severity):
        """Create monitoring alert"""
        conn = sqlite3.connect(MONITORING_DB)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (timestamp, host, alert_type, message, severity)
            VALUES (?, ?, ?, ?, ?)
        ''', (datetime.now().isoformat(), host, alert_type, message, severity))
        
        conn.commit()
        conn.close()
        
        logger.warning(f"ALERT [{severity}] {host}: {message}")
        
        # Send notification if configured
        self.send_notification(host, alert_type, message, severity)
    
    def send_notification(self, host, alert_type, message, severity):
        """Send notification via configured channels"""
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
            
            notifications = config.get('notification_settings', {})
            
            # Email notification
            if notifications.get('email_alerts'):
                self.send_email_alert(host, alert_type, message, severity)
            
            # Webhook notification
            if notifications.get('webhook_url'):
                self.send_webhook_alert(notifications['webhook_url'], host, alert_type, message, severity)
            
        except Exception as e:
            logger.error(f"Error sending notification: {e}")
    
    def send_email_alert(self, host, alert_type, message, severity):
        """Send email alert"""
        # Implementation would depend on email server configuration
        pass
    
    def send_webhook_alert(self, webhook_url, host, alert_type, message, severity):
        """Send webhook alert"""
        payload = {
            'host': host,
            'alert_type': alert_type,
            'message': message,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            logger.info(f"Webhook notification sent for {host}")
        except Exception as e:
            logger.error(f"Failed to send webhook notification: {e}")

class ReportGenerator:
    """Advanced report generation capabilities"""
    
    def __init__(self):
        self.templates_dir = Path('templates')
        self.templates_dir.mkdir(exist_ok=True)
    
    def generate_executive_summary(self, scan_results):
        """Generate executive summary report"""
        summary = {
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_hosts': len(scan_results),
            'total_open_ports': 0,
            'total_vulnerabilities': 0,
            'high_risk_hosts': [],
            'vulnerability_breakdown': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0},
            'recommendations': []
        }
        
        for host, data in scan_results.items():
            ports = data.get('ports', {})
            summary['total_open_ports'] += len(ports)
            
            host_vulns = 0
            for port_data in ports.values():
                vulns = port_data.get('vulnerabilities', [])
                host_vulns += len(vulns)
                
                for vuln in vulns:
                    severity = vuln.get('severity', 'Unknown')
                    if severity in summary['vulnerability_breakdown']:
                        summary['vulnerability_breakdown'][severity] += 1
            
            summary['total_vulnerabilities'] += host_vulns
            
            # Identify high-risk hosts
            if host_vulns > 5 or any(v.get('severity') == 'Critical' for port_data in ports.values() for v in port_data.get('vulnerabilities', [])):
                summary['high_risk_hosts'].append({
                    'host': host,
                    'vulnerability_count': host_vulns,
                    'open_ports': len(ports)
                })
        
        # Generate recommendations
        if summary['vulnerability_breakdown']['Critical'] > 0:
            summary['recommendations'].append("Immediately patch all critical vulnerabilities")
        
        if summary['vulnerability_breakdown']['High'] > 0:
            summary['recommendations'].append("Prioritize patching of high-severity vulnerabilities")
        
        if summary['total_open_ports'] > summary['total_hosts'] * 10:
            summary['recommendations'].append("Review and close unnecessary open ports")
        
        return summary
    
    def generate_trend_analysis(self, days=30):
        """Generate vulnerability trend analysis"""
        if not os.path.exists(MONITORING_DB):
            return None
        
        conn = sqlite3.connect(MONITORING_DB)
        cursor = conn.cursor()
        
        # Get data for the last N days
        start_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        cursor.execute('''
            SELECT DATE(timestamp) as date, 
                   COUNT(*) as total_scans,
                   SUM(vulnerability_count) as total_vulns
            FROM monitoring_results 
            WHERE timestamp >= ? 
            GROUP BY DATE(timestamp)
            ORDER BY date
        ''', (start_date,))
        
        results = cursor.fetchall()
        conn.close()
        
        return {
            'period': f"{days} days",
            'data': [{'date': row[0], 'scans': row[1], 'vulnerabilities': row[2]} for row in results]
        }

def main():
    parser = argparse.ArgumentParser(description='NetSnipe Utilities')
    parser.add_argument('--update-vulns', action='store_true', help='Update vulnerability database')
    parser.add_argument('--monitor', help='Start monitoring host (IP or hostname)')
    parser.add_argument('--monitor-ports', help='Ports to monitor (comma-separated)')
    parser.add_argument('--monitor-interval', type=int, default=300, help='Monitoring interval in seconds')
    parser.add_argument('--generate-summary', help='Generate executive summary from scan results file')
    parser.add_argument('--trend-analysis', type=int, help='Generate trend analysis for N days')
    parser.add_argument('--show-alerts', action='store_true', help='Show recent alerts')
    
    args = parser.parse_args()
    
    if args.update_vulns:
        updater = VulnDBUpdater()
        updater.update_from_nvd()
    
    if args.monitor:
        monitor = NetworkMonitor()
        ports = [int(p) for p in args.monitor_ports.split(',')] if args.monitor_ports else None
        monitor.add_host(args.monitor, ports)
        monitor.start_monitoring(args.monitor_interval)
        
        # Keep monitoring running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Monitoring stopped")
    
    if args.generate_summary:
        generator = ReportGenerator()
        with open(args.generate_summary, 'r') as f:
            scan_results = json.load(f)
        
        summary = generator.generate_executive_summary(scan_results)
        print(json.dumps(summary, indent=2))
    
    if args.trend_analysis:
        generator = ReportGenerator()
        analysis = generator.generate_trend_analysis(args.trend_analysis)
        if analysis:
            print(json.dumps(analysis, indent=2))
        else:
            print("No monitoring data available")
    
    if args.show_alerts:
        if os.path.exists(MONITORING_DB):
            conn = sqlite3.connect(MONITORING_DB)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT timestamp, host, alert_type, message, severity
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT 20
            ''')
            
            alerts = cursor.fetchall()
            conn.close()
            
            print("Recent Alerts:")
            for alert in alerts:
                print(f"[{alert[4]}] {alert[0]} - {alert[1]}: {alert[3]}")
        else:
            print("No alerts database found")

if __name__ == '__main__':
    main()