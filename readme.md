
# NetSnipe Enhanced
**Advanced Network Security Scanner & Monitoring Tool**

A comprehensive penetration testing and network reconnaissance tool for Linux with advanced features for vulnerability assessment, network monitoring, and security analysis.

## 🚀 New Features (Enhanced Version)

### Core Scanning Capabilities
- **Multi-Protocol Scanning**: TCP, SYN, UDP port scanning
- **Service Detection**: Enhanced banner grabbing with protocol-specific probes
- **OS Fingerprinting**: TTL-based and banner-based OS detection
- **Network Discovery**: Subnet scanning and host enumeration
- **Vulnerability Assessment**: Comprehensive CVE database with severity scoring

### Advanced Features
- **Continuous Monitoring**: Real-time network monitoring with baseline comparison
- **Automated Reporting**: HTML, CSV, and JSON report generation
- **Executive Summaries**: High-level security overview for management
- **Scan History**: Persistent storage and analysis of scan results
- **DNS Enumeration**: Comprehensive DNS record analysis
- **Traceroute Integration**: Network path analysis
- **Multi-format Output**: JSON, HTML, CSV reporting

### Professional Features
- **Vulnerability Database**: 15+ services with 30+ CVEs and auto-updates
- **Threat Intelligence**: CVSS scoring, exploitability assessment
- **Alerting System**: Email, webhook, and real-time notifications
- **Trending Analysis**: Historical vulnerability tracking
- **Configuration Profiles**: Stealth, aggressive, and balanced scan modes

## 📋 Requirements

### System Dependencies
- Python 3.7+
- nmap
- traceroute
- dnsutils (dig)
- Standard Linux tools (ping, etc.)

### Python Dependencies
- aiohttp
- requests
- python-nmap
- scapy
- colorama
- tqdm
- tabulate
- matplotlib
- plotly
- jinja2
- pdfkit

## 🛠️ Installation

### Quick Installation
```bash
# Clone the repository
git clone https://github.com/okay633/netsnipe.git
cd netsnipe

# Run the installation script
chmod +x install.sh
./install.sh
```

### Manual Installation
```bash
# Install system dependencies
sudo apt-get install python3 python3-pip python3-venv git nmap traceroute dnsutils

# Create virtual environment
python3 -m venv netsnipe-env
source netsnipe-env/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Make scripts executable
chmod +x netsnipe.py netsnipe_utils.py
```

## 🎯 Usage

### Basic Scanning
```bash
# Basic port scan
netsnipe 192.168.1.1

# Scan specific ports
netsnipe 192.168.1.1 -p 22,80,443

# Scan with stealth mode
netsnipe 192.168.1.1 -s

# UDP scan
netsnipe 192.168.1.1 -t udp -p 53,161

# Network range discovery
netsnipe 192.168.1.0/24 --discover
```

### Advanced Scanning
```bash
# Service-specific scans
netsnipe 192.168.1.1 --service-type web
netsnipe 192.168.1.1 --service-type database

# Comprehensive scan with HTML report
netsnipe 192.168.1.1 -f html -o security_report.html

# Stealth scan with CSV output
netsnipe 192.168.1.1 -s -f csv -o stealth_scan.csv
```

### Network Monitoring
```bash
# Start continuous monitoring
netsnipe-utils --monitor 192.168.1.1 --monitor-interval 300

# Monitor specific ports
netsnipe-utils --monitor 192.168.1.1 --monitor-ports 22,80,443

# Show monitoring alerts
netsnipe-utils --show-alerts
```

### Vulnerability Management
```bash
# Update vulnerability database
netsnipe-utils --update-vulns

# Generate executive summary
netsnipe-utils --generate-summary scan_results.json

# Analyze trends
netsnipe-utils --trend-analysis 30
```

### Additional Tools
```bash
# DNS enumeration
netsnipe example.com --dns-enum

# Traceroute analysis
netsnipe example.com --traceroute

# Show scan history
netsnipe --show-history
```

## 📊 Output Formats

### JSON Output (Default)
```json
{
  "192.168.1.1": {
    "target": "192.168.1.1",
    "scan_time": "2024-01-15T10:30:00",
    "scan_type": "tcp",
    "os_fingerprint": "Linux",
    "ports": {
      "22": {
        "service": "OpenSSH",
        "version": "8.0p1",
        "banners": {...},
        "vulnerabilities": [
          {
            "cve": "CVE-2019-6111",
            "severity": "Medium",
            "cvss_score": 5.9,
            "description": "Improper validation of SCP arguments"
          }
        ],
        "vulnerable": true
      }
    }
  }
}
```

### HTML Report
Professional-looking HTML reports with:
- Executive summary
- Vulnerability breakdown
- Color-coded risk levels
- Detailed port analysis
- Remediation recommendations

### CSV Export
Structured data for analysis:
- Target, Port, Service, Version
- Vulnerability status
- CVE information
- Severity ratings

## 🔧 Configuration

### Configuration File (`config.json`)
```json
{
  "timeout": 2,
  "max_threads": 100,
  "stealth_delay": [0.1, 0.5],
  "report_format": "json",
  "scan_profiles": {
    "stealth": {
      "timeout": 5,
      "max_threads": 10,
      "stealth_delay": [1.0, 3.0]
    },
    "aggressive": {
      "timeout": 0.5,
      "max_threads": 500,
      "stealth_delay": [0.0, 0.1]
    }
  },
  "notification_settings": {
    "email_alerts": false,
    "webhook_url": "",
    "slack_webhook": "",
    "discord_webhook": ""
  }
}
```

### Setup Wizard
```bash
# Run configuration wizard
python3 setup_wizard.py
```

## 🛡️ Security Features

### Vulnerability Database
- **15+ Services**: Apache, nginx, OpenSSH, MySQL, PostgreSQL, Redis, etc.
- **30+ CVEs**: Critical, High, Medium, Low severity classifications
- **CVSS Scoring**: Professional vulnerability assessment
- **Exploitability Assessment**: Complexity and feasibility analysis
- **Auto-Updates**: Integration with NVD API

### Monitoring & Alerting
- **Baseline Comparison**: Detects network changes
- **Real-time Alerts**: Instant notification of security events
- **Trend Analysis**: Historical security posture tracking
- **Multi-channel Notifications**: Email, webhooks, Slack, Discord

### Stealth Capabilities
- **Randomized Timing**: Evade detection systems
- **SYN Scanning**: Minimize connection footprint
- **Distributed Scanning**: Spread across time/threads
- **Custom Profiles**: Tailored evasion techniques

## 📈 Reporting & Analysis

### Executive Summary
- Total vulnerabilities by severity
- High-risk host identification
- Security trend analysis
- Actionable recommendations

### Detailed Reports
- Port-by-port analysis
- Service version detection
- Vulnerability correlation
- Remediation prioritization

### Trend Analysis
- Historical vulnerability tracking
- Risk progression monitoring
- Compliance reporting
- Security metrics dashboard

## 🔄 Continuous Monitoring

### Features
- **Baseline Detection**: Establish security baselines
- **Change Monitoring**: Track network modifications
- **Automated Scanning**: Schedule regular assessments
- **Alert Generation**: Immediate threat notification
- **Historical Analysis**: Long-term security trends

### Monitoring Setup
```bash
# Monitor critical server
netsnipe-utils --monitor 192.168.1.10 --monitor-ports 22,80,443,3306

# Start monitoring service
sudo systemctl start netsnipe-monitor
```

## 🎛️ Advanced Configuration

### Service Profiles
```bash
# Web services
netsnipe target --service-type web

# Database services  
netsnipe target --service-type database

# Remote access services
netsnipe target --service-type ssh,rdp,vnc
```

### Scan Profiles
```bash
# Stealth mode
netsnipe target --profile stealth

# Aggressive mode
netsnipe target --profile aggressive

# Balanced mode (default)
netsnipe target --profile balanced
```

### Custom Vulnerability Database
```bash
# Add custom signatures
netsnipe-utils --add-signature service version cve description

# Update from NVD
export NVD_API_KEY="your-api-key"
netsnipe-utils --update-vulns
```

## 🔐 Security Best Practices

### Legal Compliance
- **Authorization Required**: Only scan systems you own or have explicit permission to test
- **Documentation**: Maintain scan logs and authorization records
- **Responsible Disclosure**: Report vulnerabilities through proper channels

### Operational Security
- **Rate Limiting**: Use appropriate delays to avoid detection
- **Traffic Distribution**: Spread scans across time and sources
- **Log Management**: Secure storage of scan results and history

## 🛠️ Development & Customization

### Adding New Modules
```python
# Custom banner grabber
def get_custom_banner(target, port):
    # Implementation
    pass

# Custom vulnerability check
def check_custom_vuln(service, version, banners):
    # Implementation
    pass
```

### Plugin System
```python
# Example plugin structure
class CustomPlugin:
    def __init__(self):
        self.name = "CustomPlugin"
    
    def scan(self, target, port):
        # Custom scanning logic
        pass
    
    def analyze(self, results):
        # Custom analysis logic
        pass
```

## 📚 Documentation

### API Reference
- [Core Functions](docs/api/core.md)
- [Vulnerability Database](docs/api/vulndb.md)
- [Monitoring System](docs/api/monitoring.md)
- [Report Generation](docs/api/reporting.md)

### Tutorials
- [Basic Scanning](docs/tutorials/basic-scanning.md)
- [Advanced Features](docs/tutorials/advanced-features.md)
- [Custom Signatures](docs/tutorials/custom-signatures.md)
- [Monitoring Setup](docs/tutorials/monitoring-setup.md)

## 🤝 Contributing

### Development Setup
```bash
# Fork and clone
git clone https://github.com/yourusername/netsnipe.git
cd netsnipe

# Create development environment
python3 -m venv dev-env
source dev-env/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

### Contribution Guidelines
- Follow Python PEP 8 style guidelines
- Add unit tests for new features
- Update documentation
- Submit pull requests for review

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

NetSnipe is intended for legitimate security testing and network administration purposes only. Users are responsible for complying with all applicable laws and regulations. The developers assume no liability for misuse of this tool.

## 🔗 Related Projects

- [Nmap](https://nmap.org/) - Network discovery and security auditing
- [Masscan](https://github.com/robertdavidgraham/masscan) - High-speed port scanner
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanner
- [OpenVAS](https://www.openvas.org/) - Vulnerability assessment system

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/okay633/netsnipe/issues)
- **Discussions**: [GitHub Discussions](https://github.com/okay633/netsnipe/discussions)
- **Security**: security@netsnipe.org
- **Documentation**: [Wiki](https://github.com/okay633/netsnipe/wiki)

---

**NetSnipe Enhanced** - Professional Network Security Assessment Tool

*Built for security professionals, penetration testers, and network administrators who need comprehensive network analysis capabilities.*


