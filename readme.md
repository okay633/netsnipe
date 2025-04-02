
# NetSnipe
A penetration testing tool for network reconnaissance and vulnerability probing on Linux.

## Features
- Port scanning with optional stealth mode
- Service and version detection via banners
- Vulnerability checking with CVE data
- JSON output for automation and reporting

## Installation
1. Clone this repo: `git clone https://github.com/yourusername/netsnipe.git`
2. Navigate to the directory: `cd netsnipe`
3. Make the script executable: `chmod +x netsnipe.py`

## Requirements
- Python 3 (standard library only, no external dependencies)

## Usage
Run the tool with the following options:
- `./netsnipe.py <target>` - Scan common ports (1-1024)
- `./netsnipe.py <target> -p <ports>` - Scan specific ports (e.g., `22,80,443`)
- `./netsnipe.py <target> -s` - Enable stealth mode (randomized timing)
- `./netsnipe.py <target> -o <output.json>` - Save results to a JSON file
- `./netsnipe.py --update-db` - Placeholder for future database updates

### Sample Usage
$ ./netsnipe.py 192.168.1.1 -p 22,80
Sample Output
```
Scanning 192.168.1.1...
Port 22: OpenSSH 7.6p1 [VULNERABLE] CVE: CVE-2018-15473 - User enumeration via timing differences in authentication. (Severity: Medium)
Port 80: Apache 2.4.49 [VULNERABLE] CVE: CVE-2021-41773 - Path traversal and file disclosure vulnerability in Apache HTTP Server. (Severity: High)

Vulnerability Database
Ships with a production-grade vuln_db.json covering 30+ vulnerabilities across 15+ services (e.g., Apache, OpenSSH, nginx, MySQL).

Includes CVEs, descriptions, and severity ratings for actionable insights.
Expandable via manual edits or future automated updates.
```
### Notes
Use responsibly and only on systems you have explicit permission to test.
The vulnerability database can be extended with data from sources like NVD (National Vulnerability Database).

Future Enhancements
Automated vuln database updates via NVD API
Support for additional services and version ranges
Proxy integration for anonymity
text


