# NetSnipe
A production-ready pentest tool for network recon and vulnerability probing.

## Features
- Port scanning with stealth mode
- Service and version detection
- Vulnerability checking with CVE data
- JSON output for automation

## Installation
1. Clone this repo: `git clone https://github.com/okay633/netsnipe.git`
2. `cd netsnipe`
3. `chmod +x netsnipe.py`

## Usage
- `./netsnipe.py <target> [-p ports] [-s] [-o output.json] [--update-db]`

## Requirements
- Python 3

## Notes
- Use responsibly and only on systems you have permission to test.
- Expand `vuln_db.json` with real data from NVD or other sources.
