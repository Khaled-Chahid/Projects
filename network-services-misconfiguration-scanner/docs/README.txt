NETWORK SERVICES MISCONFIGURATION SCANNER
Version 1.0.0

Start with ../README.md for the GitHub-formatted guide.

Purpose
  Discover selected service ports and verify specific FTP, SMB, DNS, SNMP,
  and SSH configuration behaviors. Results include evidence, limitations,
  impact, and remediation. Linux scanner; Windows/Linux network targets.

From the project root, install on Kali/Debian/Ubuntu
  sudo apt install python3 python3-venv nmap smbclient snmp
  bash scripts/setup.sh

Run against your authorized lab target
  bash scripts/scan.sh 192.0.2.10 --domain lab.test
  bash scripts/scan.sh --help

Output
  report.html and report.json in a new app/reports/ run directory.

Read next
  DOCUMENTATION.md  - architecture, checks, lesson mapping, interview guide
  LAB.md            - practical validation and demo steps
  TESTING.md        - verification completed and remaining coverage

This is a bounded configuration scanner. A negative or skipped result
does not establish that a host is secure. No exploitation is performed.
