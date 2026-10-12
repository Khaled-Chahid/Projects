# Network Services Misconfiguration Scanner

A small Python CLI for checking selected configuration weaknesses in FTP, SMB,
DNS, SNMP, and SSH. It combines service discovery, protocol interaction, and
evidence-based reporting. Bash scripts prepare the environment and launch scans.

The scanner runs on **Linux (including Kali and WSL2)**. The target may run
Windows, Linux, or another implementation of a supported protocol. Version 1
accepts **one IPv4 address** and checks one configured port per service.

## What it checks

| Service | Checks | Default endpoint |
| --- | --- | --- |
| FTP | Anonymous login; listing the login directory | TCP/21 |
| SMB | SMBv1; signing requirement; disk-share names; anonymous share-root listing | TCP/445 |
| DNS | Unsigned AXFR of a supplied zone after verifying an authoritative SOA | TCP/53 |
| SNMP | One SNMPv2c GET of `sysDescr.0` using `public` or one supplied community | UDP/161 |
| SSH | Offered key exchange, host signature, cipher, and MAC names against an explicit legacy denylist | TCP/22 |

There are **12 check definitions**. Results are scoped to the tested source,
port, identity, zone, or algorithm category. Closed ports and unmet prerequisites
appear as skipped checks. An open port is an inventory item, not a finding.

The scanner does not perform password guessing, upload files, execute remote
commands, exploit CVEs, audit all ports, or certify that a host is secure.
Use it only against systems you own or are authorized to assess.

## Install

Python **3.10 or newer** is required. From the project root on Kali, Debian,
or Ubuntu:

```bash
sudo apt update
sudo apt install python3 python3-venv nmap smbclient snmp
bash scripts/setup.sh
bash scripts/scan.sh --doctor
```

`bash scripts/...` also works when an archive extractor does not preserve
Unix executable permissions.

`scripts/setup.sh` creates `app/.venv` inside the project and installs the pinned Python
dependency. It checks system tools and tells you if any are missing. It does not
change service configurations or install system packages automatically.
Running scans does not require root: Nmap uses TCP connect scans; SNMP uses a
normal UDP request. Internet access is needed for installation, not for scanning.

## Usage

Replace the documentation addresses below with your lab target.

```bash
# All supported service ports. DNS needs a zone name to perform AXFR.
bash scripts/scan.sh 192.0.2.10 --domain lab.test

# Select services.
bash scripts/scan.sh 192.0.2.10 --services ftp,smb,ssh

# A nonstandard port and an explicit new report directory.
bash scripts/scan.sh 192.0.2.10 --services ssh --port ssh=2222 --output app/reports/ssh-lab

# Test a known share even if listing all shares is refused.
bash scripts/scan.sh 192.0.2.10 --services smb --smb-share documents

# Record intentionally public FTP behavior as review items.
bash scripts/scan.sh 192.0.2.10 --services ftp --allow-anonymous-ftp

# Equivalent direct Python invocation.
app/.venv/bin/python app/scanner.py 192.0.2.10 --services ftp
```

`--port SERVICE=PORT` can be repeated. Only the configured ports are scanned;
there is no implicit all-port discovery. `--domain` supplies a DNS **zone**, which
may differ from a host's domain suffix. Without it, DNS-001 is skipped.

For SNMP, the default is a single read attempt using `public`. To use another
community, create a private text file under `app/` and pass
`--community-file app/community.txt`.
The supported character set is letters, numbers, and `._@%:+/=!-` (1–128
characters); whitespace and configuration directives are rejected. The secret
is placed in a temporary mode-0600 Net-SNMP config, not in command-line arguments,
and is redacted from evidence. SNMPv2c still sends its community over the network
without encryption. The input file remains yours to protect and remove.

## Read the results

| Status | Meaning |
| --- | --- |
| `detected` | The named behavior was observed with evidence. Check its policy assessment. |
| `not_detected` | A relevant negative observation was obtained within the documented scope. |
| `inconclusive` | Evidence was insufficient: timeout, malformed reply, missing tool, partial transfer, etc. |
| `skipped` | The check was not executed, for example because a port was closed or no zone was supplied. |

The default `internal-services-v1` policy expects restricted anonymous access,
restricted AXFR, modern SMB settings, and the absence of the listed legacy SSH
algorithms. `--allow-anonymous-ftp`, `--allow-anonymous-smb`, and `--allow-axfr`
keep the observed behavior and evidence but classify the relevant findings as
informational review items. These flags do not hide results or alter probes.

Findings contain an ID, timestamp, endpoint, status, severity, assessment,
evidence, impact, recommendation, and limitations. Severities are documented
project priorities, **not CVSS scores**. Severity `none` means the check did not
establish a finding; it is not a security rating.

Each run creates:

- `report.html`: a standalone report that opens locally in a browser.
- `report.json`: structured results for comparison or further processing.

By default, output goes under `app/reports/` in the project. A specified
output directory must not exist; reports are never silently overwritten.
New run directories and report files are private on POSIX systems. Review
internal hostnames, share names, and banners before sharing a report.

| Exit code | Meaning |
| --- | --- |
| `0` | Completed with no policy violations or inconclusive checks; skipped checks may remain. |
| `1` | Completed with one or more policy violations and no inconclusive checks. |
| `2` | Invalid input, missing prerequisites, save failure, or one or more inconclusive checks. Review the report when present. |
| `130` | Interrupted; results completed before interruption are saved when possible. |

Code `2` takes precedence over code `1`: a scan may contain both findings and
inconclusive checks. Always inspect coverage, not just the exit code.

## Project layout

| Path | Responsibility |
| --- | --- |
| `app/scanner.py` | CLI validation, scan sequence, error isolation, exit codes |
| `app/core.py` | Shared result model, bounded command runner, discovery |
| `app/checks/` | One readable Python module per supported service |
| `app/reporting.py` | Console, JSON, and HTML output |
| `app/requirements*.txt`, `app/.gitignore` | Runtime and test dependencies; ignores generated files inside `app/` |
| `scripts/setup.sh`, `scripts/scan.sh` | Environment setup and argument-preserving launcher |
| `tests/` | Regression tests and local protocol tests |
| `examples/` | Labeled example reports |
| `docs/DOCUMENTATION.md` | Check design, lesson mapping, implementation decisions |
| `docs/LAB.md` | Lab scenarios, validation steps, and demo preparation |
| `docs/TESTING.md` | Verification actually performed and remaining coverage |
| `docs/README.txt` | Short plain-text orientation guide |

No database, background agent, web server, or plugin framework is required.
The internal `.gitignore` applies only inside `app/`. Keep local credentials and
generated reports there, or explicitly exclude other locations in your own Git
repository before committing.

## Tests

```bash
app/.venv/bin/python -m pip install -r app/requirements-dev.txt
PYTHONDONTWRITEBYTECODE=1 app/.venv/bin/python -m unittest discover -s tests -v
bash -n scripts/setup.sh scripts/scan.sh
```

The test suite only uses loopback sockets and fixtures. It never scans addresses
on your LAN. The development dependency `pyftpdlib` provides a real local FTP
service. See [TESTING.md](docs/TESTING.md) for the distinction between unit tests,
controlled DNS responders, actual services, and pending Windows validation.

## Scope and references

The design follows the service-level concepts in the supplied *Footprinting*
and *Attacking Common Services* study notes. Original explanations and tests are
included; the course files are not redistributed. The technical references and
precise mapping to the lesson filenames are in [DOCUMENTATION.md](docs/DOCUMENTATION.md).

Nmap, Samba, Net-SNMP, dnspython, and test dependencies remain separate projects
with their own licenses. They are not bundled in this repository.
This repository does not include a license file.
