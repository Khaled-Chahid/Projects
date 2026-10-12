# Lab and presentation guide

## A small lab is enough

Use a Linux scanner VM, one Linux target VM, and one Windows target VM. Keep
target VMs on a private lab network and use snapshots before changing settings.
You do not need every service on every OS: coverage concerns the protocol and
implementation you actually test. Do not publish real internal reports.

Start with the local FTP exercise below, then test Samba/Windows SMB, BIND DNS,
Net-SNMP, and OpenSSH individually. Only then run all services together. Record
the target implementation/version, source address, selected ports, configuration,
manual observation, scanner result, and report path for each case.

## First working demo: FTP on loopback

From the project root:

```bash
app/.venv/bin/python -m pip install -r app/requirements-dev.txt
mkdir -p /tmp/nsms-demo-data
printf 'Public lab file\n' > /tmp/nsms-demo-data/example.txt
app/.venv/bin/python -m pyftpdlib --interface 127.0.0.1 --port 2121 --directory /tmp/nsms-demo-data
```

Leave the server in that terminal. In a second terminal:

```bash
bash scripts/scan.sh 127.0.0.1 --services ftp --port ftp=2121 --output app/reports/ftp-anonymous
```

Expected: FTP-001 and FTP-002 are `detected`. Open
`app/reports/ftp-anonymous/report.html` and expand the evidence. The scanner lists
metadata; it does not download `example.txt`.

Stop the FTP server with Ctrl+C. Restart it with a lab-only account:

```bash
app/.venv/bin/python -m pyftpdlib --interface 127.0.0.1 --port 2121 --directory /tmp/nsms-demo-data --username labuser --password demo-only-password
```

Run again with a new report directory:

```bash
bash scripts/scan.sh 127.0.0.1 --services ftp --port ftp=2121 --output app/reports/ftp-authenticated
```

Expected: FTP-001 is `not_detected` following a refused anonymous login;
FTP-002 is `skipped`. This demonstrates a finding disappearing after a meaningful
configuration change. The demonstration password is for this loopback fixture,
not a credential recommendation.

For an intentional public service, rerun the anonymous case with
`--allow-anonymous-ftp`: evidence stays visible but its assessment becomes
`review`. Stop the fixture after the demo and remove its temporary directory.

## Acceptance matrix

These are tasks for your own lab, not claims that every row was completed during
development. The completed subset is in `TESTING.md`.

| Service | Positive case | Negative / restricted case | Failure case |
| --- | --- | --- | --- |
| FTP | Anonymous login and LIST allowed | Anonymous login disabled; separately allow login but deny LIST | Drop the data connection, require FTPS, or stop the server |
| SMBv1 | A disposable legacy test service offers SMBv1 | Modern dialects only | NSE negotiation missing or interrupted |
| SMB signing | The server negotiates optional signing | Require signing | An unrecognized negotiation response |
| SMB access | Dedicated guest-readable lab share | Deny anonymous/guest access | Nonexistent share; unreachable service; client error |
| DNS | Known authoritative zone allows AXFR from scanner | Same zone refuses transfer | Wrong zone, SERVFAIL, interrupted transfer |
| SNMP | `public` reads sysDescr.0 from scanner source | Restrict the source/community | Silence should be `inconclusive`, not `not_detected` |
| SSH | A disposable test service offers one denylisted algorithm | Remove that offered algorithm | Truncated or absent algorithm lists |

Compare one condition at a time. Keep the same source address and port when
changing server settings. A different network location can change the result.

## Service-specific setup notes

### Linux FTP

The loopback fixture provides the easiest reproducible demonstration. On a VM
with vsftpd, compare anonymous disabled/enabled with a dedicated public
directory. Listing permission, local filesystem permissions, passive port
reachability, and TLS requirements can affect the observation independently.
Check the server log when a test is inconclusive.

### Linux Samba

Use a standalone Samba server with one share containing disposable data. Check
the effective configuration with `testparm -s`. Settings relevant to the tests
include `server min protocol`, `server signing`, `map to guest`, and `guest ok`.
Filesystem permissions must also allow the intended guest account to list the
directory. A root listing is tested without file reads or writes.

From the scanner VM, compare with these commands:

```bash
nmap -sT -Pn -n -p445 --script smb-protocols,smb2-security-mode 192.0.2.10
smbclient -N -U '%' --use-kerberos=off -L 192.0.2.10
smbclient -N -U '%' --use-kerberos=off //192.0.2.10/data -c 'ls'
bash scripts/scan.sh 192.0.2.10 --services smb --smb-share data
```

Keep legacy SMB testing on a disposable VM snapshot. You do not need to enable
SMBv1 on your normal Windows workstation to demonstrate the modern-only case.

### Windows SMB

Use a Windows Server/Windows VM with File and Printer Sharing reachable only
from the scanner's lab network. In PowerShell, record:

```powershell
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, RequireSecuritySignature
Get-SmbShare
```

Run the same SMB scan from Kali. Compare the **server's inbound** signing
requirement with SMB-002; client outbound settings answer a different question.
Current Windows versions and Group Policy may require signing or block guest
access. Record the effective settings rather than assuming a default.

For a remediation demonstration on the lab server, requiring server signing is
available through `Set-SmbServerConfiguration -RequireSecuritySignature $true`.
Confirm the effective value and rerun the scan. Do not describe this lab change
as evidence that every form of relay is impossible.

### DNS

On a Linux VM, create a BIND primary zone such as `lab.test` with SOA, NS, and
one A record. Make the scanner's source IP explicitly allowed in `allow-transfer`
for the positive case, then set `allow-transfer { none; };` for the negative
case. A successful transfer from an intentionally allowed source can be marked
with `--allow-axfr`. Validate the server configuration and zone before reloading.

```bash
dig @192.0.2.10 lab.test SOA +tcp
dig @192.0.2.10 lab.test AXFR
bash scripts/scan.sh 192.0.2.10 --services dns --domain lab.test
```

Windows DNS supports zone-transfer configuration through the zone's properties.
Use a separate test zone and compare the same source-restricted cases. Neither
BIND nor Windows DNS acceptance is implied by the controlled wire-responder tests.

### SNMP

On a Linux lab VM with Net-SNMP, configure a read-only community for the scanner's
source. The scanner requests only `.1.3.6.1.2.1.1.1.0` (`sysDescr.0`). Test the
default `public` case, then a restricted source or an unconfigured community.

```bash
snmpget -v2c -c public -On 192.0.2.10 .1.3.6.1.2.1.1.1.0
bash scripts/scan.sh 192.0.2.10 --services snmp
```

The manual command uses a public lab value. Use `--community-file` for a real
secret. A timeout after a restriction is useful negative *lab evidence*, but the
remote scanner still labels silence `inconclusive` because it cannot distinguish
filtering, loss, service failure, and an incorrect community.

### SSH

Run an OpenSSH service in a disposable target VM, or use the ordinary modern
configuration for the negative case. Collect its offer independently:

```bash
nmap -sT -Pn -n -p22 --script ssh2-enum-algos -v 192.0.2.10
bash scripts/scan.sh 192.0.2.10 --services ssh
```

For a positive case, use a separate lab instance with an explicitly selected
denylisted algorithm that the installed SSH build still supports. Do not change
your normal remote-administration service. Match the offered names against the
exact policy in `DOCUMENTATION.md`; a negotiation offer is not a login or an
observed authenticated session.

## Five-minute presentation

1. State the scope: five services, twelve checks, one IPv4 target, Linux runner.
2. Show the three main files and the five service modules.
3. Run the local FTP case and open a finding's evidence.
4. Disable anonymous access, rerun, and explain the changed result.
5. Show an inconclusive case and explain why a timeout is not a security pass.
6. Point to tests and your completed platform matrix. State remaining limitations.

Before publishing, run the test suite, ensure reports contain only disposable
lab data, and add screenshots from your own demonstration if useful. Fill in
only the validation you actually performed. No specific institution's project
acceptance or disclosure requirements are assumed by this repository.

References: [Microsoft SMB signing](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing),
[BIND configuration reference](https://bind9.readthedocs.io/en/latest/reference.html),
and the primary references in `DOCUMENTATION.md`.
