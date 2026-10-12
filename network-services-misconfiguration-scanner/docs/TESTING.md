# Verification record

This records what was actually verified for version 1.0.0 on 9 October 2026.
It distinguishes local protocol tests from acceptance on production service
implementations. A passing test suite does not establish universal platform
compatibility or complete security coverage.

## Automated checks

**57 tests passed** using Python 3.12.14, dnspython 2.8.0, and pyftpdlib 2.1.0
on Linux. Tests run through the standard-library `unittest` runner:

```bash
# Run from the project root.
app/.venv/bin/python -m pip install -r app/requirements-dev.txt
PYTHONDONTWRITEBYTECODE=1 app/.venv/bin/python -m unittest discover -s tests -v
```

The development requirements include pyasyncore and pyasynchat for pyftpdlib on
Python versions where the original standard-library modules have been removed.
Tests use loopback sockets, temporary directories, and controlled command/XML
fixtures; they do not require privileged ports or contact LAN targets.

| Area | Evidence covered by the tests |
| --- | --- |
| FTP | Real pyftpdlib anonymous login, denied login, denied LIST, completed empty listing; silent server, closed port, and passive-connection failure handling |
| SMB | Nmap dialect parsing with colon and dot notation; required/optional signing; absent NSE evidence; share names versus root listing; explicit denial, missing path, timeout, and misleading zero exit |
| DNS | Controlled TCP responders with authoritative SOA followed by completed, refused, partial, or failed AXFR; non-authoritative replies and absent zone prerequisites |
| SNMP | Typed response for the requested OID; silence and missing OID remain inconclusive; temporary config permissions, cleanup, and community redaction |
| SSH | Explicit algorithm denylist, RSA/SHA-2 distinction, complete versus missing lists, and directional cipher/MAC coverage |
| Discovery | Successful, failed, incomplete, and wrong-target Nmap XML; open/closed port handling; SNMP does not depend on TCP discovery |
| Execution | Argument arrays, unavailable tools, command deadlines and output caps, module failure isolation, input validation, interruption, and exit codes |
| Reports | Summary and policy assessments; HTML escaping and terminal-control removal; private files and refusal to overwrite existing report directories |

SMB, SSH, and SNMP command-result tests exercise interpretation using fixtures.
They are complemented by the separate live integration run below. DNS wire
responders exercise actual TCP and DNS messages but are not a BIND server.

Both Bash scripts passed `bash -n` and ShellCheck 0.9.0 without diagnostics.
The Python source also passed bytecode compilation. These checks verify syntax
and selected script issues; they are not a substitute for protocol tests.
The launcher was separately checked from a project path containing spaces:
arguments stayed intact, shell metacharacters stayed literal, the child's exit
code was preserved, and a missing environment produced the setup instruction.

## Live five-service integration

The scanner was also run against five simultaneous loopback endpoints with
custom ports. Nmap discovery, actual NSE scripts, smbclient, and snmpget were
used rather than replaced with command-result fixtures in this run.

| Component | Version / implementation | Observation |
| --- | --- | --- |
| TCP discovery and NSE | Nmap 7.94SVN | Inventory plus SMB negotiation and SSH algorithm inventory completed |
| FTP target | pyftpdlib 2.1.0 | Anonymous login and directory listing detected |
| SMB target | Impacket 0.13.0 SimpleSMBServer | SMBv1, optional signing, share names, and anonymous root listing detected |
| SMB client | Samba smbclient 4.19.5-Ubuntu | Empty-credential enumeration and listing executed over SMB2/3 |
| DNS target | Controlled dnspython TCP responder | Authoritative SOA and completed AXFR detected |
| SNMP target and client | Net-SNMP 5.9.4.pre2 | Actual snmpd returned sysDescr.0 through snmpget |
| SSH target | Paramiko 3.5.1 | Modern KEX, RSA/SHA-2 signatures, AES-CTR, and HMAC-SHA-2 produced four scoped negative results |

The resulting report contains **12 checks: 8 detected, 4 not_detected,
0 inconclusive, and 0 skipped** under the default policy. A separate request
using an unconfigured SNMP community timed out and was correctly classified as
`inconclusive`, rather than evidence that SNMP access is universally disabled.

The saved HTML and JSON are in `examples/`. They contain the actual observations
from that run and an explicit local-integration label. Random high ports in the
sample are temporary fixture endpoints, not the defaults for deployment.
The intentionally permissive fixture settings explain the eight findings.

The restricted development environment required explicitly configured loopback
interfaces for the SMB client and SNMP daemon. Third-party clients and servers
were run from temporary test directories and are not bundled. Impacket labels
its IPC$ fixture share as a disk share in this setup; the sample records that
returned inventory. It does not assert that Windows IPC$ is a disk share.

## Remaining acceptance work

| Target / environment | Status and next step |
| --- | --- |
| Windows SMB / Windows Server | Not exercised against an actual Windows host. Verify dialects, signing, guest policy, and root-listing behavior using the matrix in LAB.md. |
| Samba server | smbclient was verified; a production Samba server was not. Compare guest restrictions and signing settings on a lab VM. |
| BIND DNS | Controlled DNS responders were verified; a live BIND transfer was not. Test the same zone with allowed and refused AXFR. |
| OpenSSH server | Algorithm parsing and a live Paramiko server were verified. Confirm positive and modern-only cases against a lab OpenSSH instance. |
| vsftpd / Windows FTP | Live FTP tests used pyftpdlib. Test anonymous and restricted behavior against the implementation you will demonstrate. |
| Python / Linux versions | Executed on Python 3.12.14. Python 3.10+ is the declared baseline; other Python versions and Kali/WSL installations still need their own installation smoke test. |
| HTML presentation | Generation, escaping, and standalone output were checked. Open the sample in your intended browser before presenting it; browser rendering was not visually validated in this environment. |

These gaps do not change the recorded local results. They limit claims about
specific implementations and environments. Use the reproducible FTP demo and
manual comparison commands in [LAB.md](LAB.md) to complete the cases relevant
to your presentation. Record your own service versions and report paths.

## What a successful run establishes

The scan establishes the listed observations from one source, with one policy,
the supplied zone/community/identity, and the selected ports. Four SSH negatives
mean no matches in the documented categories; they do not certify the SSH host.
A refused AXFR applies to the supplied zone, and a denied SMB listing applies
to the tested roots. Review skipped and inconclusive checks separately from
policy findings when evaluating a target.
