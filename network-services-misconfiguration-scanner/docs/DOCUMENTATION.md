# Technical documentation

## Purpose and boundaries

The scanner answers a narrow question: **which supported service behaviors can
this source observe, and which conflict with the selected policy?**

It performs service-level enumeration, confirms specific behaviors, and presents
evidence. Its result is a configuration review from one network vantage point.
It cannot determine every local setting or the business purpose of a service.
The implementation is intentionally sequential and uses one IP per run so that
execution order, network traffic, and failures are easy to explain.

The default policy is `internal-services-v1`. Its assumptions are visible and
can be relaxed for intentional anonymous FTP, anonymous SMB, or AXFR access.
Each exception changes the assessment to `review` and severity to `info`, while
retaining `detected` and the evidence. This separates fact from interpretation.

## From lesson to implementation

| Supplied lesson | Concept used | Implementation |
| --- | --- | --- |
| `2. Enumeration Methodology.md` | Start from exposed services and progressively confirm observations | `core.discover()` followed by service checks |
| `3. Service misconfigurations.md` | Authentication, access rights, and insecure defaults | Explicit rules with an observed result and policy assessment |
| `6. FTP.md`, `5. Attacking FTP.md` | Anonymous login, reply codes, directory listing | `app/checks/ftp.py` |
| `7. SMB.md`, `7. Attacking SMB.md` | Dialects, anonymous access, share enumeration, permissions | `app/checks/smb.py` |
| `9. DNS.md`, `13. Attacking DNS.md` | Authoritative DNS and zone transfer | `app/checks/dns.py` |
| `12. SNMP.md` | Community strings, OIDs, read access | `app/checks/snmp.py` |
| `17. Linux Remote Management Protocols.md` | SSH negotiation and algorithm enumeration | `app/checks/ssh.py` |
| `2. The Concept of Attacks.md` | Explain the source, service, access context, and observed result | Evidence and limitation fields in every finding |

SMB signing inspection and the exact SSH policy are small documented extensions
supported by the official references below. The broader notes on cloud assets,
staff, databases, mail, NFS, IPMI, RDP, exploitation, and finding secrets establish
context but are outside version 1's checks. More uploaded material does not mean
the tool implements every lesson.

Some distinctions matter when translating study notes into code:

- FTP control commands are sent by a client. Passive FTP data uses a negotiated
  server port; it is not always port 20. The listing uses passive mode and keeps
  the data connection on the target IP.
- `anonymous_enable`, `anon_upload_enable`, `dirmessage_enable`, and ownership
  settings describe different behavior. A remote login does not reveal the
  complete local configuration file.
- `smbclient -N` suppresses the password prompt. It does not by itself select an
  empty username. This tool also supplies `-U %` and disables Kerberos; a server
  may still map the session to Guest.
- Share permissions and filesystem permissions both affect access. Seeing a
  share name, listing its root, reading a file, and writing a file are distinct
  tests. Version 1 implements the first two.
- An SNMP community can be restricted by source and view. A successful GET of
  one OID does not establish access to the full MIB or any write permission.
- An SSH banner cannot prove `PermitRootLogin` or `PasswordAuthentication`.
  `ssh-rsa` names SHA-1 signatures; RSA keys can also use RSA/SHA-2 signatures.

## Architecture and data flow

1. `app/scanner.py` validates the single IPv4 target, service selection, optional
   zone, share names, time limits, and port overrides.
2. `app/core.py` invokes a TCP connect/version scan on only the selected TCP ports.
   Nmap XML provides port states and fingerprints. No OS guess is treated as fact.
3. `app/scanner.py` calls `run(Context)` on each service module. Closed TCP ports
   produce skipped checks. Unknown/filtered discovery does not automatically
   prevent a protocol attempt. SNMP is tested independently over UDP.
4. Each module returns `Finding` objects. Modules handle expected transport and
   parsing failures. A final isolation boundary records unexpected module errors
   as inconclusive and allows other services to finish.
5. `app/reporting.py` renders the same model as console lines, JSON, and HTML.

Shared code stays in one file. There is no factory hierarchy or dynamic plugin
registration. `app/checks/__init__.py` only makes the service directory importable.
This keeps the code understandable while preserving a clear boundary per service.

### Role of the dependencies

| Dependency | Work delegated | Work implemented by this project |
| --- | --- | --- |
| Nmap | TCP discovery, light version probes, SMB negotiation, SSH algorithm inventory | Scope selection, structured XML parsing, result handling, policy comparison |
| Python `ftplib` | FTP protocol client | Login/listing sequence, bounded reads, response classification |
| dnspython | DNS message encoding and AXFR protocol validation | Zone prerequisite, authoritative SOA check, response classification, transfer caps |
| Samba `smbclient` | Anonymous SMB share operations | Explicit identity, bounded share selection, operation-level result interpretation |
| Net-SNMP `snmpget` | SNMPv2c request/response handling | One-OID/one-community scope, secret handling, evidence classification |
| Bash | Environment checks and process launch | Reproducible setup, quoting, signals, and exit-code preservation |

The tool is an orchestration and verification project, not an implementation of
SMB or SSH cryptography. That boundary is deliberate and should be stated in an
interview. The original engineering work is in scope control, check semantics,
evidence, error handling, tests, reporting, and documentation.

## Check catalogue

| ID | Detection evidence | Negative evidence | Important limits |
| --- | --- | --- | --- |
| FTP-001 | Completed anonymous login with final code 230 | Login rejected with 530 | Plain FTP, one identity and one placeholder password; 530 can reflect account or transport policy |
| FTP-002 | LIST data channel completes with 226 or 250 | LIST refused with 550 after login | Login directory only; an empty completed listing is valid; no file contents or writes |
| SMB-001 | `smb-protocols` XML lists `NT LM 0.12` / SMBv1 | The completed script lists modern dialects without SMBv1 | No returned dialect inventory means inconclusive; this is not an EternalBlue check |
| SMB-002 | Explicit negotiated message says signing is not required | Explicit negotiated message says signing is required | Limited to dialects reported by the script, not every possible session or relay condition |
| SMB-003 | `smbclient -g -L` returns disk-share records with empty credentials | Explicit authentication/access denial | Zero exit alone and an empty/unrecognized inventory do not prove a negative |
| SMB-004 | A tested root LIST completes with smbclient's expected blocks footer | Explicit access/authentication denial for all tested roots | Up to five roots, SMB2/3 only; missing paths and transport errors are inconclusive |
| DNS-001 | Complete unsigned AXFR after authoritative SOA | AXFR explicitly REFUSED after authoritative SOA | One supplied zone and source; partial data or SERVFAIL is inconclusive |
| SNMP-001 | Typed sysDescr.0 value returned by one successful SNMPv2c GET | No general negative conclusion from silence | `No Such Object`, timeout, and errors are inconclusive; SNMP can silently discard unauthorized requests |
| SSH-001 | Offered KEX name matches the project denylist | Complete KEX list with no match | Policy comparison, not a full cryptographic audit |
| SSH-002 | Offered host-signature name matches denylist | Complete host-signature list with no match | RSA/SHA-2 is not classified as `ssh-rsa` |
| SSH-003 | Offered cipher in either direction matches denylist | Combined list, or both directions, with no match | A missing direction cannot clear the category |
| SSH-004 | Offered MAC in either direction matches denylist | Combined list, or both directions, with no match | Algorithm availability, not an algorithm selected in an authenticated session |

For SMB-004, any successful tested root is enough to detect anonymous listing.
All explicit denials produce `not_detected` for the tested roots only. Mixed
denials and unknown results remain `inconclusive` unless one succeeds. Individual
attempts remain in the evidence. Unknown or unsupported share names are not
interpolated into commands; users can provide supported names explicitly.

### SSH policy, exactly

- KEX: `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`,
  `diffie-hellman-group-exchange-sha1`.
- Host signatures: `ssh-rsa`, `ssh-dss`.
- Ciphers: `arcfour`, `arcfour128`, `arcfour256`, `3des-cbc`, `blowfish-cbc`,
  `cast128-cbc`, `aes128-cbc`, `aes192-cbc`, `aes256-cbc`,
  `rijndael-cbc@lysator.liu.se`, `none`.
- MACs: `hmac-md5`, `hmac-md5-96`, their `-etm@openssh.com` variants,
  `hmac-sha1-96`, `hmac-sha1-96-etm@openssh.com`, `none`.

The denylist is a fixed educational baseline, not a claim of compliance with
an external standard. Unknown algorithm names are retained in evidence but are
not automatically marked weak. Full-length `hmac-sha1` is not on this list;
absence of a match does not make the remaining offer future-proof. Revise the
policy deliberately and update tests when adding a rule.

### Severity rationale

SMBv1 receives `high` as a legacy-protocol removal priority. Anonymous access,
unsigned AXFR, optional SMB signing, default-public SNMP access, and listed SSH
algorithms receive `medium`. Share-name disclosure and user-supplied SNMPv2c
read access receive `low`. These are starting priorities for an internal-services
review. Network exposure, business need, data sensitivity, and compensating
controls still require analyst judgment. No composite host risk score is emitted.

## Reliability and operational details

- External commands use argument arrays with `shell=False` (the Python default),
  disconnected stdin, a predictable locale, and a separate process group.
- A selector-based runner reads stdout and stderr without deadlocking. It kills
  the process group on timeout, interruption, or more than 1 MiB of output.
- Default socket timeout is 5 seconds. FTP also has a total deadline of four
  socket timeouts, a 150-line control cap, and a 64 KiB directory-listing cap.
  Timeouts are upper bounds per operation, not a promise about total scan time.
- DNS streams at most 10,000 records and approximately 2 MiB of text. Its lifetime
  is at most the smaller of the tool timeout and four socket timeouts. The
  pinned dnspython `xfr()` streaming interface is retained despite its upstream
  deprecation because it permits these caps without building a complete zone in
  memory. Any future migration must preserve completion validation and caps.
- No AXFR-discovered hosts or names become new scan targets. FTP passive data
  connects back to the target IP; SMB uses the supplied IP explicitly.
- FTP raw text, DNS names, and SMB output may contain internal information.
  Samples are bounded. Reports escape HTML and strip terminal control characters.
  HTML has a restrictive Content Security Policy and no external resources.
- SNMP community values are kept out of saved settings and command arguments.
  This protects local reporting, not the unencrypted SNMPv2c transport itself.
- A report's `not_detected` result is always specific to that check. A timeout,
  unavailable executable, malformed response, or absent NSE table is not a pass.
- A second scan never automatically replaces a previous output directory.
- SMB share tests require a recent Samba client supporting `--use-kerberos=off`.
  Client/NSE output changes can require parser updates; unsupported output stays
  inconclusive. The tested versions are recorded in `TESTING.md`.

## Explaining the project

A short introduction:

> I built a Python scanner for five network services. It discovers selected
> service ports, verifies a defined set of configuration weaknesses, and produces
> evidence-backed HTML and JSON reports. I used Bash for setup and repeatable
> execution. I focused on distinguishing verified findings from incomplete checks
> and tested positive, negative, and failure cases.

Adjust claims about platform coverage to your own completed lab work.

| Interview question | Concrete answer |
| --- | --- |
| Why Python and Bash? | Python manages structured protocol results and reports; Bash handles the environment and process launch. |
| Why use Nmap instead of writing a port scanner? | Nmap already performs service discovery; the project's focus is reliable interpretation and verification of selected behaviors. |
| What is a false positive here? | Calling share-name visibility file-read access, or claiming a partial AXFR completed. The tests include these distinctions. |
| What happens on timeout? | The affected check becomes inconclusive with a reason; other services continue. |
| Can it scan Windows? | It speaks network protocols from Linux. Actual Windows acceptance must be demonstrated in the lab matrix, not inferred from unit tests. |
| Does SMB signing prove a relay exploit? | No. The result records a negotiated signing requirement and explains the conditional risk. |
| What would you add next? | One new service/check with a clear evidence rule and paired lab cases, after closing the current validation gaps. |

## Primary technical references

These sources were consulted for protocol/API behavior. They are dependencies
and references, not an endorsement of this project.

- [Nmap XML output](https://nmap.org/book/output-formats-xml-output.html)
- [Nmap smb-protocols](https://nmap.org/nsedoc/scripts/smb-protocols.html)
- [Nmap smb2-security-mode](https://nmap.org/nsedoc/scripts/smb2-security-mode.html)
- [Nmap ssh2-enum-algos](https://nmap.org/nsedoc/scripts/ssh2-enum-algos.html)
- [Samba smbclient manual](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
- [Python ftplib](https://docs.python.org/3/library/ftplib.html)
- [dnspython DNS queries and transfers](https://dnspython.readthedocs.io/en/stable/query.html)
- [Net-SNMP snmpget manual](https://www.net-snmp.org/docs/man/snmpget.html)
- [OpenSSH legacy options](https://www.openssh.com/legacy.html)

The project does not redistribute the uploaded study notes or third-party
programs. Preserve dependency licenses when packaging them independently.
