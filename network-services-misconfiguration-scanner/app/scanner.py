#!/usr/bin/env python3
"""CLI and sequential scan orchestration. Run --help for examples and options."""

import argparse
import importlib
import importlib.util
import json
from pathlib import Path
import platform
import shutil
import sys

from core import (Context, DEFAULT_PORTS, Finding, POLICY, VERSION, clean,
                  discover, ipv4, utc_now, valid_share)
from reporting import print_results, save_report, summary

CHECK_IDS = {
    "ftp": [("FTP-001", "Anonymous FTP login accepted"), ("FTP-002", "FTP directory listing available anonymously")],
    "smb": [("SMB-001", "SMBv1 offered"), ("SMB-002", "SMB signing not required"),
            ("SMB-003", "Disk share names exposed without credentials"), ("SMB-004", "Share root listing available without credentials")],
    "dns": [("DNS-001", "Unsigned DNS zone transfer accepted")],
    "snmp": [("SNMP-001", "SNMPv2c read access accepted")],
    "ssh": [("SSH-001", "Legacy SSH key exchange offered"), ("SSH-002", "Legacy SSH host signature offered"),
            ("SSH-003", "Legacy SSH cipher offered"), ("SSH-004", "Legacy SSH MAC offered")],
}


def parser():
    p = argparse.ArgumentParser(description="Verify selected network service misconfigurations on one authorized IPv4 target.")
    p.add_argument("target", nargs="?", help="one IPv4 address")
    p.add_argument("--services", default="ftp,smb,dns,snmp,ssh", help="comma-separated subset: ftp,smb,dns,snmp,ssh")
    p.add_argument("--port", action="append", default=[], metavar="SERVICE=PORT", help="override one service's port; repeatable")
    p.add_argument("--domain", help="known DNS zone for AXFR; no zone discovery is performed")
    p.add_argument("--community-file", type=Path, help="file with one SNMP community; otherwise test public once")
    p.add_argument("--smb-share", action="append", default=[], help="known disk share to list; repeatable, maximum five")
    p.add_argument("--timeout", type=float, default=5, help="network operation timeout in seconds (default: 5)")
    p.add_argument("--tool-timeout", type=float, default=45, help="time limit for each external command (default: 45)")
    p.add_argument("--allow-anonymous-ftp", action="store_true", help="record anonymous FTP as intentional review items")
    p.add_argument("--allow-anonymous-smb", action="store_true", help="record anonymous SMB as intentional review items")
    p.add_argument("--allow-axfr", action="store_true", help="record AXFR from this scanner as an intentional review item")
    p.add_argument("--output", type=Path, help="new report directory; must not exist")
    p.add_argument("--doctor", action="store_true", help="check dependencies locally and exit")
    p.add_argument("--version", action="version", version=VERSION)
    return p


def validate(args, p):
    try:
        args.target = ipv4(args.target or "")
        services = list(dict.fromkeys(args.services.lower().split(",")))
        if any(s not in DEFAULT_PORTS for s in services):
            raise ValueError("Unknown service. Choose from ftp,smb,dns,snmp,ssh")
        if not 0.2 <= args.timeout <= 60 or not 5 <= args.tool_timeout <= 300:
            raise ValueError("--timeout must be 0.2..60 and --tool-timeout must be 5..300")
        ports = dict(DEFAULT_PORTS)
        for value in args.port:
            name, port = value.split("=", 1)
            if name not in services or not 1 <= int(port) <= 65535:
                raise ValueError("Port override must use a selected service and a port from 1 to 65535")
            ports[name] = int(port)
        tcp_ports = [ports[s] for s in services if s != "snmp"]
        if len(set(tcp_ports)) != len(tcp_ports):
            raise ValueError("Each selected TCP service must have a distinct port")
        if len(args.smb_share) > 5 or any(not valid_share(x) for x in args.smb_share):
            raise ValueError("Use at most five share names: letters, numbers, spaces, _, $, ., or -")
        if args.domain:
            import re
            domain = args.domain.rstrip(".")
            if len(domain) > 253 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", x) for x in domain.split(".")):
                raise ValueError("Provide a DNS zone name, such as lab.test")
            args.domain = domain.lower() + "."
        community = "public"
        if args.community_file:
            if args.community_file.stat().st_size > 256:
                raise ValueError("Community file is too large")
            community = args.community_file.read_text(encoding="utf-8").rstrip("\r\n")
            from checks.snmp import valid_community
            if not valid_community(community):
                raise ValueError("Unsupported community characters; see README")
        if args.output and args.output.exists():
            raise ValueError("Output directory already exists; choose a new path")
        return services, ports, community
    except (ValueError, OSError, UnicodeError) as exc:
        p.error(str(exc))


def doctor():
    checks = {"python_3_10_or_newer": sys.version_info >= (3, 10), "linux": sys.platform.startswith("linux"),
              "dnspython": importlib.util.find_spec("dns") is not None,
              **{x: shutil.which(x) is not None for x in ("nmap", "smbclient", "snmpget")}}
    print(json.dumps(checks, indent=2))
    return 0 if all(checks.values()) else 2


def placeholders(service, port, state, reason):
    return [Finding(key, service, port, title, state, "none", {"reason": reason},
                    "Not assessed.", "Resolve the stated cause and rerun this check.",
                    "No security conclusion is available from an unexecuted or failed check.")
            for key, title in CHECK_IDS[service]]


def execute(args, services, ports, community):
    started = utc_now()
    report = {"scanner_version": VERSION, "schema_version": "1.0", "target": args.target,
              "started_at": started, "report_kind": "Live scan", "interrupted": False,
              "policy": {"name": POLICY, "allow_anonymous_ftp": args.allow_anonymous_ftp,
                         "allow_anonymous_smb": args.allow_anonymous_smb, "allow_axfr": args.allow_axfr},
              "settings": {"services": services, "ports": {s: ports[s] for s in services}, "domain": args.domain,
                           "timeout_seconds": args.timeout, "tool_timeout_seconds": args.tool_timeout,
                           "snmp_community": "public (default)" if community == "public" else "user-supplied (redacted)",
                           "smb_shares": args.smb_share, "python": platform.python_version()},
              "inventory": [], "findings": []}
    completed = set()
    try:
        print(f"Target {args.target} | discovering selected service ports", flush=True)
        report["inventory"] = discover(args.target, services, ports, args.tool_timeout)
        for service in services:
            print(f"Checking {service.upper()} on port {ports[service]}...", flush=True)
            item = next(x for x in report["inventory"] if x["service"] == service)
            if item["state"] == "closed":
                findings = placeholders(service, ports[service], "skipped", "TCP port was closed at discovery time.")
            else:
                ctx = Context(args.target, ports[service], args.timeout, args.tool_timeout, args.domain,
                              community, args.smb_share, args.allow_anonymous_ftp, args.allow_anonymous_smb, args.allow_axfr)
                try:
                    findings = importlib.import_module("checks." + service).run(ctx)
                except Exception as exc:
                    # Preserve other services' results, while clearly flagging an implementation failure.
                    message = type(exc).__name__ + ": " + str(exc)
                    if service == "snmp":
                        message = message.replace(community, "[redacted]")
                    findings = placeholders(service, ports[service], "inconclusive",
                                            "Unexpected probe error: " + clean(message))
                if service == "snmp" and any(f.status == "detected" for f in findings):
                    item["state"] = "open"
                    item["fingerprint"] = {"name": "snmp", "version": "2c", "method": "protocol response"}
            report["findings"].extend(x.to_dict() for x in findings)
            completed.add(service)
    except KeyboardInterrupt:
        report["interrupted"] = True
        for service in services:
            if service not in completed:
                report["findings"].extend(x.to_dict() for x in placeholders(service, ports[service], "skipped", "Run interrupted."))
    report["finished_at"] = utc_now()
    report["summary"] = summary(report["findings"])
    return report


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    if args.doctor:
        return doctor()
    if not sys.platform.startswith("linux"):
        p.error("Run the scanner on Linux or WSL2; targets may run Windows or Linux")
    services, ports, community = validate(args, p)
    output = args.output or Path(__file__).resolve().parent / "reports" / (args.target + "_" + utc_now().replace(":", "-") + "_" + str(__import__('os').getpid()))
    report = execute(args, services, ports, community)
    try:
        destination = save_report(report, output)
    except OSError as exc:
        print("Could not save report: " + clean(exc), file=sys.stderr)
        return 2
    print_results(report)
    print(f"\nJSON: {destination / 'report.json'}\nHTML: {destination / 'report.html'}")
    if report["interrupted"]:
        return 130
    if report["summary"]["inconclusive"]:
        return 2
    return 1 if report["summary"]["policy_violations"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
