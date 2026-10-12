"""Small shared types, bounded subprocess execution, and Nmap discovery."""

from __future__ import annotations

import ipaddress
import os
import re
import selectors
import shutil
import signal
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

VERSION = "1.0.0"
POLICY = "internal-services-v1"
DEFAULT_PORTS = {"ftp": 21, "smb": 445, "dns": 53, "snmp": 161, "ssh": 22}
STATES = {"detected", "not_detected", "inconclusive", "skipped"}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean(value, limit=4000):
    """Treat remote output as untrusted text, including terminal control bytes."""
    value = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", str(value))
    value = "".join(c for c in value if c in "\n\t" or c.isprintable())
    return value[:limit] + (" [truncated]" if len(value) > limit else "")


@dataclass
class Finding:
    check_id: str
    service: str
    port: int
    title: str
    status: str
    severity: str
    evidence: dict
    impact: str
    remediation: str
    limitations: str
    assessment: str = ""
    observed_at: str = field(default_factory=utc_now)

    def __post_init__(self):
        if self.status not in STATES:
            raise ValueError("Unknown check status")
        if self.status != "detected":
            self.severity = "none"
        self.assessment = (
            "policy_violation" if self.status == "detected" and self.severity != "info"
            else "review" if self.status == "detected"
            else "no_violation_observed" if self.status == "not_detected"
            else "not_assessed"
        )

    def to_dict(self):
        return asdict(self)


@dataclass
class Context:
    target: str
    port: int
    timeout: float = 5.0
    tool_timeout: float = 45.0
    domain: str | None = None
    community: str = "public"
    shares: list[str] = field(default_factory=list)
    allow_anonymous_ftp: bool = False
    allow_anonymous_smb: bool = False
    allow_axfr: bool = False


class ProbeError(Exception):
    """A probe could not produce reliable evidence."""


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def run_command(args, timeout=45.0, max_bytes=1_048_576, env_extra=None):
    """No shell; stop on timeout or excessive output; kill the whole process group."""
    if not shutil.which(args[0]):
        raise ProbeError(f"Required executable is missing: {args[0]}")
    env = dict(os.environ, LC_ALL="C", LANG="C")
    if env_extra:
        env.update(env_extra)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    deadline = time.monotonic() + timeout
    with subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=env, start_new_session=True) as proc:
        try:
            with selectors.DefaultSelector() as sel:
                sel.register(proc.stdout, selectors.EVENT_READ, "stdout")
                sel.register(proc.stderr, selectors.EVENT_READ, "stderr")
                while sel.get_map():
                    left = deadline - time.monotonic()
                    if left <= 0:
                        raise ProbeError(f"{args[0]} exceeded its {timeout:g}s time limit")
                    for key, _ in sel.select(min(left, 0.2)):
                        block = os.read(key.fileobj.fileno(), 16384)
                        if not block:
                            sel.unregister(key.fileobj)
                            continue
                        total += len(block)
                        if total > max_bytes:
                            raise ProbeError(f"{args[0]} exceeded the output limit")
                        buffers[key.data].extend(block)
                proc.wait(timeout=max(0.01, deadline - time.monotonic()))
        except BaseException:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            raise
    return CommandResult(proc.returncode,
                         buffers["stdout"].decode("utf-8", "replace"),
                         buffers["stderr"].decode("utf-8", "replace"))


def parse_nmap(text, target):
    """Require a complete successful run and the requested host in structured XML."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ProbeError("Nmap returned incomplete or invalid XML") from exc
    if root.tag != "nmaprun":
        raise ProbeError("Unexpected XML root")
    finished = root.find("runstats/finished")
    if finished is None or finished.get("exit") != "success":
        raise ProbeError("Nmap did not report successful completion")
    for host in root.findall("host"):
        if any(a.get("addr") == target for a in host.findall("address")):
            return host
    raise ProbeError("Nmap returned no result for the requested address")


def nmap_host(target, ports, timeout=45.0, scripts=(), script_args=None):
    args = ["nmap", "--unprivileged", "-sT", "-Pn", "-n",
            "--max-retries", "1", "--host-timeout", f"{max(1, int(timeout - 2))}s",
            "-p", ",".join(str(p) for p in sorted(set(ports))), "-oX", "-"]
    if scripts:
        args += ["--script", ",".join(scripts), "--script-timeout", f"{max(1, int(timeout / 2))}s"]
    else:
        args += ["-sV", "--version-light"]
    if script_args:
        args += ["--script-args", script_args]
    args.append(target)
    result = run_command(args, timeout)
    if result.returncode != 0:
        raise ProbeError("Nmap failed: " + clean(result.stderr, 400))
    return parse_nmap(result.stdout, target)


def discover(target, services, ports, timeout):
    tcp_services = [s for s in services if s != "snmp"]
    inventory = []
    if tcp_services:
        try:
            host = nmap_host(target, [ports[s] for s in tcp_services], timeout)
            for name in tcp_services:
                item = host.find(f"ports/port[@protocol='tcp'][@portid='{ports[name]}']")
                state = item.find("state") if item is not None else None
                service = item.find("service") if item is not None else None
                details = dict(service.attrib) if service is not None else {}
                inventory.append({"service": name, "port": ports[name], "transport": "tcp",
                                  "state": state.get("state") if state is not None else "unknown",
                                  "fingerprint": {k: clean(v, 500) for k, v in details.items()},
                                  "note": "Port assignment is a candidate; protocol checks provide evidence."})
        except (ProbeError, OSError, subprocess.SubprocessError) as exc:
            inventory.extend({"service": s, "port": ports[s], "transport": "tcp",
                              "state": "unknown", "fingerprint": {}, "note": clean(exc)}
                             for s in tcp_services)
    if "snmp" in services:
        inventory.append({"service": "snmp", "port": ports["snmp"], "transport": "udp",
                          "state": "unknown", "fingerprint": {},
                          "note": "SNMP uses a direct UDP GET; no TCP or ping prerequisite."})
    return inventory


def ipv4(value):
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise ValueError("Use one IPv4 address, not a hostname, range, or CIDR") from exc
    if address.is_multicast or address.is_unspecified or str(address) == "255.255.255.255":
        raise ValueError("Use a unicast IPv4 address")
    return str(address)


def valid_share(name):
    return bool(re.fullmatch(r"[A-Za-z0-9_$ .-]{1,80}", name)) and name not in {".", ".."}
