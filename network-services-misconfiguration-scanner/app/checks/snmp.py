"""One SNMPv2c GET, with a private temporary client config instead of a CLI secret."""

import os
from pathlib import Path
import re
import subprocess
import tempfile

from core import Finding, ProbeError, clean, run_command

OID = ".1.3.6.1.2.1.1.1.0"  # sysDescr.0


def valid_community(value):
    return bool(re.fullmatch(r"[A-Za-z0-9._@%:+/=!-]{1,128}", value))


def analyze(reply):
    # NoSuchObject, timeout, or an empty output must never become a clean result.
    if reply.returncode == 0 and re.search(r"(?m)^\.?1\.3\.6\.1\.2\.1\.1\.1\.0\s*=\s*STRING:", reply.stdout):
        return "detected"
    return "inconclusive"


def run(ctx):
    evidence = {"version": "2c", "oid": OID,
                "community_label": "public (default)" if ctx.community == "public" else "user-supplied (redacted)"}
    status = "inconclusive"
    try:
        if not valid_community(ctx.community):
            raise ProbeError("Community format is unsupported; see README")
        with tempfile.TemporaryDirectory(prefix="nsms-snmp-") as folder:
            config = Path(folder) / "snmp.conf"
            fd = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as handle:
                handle.write("defCommunity " + ctx.community + "\n")
            reply = run_command(["snmpget", "-v2c", "-m", "", "-On", "-t", str(ctx.timeout),
                                 "-r", "0", f"udp:{ctx.target}:{ctx.port}", OID],
                                min(ctx.tool_timeout, ctx.timeout + 3),
                                env_extra={"SNMPCONFPATH": folder})
            status = analyze(reply)
            evidence["reply"] = clean((reply.stdout + "\n" + reply.stderr).replace(ctx.community, "[redacted]"), 1800)
            evidence["exit_code"] = reply.returncode
    except (ProbeError, OSError, subprocess.SubprocessError) as exc:
        evidence["reason"] = clean(str(exc).replace(ctx.community, "[redacted]"))
    return [Finding("SNMP-001", "snmp", ctx.port, "SNMPv2c read access accepted", status,
                    "medium" if ctx.community == "public" else "low", evidence,
                    "Community-based SNMP exposes the requested system description without encrypted transport.",
                    "Prefer SNMPv3 authPriv, restrict management sources, and replace default community strings.",
                    "One community and one read-only OID are tested. No response is inconclusive; write access, "
                    "other communities, other OIDs, SNMPv1, and SNMPv3 configuration are not assessed.")]
