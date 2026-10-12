"""SMB negotiation with Nmap; bounded anonymous enumeration with smbclient."""

import re
import subprocess

from core import Finding, ProbeError, clean, nmap_host, run_command, valid_share

CHECKS = {
    "SMB-001": ("SMBv1 offered", "high", "Legacy SMB increases exposure to obsolete protocol behavior.",
                "Disable SMBv1 after checking legacy dependencies."),
    "SMB-002": ("SMB signing not required", "medium", "Optional signing can contribute to relay or tampering risk, subject to other controls.",
                "Require SMB signing and verify compatibility with clients."),
    "SMB-003": ("Disk share names exposed without credentials", "low", "Share names can disclose the purpose of network resources.",
                "Restrict anonymous share enumeration where it is not intended."),
    "SMB-004": ("Share root listing available without credentials", "medium", "Unauthenticated directory access exposes names and metadata in the tested share.",
                "Restrict guest access and review both share and filesystem permissions."),
}


def result(ctx, key, status, evidence):
    title, severity, impact, remediation = CHECKS[key]
    if key in {"SMB-003", "SMB-004"} and ctx.allow_anonymous_smb:
        severity = "info"
    return Finding(key, "smb", ctx.port, title, status, severity, evidence, impact, remediation,
                   "Signing evidence concerns negotiated dialects only. Empty credentials may map to Guest. "
                   "Share tests use SMB2/3 and at most five share roots; file read/write and exploitation are not tested.")


def negotiation(ctx, host):
    findings = []
    dialect_script = host.find("hostscript/script[@id='smb-protocols']")
    dialects = [] if dialect_script is None else [e.text or "" for e in dialect_script.findall("table[@key='dialects']/elem")]
    if any("NT LM 0.12" in x or "SMBv1" in x for x in dialects):
        status = "detected"
    elif any(re.fullmatch(r"[23][.:]\d(?:[.:]\d)?", x) for x in dialects):
        status = "not_detected"
    else:
        status = "inconclusive"
    findings.append(result(ctx, "SMB-001", status, {"dialects": dialects,
                    "reason": "Based on explicit smb-protocols XML; absent output is not a negative result."}))
    script = host.find("hostscript/script[@id='smb2-security-mode']")
    modes = {} if script is None else {
        t.get("key", "unknown"): [e.text or "" for e in t.findall("elem")]
        for t in script.findall("table")}
    values = [x for v in modes.values() for x in v]
    optional = {"Message signing enabled but not required", "Message signing is disabled and not required!"}
    if any(x in optional for x in values):
        status = "detected"
    elif values and all(x == "Message signing enabled and required" for x in values):
        status = "not_detected"
    else:
        status = "inconclusive"
    findings.append(result(ctx, "SMB-002", status, {"negotiated_modes": modes,
                    "reason": "No conclusion is made for unreported dialects or unknown messages."}))
    return findings


DENIALS = {"NT_STATUS_ACCESS_DENIED", "NT_STATUS_LOGON_FAILURE", "NT_STATUS_ACCOUNT_DISABLED",
           "NT_STATUS_ACCOUNT_RESTRICTION", "NT_STATUS_LOGON_TYPE_NOT_GRANTED"}


def error_codes(text):
    """Read status tokens from operation errors, not from a directory filename."""
    codes = []
    for line in text.splitlines():
        stripped = line.strip()
        if (re.fullmatch(r"NT_STATUS_[A-Z0-9_]+", stripped)
                or re.match(r"NT_STATUS_[A-Z0-9_]+\s+(?:listing|opening|getting|connecting)\b", stripped)
                or re.search(r"\b(?:failed|Error)\b.*NT_STATUS_", stripped)):
            codes.extend(re.findall(r"NT_STATUS_[A-Z0-9_]+", stripped))
    return codes


def denied(text):
    return any(x in DENIALS for x in error_codes(text))


def parse_listing(result):
    output = result.stdout + "\n" + result.stderr
    if denied(output):
        return "not_detected"
    # smbclient can exit zero while its internal 'ls' command failed.
    if result.returncode or error_codes(output):
        return "inconclusive"
    if re.search(r"\b\d+ blocks of size \d+\. \d+ blocks available\b", output):
        return "detected"
    return "inconclusive"


def access_checks(ctx):
    base = ["smbclient", "-N", "-U", "%", "--use-kerberos=off", "-I", ctx.target,
            "-p", str(ctx.port), "-t", str(max(1, int(ctx.timeout))),
            "--option=client min protocol=SMB2_02", "--option=client max protocol=SMB3"]
    found = []
    evidence = {}
    try:
        reply = run_command(base + ["-g", "-L", ctx.target], ctx.tool_timeout)
        output = reply.stdout + "\n" + reply.stderr
        found = [line.split("|", 2)[1] for line in reply.stdout.splitlines()
                 if line.startswith("Disk|") and len(line.split("|", 2)) >= 2]
        status = "detected" if found else "not_detected" if denied(output) else "inconclusive"
        evidence = {"shares": [clean(x, 80) for x in found[:20]], "reply_sample": clean(output, 1500)}
    except (ProbeError, OSError, subprocess.SubprocessError) as exc:
        status, evidence = "inconclusive", {"reason": clean(exc)}
    findings = [result(ctx, "SMB-003", status, evidence)]
    # Explicit share names also work when enumeration itself is denied.
    candidates = list(dict.fromkeys(ctx.shares or found))
    candidates = [x for x in candidates if valid_share(x)][:5]
    if not candidates:
        findings.append(result(ctx, "SMB-004", "skipped", {
            "reason": "No supported disk share names available; provide --smb-share if known."}))
        return findings
    attempts = []
    for share in candidates:
        try:
            reply = run_command(base + [f"//{ctx.target}/{share}", "-c", "ls"], ctx.tool_timeout)
            attempts.append({"share": share, "status": parse_listing(reply),
                             "reply_sample": clean(reply.stdout + "\n" + reply.stderr, 1800)})
        except (ProbeError, OSError, subprocess.SubprocessError) as exc:
            attempts.append({"share": share, "status": "inconclusive", "reason": clean(exc)})
    status = "detected" if any(x["status"] == "detected" for x in attempts) else (
        "not_detected" if all(x["status"] == "not_detected" for x in attempts) else "inconclusive")
    findings.append(result(ctx, "SMB-004", status, {"attempts": attempts, "max_shares": 5}))
    return findings


def run(ctx):
    try:
        host = nmap_host(ctx.target, [ctx.port], ctx.tool_timeout,
                         ["smb-protocols", "smb2-security-mode"], f"smbport={ctx.port}")
        findings = negotiation(ctx, host)
    except (ProbeError, OSError, subprocess.SubprocessError) as exc:
        findings = [result(ctx, key, "inconclusive", {"reason": clean(exc)})
                    for key in ("SMB-001", "SMB-002")]
    return findings + access_checks(ctx)
