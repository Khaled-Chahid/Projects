"""SSH algorithm inventory compared with a small, explicit legacy denylist."""

import subprocess

from core import Finding, ProbeError, clean, nmap_host

# Project policy, not an exhaustive cryptographic compliance standard.
RULES = {
    "kex_algorithms": ("SSH-001", "Legacy SSH key exchange offered", {
        "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}),
    "server_host_key_algorithms": ("SSH-002", "Legacy SSH host signature offered", {"ssh-rsa", "ssh-dss"}),
    "encryption_algorithms": ("SSH-003", "Legacy SSH cipher offered", {
        "arcfour", "arcfour128", "arcfour256", "3des-cbc", "blowfish-cbc", "cast128-cbc",
        "aes128-cbc", "aes192-cbc", "aes256-cbc", "rijndael-cbc@lysator.liu.se", "none"}),
    "mac_algorithms": ("SSH-004", "Legacy SSH MAC offered", {
        "hmac-md5", "hmac-md5-96", "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com",
        "hmac-sha1-96", "hmac-sha1-96-etm@openssh.com", "none"}),
}


def result(ctx, key, status, evidence):
    check_id, title, _ = RULES[key]
    return Finding(check_id, "ssh", ctx.port, title, status, "medium", evidence,
                   "Legacy algorithms remain available to clients; actual session selection depends on negotiation.",
                   "Remove the listed algorithms after testing client compatibility; keep the SSH implementation updated.",
                   "Only offered algorithm names are checked against the documented project policy. "
                   "No authentication or root-login setting is inferred. ssh-rsa denotes SHA-1 signatures, not every RSA key.")


def analyze(ctx, script):
    tables = {} if script is None else {t.get("key"): [e.text or "" for e in t.findall("elem")]
                                       for t in script.findall("table")}
    findings = []
    for key, (_, _, disallowed) in RULES.items():
        groups = {k: v for k, v in tables.items() if k in {
            key, key + "_client_to_server", key + "_server_to_client"}}
        values = sorted({x for v in groups.values() for x in v})
        matches = sorted(set(values) & disallowed)
        complete = bool(groups.get(key)) or (
            bool(groups.get(key + "_client_to_server")) and bool(groups.get(key + "_server_to_client")))
        status = "detected" if matches else "not_detected" if complete else "inconclusive"
        findings.append(result(ctx, key, status, {"offered": groups, "policy_matches": matches,
                        "inventory_complete_for_category": complete}))
    return findings


def run(ctx):
    try:
        host = nmap_host(ctx.target, [ctx.port], ctx.tool_timeout, ["+ssh2-enum-algos"])
        script = host.find(f"ports/port[@portid='{ctx.port}']/script[@id='ssh2-enum-algos']")
        return analyze(ctx, script)
    except (ProbeError, OSError, subprocess.SubprocessError) as exc:
        return [result(ctx, key, "inconclusive", {"reason": clean(exc)}) for key in RULES]
