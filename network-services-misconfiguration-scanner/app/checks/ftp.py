"""FTP anonymous login and one bounded passive directory listing."""

import ftplib
import time

from core import Finding, clean

LOGIN = ("FTP-001", "Anonymous FTP login accepted")
LIST = ("FTP-002", "FTP directory listing available anonymously")


def result(ctx, check, status, evidence):
    return Finding(check[0], "ftp", ctx.port, check[1], status,
                   "info" if ctx.allow_anonymous_ftp else "medium", evidence,
                   "Anonymous access can expose published directory information; file access depends on permissions.",
                   "Disable anonymous access unless intentional; otherwise isolate public data and restrict permissions.",
                   "Plain FTP only. One anonymous identity and the login directory are tested. No file read, write, or FTPS audit.")


class DeadlineFTP(ftplib.FTP):
    def __init__(self, timeout):
        super().__init__(timeout=timeout, encoding="utf-8")
        self.deadline = time.monotonic() + timeout * 4
        self.control_lines = 0
        self.last_command = ""
        self.trust_server_pasv_ipv4_address = False

    def putcmd(self, line):
        self.last_command = line.split(" ", 1)[0].upper()
        return super().putcmd(line)

    def remaining(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("FTP check time limit reached")
        return min(left, self.timeout)

    def getline(self):
        self.control_lines += 1
        if self.control_lines > 150:
            raise ftplib.Error("FTP control response limit reached")
        self.sock.settimeout(self.remaining())
        return super().getline()


def run(ctx):
    client = DeadlineFTP(ctx.timeout)
    evidence = {}
    findings = []
    try:
        evidence["banner"] = clean(client.connect(ctx.target, ctx.port, ctx.timeout), 500)
        try:
            reply = client.login("anonymous", "scanner@example.invalid")
        except ftplib.error_perm as exc:
            code = str(exc)[:3]
            # 530 is a refused login. 534, for example, may require TLS.
            status = "not_detected" if code == "530" else "inconclusive"
            return [result(ctx, LOGIN, status, {**evidence, "reply": clean(exc)}),
                    result(ctx, LIST, "skipped", {"reason": "Anonymous login was not accepted."})]
        if not reply.startswith("230"):
            raise ftplib.Error("Unexpected final login reply: " + reply)
        findings.append(result(ctx, LOGIN, "detected", {**evidence, "reply": clean(reply)}))
        client.voidcmd("TYPE A")
        data = bytearray()
        with client.transfercmd("LIST") as connection:
            while True:
                connection.settimeout(client.remaining())
                chunk = connection.recv(4096)
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > 65536:
                    raise ftplib.Error("Directory listing exceeded the 64 KiB limit")
        reply = client.voidresp()
        if not reply.startswith(("226", "250")):
            raise ftplib.Error("Unrecognized listing completion: " + reply)
        lines = data.decode("utf-8", "replace").splitlines()
        findings.append(result(ctx, LIST, "detected", {
            "reply": clean(reply), "listing_sample": [clean(x, 250) for x in lines[:5]],
            "line_count": len(lines), "note": "A completed empty listing is also valid evidence of listing permission."}))
    except (ftplib.Error, OSError, EOFError, UnicodeError) as exc:
        check = LIST if findings else LOGIN
        status = "not_detected" if (findings and client.last_command == "LIST"
                                    and isinstance(exc, ftplib.error_perm) and str(exc).startswith("550")) else "inconclusive"
        findings.append(result(ctx, check, status, {**evidence, "reason": clean(exc)}))
        if check == LOGIN:
            findings.append(result(ctx, LIST, "skipped", {"reason": "Login could not be verified."}))
    finally:
        client.close()
    return findings
