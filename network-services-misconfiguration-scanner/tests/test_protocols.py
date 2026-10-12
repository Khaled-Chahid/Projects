"""Loopback socket tests: FTP via pyftpdlib; DNS via a controlled wire responder.

DNS responders exercise protocol outcomes, not a real BIND/Windows DNS deployment.
"""

from contextlib import contextmanager
import importlib.util
import logging
from pathlib import Path
import ftplib
import socket
import socketserver
import struct
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import dns.flags
import dns.message
import dns.rcode
import dns.rrset

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

from core import Context
from checks import dns as dns_check
from checks import ftp


def receive_exact(sock, size):
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise EOFError("Incomplete request")
        data += part
    return data


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            self.respond()
        except (OSError, EOFError, dns.exception.DNSException):
            # Connect scans and version probes may close before a DNS request.
            return

    def respond(self):
        length = struct.unpack("!H", receive_exact(self.request, 2))[0]
        query = dns.message.from_wire(receive_exact(self.request, length))
        answer = dns.message.make_response(query)
        answer.flags |= dns.flags.AA
        soa = dns.rrset.from_text("lab.test.", 60, "IN", "SOA", "ns.lab.test. admin.lab.test. 1 60 60 60 60")
        mode = self.server.mode
        if query.question[0].rdtype == 6:
            if mode == "non_authoritative":
                answer.flags &= ~dns.flags.AA
            answer.answer = [soa]
        elif mode == "refused":
            answer.set_rcode(dns.rcode.REFUSED)
        elif mode == "servfail":
            answer.set_rcode(dns.rcode.SERVFAIL)
        else:
            answer.answer = [soa, dns.rrset.from_text("www.lab.test.", 60, "IN", "A", "192.0.2.10")]
            if mode != "partial":
                answer.answer.append(soa)
        wire = answer.to_wire()
        self.request.sendall(struct.pack("!H", len(wire)) + wire)


@contextmanager
def dns_server(mode):
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), DNSHandler) as server:
        server.mode = mode
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join()


class DNSWireTests(unittest.TestCase):
    def scan(self, mode):
        with dns_server(mode) as port:
            return dns_check.run(Context("127.0.0.1", port, timeout=0.3, domain="lab.test."))[0]

    def test_complete_axfr_detected(self):
        finding = self.scan("accepted")
        self.assertEqual(finding.status, "detected", finding.evidence)
        self.assertTrue(finding.evidence["completed"])

    def test_explicit_refusal_is_negative(self):
        self.assertEqual(self.scan("refused").status, "not_detected")

    def test_partial_axfr_is_not_success(self):
        self.assertEqual(self.scan("partial").status, "inconclusive")

    def test_servfail_is_not_negative(self):
        self.assertEqual(self.scan("servfail").status, "inconclusive")

    def test_non_authoritative_is_inconclusive(self):
        self.assertEqual(self.scan("non_authoritative").status, "inconclusive")

    def test_missing_zone_skipped(self):
        self.assertEqual(dns_check.run(Context("127.0.0.1", 53))[0].status, "skipped")


@contextmanager
def ftp_server(anonymous=True, listing=True, empty=False):
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.ioloop import IOLoop
    from pyftpdlib.servers import FTPServer
    logging.getLogger("pyftpdlib").setLevel(logging.CRITICAL)
    with tempfile.TemporaryDirectory() as folder:
        if not empty:
            (Path(folder) / "example.txt").write_text("Lab fixture, not sensitive data.")
        authorizer = DummyAuthorizer()
        if anonymous:
            authorizer.add_anonymous(folder, perm="elr" if listing else "er")
        class Handler(FTPHandler):
            auth_failed_timeout = 0
            banner = "Loopback FTP test service"
        Handler.authorizer = authorizer
        loop = IOLoop()
        server = FTPServer(("127.0.0.1", 0), Handler, ioloop=loop)
        port = server.socket.getsockname()[1]
        thread = threading.Thread(target=server.serve_forever, kwargs={"timeout": 0.02, "handle_exit": False}, daemon=True)
        thread.start()
        try:
            yield port
        finally:
            server.close_all()
            thread.join(timeout=1)
            loop.close()


@unittest.skipUnless(importlib.util.find_spec("pyftpdlib"), "Install app/requirements-dev.txt for real FTP tests")
class FTPLiveTests(unittest.TestCase):
    def test_login_and_listing(self):
        with ftp_server() as port:
            findings = ftp.run(Context("127.0.0.1", port, timeout=0.5))
        self.assertEqual([x.status for x in findings], ["detected", "detected"])
        self.assertIn("example.txt", str(findings[1].evidence))

    def test_login_refused(self):
        with ftp_server(anonymous=False) as port:
            findings = ftp.run(Context("127.0.0.1", port, timeout=0.5))
        self.assertEqual([x.status for x in findings], ["not_detected", "skipped"])

    def test_login_allowed_listing_denied(self):
        with ftp_server(listing=False) as port:
            findings = ftp.run(Context("127.0.0.1", port, timeout=0.5))
        self.assertEqual([x.status for x in findings], ["detected", "not_detected"])

    def test_empty_directory_is_success(self):
        with ftp_server(empty=True) as port:
            findings = ftp.run(Context("127.0.0.1", port, timeout=0.5))
        self.assertEqual(findings[1].status, "detected")
        self.assertEqual(findings[1].evidence["line_count"], 0)


class FTPFailureTests(unittest.TestCase):
    def test_data_setup_denial_is_not_a_listing_denial(self):
        class RefusePassive:
            last_command = 'PASV'
            def __init__(self, timeout): pass
            def connect(self, *args): return '220 test'
            def login(self, *args): return '230 logged in'
            def voidcmd(self, *args): return '200 type set'
            def transfercmd(self, *args): raise ftplib.error_perm('550 passive connection denied')
            def close(self): pass
        with patch('checks.ftp.DeadlineFTP', RefusePassive):
            findings = ftp.run(Context('127.0.0.1', 21))
        self.assertEqual([x.status for x in findings], ['detected', 'inconclusive'])

    def test_closed_port_is_inconclusive_not_clean(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            findings = ftp.run(Context("127.0.0.1", port, timeout=0.1))
        self.assertEqual([x.status for x in findings], ["inconclusive", "skipped"])

    def test_silent_server_times_out(self):
        class Silent(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(0.5)
                try:
                    self.request.recv(1)
                except OSError:
                    pass
        with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Silent) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
            thread.start()
            try:
                findings = ftp.run(Context("127.0.0.1", server.server_address[1], timeout=0.05))
                self.assertEqual(findings[0].status, "inconclusive")
            finally:
                server.shutdown()
                thread.join()


if __name__ == "__main__":
    unittest.main()
