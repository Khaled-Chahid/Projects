"""Regression tests for false positives, false negatives, scope, and reporting."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

from core import CommandResult, Context, Finding, ProbeError, clean, discover, ipv4, parse_nmap, run_command
from checks import smb, snmp, ssh
from reporting import render_html, save_report, summary
import scanner


def host_xml(scripts="", ports="", finished="success", address="127.0.0.1"):
    return (f'<nmaprun><host><address addr="{address}"/><ports>{ports}</ports>'
            f'<hostscript>{scripts}</hostscript></host><runstats><finished exit="{finished}"/></runstats></nmaprun>')


class DiscoveryTests(unittest.TestCase):
    def test_reject_invalid_xml(self):
        with self.assertRaises(ProbeError):
            parse_nmap("<nmaprun>", "127.0.0.1")

    def test_reject_failed_scan(self):
        with self.assertRaises(ProbeError):
            parse_nmap(host_xml(finished="error"), "127.0.0.1")

    def test_reject_wrong_host(self):
        with self.assertRaises(ProbeError):
            parse_nmap(host_xml(address="192.0.2.9"), "127.0.0.1")

    def test_closed_and_open_are_distinct(self):
        host = parse_nmap(host_xml(ports='<port portid="21" protocol="tcp"><state state="closed"/></port>'
                                  '<port portid="22" protocol="tcp"><state state="open"/><service name="ssh" method="probed"/></port>'), "127.0.0.1")
        with patch("core.nmap_host", return_value=host):
            inventory = discover("127.0.0.1", ["ftp", "ssh"], {"ftp": 21, "ssh": 22}, 10)
        self.assertEqual([x["state"] for x in inventory], ["closed", "open"])
        self.assertEqual(inventory[1]["fingerprint"]["method"], "probed")

    def test_missing_port_is_unknown(self):
        with patch("core.nmap_host", return_value=parse_nmap(host_xml(), "127.0.0.1")):
            self.assertEqual(discover("127.0.0.1", ["ftp"], {"ftp": 21}, 10)[0]["state"], "unknown")

    def test_discovery_failure_does_not_mean_closed(self):
        with patch("core.nmap_host", side_effect=ProbeError("timeout")):
            self.assertEqual(discover("127.0.0.1", ["ftp"], {"ftp": 21}, 10)[0]["state"], "unknown")

    def test_snmp_has_no_tcp_dependency(self):
        with patch("core.nmap_host") as nmap:
            inventory = discover("127.0.0.1", ["snmp"], {"snmp": 161}, 10)
        nmap.assert_not_called()
        self.assertEqual(inventory[0]["transport"], "udp")


class SMBTests(unittest.TestCase):
    def setUp(self):
        self.ctx = Context("127.0.0.1", 445)

    def test_smb1_observed(self):
        host = ET.fromstring('<host><hostscript><script id="smb-protocols"><table key="dialects">'
                             '<elem>NT LM 0.12 (SMBv1) [dangerous, but default]</elem></table></script></hostscript></host>')
        self.assertEqual(smb.negotiation(self.ctx, host)[0].status, "detected")

    def test_modern_dialects_only(self):
        host = ET.fromstring('<host><hostscript><script id="smb-protocols"><table key="dialects">'
                             '<elem>3.1.1</elem></table></script></hostscript></host>')
        self.assertEqual(smb.negotiation(self.ctx, host)[0].status, "not_detected")

    def test_missing_scripts_inconclusive(self):
        self.assertEqual([x.status for x in smb.negotiation(self.ctx, ET.fromstring("<host/>"))], ["inconclusive"] * 2)

    def test_older_nmap_colon_dialect_names(self):
        host = ET.fromstring('<host><hostscript><script id="smb-protocols"><table key="dialects">'
                             '<elem>2:0:2</elem><elem>3:1:1</elem></table></script></hostscript></host>')
        self.assertEqual(smb.negotiation(self.ctx, host)[0].status, "not_detected")

    def test_required_vs_optional_signing(self):
        for message, expected in [("Message signing enabled and required", "not_detected"),
                                  ("Message signing enabled but not required", "detected"),
                                  ("Message signing is disabled and not required!", "detected"),
                                  ("Message signing is disabled!", "inconclusive"),
                                  ("ERROR", "inconclusive")]:
            with self.subTest(message=message):
                host = ET.fromstring(f'<host><hostscript><script id="smb2-security-mode"><table key="3.1.1"><elem>{message}</elem></table></script></hostscript></host>')
                self.assertEqual(smb.negotiation(self.ctx, host)[1].status, expected)

    def test_smbclient_zero_exit_with_denied_ls(self):
        self.assertEqual(smb.parse_listing(CommandResult(0, "NT_STATUS_ACCESS_DENIED listing \\*", "")), "not_detected")

    def test_smbclient_arbitrary_success_not_proof(self):
        self.assertEqual(smb.parse_listing(CommandResult(0, "connected", "")), "inconclusive")

    def test_completed_empty_directory(self):
        self.assertEqual(smb.parse_listing(CommandResult(0, " 100 blocks of size 1024. 90 blocks available", "")), "detected")

    def test_filename_is_not_an_access_denial(self):
        output = '  NT_STATUS_ACCESS_DENIED  A  24  Fri Oct  9 10:00:00 2026\n100 blocks of size 512. 40 blocks available'
        self.assertEqual(smb.parse_listing(CommandResult(0, output, "")), "detected")

    def test_missing_share_is_inconclusive(self):
        self.assertEqual(smb.parse_listing(CommandResult(1, 'tree connect failed: NT_STATUS_BAD_NETWORK_NAME', '')), 'inconclusive')

    def test_share_names_do_not_prove_listing(self):
        with patch("checks.smb.run_command", side_effect=[CommandResult(0, "Disk|data|Files", ""),
                                                          CommandResult(0, "NT_STATUS_ACCESS_DENIED", "")]):
            findings = smb.access_checks(self.ctx)
        self.assertEqual([x.status for x in findings], ["detected", "not_detected"])

    def test_explicit_share_tried_after_enumeration_denied(self):
        self.ctx.shares = ["public"]
        with patch("checks.smb.run_command", side_effect=[CommandResult(1, "NT_STATUS_ACCESS_DENIED", ""),
                                                          CommandResult(0, "100 blocks of size 512. 50 blocks available", "")]) as command:
            findings = smb.access_checks(self.ctx)
        self.assertEqual(findings[1].status, "detected")
        self.assertIn("//127.0.0.1/public", command.call_args_list[1].args[0])

    def test_listing_timeout_is_inconclusive(self):
        self.ctx.shares = ["data"]
        with patch("checks.smb.run_command", side_effect=ProbeError("timeout")):
            findings = smb.access_checks(self.ctx)
        self.assertTrue(all(x.status == "inconclusive" for x in findings))


class SSHTests(unittest.TestCase):
    def setUp(self):
        self.ctx = Context("127.0.0.1", 22)

    def test_legacy_names_are_detected(self):
        script = ET.fromstring('<script><table key="kex_algorithms"><elem>diffie-hellman-group1-sha1</elem></table>'
                                '<table key="server_host_key_algorithms"><elem>ssh-rsa</elem></table>'
                                '<table key="encryption_algorithms"><elem>aes128-cbc</elem></table>'
                                '<table key="mac_algorithms"><elem>hmac-md5</elem></table></script>')
        self.assertEqual([x.status for x in ssh.analyze(self.ctx, script)], ["detected"] * 4)

    def test_rsa_sha2_not_confused_with_ssh_rsa(self):
        script = ET.fromstring('<script><table key="server_host_key_algorithms"><elem>rsa-sha2-512</elem></table></script>')
        self.assertEqual(ssh.analyze(self.ctx, script)[1].status, "not_detected")

    def test_absent_inventory_is_inconclusive(self):
        self.assertTrue(all(x.status == "inconclusive" for x in ssh.analyze(self.ctx, None)))

    def test_one_direction_cannot_clear_both_directions(self):
        script = ET.fromstring('<script><table key="encryption_algorithms_client_to_server"><elem>aes128-ctr</elem></table></script>')
        self.assertEqual(ssh.analyze(self.ctx, script)[2].status, "inconclusive")

    def test_directions_are_both_checked(self):
        script = ET.fromstring('<script><table key="encryption_algorithms_client_to_server"><elem>aes128-ctr</elem></table>'
                                '<table key="encryption_algorithms_server_to_client"><elem>aes128-cbc</elem></table></script>')
        self.assertEqual(ssh.analyze(self.ctx, script)[2].status, "detected")


class SNMPTests(unittest.TestCase):
    def test_valid_sysdescr(self):
        self.assertEqual(snmp.analyze(CommandResult(0, '.1.3.6.1.2.1.1.1.0 = STRING: "Lab agent"', "")), "detected")

    def test_timeout_and_no_such_object_are_inconclusive(self):
        for reply in [CommandResult(1, "", "Timeout"), CommandResult(0, ".1.3.6.1.2.1.1.1.0 = No Such Object", "")]:
            self.assertEqual(snmp.analyze(reply), "inconclusive")

    def test_community_not_on_command_line_and_config_removed(self):
        seen = []
        def command(args, timeout, env_extra):
            self.assertNotIn("ExampleSecret", " ".join(args))
            path = Path(env_extra["SNMPCONFPATH"]) / "snmp.conf"
            seen.append(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertIn("ExampleSecret", path.read_text())
            return CommandResult(0, '.1.3.6.1.2.1.1.1.0 = STRING: "ExampleSecret"', "")
        with patch("checks.snmp.run_command", side_effect=command):
            finding = snmp.run(Context("127.0.0.1", 161, community="ExampleSecret"))[0]
        self.assertFalse(seen[0].exists())
        self.assertNotIn("ExampleSecret", json.dumps(finding.to_dict()))


class SafetyAndCLITests(unittest.TestCase):
    def test_exit_codes_preserve_partial_coverage(self):
        for inconclusive, violations, interrupted, expected in [(0, 0, False, 0), (0, 1, False, 1),
                                                                 (1, 1, False, 2), (0, 0, True, 130)]:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as folder:
                report = {"summary": {"inconclusive": inconclusive, "policy_violations": violations}, "interrupted": interrupted}
                with patch('scanner.execute', return_value=report), patch('scanner.save_report', return_value=Path(folder)), patch('scanner.print_results'), redirect_stdout(io.StringIO()):
                    self.assertEqual(scanner.main(['127.0.0.1', '--services', 'ftp']), expected)

    def test_target_validation(self):
        for value in ["--help", "127.0.0.1;whoami", "127.0.0.0/24", "example.com", "::1", "0.0.0.0", "224.0.0.1"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                ipv4(value)

    def test_loopback_accepted_for_lab(self):
        self.assertEqual(ipv4("127.0.0.1"), "127.0.0.1")

    def test_command_arguments_not_shell_code(self):
        value = "$(touch NEVER_CREATED);`id`"
        result = run_command([sys.executable, "-c", "import sys;print(sys.argv[1])", value])
        self.assertEqual(result.stdout.strip(), value)

    def test_command_timeout(self):
        with self.assertRaises(ProbeError):
            run_command([sys.executable, "-c", "import time;time.sleep(3)"], timeout=0.05)

    def test_command_output_limit(self):
        with self.assertRaises(ProbeError):
            run_command([sys.executable, "-c", "print('A'*100000)"], max_bytes=1024)

    def test_missing_tool(self):
        with self.assertRaises(ProbeError):
            run_command(["nsms-nonexistent-command"])

    def test_terminal_escape_removed(self):
        self.assertEqual(clean("\x1b[31mred\x00"), "red")

    def test_invalid_port_rejected_before_network(self):
        p = scanner.parser()
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            scanner.validate(p.parse_args(["127.0.0.1", "--port", "ftp=99999"]), p)

    def test_invalid_domain_rejected(self):
        p = scanner.parser()
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            scanner.validate(p.parse_args(["127.0.0.1", "--domain", "lab.test\nAXFR"]), p)

    def test_service_failure_does_not_drop_other_results(self):
        p = scanner.parser()
        args = p.parse_args(["127.0.0.1", "--services", "ftp,dns"])
        services, ports, community = scanner.validate(args, p)
        inventory = [{"service": s, "state": "unknown"} for s in services]
        with patch("scanner.discover", return_value=inventory), patch("checks.ftp.run", side_effect=RuntimeError("unexpected")), redirect_stdout(io.StringIO()):
            report = scanner.execute(args, services, ports, community)
        self.assertEqual(len(report["findings"]), 3)
        self.assertEqual(report["findings"][-1]["status"], "skipped")
        self.assertEqual(report["findings"][0]["status"], "inconclusive")


class ReportTests(unittest.TestCase):
    def report(self):
        finding = Finding("FTP-001", "ftp", 21, '<script>alert(1)</script>', "detected", "medium",
                          {"reply": "<img src=x onerror=alert(1)>"}, "Impact", "Fix", "Scope")
        return {"target": "127.0.0.1", "scanner_version": "1.0.0", "policy": {"name": "internal-services-v1"},
                "started_at": "2026-10-09T00:00:00Z", "finished_at": "2026-10-09T00:00:01Z", "settings": {},
                "inventory": [], "findings": [finding.to_dict()], "summary": summary([finding.to_dict()])}

    def test_html_escapes_remote_data(self):
        html = render_html(self.report())
        self.assertNotIn("<script>", html)
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("Content-Security-Policy", html)

    def test_json_and_html_created_with_private_permissions(self):
        with tempfile.TemporaryDirectory() as folder:
            path = save_report(self.report(), Path(folder) / "run")
            self.assertEqual(json.loads((path / "report.json").read_text())["target"], "127.0.0.1")
            self.assertEqual((path / "report.json").stat().st_mode & 0o777, 0o600)
            self.assertTrue((path / "report.html").exists())

    def test_existing_report_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(FileExistsError):
                save_report(self.report(), folder)

    def test_accepted_behavior_is_review_not_violation(self):
        finding = smb.result(Context("127.0.0.1", 445, allow_anonymous_smb=True), "SMB-004", "detected", {})
        self.assertEqual(finding.assessment, "review")
        self.assertEqual(summary([finding.to_dict()])["policy_violations"], 0)

    def test_inconclusive_has_no_severity(self):
        finding = smb.result(Context("127.0.0.1", 445), "SMB-001", "inconclusive", {})
        self.assertEqual(finding.severity, "none")


if __name__ == "__main__":
    unittest.main()
