"""
Tests for the host scanning module.

Uses a FakeShell that simulates RemoteShell responses so no real SSH
connection is needed.
"""
import json
from typing import Dict, Optional
from adsyslib.core import CommandResult
from adsyslib.host.session import HostSession, HostReport
from adsyslib.host.scanners import ScanResult
from adsyslib.host.scanners.postfix import PostfixScanner
from adsyslib.host.scanners.dns import DnsScanner
from adsyslib.host.scanners.dovecot import DovecotScanner
from adsyslib.host.scanners.nginx import NginxScanner


# ---------------------------------------------------------------------------
# Fake shell
# ---------------------------------------------------------------------------

class FakeShell:
    """Simulates RemoteShell for unit tests."""

    def __init__(self, commands: Optional[Dict[str, str]] = None, files: Optional[Dict[str, str]] = None):
        self._commands = commands or {}
        self._files = files or {}
        self.host = "test.host"
        self.user = "root"

    def run(self, cmd, check: bool = False, **_) -> CommandResult:
        if isinstance(cmd, list):
            key = " ".join(str(c) for c in cmd)
        else:
            key = str(cmd)
        stdout = self._commands.get(key, "")
        exit_code = 0 if key in self._commands else 1
        return CommandResult(stdout=stdout, stderr="", exit_code=exit_code, command=key, duration=0.0)

    def read_text(self, path: str) -> Optional[str]:
        return self._files.get(path)


# ---------------------------------------------------------------------------
# PostfixScanner
# ---------------------------------------------------------------------------

POSTFIX_CONF = (
    "myhostname = mail.corp.com\n"
    "smtpd_tls_security_level = may\n"
    "smtp_tls_security_level = may\n"
    "smtpd_tls_cert_file = /etc/ssl/certs/mail.crt\n"
)

MAILQ_EMPTY = "Mail queue is empty"
MAILQ_FULL = (
    "Inst openssl\nInst curl\n"
    "-Queue ID- --Size-- ----Arrival Time---- -Sender/Recipient-------\n"
    "150 Kbytes in 120 Requests."
)


def _postfix_shell(active=True, conf=POSTFIX_CONF, mailq=MAILQ_EMPTY):
    return FakeShell(commands={
        "systemctl is-active postfix": "active" if active else "inactive",
        "postconf -n": conf,
        "mailq": mailq,
        "tail -50 /var/log/mail.log": "May 13 10:00:00 mail postfix/smtpd: connect from foo[1.2.3.4]",
    })


class TestPostfixScanner:
    def test_active(self):
        r = PostfixScanner(_postfix_shell()).scan()
        assert r.active is True

    def test_inactive(self):
        r = PostfixScanner(_postfix_shell(active=False)).scan()
        assert r.active is False
        assert any("not running" in i for i in r.issues)

    def test_tls_may_no_issue(self):
        r = PostfixScanner(_postfix_shell()).scan()
        tls_issues = [i for i in r.issues if "tls" in i.lower()]
        assert tls_issues == []

    def test_tls_none_flagged(self):
        conf = "smtpd_tls_security_level = none\nsmtp_tls_security_level = none\n"
        r = PostfixScanner(_postfix_shell(conf=conf)).scan()
        assert any("smtpd_tls" in i for i in r.issues)

    def test_queue_depth_empty(self):
        r = PostfixScanner(_postfix_shell(mailq=MAILQ_EMPTY)).scan()
        assert r.metrics["queue_depth"] == 0

    def test_queue_depth_high_flagged(self):
        r = PostfixScanner(_postfix_shell(mailq=MAILQ_FULL)).scan()
        assert r.metrics["queue_depth"] == 120
        assert any("queue" in i for i in r.issues)

    def test_config_keys_present(self):
        r = PostfixScanner(_postfix_shell()).scan()
        assert "smtpd_tls_security_level" in r.config
        assert r.config["smtpd_tls_security_level"] == "may"

    def test_ok_when_no_issues(self):
        r = PostfixScanner(_postfix_shell()).scan()
        assert r.ok() is True


# ---------------------------------------------------------------------------
# DnsScanner
# ---------------------------------------------------------------------------

NAMED_CONF = """\
options {
    listen-on { 127.0.0.1; };
    recursion yes;
    forwarders { 8.8.8.8; 8.8.4.4; };
    dnssec-validation yes;
};
"""

RNDC_STATUS = """\
version: 9.16.1
number of zones: 12
server is up and running
"""


def _dns_shell(active=True, conf=NAMED_CONF, rndc=RNDC_STATUS, conf_ok=True):
    cmds = {
        "systemctl is-active named": "active" if active else "inactive",
        "systemctl is-active bind9": "inactive",
        "named -v": "BIND 9.16.1",
        "rndc status": rndc,
    }
    if conf_ok:
        cmds["named-checkconf"] = ""
    files = {"/etc/named.conf": conf}
    return FakeShell(commands=cmds, files=files)


class TestDnsScanner:
    def test_active(self):
        r = DnsScanner(_dns_shell()).scan()
        assert r.active is True

    def test_inactive(self):
        r = DnsScanner(_dns_shell(active=False)).scan()
        assert r.active is False
        assert any("not running" in i for i in r.issues)

    def test_zone_count_from_rndc(self):
        r = DnsScanner(_dns_shell()).scan()
        assert r.metrics["zone_count"] == 12

    def test_dnssec_ok(self):
        r = DnsScanner(_dns_shell()).scan()
        assert r.config.get("dnssec_validation") == "yes"
        assert not any("dnssec" in i for i in r.issues)

    def test_dnssec_missing_flagged(self):
        conf = NAMED_CONF.replace("dnssec-validation yes", "dnssec-validation no")
        r = DnsScanner(_dns_shell(conf=conf)).scan()
        assert any("dnssec" in i for i in r.issues)

    def test_open_resolver_flagged(self):
        conf = "options { recursion yes; };\n"
        r = DnsScanner(_dns_shell(conf=conf)).scan()
        assert any("open resolver" in i for i in r.issues)

    def test_forwarders_suppress_open_resolver(self):
        r = DnsScanner(_dns_shell()).scan()
        assert not any("open resolver" in i for i in r.issues)

    def test_conf_check_ok(self):
        r = DnsScanner(_dns_shell()).scan()
        assert r.metrics["conf_check_ok"] is True


# ---------------------------------------------------------------------------
# DovecotScanner
# ---------------------------------------------------------------------------

DOVECONF = """\
protocols = imap lmtp
ssl = required
ssl_cert = </etc/ssl/certs/dovecot.crt
ssl_key = </etc/ssl/private/dovecot.key
ssl_min_protocol = TLSv1.2
auth_mechanisms = plain login
disable_plaintext_auth = yes
mail_location = maildir:~/Maildir
"""


def _dovecot_shell(active=True, conf=DOVECONF):
    return FakeShell(commands={
        "systemctl is-active dovecot": "active" if active else "inactive",
        "dovecot --version": "2.3.19",
        "doveconf -n": conf,
        "doveadm who": "username  pid  ip\nryan  12345  10.0.0.1",
    })


class TestDovecotScanner:
    def test_active(self):
        r = DovecotScanner(_dovecot_shell()).scan()
        assert r.active is True

    def test_inactive(self):
        r = DovecotScanner(_dovecot_shell(active=False)).scan()
        assert r.active is False
        assert any("not running" in i for i in r.issues)

    def test_ssl_required_no_issue(self):
        r = DovecotScanner(_dovecot_shell()).scan()
        ssl_issues = [i for i in r.issues if "ssl" in i.lower() or "plain" in i.lower()]
        assert ssl_issues == []

    def test_ssl_no_flagged(self):
        conf = DOVECONF.replace("ssl = required", "ssl = no")
        r = DovecotScanner(_dovecot_shell(conf=conf)).scan()
        assert any("ssl=no" in i for i in r.issues)

    def test_ssl_yes_suggests_required(self):
        conf = DOVECONF.replace("ssl = required", "ssl = yes")
        r = DovecotScanner(_dovecot_shell(conf=conf)).scan()
        assert any("ssl=required" in i for i in r.issues)

    def test_plaintext_auth_disabled_ok(self):
        r = DovecotScanner(_dovecot_shell()).scan()
        assert not any("plaintext" in i.lower() for i in r.issues)

    def test_weak_tls_protocol_flagged(self):
        conf = DOVECONF.replace("ssl_min_protocol = TLSv1.2", "ssl_min_protocol = TLSv1")
        r = DovecotScanner(_dovecot_shell(conf=conf)).scan()
        assert any("TLSv1" in i for i in r.issues)

    def test_active_connections(self):
        r = DovecotScanner(_dovecot_shell()).scan()
        assert r.metrics["active_connections"] == 1


# ---------------------------------------------------------------------------
# NginxScanner
# ---------------------------------------------------------------------------

NGINX_T_OUTPUT = """\
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
server {
    listen 443 ssl;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_certificate /etc/ssl/certs/nginx.crt;
    add_header Strict-Transport-Security "max-age=31536000";
}
"""

NGINX_T_WEAK = """\
nginx: configuration file /etc/nginx/nginx.conf test is successful
server {
    ssl_protocols SSLv3 TLSv1;
    ssl_certificate /etc/ssl/certs/nginx.crt;
}
"""


def _nginx_shell(active=True, nginx_t=NGINX_T_OUTPUT):
    return FakeShell(commands={
        "systemctl is-active nginx": "active" if active else "inactive",
        "nginx -v": "nginx version: nginx/1.24.0",
        "nginx -t": nginx_t,
        "nginx -T": nginx_t,
        "ls /etc/nginx/sites-enabled": "default\nmail.conf",
    })


class TestNginxScanner:
    def test_active(self):
        r = NginxScanner(_nginx_shell()).scan()
        assert r.active is True

    def test_inactive(self):
        r = NginxScanner(_nginx_shell(active=False)).scan()
        assert r.active is False
        assert any("not running" in i for i in r.issues)

    def test_conf_test_ok(self):
        r = NginxScanner(_nginx_shell()).scan()
        assert r.metrics["conf_test_ok"] is True

    def test_strong_tls_no_issues(self):
        r = NginxScanner(_nginx_shell()).scan()
        tls_issues = [i for i in r.issues if "protocol" in i.lower() or "ssl" in i.lower()]
        assert tls_issues == []

    def test_weak_tls_flagged(self):
        r = NginxScanner(_nginx_shell(nginx_t=NGINX_T_WEAK)).scan()
        assert any("SSLv3" in i or "TLSv1" in i for i in r.issues)

    def test_hsts_configured(self):
        r = NginxScanner(_nginx_shell()).scan()
        assert r.config["tls"].get("hsts_configured") is True

    def test_hsts_missing_flagged(self):
        nginx_t = NGINX_T_OUTPUT.replace('add_header Strict-Transport-Security "max-age=31536000";', "")
        r = NginxScanner(_nginx_shell(nginx_t=nginx_t)).scan()
        assert any("HSTS" in i for i in r.issues)

    def test_enabled_sites(self):
        r = NginxScanner(_nginx_shell()).scan()
        assert "default" in r.metrics["enabled_sites"]


# ---------------------------------------------------------------------------
# HostSession / HostReport
# ---------------------------------------------------------------------------

class FakeRemoteShell:
    """Minimal RemoteShell stand-in for session-level tests."""
    host = "test.corp.com"
    user = "root"

    def connect(self): return self
    def disconnect(self): pass
    def run(self, cmd, check=False, **_):
        if isinstance(cmd, list):
            key = " ".join(str(c) for c in cmd)
        else:
            key = str(cmd)
        stdout = {
            "systemctl is-active postfix": "active",
            "systemctl is-active named":   "inactive",
            "systemctl is-active bind9":   "inactive",
            "systemctl is-active dovecot": "active",
            "systemctl is-active nginx":   "active",
            "postconf -n": "smtpd_tls_security_level = may\nsmtp_tls_security_level = may\n",
            "mailq": "Mail queue is empty",
            "doveconf -n": "ssl = required\ndisable_plaintext_auth = yes\n",
            "doveadm who": "username pid ip",
            "nginx -t": "nginx: configuration file test is successful",
            "nginx -T": "ssl_protocols TLSv1.2 TLSv1.3;\nadd_header Strict-Transport-Security max-age=31536000;",
            "rndc status": "number of zones: 5\n",
            "named-checkconf": "",
        }.get(key, "")
        return CommandResult(stdout=stdout, stderr="", exit_code=0 if stdout else 1, command=key, duration=0.0)
    def read_text(self, path): return None


class TestHostSession:
    def _session(self):
        s = HostSession.__new__(HostSession)
        s.host = "test.corp.com"
        s.user = "root"
        s._shell = FakeRemoteShell()
        s._scanners = {}
        return s

    def test_postfix_scanner_accessible(self):
        host = self._session()
        assert isinstance(host.postfix, PostfixScanner)

    def test_dns_scanner_accessible(self):
        host = self._session()
        assert isinstance(host.dns, DnsScanner)

    def test_dovecot_scanner_accessible(self):
        host = self._session()
        assert isinstance(host.dovecot, DovecotScanner)

    def test_nginx_scanner_accessible(self):
        host = self._session()
        assert isinstance(host.nginx, NginxScanner)

    def test_scanners_are_cached(self):
        host = self._session()
        s1 = host.postfix
        s2 = host.postfix
        assert s1 is s2

    def test_scan_all_returns_report(self):
        host = self._session()
        report = host.scan_all()
        assert isinstance(report, HostReport)
        assert set(report.results.keys()) == {"postfix", "dns", "dovecot", "nginx"}

    def test_scan_subset(self):
        host = self._session()
        report = host.scan_all(services=["postfix", "nginx"])
        assert set(report.results.keys()) == {"postfix", "nginx"}

    def test_report_to_json(self):
        host = self._session()
        report = host.scan_all(services=["postfix"])
        data = json.loads(report.to_json())
        assert data["host"] == "test.corp.com"
        assert "postfix" in data["services"]

    def test_report_issues(self):
        host = self._session()
        report = host.scan_all()
        issues = report.issues()
        # dns is inactive so should have issues
        assert "dns" in issues

    def test_report_summary_keys(self):
        host = self._session()
        report = host.scan_all()
        s = report.summary()
        assert "host" in s
        assert "ok" in s
        assert "services" in s
