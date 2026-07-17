"""
Tests for the compliance audit package module.

Uses a fake CollectionContext so tests are hermetic — no real SSH,
no real filesystem reads, no package manager calls.
"""
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from adsyslib.compliance import (
    AuditPackage,
    ControlResult,
    compare_packages,
    load_package,
)
from adsyslib.compliance.collectors import (
    admin,
    auth,
    config_mgmt,
    entitlements,
    network,
    patching,
    storage,
)
from adsyslib.compliance.collectors import logging as logging_col
from adsyslib.compliance.context import CollectionContext
from adsyslib.compliance.controls import control_title, get_controls_for_frameworks
from adsyslib.core import CommandResult

# ---------------------------------------------------------------------------
# Fake context
# ---------------------------------------------------------------------------

class FakeContext(CollectionContext):
    """
    Programmable fake for unit testing collectors without touching disk or SSH.
    """

    def __init__(
        self,
        files: Optional[Dict[str, str]] = None,
        commands: Optional[Dict[str, str]] = None,
        dirs: Optional[List[str]] = None,
    ):
        self._files = files or {}
        self._commands = commands or {}
        self._dirs = set(dirs or [])

    def run(self, cmd, check: bool = False, **kwargs) -> CommandResult:
        if isinstance(cmd, list):
            key = " ".join(str(c) for c in cmd)
        else:
            key = str(cmd)

        # Try exact match first, then prefix match
        stdout = self._commands.get(key, "")
        exit_code = 0 if stdout or key in self._commands else 1
        return CommandResult(stdout=stdout, stderr="", exit_code=exit_code, command=key, duration=0.0)

    def read_text(self, path: str) -> Optional[str]:
        return self._files.get(path)

    def list_dir(self, path: str) -> List[str]:
        prefix = path.rstrip("/") + "/"
        names = [k[len(prefix):] for k in self._files if k.startswith(prefix) and "/" not in k[len(prefix):]]
        return names

    def is_dir(self, path: str) -> bool:
        return path in self._dirs

    def path_exists(self, path: str) -> bool:
        return path in self._files or path in self._dirs

    def path_stat(self, path: str) -> Optional[Dict[str, Any]]:
        if path not in self._files and path not in self._dirs:
            return None
        return {"permissions": "700", "owner_uid": 0, "mtime": 1700000000.0}


# ---------------------------------------------------------------------------
# controls.py
# ---------------------------------------------------------------------------

class TestControls:
    def test_known_control_title(self):
        assert control_title("AC-2") == "Account Management"

    def test_unknown_control_returns_id(self):
        assert control_title("XX-99") == "XX-99"

    def test_fedramp_controls_populated(self):
        ctrls = get_controls_for_frameworks(["fedramp"])
        assert "AC-2" in ctrls
        assert "IA-2" in ctrls
        assert len(ctrls) > 5

    def test_multi_framework_deduplicates(self):
        fedramp = get_controls_for_frameworks(["fedramp"])
        hipaa = get_controls_for_frameworks(["hipaa"])
        both = get_controls_for_frameworks(["fedramp", "hipaa"])
        assert len(both) == len(set(fedramp) | set(hipaa))

    def test_unknown_framework_returns_empty(self):
        assert get_controls_for_frameworks(["nonexistent"]) == []


# ---------------------------------------------------------------------------
# auth collector
# ---------------------------------------------------------------------------

SSHD_HARDENED = """\
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
UsePAM yes
Protocol 2
"""

LOGIN_DEFS_90 = """\
PASS_MAX_DAYS 90
PASS_MIN_DAYS 1
PASS_MIN_LEN 12
PASS_WARN_AGE 7
"""

PAM_GOOGLE = "auth required pam_google_authenticator.so\n"


class TestAuthCollector:
    def _ctx(self, sshd=SSHD_HARDENED, login_defs=LOGIN_DEFS_90, pam=""):
        return FakeContext(files={
            "/etc/ssh/sshd_config": sshd,
            "/etc/login.defs": login_defs,
            "/etc/pam.d/sshd": pam,
        })

    def test_root_login_no(self):
        data = auth.collect(ctx=self._ctx())
        assert data["sshd"]["permit_root_login"] == "no"

    def test_password_max_days(self):
        data = auth.collect(ctx=self._ctx())
        assert data["password_policy"]["pass_max_days"] == "90"

    def test_mfa_detected_via_pam(self):
        data = auth.collect(ctx=self._ctx(pam=PAM_GOOGLE))
        assert data["mfa"]["mfa_detected"] is True
        assert "pam_google_authenticator" in data["mfa"]["pam_modules"]

    def test_mfa_not_detected(self):
        data = auth.collect(ctx=self._ctx(pam="auth required pam_unix.so\n"))
        assert data["mfa"]["mfa_detected"] is False

    def test_missing_sshd_config(self):
        ctx = FakeContext(files={"/etc/login.defs": LOGIN_DEFS_90})
        data = auth.collect(ctx=ctx)
        assert data["sshd"]["permit_root_login"] == "unknown"

    def test_pubkey_auth_parsed(self):
        data = auth.collect(ctx=self._ctx())
        assert data["sshd"]["pubkey_authentication"] == "yes"


# ---------------------------------------------------------------------------
# admin collector
# ---------------------------------------------------------------------------

PASSWD_ONLY_ROOT = "root:x:0:0:root:/root:/bin/bash\nryan:x:1000:1000::/home/ryan:/bin/bash\n"
PASSWD_EXTRA_UID0 = "root:x:0:0:root:/root:/bin/bash\nbaduser:x:0:0::/home/bad:/bin/bash\n"
SUDOERS = "%sudo ALL=(ALL:ALL) ALL\nDefaults env_reset\n"
SSHD_HARDENING = "X11Forwarding no\nPermitEmptyPasswords no\n"


class TestAdminCollector:
    def _ctx(self, passwd=PASSWD_ONLY_ROOT, sshd=SSHD_HARDENING, sudoers=SUDOERS):
        return FakeContext(
            files={
                "/etc/ssh/sshd_config": sshd,
                "/etc/sudoers": sudoers,
            },
            commands={"getent passwd": passwd},
        )

    def test_only_root_uid0(self):
        data = admin.collect(ctx=self._ctx())
        unames = [a["username"] for a in data["privileged_accounts"]]
        assert unames == ["root"]

    def test_extra_uid0_detected(self):
        data = admin.collect(ctx=self._ctx(passwd=PASSWD_EXTRA_UID0))
        unames = [a["username"] for a in data["privileged_accounts"]]
        assert "baduser" in unames

    def test_x11forwarding_no(self):
        data = admin.collect(ctx=self._ctx())
        assert data["sshd_hardening"]["x11forwarding"] == "no"

    def test_permit_empty_passwords_no(self):
        data = admin.collect(ctx=self._ctx())
        assert data["sshd_hardening"]["permitemptypasswords"] == "no"

    def test_sudoers_parsed(self):
        data = admin.collect(ctx=self._ctx())
        rule_types = [r["type"] for r in data["sudoers"]]
        assert "grant" in rule_types
        assert "default" in rule_types


# ---------------------------------------------------------------------------
# entitlements collector
# ---------------------------------------------------------------------------

GROUP_TEXT = (
    "root:x:0:\n"
    "sudo:x:27:ryan,alice\n"
    "docker:x:998:ryan\n"
)


class TestEntitlementsCollector:
    def _ctx(self):
        return FakeContext(commands={"getent group": GROUP_TEXT})

    def test_groups_parsed(self):
        data = entitlements.collect(ctx=self._ctx())
        names = [g["name"] for g in data["local_groups"]]
        assert "sudo" in names
        assert "docker" in names

    def test_sudo_members(self):
        data = entitlements.collect(ctx=self._ctx())
        sudo = next(g for g in data["local_groups"] if g["name"] == "sudo")
        assert "ryan" in sudo["members"]
        assert "alice" in sudo["members"]

    def test_no_aws_by_default(self):
        data = entitlements.collect(ctx=self._ctx())
        assert "aws_iam" not in data

    def test_no_ad_by_default(self):
        data = entitlements.collect(ctx=self._ctx())
        assert "active_directory" not in data

    # --- Active Directory entitlements ---

    def test_ad_realm_joined(self):
        ctx = FakeContext(commands={
            "realm list": "corp.example.com\n  domain-name: corp.example.com\n",
            "getent group": GROUP_TEXT,
        })
        data = entitlements.collect(ctx=ctx, include_ad=True)
        ad = data["active_directory"]
        assert ad["joined"] is True
        assert ad["domain"] == "corp.example.com"
        assert ad["tool_used"] == "realm"

    def test_ad_not_joined_when_realm_fails(self):
        ctx = FakeContext()
        data = entitlements.collect(ctx=ctx, include_ad=True)
        ad = data["active_directory"]
        assert ad["joined"] is False
        assert ad["tool_used"] is None

    def test_ad_net_ads_fallback(self):
        ctx = FakeContext(commands={
            "net ads info": "Realm: CORP.EXAMPLE.COM\nLDAP server name: dc1.corp.example.com\n",
            "net ads group members Domain Admins": "CORP\\\\administrator\nCORP\\\\svcaccount\n",
            "net ads user": "administrator\nalice\nbob\n",
        })
        data = entitlements.collect(ctx=ctx, include_ad=True)
        ad = data["active_directory"]
        assert ad["joined"] is True
        assert ad["tool_used"] == "net_ads"
        assert len(ad["privileged_groups"]) == 1
        assert ad["privileged_groups"][0]["name"] == "Domain Admins"

    def test_ad_wbinfo_fallback(self):
        ctx = FakeContext(commands={
            "wbinfo --own-domain": "CORP\n",
            "wbinfo -u": "CORP\\\\alice\nCORP\\\\bob\n",
            "wbinfo --group-info Domain Admins": "Domain Admins:x:10512:CORP\\\\alice,CORP\\\\bob",
        })
        data = entitlements.collect(ctx=ctx, include_ad=True)
        ad = data["active_directory"]
        assert ad["joined"] is True
        assert ad["tool_used"] == "wbinfo"
        assert len(ad["domain_users_sample"]) == 2


# ---------------------------------------------------------------------------
# logging collector
# ---------------------------------------------------------------------------

AUDIT_RULES = "-a always,exit -F arch=b64 -S execve\n-a always,exit -F arch=b64 -S open\n"
RSYSLOG_CONF = "*.* @siem.example.com:514\n"


class TestLoggingCollector:
    def _ctx(self, auditd_active=True, rules=AUDIT_RULES, rsyslog=RSYSLOG_CONF):
        active_str = "active" if auditd_active else "inactive"
        return FakeContext(
            files={
                "/etc/audit/audit.rules": rules,
                "/etc/rsyslog.conf": rsyslog,
                "/var/log/audit": "",  # exists as a "dir"
            },
            commands={"systemctl is-active auditd": active_str},
            dirs={"/var/log/audit", "/etc/rsyslog.d"},
        )

    def test_auditd_active(self):
        data = logging_col.collect(ctx=self._ctx())
        assert data["auditd"]["active"] is True

    def test_auditd_inactive(self):
        data = logging_col.collect(ctx=self._ctx(auditd_active=False))
        assert data["auditd"]["active"] is False

    def test_rules_counted(self):
        data = logging_col.collect(ctx=self._ctx())
        assert data["auditd"]["rules_count"] == 2

    def test_log_forwarding_detected(self):
        data = logging_col.collect(ctx=self._ctx())
        assert data["log_forwarding"]["forwarding_configured"] is True

    def test_no_log_forwarding(self):
        data = logging_col.collect(ctx=self._ctx(rsyslog="# just comments\n"))
        assert data["log_forwarding"]["forwarding_configured"] is False


# ---------------------------------------------------------------------------
# network collector
# ---------------------------------------------------------------------------

SSHD_STRONG = """\
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,ecdh-sha2-nistp521
Protocol 2
"""

SSHD_WEAK = """\
Ciphers aes128-cbc,3des-cbc
MACs hmac-md5
KexAlgorithms diffie-hellman-group1-sha1
Protocol 1
"""


class TestNetworkCollector:
    def test_strong_config_no_weak(self):
        ctx = FakeContext(files={"/etc/ssh/sshd_config": SSHD_STRONG})
        data = network.collect(ctx=ctx)
        crypto = data["sshd_crypto"]
        assert crypto["weak_ciphers_found"] == []
        assert crypto["weak_macs_found"] == []
        assert crypto["weak_kex_found"] == []

    def test_weak_config_detected(self):
        ctx = FakeContext(files={"/etc/ssh/sshd_config": SSHD_WEAK})
        data = network.collect(ctx=ctx)
        crypto = data["sshd_crypto"]
        assert "3des-cbc" in crypto["weak_ciphers_found"]
        assert "hmac-md5" in crypto["weak_macs_found"]
        assert "diffie-hellman-group1-sha1" in crypto["weak_kex_found"]

    def test_protocol_version(self):
        ctx = FakeContext(files={"/etc/ssh/sshd_config": SSHD_STRONG})
        data = network.collect(ctx=ctx)
        assert data["sshd_crypto"]["protocol"] == "2"


# ---------------------------------------------------------------------------
# storage collector
# ---------------------------------------------------------------------------

LSBLK_LUKS = json.dumps({
    "blockdevices": [
        {"name": "sda", "type": "disk", "fstype": None, "mountpoint": None, "children": [
            {"name": "sda1", "type": "part", "fstype": "crypto_LUKS", "mountpoint": None, "children": [
                {"name": "dm-0", "type": "crypt", "fstype": "ext4", "mountpoint": "/"}
            ]}
        ]}
    ]
})

LSBLK_PLAIN = json.dumps({
    "blockdevices": [
        {"name": "sda", "type": "disk", "fstype": None, "mountpoint": None, "children": [
            {"name": "sda1", "type": "part", "fstype": "ext4", "mountpoint": "/"}
        ]}
    ]
})

CRYPTTAB = "luks-abc /dev/sda1 none luks\n"


class TestStorageCollector:
    def test_luks_detected(self):
        ctx = FakeContext(commands={"lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT --json": LSBLK_LUKS})
        data = storage.collect(ctx=ctx)
        assert data["encryption_detected"] is True
        assert len(data["luks_volumes"]) >= 1

    def test_plain_disk_not_encrypted(self):
        ctx = FakeContext(commands={"lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT --json": LSBLK_PLAIN})
        data = storage.collect(ctx=ctx)
        assert data["encryption_detected"] is False

    def test_crypttab_parsed(self):
        ctx = FakeContext(
            commands={"lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT --json": LSBLK_PLAIN},
            files={"/etc/crypttab": CRYPTTAB},
        )
        data = storage.collect(ctx=ctx)
        assert len(data["crypttab"]) == 1
        assert data["crypttab"][0]["name"] == "luks-abc"
        assert data["encryption_detected"] is True


# ---------------------------------------------------------------------------
# config_mgmt collector
# ---------------------------------------------------------------------------

ANSIBLE_LOG = """\
2024-01-15 10:00:00,000 PLAY [all] ****
2024-01-15 10:01:00,000 TASK [Gathering Facts]
2024-01-15 10:01:05,123 ok: [host1]
"""

TERRAFORM_STATE = json.dumps({
    "version": 4,
    "terraform_version": "1.5.0",
    "serial": 42,
    "lineage": "abc-123",
    "resources": [],
})

GIT_LOG_OUTPUT = "deadbeef|deploy@example.com|2024-01-15 10:00:00 +0000|Apply config changes"


class TestConfigMgmtCollector:
    # --- ansible evidence ---

    def test_ansible_log_present(self):
        ctx = FakeContext(files={"/var/log/ansible.log": ANSIBLE_LOG})
        data = config_mgmt.collect(ctx=ctx)
        assert data["ansible"]["log_exists"] is True

    def test_ansible_log_missing(self):
        ctx = FakeContext()
        data = config_mgmt.collect(ctx=ctx)
        assert data["ansible"]["log_exists"] is False
        assert data["ansible"]["last_run"] is None

    def test_ansible_last_run_parsed(self):
        ctx = FakeContext(
            files={"/var/log/ansible.log": ANSIBLE_LOG},
            commands={"tail -20 /var/log/ansible.log": ANSIBLE_LOG},
        )
        data = config_mgmt.collect(ctx=ctx)
        assert data["ansible"]["last_run"] is not None
        assert data["ansible"]["last_run"].startswith("2024-01-15")

    # --- terraform evidence ---

    def test_terraform_state_parsed(self):
        ctx = FakeContext(files={"terraform.tfstate": TERRAFORM_STATE})
        data = config_mgmt.collect(
            ctx=ctx,
            terraform_state_paths=["terraform.tfstate"],
            git_config_paths=[],
        )
        tf = data["terraform"]
        assert tf["serial"] == 42
        assert tf["terraform_version"] == "1.5.0"
        assert tf["lineage"] == "abc-123"

    def test_terraform_state_missing(self):
        ctx = FakeContext()
        data = config_mgmt.collect(
            ctx=ctx,
            terraform_state_paths=["terraform.tfstate"],
            git_config_paths=[],
        )
        assert data["terraform"] == {}

    def test_terraform_invalid_json_skipped(self):
        ctx = FakeContext(files={"terraform.tfstate": "not-json"})
        data = config_mgmt.collect(
            ctx=ctx,
            terraform_state_paths=["terraform.tfstate"],
            git_config_paths=[],
        )
        assert data["terraform"] == {}

    def test_terraform_first_valid_state_wins(self):
        ctx = FakeContext(
            files={
                "bad.tfstate": "not-json",
                "terraform.tfstate": TERRAFORM_STATE,
            }
        )
        data = config_mgmt.collect(
            ctx=ctx,
            terraform_state_paths=["bad.tfstate", "terraform.tfstate"],
            git_config_paths=[],
        )
        assert data["terraform"]["serial"] == 42

    # --- git evidence ---

    def test_git_repo_found(self):
        ctx = FakeContext(
            dirs={"/etc/ansible"},
            commands={"git -C /etc/ansible log -1 --format=%H|%ae|%ai|%s": GIT_LOG_OUTPUT},
        )
        data = config_mgmt.collect(
            ctx=ctx,
            terraform_state_paths=[],
            git_config_paths=["/etc/ansible"],
        )
        repos = data["git_repos"]
        assert len(repos) == 1
        assert repos[0]["path"] == "/etc/ansible"
        assert repos[0]["last_commit_sha"] == "deadbeef"
        assert repos[0]["author_email"] == "deploy@example.com"
        assert "Apply config" in repos[0]["message"]

    def test_git_path_not_a_dir_skipped(self):
        ctx = FakeContext()
        data = config_mgmt.collect(
            ctx=ctx,
            terraform_state_paths=[],
            git_config_paths=["/etc/ansible"],
        )
        assert data["git_repos"] == []

    def test_git_command_fails_skipped(self):
        ctx = FakeContext(dirs={"/etc/ansible"})
        # No matching command → exit_code=1, ok() returns False
        data = config_mgmt.collect(
            ctx=ctx,
            terraform_state_paths=[],
            git_config_paths=["/etc/ansible"],
        )
        assert data["git_repos"] == []

    def test_git_malformed_output_skipped(self):
        ctx = FakeContext(
            dirs={"/opt/config"},
            commands={"git -C /opt/config log -1 --format=%H|%ae|%ai|%s": "only|three|parts"},
        )
        data = config_mgmt.collect(
            ctx=ctx,
            terraform_state_paths=[],
            git_config_paths=["/opt/config"],
        )
        assert data["git_repos"] == []

    # --- top-level collect() ---

    def test_config_mgmt_detected_when_ansible_present(self):
        ctx = FakeContext(files={"/var/log/ansible.log": ANSIBLE_LOG})
        data = config_mgmt.collect(ctx=ctx, terraform_state_paths=[], git_config_paths=[])
        assert data["config_mgmt_detected"] is True

    def test_config_mgmt_detected_when_terraform_present(self):
        ctx = FakeContext(files={"terraform.tfstate": TERRAFORM_STATE})
        data = config_mgmt.collect(
            ctx=ctx,
            terraform_state_paths=["terraform.tfstate"],
            git_config_paths=[],
        )
        assert data["config_mgmt_detected"] is True

    def test_config_mgmt_detected_when_git_present(self):
        ctx = FakeContext(
            dirs={"/etc/ansible"},
            commands={"git -C /etc/ansible log -1 --format=%H|%ae|%ai|%s": GIT_LOG_OUTPUT},
        )
        data = config_mgmt.collect(
            ctx=ctx,
            terraform_state_paths=[],
            git_config_paths=["/etc/ansible"],
        )
        assert data["config_mgmt_detected"] is True

    def test_config_mgmt_not_detected_when_nothing_present(self):
        ctx = FakeContext()
        data = config_mgmt.collect(
            ctx=ctx,
            terraform_state_paths=["terraform.tfstate"],
            git_config_paths=["/etc/ansible"],
        )
        assert data["config_mgmt_detected"] is False


# ---------------------------------------------------------------------------
# patching collector
# ---------------------------------------------------------------------------

APT_OUTPUT_PENDING = (
    "Reading package lists...\n"
    "Inst openssl [1.1.1] (1.1.2 Ubuntu)\n"
    "Inst curl [7.80] (7.81 Ubuntu)\n"
    "2 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
)

APT_OUTPUT_CLEAN = "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"


class TestPatchingCollector:
    def _ctx_apt(self, apt_out, clamav_active=False):
        cmds = {
            "which apt-get": "/usr/bin/apt-get",
            "apt-get --simulate upgrade": apt_out,
        }
        if clamav_active:
            cmds["systemctl is-active clamav-daemon"] = "active"
        return FakeContext(commands=cmds)

    def test_pending_updates_detected(self):
        data = patching.collect(ctx=self._ctx_apt(APT_OUTPUT_PENDING))
        assert data["pending_updates"]["manager"] == "apt"
        assert data["pending_updates"]["pending_count"] == 2

    def test_no_pending_updates(self):
        data = patching.collect(ctx=self._ctx_apt(APT_OUTPUT_CLEAN))
        assert data["pending_updates"]["pending_count"] == 0

    def test_malware_protection_active(self):
        data = patching.collect(ctx=self._ctx_apt(APT_OUTPUT_CLEAN, clamav_active=True))
        assert data["malware_protection"]["protection_active"] is True
        assert "clamav-daemon" in data["malware_protection"]["active_services"]

    def test_no_malware_protection(self):
        data = patching.collect(ctx=self._ctx_apt(APT_OUTPUT_CLEAN))
        assert data["malware_protection"]["protection_active"] is False


# ---------------------------------------------------------------------------
# package.py — AuditPackage serialization
# ---------------------------------------------------------------------------

class TestAuditPackage:
    def _pkg(self):
        return AuditPackage(
            frameworks=["fedramp"],
            controls=[
                ControlResult(id="AC-2", title="Account Management", status="pass", evidence="ok"),
                ControlResult(id="IA-2", title="Identification", status="fail", evidence="no MFA"),
            ],
        )

    def test_to_json_roundtrip(self):
        pkg = self._pkg()
        data = json.loads(pkg.to_json())
        assert data["frameworks"] == ["fedramp"]
        assert len(data["controls"]) == 2

    def test_to_csv_has_header(self):
        csv_text = self._pkg().to_csv()
        assert "control_id" in csv_text.splitlines()[0]
        assert "AC-2" in csv_text

    def test_summary_counts(self):
        s = self._pkg().summary()
        assert s["control_counts"]["pass"] == 1
        assert s["control_counts"]["fail"] == 1
        assert s["total"] == 2

    def test_save_load_json(self, tmp_path):
        pkg = self._pkg()
        out = str(tmp_path / "pkg.json")
        pkg.save(out, fmt="json")
        loaded = load_package(out)
        assert loaded.frameworks == pkg.frameworks
        assert len(loaded.controls) == len(pkg.controls)
        assert loaded.controls[0].id == "AC-2"

    def test_save_yaml(self, tmp_path):
        pkg = self._pkg()
        out = str(tmp_path / "pkg.yaml")
        pkg.save(out, fmt="yaml")
        content = Path(out).read_text()
        assert "fedramp" in content

    def test_save_unsupported_format(self, tmp_path):
        with pytest.raises(ValueError, match="Unsupported format"):
            self._pkg().save(str(tmp_path / "x.xml"), fmt="xml")


# ---------------------------------------------------------------------------
# drift.py
# ---------------------------------------------------------------------------

class TestDrift:
    def _pkg(self, controls):
        return AuditPackage(frameworks=["fedramp"], controls=controls)

    def test_regression_detected(self):
        baseline = self._pkg([ControlResult("AC-2", "Account Mgmt", "pass", "ok")])
        current = self._pkg([ControlResult("AC-2", "Account Mgmt", "fail", "too many admins")])
        report = compare_packages(baseline, current)
        assert len(report.regressions) == 1
        assert report.regressions[0].control_id == "AC-2"

    def test_resolution_detected(self):
        baseline = self._pkg([ControlResult("IA-2", "MFA", "fail", "no mfa")])
        current = self._pkg([ControlResult("IA-2", "MFA", "pass", "duo active")])
        report = compare_packages(baseline, current)
        assert len(report.resolutions) == 1

    def test_unchanged_not_regressed(self):
        ctrl = ControlResult("SC-8", "TLS", "pass", "ok")
        baseline = self._pkg([ctrl])
        current = self._pkg([ctrl])
        report = compare_packages(baseline, current)
        assert report.regressions == []
        assert report.resolutions == []

    def test_new_controls_tracked(self):
        baseline = self._pkg([ControlResult("AC-2", "Account Mgmt", "pass")])
        current = self._pkg([
            ControlResult("AC-2", "Account Mgmt", "pass"),
            ControlResult("IA-5", "Auth Mgmt", "pass"),
        ])
        report = compare_packages(baseline, current)
        assert "IA-5" in report.new_controls

    def test_removed_controls_tracked(self):
        baseline = self._pkg([
            ControlResult("AC-2", "Account Mgmt", "pass"),
            ControlResult("IA-5", "Auth Mgmt", "pass"),
        ])
        current = self._pkg([ControlResult("AC-2", "Account Mgmt", "pass")])
        report = compare_packages(baseline, current)
        assert "IA-5" in report.removed_controls

    def test_regressions_sort_first(self):
        baseline = self._pkg([
            ControlResult("AC-2", "Account Mgmt", "pass"),
            ControlResult("IA-2", "MFA", "fail"),
        ])
        current = self._pkg([
            ControlResult("AC-2", "Account Mgmt", "fail"),  # regression
            ControlResult("IA-2", "MFA", "pass"),           # resolution
        ])
        report = compare_packages(baseline, current)
        # Regressions first
        assert report.control_drifts[0].regressed

    def test_save_load_json(self, tmp_path):
        baseline = self._pkg([ControlResult("AC-2", "Account Mgmt", "pass")])
        current = self._pkg([ControlResult("AC-2", "Account Mgmt", "fail")])
        report = compare_packages(baseline, current)
        out = str(tmp_path / "drift.json")
        report.save(out)
        data = json.loads(Path(out).read_text())
        assert data["control_drifts"][0]["control_id"] == "AC-2"


# ---------------------------------------------------------------------------
# builder.py — control evaluators via build_package with fake context
# ---------------------------------------------------------------------------

def _make_full_ctx():
    """Fake context representing a well-hardened system."""
    return FakeContext(
        files={
            "/etc/ssh/sshd_config": (
                "PermitRootLogin no\n"
                "PasswordAuthentication no\n"
                "PubkeyAuthentication yes\n"
                "UsePAM yes\n"
                "X11Forwarding no\n"
                "PermitEmptyPasswords no\n"
                "Ciphers chacha20-poly1305@openssh.com\n"
                "MACs hmac-sha2-512\n"
                "KexAlgorithms curve25519-sha256\n"
                "Protocol 2\n"
            ),
            "/etc/login.defs": "PASS_MAX_DAYS 90\n",
            "/etc/pam.d/sshd": "auth required pam_google_authenticator.so\n",
            "/etc/sudoers": "%sudo ALL=(ALL:ALL) ALL\n",
            "/etc/audit/audit.rules": "-a always,exit -F arch=b64 -S execve\n",
            "/etc/rsyslog.conf": "*.* @siem.corp:514\n",
            "/etc/crypttab": "luks-vol /dev/sda1 none luks\n",
        },
        commands={
            "getent passwd": "root:x:0:0:root:/root:/bin/bash\nryan:x:1000:1000::/home/ryan:/bin/bash\n",
            "getent group": "root:x:0:\nsudo:x:27:ryan\n",
            "systemctl is-active auditd": "active",
            "lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT --json": LSBLK_LUKS,
            "which apt-get": "/usr/bin/apt-get",
            "apt-get --simulate upgrade": "0 upgraded, 0 newly installed.\n",
        },
        dirs={"/etc/sudoers.d", "/etc/rsyslog.d", "/var/log/audit"},
    )


class TestBuilder:
    def test_fedramp_control_count(self):
        # Patch collectors to use our fake context
        from adsyslib.compliance import builder as b
        from adsyslib.compliance.controls import FRAMEWORK_CONTROLS
        ctx = _make_full_ctx()

        import adsyslib.compliance.collectors.admin as _admin
        import adsyslib.compliance.collectors.auth as _auth
        import adsyslib.compliance.collectors.config_mgmt as _cm
        import adsyslib.compliance.collectors.entitlements as _ent
        import adsyslib.compliance.collectors.logging as _log
        import adsyslib.compliance.collectors.network as _net
        import adsyslib.compliance.collectors.patching as _pat
        import adsyslib.compliance.collectors.storage as _stor

        # Call build_package passing ctx through each collector manually
        # rather than monkey-patching — verify the evaluator logic directly
        auth_d = _auth.collect(ctx=ctx)
        admin_d = _admin.collect(ctx=ctx)
        cm_d = _cm.collect(ctx=ctx)
        ent_d = _ent.collect(ctx=ctx)
        log_d = _log.collect(ctx=ctx)
        net_d = _net.collect(ctx=ctx)
        stor_d = _stor.collect(ctx=ctx)
        pat_d = _pat.collect(ctx=ctx)

        all_controls = (
            b._auth_controls(auth_d)
            + b._cm_controls(cm_d)
            + b._admin_controls(admin_d)
            + b._entitlement_controls(ent_d)
            + b._logging_controls(log_d)
            + b._network_controls(net_d)
            + b._storage_controls(stor_d)
            + b._patching_controls(pat_d)
        )

        ids = {c.id for c in all_controls}
        fedramp_ids = set(FRAMEWORK_CONTROLS["fedramp"])
        # Every FedRAMP control should have an evaluator
        assert fedramp_ids <= ids, f"Missing evaluators: {fedramp_ids - ids}"

    def test_ac17_root_login_no_passes(self):
        from adsyslib.compliance import builder as b
        data = auth.collect(ctx=_make_full_ctx())
        results = b._auth_controls(data)
        ac17 = next(c for c in results if c.id == "AC-17")
        assert ac17.status == "pass"

    def test_ia2_mfa_passes(self):
        from adsyslib.compliance import builder as b
        data = auth.collect(ctx=_make_full_ctx())
        results = b._auth_controls(data)
        ia2 = next(c for c in results if c.id == "IA-2")
        assert ia2.status == "pass"

    def test_ia8_pubkey_passes(self):
        from adsyslib.compliance import builder as b
        data = auth.collect(ctx=_make_full_ctx())
        results = b._auth_controls(data)
        ia8 = next(c for c in results if c.id == "IA-8")
        assert ia8.status == "pass"

    def test_ia8_password_only_fails(self):
        from adsyslib.compliance import builder as b
        ctx = FakeContext(files={
            "/etc/ssh/sshd_config": "PasswordAuthentication yes\nPubkeyAuthentication no\n",
            "/etc/login.defs": "PASS_MAX_DAYS 90\n",
        })
        data = auth.collect(ctx=ctx)
        results = b._auth_controls(data)
        ia8 = next(c for c in results if c.id == "IA-8")
        assert ia8.status == "fail"

    def test_ac6_extra_uid0_fails(self):
        from adsyslib.compliance import builder as b
        ctx = FakeContext(commands={"getent passwd": PASSWD_EXTRA_UID0})
        data = admin.collect(ctx=ctx)
        results = b._admin_controls(data)
        ac6 = next(c for c in results if c.id == "AC-6")
        assert ac6.status == "fail"

    def test_sc28_encryption_passes(self):
        from adsyslib.compliance import builder as b
        ctx = FakeContext(commands={"lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT --json": LSBLK_LUKS})
        data = storage.collect(ctx=ctx)
        results = b._storage_controls(data)
        sc28 = next(c for c in results if c.id == "SC-28")
        assert sc28.status == "pass"

    def test_si2_pending_updates_fails(self):
        from adsyslib.compliance import builder as b
        ctx = FakeContext(commands={
            "which apt-get": "/usr/bin/apt-get",
            "apt-get --simulate upgrade": APT_OUTPUT_PENDING,
        })
        data = patching.collect(ctx=ctx)
        results = b._patching_controls(data)
        si2 = next(c for c in results if c.id == "SI-2")
        assert si2.status == "fail"


# ---------------------------------------------------------------------------
# ERS schema validation
# ---------------------------------------------------------------------------

class TestAuditPackageValidation:
    def _valid_package(self):
        return AuditPackage(
            frameworks=["fedramp"],
            controls=[
                ControlResult(
                    id="IA-2",
                    title="Identification and Authentication",
                    status="pass",
                    framework="nist-800-53",
                )
            ],
        )

    def test_valid_package_has_no_errors(self):
        errors = self._valid_package().validate()
        assert errors == []

    def test_empty_package_id_flagged(self):
        pkg = self._valid_package()
        pkg.package_id = ""
        errors = pkg.validate()
        assert any("package_id" in e for e in errors)

    def test_empty_hostname_flagged(self):
        pkg = self._valid_package()
        pkg.hostname = ""
        errors = pkg.validate()
        assert any("hostname" in e for e in errors)

    def test_empty_generated_at_flagged(self):
        pkg = self._valid_package()
        pkg.generated_at = ""
        errors = pkg.validate()
        assert any("generated_at" in e for e in errors)

    def test_empty_frameworks_flagged(self):
        pkg = self._valid_package()
        pkg.frameworks = []
        errors = pkg.validate()
        assert any("frameworks" in e for e in errors)

    def test_unknown_framework_flagged(self):
        pkg = self._valid_package()
        pkg.frameworks = ["fedramp", "pci-dss"]
        errors = pkg.validate()
        assert any("pci-dss" in e for e in errors)

    def test_empty_controls_flagged(self):
        pkg = self._valid_package()
        pkg.controls = []
        errors = pkg.validate()
        assert any("controls" in e for e in errors)

    def test_invalid_control_status_flagged(self):
        pkg = self._valid_package()
        pkg.controls[0].status = "unknown"
        errors = pkg.validate()
        assert any("invalid status" in e for e in errors)

    def test_empty_control_framework_flagged(self):
        pkg = self._valid_package()
        pkg.controls[0].framework = ""
        errors = pkg.validate()
        assert any("framework is empty" in e for e in errors)

    def test_multiple_errors_reported(self):
        pkg = self._valid_package()
        pkg.hostname = ""
        pkg.frameworks = []
        errors = pkg.validate()
        assert len(errors) >= 2

    def test_all_known_frameworks_accepted(self):
        for fw in ("fedramp", "hipaa", "sox", "glba"):
            pkg = AuditPackage(
                frameworks=[fw],
                controls=[
                    ControlResult(id="AC-2", title="Account Management", status="pass", framework="nist-800-53")
                ],
            )
            assert pkg.validate() == [], f"Framework {fw!r} should be valid"
