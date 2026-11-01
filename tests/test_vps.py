import contextlib
import io
import itertools
import os
import shlex
import shutil
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from test_security import app


class SetupCommandsTests(unittest.TestCase):
    def test_installation_under_errexit_handles_empty_or_single_key_file(self):
        for content in ("", "ssh-ed25519 NEW old-label\n"):
            with self.subTest(content=content), tempfile.TemporaryDirectory(prefix="sshstore-install-") as home:
                folder = Path(home) / ".ssh"
                folder.mkdir()
                (folder / "authorized_keys").write_text(content)
                command = "set -e; " + app.install_cmd("ssh-ed25519 NEW phone", "ssh-ed25519 REC recovery")
                result = subprocess.run(["sh", "-c", command], env={**os.environ, "HOME": home}, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((folder / "authorized_keys").read_text().splitlines(),
                                 ["ssh-ed25519 NEW phone", "ssh-ed25519 REC recovery"])

    def test_root_wrapper_preserves_connection_even_when_sudo_clears_environment(self):
        with tempfile.TemporaryDirectory(prefix="sshstore-sudo-") as directory:
            for name, body in {"id": "echo 1000", "sudo": 'exec env -i PATH="$PATH" "$@"'}.items():
                path = Path(directory) / name
                path.write_text("#!/bin/sh\n" + body + "\n")
                path.chmod(0o755)
            command = app.vps_root('printf "%s" "$SSH_CONNECTION"')
            connection = "192.0.2.1 1234 192.0.2.2 22"
            result = subprocess.run(["sh", "-c", command],
                                    env={**os.environ, "PATH": directory + ":" + os.environ["PATH"], "SSH_CONNECTION": connection},
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, connection)

    def test_skipped_preparation_has_no_side_effect_commands(self):
        command = app.vps_prepare_cmd("alice")
        for unwanted in ("apt-get update", "adduser", "usermod", "passwd alice", "TERM=xterm", "authorized_keys"):
            self.assertNotIn(unwanted, command)
        self.assertEqual(subprocess.run(["sh", "-n", "-c", command]).returncode, 0)

    def test_root_does_not_need_a_new_password_or_sudo_membership(self):
        command = app.vps_prepare_cmd("root", admin=True)
        self.assertNotIn("passwd", command)
        self.assertNotIn("usermod", command)

    def test_preparation_contains_only_selected_steps(self):
        command = app.vps_prepare_cmd("alice", create=True, admin=True, term=True, update=True,
                                      install="echo INSTALL")
        for wanted in ("apt-get update", "adduser", "usermod -aG sudo alice", "passwd alice", "TERM=xterm", "echo INSTALL"):
            self.assertIn(wanted, command)
        self.assertLess(command.index("id alice"), command.index("apt-get update"))
        self.assertEqual(subprocess.run(["sh", "-n", "-c", command]).returncode, 0)

    def test_untrusted_login_and_transaction_id_are_rejected(self):
        for login in ("-root", "a;id", "a\nb", "root/../x"):
            with self.subTest(login=login), self.assertRaises(ValueError):
                app.vps_prepare_cmd(login)
        with self.assertRaises(ValueError):
            app.vps_ssh_cmd("../escape", "stage", 22, 4724)

    def test_all_ssh_option_combinations_have_valid_shell_syntax(self):
        for port, root, passwords, keys in itertools.product((22, 4724), (False, True), (False, True), (False, True)):
            for phase in ("stage", "finish", "commit"):
                command = app.vps_ssh_cmd("a" * 24, phase, 22, port, root=root, passwords=passwords, keys=keys)
                result = subprocess.run(["sh", "-n", "-c", command], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_configuration_preserves_unselected_settings(self):
        self.assertEqual(app.vps_settings(22, 4724, stage=True), "Port 22\nPort 4724\n")
        self.assertEqual(app.vps_settings(22, 22, root=True), "PermitRootLogin no\n")
        self.assertEqual(app.vps_settings(22, 22, passwords=True),
                         "PasswordAuthentication no\nKbdInteractiveAuthentication no\n")
        self.assertEqual(app.vps_settings(22, 22, keys=True), "PubkeyAuthentication yes\n")


class WizardTests(unittest.TestCase):
    source = {"name": "VPS", "host": "example.com", "user": "root", "port": 22, "id": "a1", "nick": "me"}

    def pc(self):
        pc = object.__new__(app.PC)
        pc.d = {"recovery": "recovery", "servers": [self.source.copy()]}
        pc.save = Mock()
        return pc

    def test_add_menu_distinguishes_connection_from_setup(self):
        pc = self.pc()
        pc.add, pc.new_vps = Mock(), Mock()
        for answer, selected in (("1", pc.add), ("2", pc.new_vps)):
            with patch.object(app, "menu", return_value=answer), contextlib.redirect_stdout(io.StringIO()):
                pc.add_menu()
            selected.assert_called_once_with()

    def test_every_setup_change_can_be_skipped(self):
        pc = self.pc()
        with patch.object(app, "menu", return_value="2"), contextlib.redirect_stdout(io.StringIO()):
            plan = pc.vps_plan(self.source)
        self.assertEqual(plan["user"], "root")
        self.assertEqual(plan["port"], 22)
        self.assertFalse(any(plan[k] for k in ("create", "admin", "update", "term", "keys", "root", "passwords")))

    def test_user_login_and_new_port_are_asked_and_separate_steps_selected(self):
        pc = self.pc()
        with patch.object(app, "menu", return_value="1"), patch.object(app, "ask", side_effect=["alice", "4724"]), contextlib.redirect_stdout(io.StringIO()):
            plan = pc.vps_plan(self.source)
        self.assertEqual((plan["user"], plan["port"]), ("alice", 4724))
        self.assertTrue(all(plan[k] for k in ("create", "admin", "update", "term", "keys", "root", "passwords")))

    def test_root_target_cannot_disable_root_login(self):
        pc = self.pc()
        # update, create, admin, term, keys, change port, root login, passwords
        with patch.object(app, "menu", side_effect=["2", "2", "2", "2", "2", "2", "1", "2"]), contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(pc.vps_plan(self.source))

    def test_deleting_old_connection_never_removes_server_keys(self):
        pc = self.pc()
        new = {**self.source, "user": "alice", "id": "b1"}
        channel = Mock()
        channel.call.side_effect = [{"servers": [self.source, new]}, {"ok": True}, {"servers": [new]}]
        with patch.object(app, "yes", return_value=True), contextlib.redirect_stdout(io.StringIO()):
            pc.vps_remove_old(channel, self.source, new)
        delete = channel.call.call_args_list[1].args[0]
        self.assertEqual(delete, {"t": "delete", "i": 0, "old": self.source})
        self.assertEqual(pc.d["servers"], [new])

    def test_same_connection_is_never_offered_for_deletion(self):
        pc = self.pc()
        with patch.object(app, "yes") as confirm:
            pc.vps_remove_old(Mock(), self.source, self.source)
        confirm.assert_not_called()

    def test_key_verification_disables_password_fallback_on_the_master_connection(self):
        pc = self.pc()
        channel = Mock()
        channel.call.side_effect = [{"servers": [self.source], "line": "ecdsa-sha2-nistp256 YWJj phone"}, {"ok": True}]
        agent = Mock(dir="/test/agent", path="/test/agent/socket")
        agent.pubfile.return_value = "/test/agent/public"
        resolved = subprocess.CompletedProcess([], 0, "hostname real.example.com\nidentityfile /test/other-private-key\n", "")
        with patch.object(app, "Agent", return_value=agent), patch.object(app.subprocess, "run", side_effect=[resolved, Mock(returncode=255), Mock()]) as run:
            rc, _ = pc.phone_ssh(channel, self.source, "true", key_only=True)
        self.assertEqual(rc, 255)
        master = run.call_args_list[1].args[0]
        self.assertNotIn("BatchMode=yes", master)  # A new port must still allow explicit host-key approval.
        self.assertIn("PreferredAuthentications=publickey", master)
        self.assertIn("PasswordAuthentication=no", master)
        self.assertIn("KbdInteractiveAuthentication=no", master)
        self.assertEqual(master[master.index("-F") + 1], os.devnull)
        self.assertIn("hostname=real.example.com", master)
        self.assertNotIn("/test/other-private-key", master)


class SSHTransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sshstore-vps-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.ssh = self.base / "etc/ssh"
        (self.ssh / "sshd_config.d").mkdir(parents=True)
        (self.ssh / "sshd_config").write_text("Port 22\nInclude /etc/ssh/sshd_config.d/*.conf\n")
        (self.ssh / "sshd_config.d/50-cloud-init.conf").write_text("PasswordAuthentication yes\nPort 2222\n")
        self.home = self.base / "home/alice"
        self.home.mkdir(parents=True)
        self.bin = self.base / "bin"
        self.bin.mkdir()
        stubs = {
            "stat": 'case "$2" in %u) echo 0;; %a) echo 700;; esac',
            "getent": 'echo "alice:x:1000:1000::' + str(self.home) + ':/bin/sh"',
            "sshd": 'if [ "$1" = -T ]; then cat "' + str(self.ssh / 'sshd_config.d/00-ssh-storage.conf') + '"; fi',
            "systemctl": 'case "$1" in is-active) exit 1;; esac',
            "setsid": 'echo "$PPID" > "$B/watcher.pid"; touch "$B/ready"',  # Simulate startup, without a persistent process.
            "flock": ('exec ' + shlex.quote(shutil.which("flock")) + ' "$@"') if shutil.which("flock") else "exit 0",
            "sleep": 'exec ' + shlex.quote(shutil.which("sleep")) + ' 0.01',
            "apt-get": "exit 0",
        }
        for name, body in stubs.items():
            path = self.bin / name
            path.write_text("#!/bin/sh\n" + body + "\n")
            path.chmod(0o755)
        self.env = {**os.environ, "PATH": str(self.bin) + ":" + os.environ["PATH"], "SSH_CONNECTION": "192.0.2.1 1234 192.0.2.2 22"}
        self.token = "a" * 24

    def run_phase(self, phase, **options):
        command = app.vps_ssh_cmd(self.token, phase, 22, 4724, user="alice", **options)
        script = shlex.split(command)[-1]
        script = script.replace("PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH; export PATH; ", "")
        script = script.replace("/etc/ssh", str(self.ssh)).replace("/var/lib/ssh-storage", str(self.base / "state"))
        return subprocess.run(["sh", "-c", script], env=self.env, capture_output=True, text=True, timeout=10)

    def test_rollback_restores_exact_original_files_and_removes_new_dropin(self):
        originals = {p: p.read_bytes() for p in self.ssh.rglob("*") if p.is_file()}
        result = self.run_phase("stage", keys=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Port 4724", (self.ssh / "sshd_config.d/00-ssh-storage.conf").read_text())
        rollback = self.base / f"state/vps-{self.token}/rollback.sh"
        result = subprocess.run(["sh", str(rollback)], env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({p: p.read_bytes() for p in self.ssh.rglob("*") if p.is_file()}, originals)

    def test_second_setup_does_not_overwrite_pending_backup(self):
        result = self.run_phase("stage")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        original_backup = (self.base / f"state/vps-{self.token}/main").read_bytes()
        self.token = "b" * 24
        result = self.run_phase("stage")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.base / f"state/vps-{self.token}").exists())
        self.assertEqual((self.base / ("state/vps-" + "a" * 24) / "main").read_bytes(), original_backup)

    def test_failed_socket_restart_does_not_claim_configured_or_completed_rollback(self):
        (self.bin / "systemctl").write_text('#!/bin/sh\ncase "$1" in is-active) exit 0;; daemon-reload) exit 0;; restart) exit 1;; esac\n')
        result = self.run_phase("stage")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("SSH-STORAGE-CONFIGURED", result.stdout)
        self.assertTrue((self.base / "state/vps-active").exists())
        self.assertNotEqual((self.base / f"state/vps-{self.token}/status").read_text().strip(), "rolled-back")

    def test_failed_watcher_start_does_not_change_ssh_configuration(self):
        originals = {p: p.read_bytes() for p in self.ssh.rglob("*") if p.is_file()}
        (self.bin / "setsid").write_text("#!/bin/sh\nexit 1\n")
        result = self.run_phase("stage")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual({p: p.read_bytes() for p in self.ssh.rglob("*") if p.is_file()}, originals)
        self.assertFalse((self.base / "state/vps-active").exists())

    def wait_for_status(self, expected):
        path = self.base / f"state/vps-{self.token}/status"
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if path.read_text().strip() == expected: return
            time.sleep(0.02)
        self.fail("Watcher status: " + path.read_text())

    def test_independent_watcher_rolls_back_after_parent_connection_exits(self):
        originals = {p: p.read_bytes() for p in self.ssh.rglob("*") if p.is_file()}
        (self.bin / "setsid").write_text('#!/bin/sh\nexec "$@"\n')
        result = self.run_phase("stage", keys=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.wait_for_status("rolled-back")
        self.assertEqual({p: p.read_bytes() for p in self.ssh.rglob("*") if p.is_file()}, originals)

    def test_unprivileged_new_login_marker_cancels_rollback_after_finish(self):
        (self.bin / "setsid").write_text('#!/bin/sh\nexec "$@"\n')
        for phase in ("stage", "finish"):
            result = self.run_phase(phase, keys=True, root=True, passwords=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        command = app.vps_ssh_cmd(self.token, "commit", 22, 4724, user="alice")
        result = subprocess.run(["sh", "-c", command], env={**self.env, "HOME": str(self.home)}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.wait_for_status("committed")
        self.assertFalse((self.base / "state/vps-active").exists())
        config = (self.ssh / "sshd_config.d/00-ssh-storage.conf").read_text()
        self.assertIn("PermitRootLogin no", config)
        self.assertNotIn("Port 22\n", config)


class SetupFlowTests(unittest.TestCase):
    def setUp(self):
        self.source = {"name": "test", "host": "example.com", "port": 22, "user": "root", "id": "a1", "nick": "me"}
        self.target = {**self.source, "user": "alice", "port": 4724, "id": "b1"}
        self.servers = [self.source.copy()]
        self.events = []
        self.pc = object.__new__(app.PC)
        self.pc.d = {"servers": self.servers, "recovery": "recovery"}
        self.pc.save = Mock()
        self.plan = dict(user="alice", port=4724, update=True, create=True, admin=True, term=True, keys=True, root=True, passwords=True)
        self.channel = Mock()
        self.channel.call.side_effect = self.call

    def call(self, message):
        kind = message["t"]
        self.events.append(kind)
        if kind == "list": return {"servers": self.servers.copy()}
        if kind == "add": return {"ok": True, "line": "ecdsa-sha2-nistp256 PHONE phone", "recovery": "ssh-ed25519 REC recovery"}
        if kind == "added":
            s = message["server"].copy()
            self.servers = [x for x in self.servers if self.pc.skey(x) != self.pc.skey(s)] + [s]
            return {"ok": True}
        self.fail("Unexpected phone action: " + kind)

    def execute(self, verification):
        def remote(command):
            self.events.append("command:" + command[-1])
            return 0
        def verify(ch, server, command, **options):
            self.assertTrue(options.get("key_only"))
            self.events.append("verify")
            return next(verification)
        self.pc.phone_ssh = Mock(side_effect=verify)
        with patch.object(app.subprocess, "call", side_effect=remote), patch.object(app, "yes", return_value=False), contextlib.redirect_stdout(io.StringIO()):
            return self.pc.execute_vps(self.channel, self.source, self.target, self.plan, [], False)

    def test_success_preserves_old_record_and_saves_verified_new_connection(self):
        self.assertTrue(self.execute(iter([(0, ""), (0, "SSH-STORAGE-VERIFIED")])))
        self.assertIn(self.source, self.servers)
        self.assertIn(self.target, self.servers)
        first = self.events.index("verify")
        finish = next(i for i, event in enumerate(self.events) if event.startswith("command:") and 'touch "$B/final"' in event)
        self.assertLess(first, finish)

    def test_failed_first_verification_never_applies_restrictions_or_deletes_source(self):
        self.assertFalse(self.execute(iter([(255, "")])))
        self.assertIn(self.source, self.servers)
        self.assertIn({**self.target, "pending": True}, self.servers)
        self.assertFalse(any('touch "$B/final"' in event for event in self.events))

    def test_failed_final_verification_keeps_new_connection_unverified(self):
        self.assertFalse(self.execute(iter([(0, ""), (255, "")])))
        self.assertIn(self.source, self.servers)
        self.assertIn({**self.target, "pending": True}, self.servers)

    def test_failed_in_place_setup_preserves_original_connection_metadata(self):
        self.target = self.source.copy()
        self.plan.update(user="root", port=22, create=False, admin=False, root=False, passwords=False)
        self.assertFalse(self.execute(iter([(255, "")])))
        self.assertEqual(self.servers, [self.source])


if __name__ == "__main__":
    unittest.main()
