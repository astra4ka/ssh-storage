import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="sshstore-test-") as state:
    with patch.dict(os.environ, SSHSTORE_DIR=state):
        spec = importlib.util.spec_from_file_location("sshstore", ROOT / "sshstore.py")
        app = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(app)


class NetworkTests(unittest.TestCase):
    def receive(self, value):
        sender, receiver = socket.socketpair()
        with sender, receiver:
            data = json.dumps(value).encode()
            sender.sendall(struct.pack(">I", len(data)) + data)
            return app.recv_raw(receiver)

    def test_objects_remain_compatible(self):
        self.assertEqual(self.receive({"t": "probe"}), {"t": "probe"})

    def test_non_object_messages_are_rejected(self):
        for value in ([], None, "probe", 1, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.receive(value)


class DiagnosticTests(unittest.TestCase):
    def test_process_name_is_literal_not_shell_code(self):
        name = 'worker$(printf INJECTED)`printf BACKTICK`"'
        command = app.diag_action_cmd("TERM", [(99999999, name)])
        result = subprocess.run(["sh", "-c", command], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(name, result.stdout)

    def test_invalid_actions_are_rejected(self):
        for kind, items in (("HUP", [(42, "worker")]), ("KILL", [(0, "worker")]),
                            ("TERM", [(1, "init")]), ("KILL", [(-1, "worker")])):
            with self.subTest(kind=kind, items=items), self.assertRaises(ValueError):
                app.diag_action_cmd(kind, items)


class SigningTests(unittest.TestCase):
    blob = app.ecdsa_blob(1, 2)

    def request(self, user=b"alice", service=b"ssh-connection", key=None, method=b"publickey", hostkey=None):
        return (app.sstr(b"session-id") + b"\x32" + app.sstr(user) + app.sstr(service)
                + app.sstr(method) + b"\x01" + app.sstr(b"ecdsa-sha2-nistp256")
                + app.sstr(self.blob if key is None else key)
                + (app.sstr(hostkey) if hostkey is not None else b""))

    def test_ssh_login_request_is_accepted(self):
        self.assertTrue(app.valid_sign_request(self.request(), "alice", self.blob))

    def test_openssh_hostbound_login_is_accepted_without_disabling_extension(self):
        data = self.request(method=b"publickey-hostbound-v00@openssh.com", hostkey=b"server-host-key")
        self.assertTrue(app.valid_sign_request(data, "alice", self.blob))
        self.assertFalse(app.valid_sign_request(data[:-1], "alice", self.blob))
        self.assertFalse(app.valid_sign_request(data + b"extra", "alice", self.blob))

    def test_other_users_keys_and_arbitrary_data_are_rejected(self):
        for data in (b"arbitrary document", self.request(user=b"root"),
                     self.request(service=b"other"), self.request(key=b"other-key"),
                     self.request() + b"extra", self.request()[:-1]):
            with self.subTest(data=data):
                self.assertFalse(app.valid_sign_request(data, "alice", self.blob))

    def test_truncated_ssh_strings_are_rejected(self):
        for data in (b"", b"\0\0", struct.pack(">I", 99) + b"short"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                app.read_str(data, 0)

    def run_phone_session(self, messages, approve=True):
        phone = object.__new__(app.Phone)
        peer_key = app.pubkey(bytes(range(32)))
        phone.priv = bytes(range(32))
        phone.d = {"peers": {peer_key.hex(): {"name": "test"}},
                   "servers": [{"name": "test", "user": "alice", "host": "localhost", "port": 22}]}
        phone.ks = Mock(blob=self.blob)
        phone.ks.sign.return_value = b"signature"
        phone.log = Mock()
        channel = Mock()
        channel.recv.side_effect = [{"intent": "test"}] + messages + [ConnectionError()]
        with patch.object(app, "Chan", return_value=channel), patch.object(app, "yes", side_effect=[True, approve]), contextlib.redirect_stdout(io.StringIO()):
            phone.session(Mock(), {"id": peer_key.hex(), "e": peer_key.hex()})
        return phone.ks.sign.call_count, channel

    def test_phone_signs_only_after_server_approval(self):
        request = {"t": "sign", "data": self.request().hex()}
        self.assertEqual(self.run_phone_session([request])[0], 0)
        self.assertEqual(self.run_phone_session([{"t": "use", "i": 0}, request], approve=False)[0], 0)
        self.assertEqual(self.run_phone_session([{"t": "use", "i": 0}, request])[0], 1)

    def test_phone_rejects_negative_server_index(self):
        count, channel = self.run_phone_session([{"t": "use", "i": -1}, {"t": "sign", "data": self.request().hex()}])
        self.assertEqual(count, 0)
        self.assertEqual(channel.send.call_args.args[0], {"ok": False})


class KeyInstallationTests(unittest.TestCase):
    def test_member_key_replacement_revokes_previous_key_and_preserves_others(self):
        with tempfile.TemporaryDirectory(prefix="sshstore-test-") as directory:
            authorized = Path(directory) / "authorized_keys"
            authorized.write_text("ssh-ed25519 OLD ssh-storage-member:alice:20261023\nssh-ed25519 OTHER ssh-storage-member:bob:20261023\n")
            command = app.member_key_cmd("ssh-ed25519 NEW", "alice")
            result = subprocess.run(["sh", "-c", command], env={**os.environ, "f": str(authorized), "T": " ssh-storage-member:alice:"}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            text = authorized.read_text()
            self.assertNotIn("OLD", text)
            self.assertIn("OTHER", text)
            self.assertIn("NEW", text)

    def test_install_preserves_other_phones_and_recovery_key(self):
        with tempfile.TemporaryDirectory(prefix="sshstore-test-") as home:
            ssh = Path(home) / ".ssh"
            ssh.mkdir()
            authorized = ssh / "authorized_keys"
            authorized.write_text("ecdsa-sha2-nistp256 OTHER ssh-storage-phone\n")
            command = app.install_cmd("ecdsa-sha2-nistp256 NEW ssh-storage-phone:alice", "ssh-ed25519 REC ssh-storage-recovery")
            for _ in range(2):
                result = subprocess.run(["sh", "-c", command], env={**os.environ, "HOME": home}, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            lines = authorized.read_text().splitlines()
            self.assertEqual(len(lines), 3)
            self.assertIn("ecdsa-sha2-nistp256 OTHER ssh-storage-phone", lines)

    def test_recovery_does_not_remove_old_key_before_new_login_is_verified(self):
        pc = object.__new__(app.PC)
        pc.add_server = Mock(return_value=True)
        pc.phone_ssh = Mock(return_value=(255, None))
        channel = Mock()
        channel.call.return_value = {"line": "ecdsa-sha2-nistp256 NEW ssh-storage-phone"}
        read = subprocess.CompletedProcess([], 0, "ecdsa-sha2-nistp256 OLD ssh-storage-phone:alice\n", "")
        with patch.object(app.subprocess, "run", return_value=read), patch.object(app, "menu", return_value="1"), contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(pc.bind_recovery_phone(channel, {"host": "localhost", "user": "alice", "port": 22}, "/test/key"))
        self.assertEqual(pc.phone_ssh.call_count, 1)

    def test_recovery_removes_only_the_selected_old_phone_after_verification(self):
        pc = object.__new__(app.PC)
        pc.add_server = Mock(return_value=True)
        pc.phone_ssh = Mock(side_effect=[(0, ""), (0, "SSH-STORAGE-OK")])
        channel = Mock()
        channel.call.return_value = {"line": "ecdsa-sha2-nistp256 NEW ssh-storage-phone"}
        read = subprocess.CompletedProcess([], 0, "ecdsa-sha2-nistp256 OLD ssh-storage-phone:alice\n", "")
        with patch.object(app.subprocess, "run", return_value=read), patch.object(app, "menu", return_value="1"), contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(pc.bind_recovery_phone(channel, {"host": "localhost", "user": "alice", "port": 22}, "/test/key"))
        command = pc.phone_ssh.call_args.args[2]
        self.assertIn("OLD", command)
        self.assertNotIn("NEW", command)


class StateFileTests(unittest.TestCase):
    def test_startup_cleanup_preserves_state_inside_a_temporary_directory(self):
        with tempfile.TemporaryDirectory(prefix="sshstore-cleanup-") as base:
            state = Path(base) / "sshstore-state"
            state.mkdir()
            file = state / "pc.json"
            file.write_text('{"servers": []}')
            with patch.object(app, "RAM", None), patch.object(app, "HERE", str(state)), patch.object(app.tempfile, "gettempdir", return_value=base):
                app.cleanup_stale()
            self.assertTrue(file.exists())
            self.assertEqual(file.read_text(), '{"servers": []}')

    def test_save_ignores_predictable_temp_symlink_and_uses_private_permissions(self):
        with tempfile.TemporaryDirectory(prefix="sshstore-test-") as directory:
            state = Path(directory) / "pc.json"
            victim = Path(directory) / "unrelated"
            victim.write_text("keep me")
            Path(str(state) + ".tmp").symlink_to(victim)
            app.save_json(str(state), {"me": "private"})
            self.assertEqual(victim.read_text(), "keep me")
            self.assertEqual(state.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(state.read_text()), {"me": "private"})


class CompatibilityTests(unittest.TestCase):
    def test_nix_embeds_exactly_the_same_program(self):
        source = (ROOT / "sshstore.py").read_text()
        nix = (ROOT / "ssh-storage.nix").read_text()
        embedded = nix.split('script = pkgs.writeText "sshstore.py" \'\'\n', 1)[1].split("  '';\n", 1)[0]
        escaped = source.replace("''", "'''").replace("${", "''${")
        expected = "".join("    " + line if line.strip() else line for line in escaped.splitlines(keepends=True))
        self.assertEqual(embedded, expected)

    def test_pc_menu_starts_and_exits_with_isolated_state(self):
        with tempfile.TemporaryDirectory(prefix="sshstore-test-") as directory:
            result = subprocess.run([os.sys.executable, str(ROOT / "sshstore.py")], input="7\n",
                                    env={**os.environ, "SSHSTORE_DIR": directory, "NO_COLOR": "1"},
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((Path(directory) / "pc.json").exists())

    def test_recovery_private_key_is_accepted_by_openssh(self):
        with tempfile.TemporaryDirectory(prefix="sshstore-test-") as directory:
            key = Path(directory) / "key"
            seed = bytes(range(32))
            key.write_text(app.openssh_ed25519_private(seed, app.RECOVERY_TAG))
            key.chmod(0o600)
            result = subprocess.run(["ssh-keygen", "-y", "-f", str(key)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.split()[:2], app.recovery_line(seed).split()[:2])

    def test_encrypted_channel_round_trip_and_tamper_rejection(self):
        key = bytes(range(64))
        encrypted = app.seal_sym(key, b"message", b"c0")
        self.assertEqual(app.open_sym(key, encrypted, b"c0"), b"message")
        for data, aad in ((encrypted[:-1] + bytes([encrypted[-1] ^ 1]), b"c0"), (encrypted, b"c1")):
            with self.assertRaises(ValueError):
                app.open_sym(key, data, aad)


if __name__ == "__main__":
    unittest.main()
