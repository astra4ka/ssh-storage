import contextlib
import copy
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from test_security import app, ROOT


class ProfileStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sshstore-profiles-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.old = {"me": "01" * 32, "phone": {"fp": "team"}, "recovery": "",
                    "servers": [{"name": "team-server"}], "rights": {"team": "viewer"}}
        self.original = json.dumps(self.old).encode()
        (self.root / "pc.json").write_bytes(self.original)

    def test_default_uses_existing_directory_without_migration(self):
        self.assertEqual(app.profile_directory(str(self.root), "default"), str(self.root))
        self.assertEqual((self.root / "pc.json").read_bytes(), self.original)
        self.assertFalse((self.root / "profiles").exists())

    def test_unknown_profile_cannot_escape_root_or_create_files(self):
        for name in ("../outside", "/tmp/outside", "", "team", "personal/../default"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                app.profile_directory(str(self.root), name)
        self.assertFalse((self.root / "profiles").exists())

    def test_opening_missing_personal_profile_never_creates_one(self):
        with self.assertRaises((ValueError, OSError)):
            app.profile_directory(str(self.root), "personal")
        self.assertFalse((self.root / "profiles").exists())

    def test_personal_creation_is_empty_private_and_does_not_copy_old_identity(self):
        directory = Path(app.create_personal_profile(str(self.root), phone=False))
        state = app.load_profile_state(str(directory / "pc.json"))
        self.assertNotEqual(state["me"], self.old["me"])
        self.assertEqual(state["servers"], [])
        self.assertIsNone(state["phone"])
        self.assertIsNone(state["recovery"])
        self.assertNotIn("rights", state)
        self.assertEqual((directory.stat().st_mode & 0o777), 0o700)
        self.assertEqual(((directory / "pc.json").stat().st_mode & 0o777), 0o600)
        self.assertEqual((self.root / "pc.json").read_bytes(), self.original)

    def test_existing_personal_state_is_never_replaced(self):
        directory = Path(app.create_personal_profile(str(self.root), phone=False))
        original = (directory / "pc.json").read_bytes()
        app.create_personal_profile(str(self.root), phone=False)
        self.assertEqual((directory / "pc.json").read_bytes(), original)

    def test_phone_alias_and_pairing_key_are_separate_and_no_hardware_is_touched(self):
        with patch.object(app, "Keystore") as hardware:
            directory = Path(app.create_personal_profile(str(self.root), phone=True))
        state = app.load_profile_state(str(directory / "phone.json"))
        self.assertTrue(state["alias"].startswith("ssh-storage-personal-"))
        self.assertNotEqual(state["priv"], self.old["me"])
        self.assertFalse(state["key_initialized"])
        self.assertEqual(state["peers"], {})
        self.assertEqual(state["servers"], [])
        hardware.assert_not_called()

    def test_symlinked_profile_root_or_directory_is_rejected(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / "profiles").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            app.create_personal_profile(str(self.root), phone=False)
        (self.root / "profiles").unlink()
        (self.root / "profiles").mkdir(mode=0o700)
        (self.root / "profiles/personal").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            app.profile_directory(str(self.root), "personal")
        self.assertEqual(list(outside.iterdir()), [])

    def test_missing_corrupt_or_symlinked_state_is_not_reinitialized(self):
        directory = Path(app.create_personal_profile(str(self.root), phone=False))
        file = directory / "pc.json"
        for value in ("{", "[]", '{}', '{"profile":"default"}'):
            file.write_text(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                app.create_personal_profile(str(self.root), phone=False)
            self.assertEqual(file.read_text(), value)
        file.unlink()
        with self.assertRaises((ValueError, OSError)):
            app.create_personal_profile(str(self.root), phone=False)
        file.symlink_to(self.root / "pc.json")
        with self.assertRaises(ValueError):
            app.load_profile_state(str(file))
        self.assertEqual((self.root / "pc.json").read_bytes(), self.original)

    def test_failed_state_creation_does_not_touch_default_or_leave_unowned_state(self):
        with patch.object(app, "save_json", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                app.create_personal_profile(str(self.root), phone=False)
        self.assertEqual((self.root / "pc.json").read_bytes(), self.original)
        self.assertFalse((self.root / "profiles/personal").exists())

    def test_launch_selected_profile_does_not_read_or_rewrite_default(self):
        app.create_personal_profile(str(self.root), phone=False)
        result = subprocess.run([sys.executable, str(ROOT / "sshstore.py"), "--profile", "personal"],
                                input="7\n", text=True, capture_output=True, timeout=10,
                                env={**os.environ, "SSHSTORE_DIR": str(self.root), "NO_COLOR": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Personal", result.stdout)
        self.assertEqual((self.root / "pc.json").read_bytes(), self.original)

    def test_missing_selected_profile_fails_before_creating_default_state(self):
        result = subprocess.run([sys.executable, str(ROOT / "sshstore.py"), "--profile", "personal"],
                                input="7\n", text=True, capture_output=True, timeout=10,
                                env={**os.environ, "SSHSTORE_DIR": str(self.root)})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "profiles").exists())
        self.assertEqual((self.root / "pc.json").read_bytes(), self.original)

    def test_personal_instance_lock_refuses_concurrent_use_and_releases(self):
        directory = app.create_personal_profile(str(self.root), phone=False)
        fd = app.lock_profile(directory)
        try:
            with self.assertRaises(OSError):
                app.lock_profile(directory)
        finally:
            os.close(fd)
        fd = app.lock_profile(directory)
        os.close(fd)


class ProfileKeyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sshstore-profile-key-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        directory = app.create_personal_profile(str(self.root), phone=True)
        self.file = os.path.join(directory, "phone.json")
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(app, "PROFILE", "personal"))
        self.stack.enter_context(patch.object(app, "PHONE", self.file))
        self.stack.enter_context(patch.object(app, "PHONE_BIN", str(self.root / "launcher")))
        self.stack.enter_context(patch.object(app, "strip_bashrc"))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.ks = Mock()
        self.ks.line.return_value = "ecdsa-sha2-nistp256 PUBLIC ssh-storage-phone"

    def test_new_key_uses_isolated_alias_and_records_public_identity(self):
        phone = app.Phone(self.ks)
        phone.ensure_key()
        self.assertTrue(self.ks.ALIAS.startswith("ssh-storage-personal-"))
        self.ks.ensure.assert_called_once_with(create=True)
        saved = app.load_profile_state(self.file)
        self.assertTrue(saved["key_initialized"])
        self.assertEqual(saved["ssh_public"], self.ks.line.return_value)

    def test_existing_key_is_never_regenerated_and_mismatch_is_rejected(self):
        phone = app.Phone(self.ks)
        phone.ensure_key()
        self.ks.reset_mock()
        again = app.Phone(self.ks)
        again.ensure_key()
        self.ks.ensure.assert_called_once_with(create=False)
        self.ks.line.return_value = "different key"
        with self.assertRaises(RuntimeError):
            again.ensure_key()

    def test_corrupt_alias_cannot_open_default_key(self):
        state = json.loads(Path(self.file).read_text())
        state["alias"] = "ssh-storage"
        app.save_json(self.file, state)
        with self.assertRaises(ValueError):
            app.Phone(self.ks)
        self.ks.ensure.assert_not_called()

    def test_false_initialization_flag_on_used_identity_cannot_replace_key(self):
        phone = app.Phone(self.ks)
        phone.ensure_key()
        for extra in ({"ssh_public": self.ks.line.return_value}, {"peers": {"01" * 32: {"name": "paired"}}},
                      {"servers": [{"name": "existing"}]}, {"recovery": app.recovery_line(bytes(range(32)))}):
            state = json.loads(Path(self.file).read_text())
            state.pop("ssh_public", None)
            state.update(key_initialized=False, peers={}, servers=[], recovery=None)
            state.update(extra)
            app.save_json(self.file, state)
            before = Path(self.file).read_bytes()
            self.ks.reset_mock()
            with self.subTest(extra=list(extra)), self.assertRaises(ValueError):
                app.Phone(self.ks)
            self.ks.ensure.assert_not_called()
            self.assertEqual(Path(self.file).read_bytes(), before)

    def test_missing_key_is_not_implicitly_recreated(self):
        store = app.Keystore()
        store.ALIAS = "missing"
        with patch.object(store, "_list", return_value={}), patch.object(app.subprocess, "run") as run:
            with self.assertRaises(RuntimeError):
                store.ensure(create=False)
        run.assert_not_called()

    def test_personal_recovery_has_no_ambiguous_team_question(self):
        pc = object.__new__(app.PC)
        pc.d = {"recovery": None}
        pc.save, pc.new_recovery = Mock(), Mock(return_value="public-recovery-key")
        with patch.object(app, "yes") as question:
            pc.ensure_recovery()
        question.assert_not_called()
        pc.new_recovery.assert_called_once_with()
        self.assertEqual(pc.d["recovery"], "public-recovery-key")

    def test_phone_reset_preserves_personal_ssh_key_and_default_state(self):
        default_file = self.root / "phone.json"
        default_file.write_text('{"untouched":"team"}')
        phone = app.Phone(self.ks)
        phone.ensure_key()
        before = app.load_profile_state(self.file)
        with patch.object(app, "menu", return_value="1"), patch.object(app, "confirm_wipe", return_value=True), \
                patch.object(app.subprocess, "run") as run, patch.object(app, "STATE_ROOT", str(self.root)):
            self.assertTrue(app.phone_wipe(self.ks))
        after = app.load_profile_state(self.file)
        self.assertEqual(after["alias"], before["alias"])
        self.assertEqual(after["ssh_public"], before["ssh_public"])
        self.assertEqual(after["peers"], {})
        self.assertEqual(after["servers"], [])
        self.assertNotEqual(after["priv"], before["priv"])
        self.assertEqual(default_file.read_text(), '{"untouched":"team"}')
        run.assert_not_called()

    def test_full_uninstall_is_blocked_when_personal_profile_exists(self):
        before = Path(self.file).read_bytes()
        with patch.object(app, "menu", return_value="2"), patch.object(app, "STATE_ROOT", str(self.root)), \
                patch.object(app, "pause"), patch.object(app, "confirm_wipe", return_value=True), \
                patch.object(app.subprocess, "run") as run:
            self.assertFalse(app.phone_wipe(self.ks))
        self.assertEqual(Path(self.file).read_bytes(), before)
        run.assert_not_called()

    def test_personal_rekey_alias_cannot_reference_existing_key_namespace(self):
        phone = app.Phone(self.ks)
        alias = phone.new_key_alias()
        self.assertTrue(alias.startswith("ssh-storage-personal-" + phone.d["profile_id"] + "-"))
        self.assertNotEqual(alias, phone.d["alias"])


class ProfilePCWipeTests(unittest.TestCase):
    def test_pc_reset_keeps_schema_and_default_files(self):
        with tempfile.TemporaryDirectory(prefix="sshstore-profile-wipe-") as root:
            default_file = Path(root) / "pc.json"
            default_file.write_text('{"untouched":"team"}')
            directory = app.create_personal_profile(root, phone=False)
            file = os.path.join(directory, "pc.json")
            before = app.load_profile_state(file)
            with patch.object(app, "PROFILE", "personal"), patch.object(app, "PC_STATE", file), \
                    patch.object(app, "confirm_wipe", return_value=True), contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(app.pc_wipe())
            after = app.load_profile_state(file)
            self.assertNotEqual(after["me"], before["me"])
            self.assertEqual(after["servers"], [])
            self.assertIsNone(after["phone"])
            self.assertEqual(default_file.read_text(), '{"untouched":"team"}')


class ProfileMenuTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sshstore-profile-menu-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(app, "STATE_ROOT", str(self.root)))
        self.stack.enter_context(patch.object(app, "PROFILE", "default"))
        self.stack.enter_context(patch.object(app, "IS_PHONE", False))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(patch.object(app, "pause"))
        self.execute = self.stack.enter_context(patch.object(app.os, "execv"))

    def test_cancelled_creation_has_no_state_or_key_side_effects(self):
        with patch.object(app, "menu", return_value="1"), patch.object(app, "yes", return_value=False):
            app.profiles_menu()
        self.assertEqual(list(self.root.iterdir()), [])
        self.execute.assert_not_called()

    def test_confirmed_personal_creation_switches_only_to_that_profile(self):
        with patch.object(app, "menu", return_value="1"), patch.object(app, "yes", return_value=True):
            app.profiles_menu()
        self.assertTrue((self.root / "profiles/personal/pc.json").is_file())
        self.assertFalse((self.root / "pc.json").exists())
        self.assertIn("personal", self.execute.call_args.args[1])

    def test_switching_to_default_does_not_change_personal_files(self):
        directory = Path(app.create_personal_profile(str(self.root), phone=False))
        before = (directory / "pc.json").read_bytes()
        with patch.object(app, "PROFILE", "personal"), patch.object(app, "menu", return_value="2"):
            app.profiles_menu()
        self.assertEqual((directory / "pc.json").read_bytes(), before)
        self.assertIn("default", self.execute.call_args.args[1])

    def test_restart_arguments_preserve_phone_profile_but_not_stale_install_flag(self):
        with patch.object(app, "IS_PHONE", True), patch.object(app, "PROFILE", "personal"):
            args = app.program_args()
            self.assertIn("--phone", args)
            self.assertEqual(app.requested_profile(args), "personal")
            self.assertNotIn("--install", args)
            self.assertIn("--install", app.program_args(install=True))

    def test_ambiguous_or_unknown_profile_argument_is_rejected(self):
        for args in (["--profile"], ["--profile", "team"], ["--profile", "default", "--profile=personal"]):
            with self.subTest(args=args), self.assertRaises(ValueError):
                app.requested_profile(args)

    def test_wrong_profile_pairing_is_rejected_before_approval_or_key_access(self):
        phone = object.__new__(app.Phone)
        phone.ks, phone.d = Mock(), {"servers": [], "peers": {}, "recovery": None}
        before = copy.deepcopy(phone.d)
        with patch.object(app, "PROFILE", "personal"), patch.object(app, "yes") as approve:
            with self.assertRaises(ValueError):
                phone.pair(Mock(), {"profile": "default"})
        self.assertEqual(phone.d, before)
        approve.assert_not_called()
        phone.ks.line.assert_not_called()

    def test_wrong_profile_session_is_rejected_before_signing(self):
        phone = object.__new__(app.Phone)
        phone.ks = Mock()
        with patch.object(app, "PROFILE", "personal"):
            with self.assertRaises(ValueError):
                phone.session(Mock(), {"profile": "default"})
        phone.ks.sign.assert_not_called()

    def test_discovery_does_not_select_existing_phone_for_personal_pairing(self):
        old = {"name": "old", "fp": "old", "mode": "pair", "ip": "192.0.2.1"}
        with patch.object(app, "PROFILE", "personal"), patch.object(app, "discover", return_value=[old]), \
                patch("builtins.input", return_value=""):
            self.assertIsNone(app.find_phone(mode="pair"))


class ProfilePairingTests(unittest.TestCase):
    def test_encrypted_personal_pairing_preserves_existing_credentials_and_peers(self):
        self.pair_personal(app.recovery_line(bytes(range(32))), succeeds=True)

    def test_personal_phone_refuses_missing_recovery_without_touching_existing_profile(self):
        self.pair_personal("", succeeds=False)

    def pair_personal(self, recovery, succeeds):
        with tempfile.TemporaryDirectory(prefix="sshstore-profile-pair-") as temporary:
            pc_root, phone_root = Path(temporary) / "pc", Path(temporary) / "phone"
            pc_root.mkdir(); phone_root.mkdir()
            old_pc = {"me": "01" * 32, "phone": {"fp": "team-phone"}, "recovery": "", "servers": []}
            old_phone = {"priv": "02" * 32, "peers": {"03" * 32: {"name": "team"}},
                         "servers": [{"name": "team"}], "recovery": "", "alias": "ssh-storage"}
            app.save_json(str(pc_root / "pc.json"), old_pc)
            app.save_json(str(phone_root / "phone.json"), old_phone)
            pc_before, phone_before = (pc_root / "pc.json").read_bytes(), (phone_root / "phone.json").read_bytes()
            pc_dir = app.create_personal_profile(str(pc_root), phone=False)
            phone_dir = app.create_personal_profile(str(phone_root), phone=True)
            client, server = socket.socketpair()
            server.settimeout(5)
            errors, codes = [], []
            sas = app.sas

            def capture_code(*parts):
                code = sas(*parts)
                codes.append(code)
                return code

            with patch.object(app, "PROFILE", "personal"), \
                    patch.object(app, "PC_STATE", os.path.join(pc_dir, "pc.json")), \
                    patch.object(app, "PHONE", os.path.join(phone_dir, "phone.json")), \
                    patch.object(app, "pause"), patch.object(app, "yes", return_value=True), \
                    patch.object(app, "sas", side_effect=capture_code), \
                    patch.object(app, "find_phone", return_value=("localhost", 1)), \
                    patch.object(app.socket, "create_connection", return_value=client), \
                    patch("builtins.input", side_effect=lambda prompt: codes[-1] if codes else ""), \
                    contextlib.redirect_stdout(io.StringIO()):
                pc = app.PC()
                pc.new_recovery = Mock(return_value=recovery)
                phone = app.Phone(Mock())
                phone.ks.line.return_value = "ecdsa-sha2-nistp256 PERSONAL ssh-storage-phone"
                phone.ensure_key()
                personal_before = copy.deepcopy(phone.d)

                def serve():
                    try:
                        with server: phone.pair(server, app.recv_raw(server))
                    except BaseException as e:
                        errors.append(e)

                worker = threading.Thread(target=serve, daemon=True)
                worker.start()
                try: pc.pair()
                finally:
                    client.close()
                    worker.join(timeout=6)
            self.assertFalse(worker.is_alive())
            self.assertEqual((pc_root / "pc.json").read_bytes(), pc_before)
            self.assertEqual((phone_root / "phone.json").read_bytes(), phone_before)
            self.assertNotEqual(pc.d["me"], old_pc["me"])
            self.assertNotEqual(phone.d["priv"], old_phone["priv"])
            if succeeds:
                self.assertEqual(errors, [])
                self.assertEqual(phone.d["recovery"], recovery)
                self.assertEqual(list(phone.d["peers"]), [app.pubkey(pc.me).hex()])
                self.assertEqual(pc.d["phone"]["fp"], app.fingerprint(phone.pub))
            else:
                self.assertEqual(len(errors), 1)
                self.assertIsInstance(errors[0], ValueError)
                self.assertEqual(phone.d, personal_before)
                self.assertIsNone(pc.d["phone"])


class ProfileRekeyTests(unittest.TestCase):
    def test_destructive_rekey_is_blocked_in_both_profiles_before_key_creation(self):
        with tempfile.TemporaryDirectory(prefix="sshstore-profile-rekey-") as root:
            app.create_personal_profile(root, phone=False)
            for profile in ("default", "personal"):
                pc = object.__new__(app.PC)
                pc.d = {"recovery": "public-key", "servers": []}
                pc.session, pc.new_recovery = Mock(), Mock()
                with self.subTest(profile=profile), patch.object(app, "PROFILE", profile), \
                        patch.object(app, "STATE_ROOT", root), patch.object(app, "menu", side_effect=["1", "2"]), \
                        patch.object(app, "pause"), contextlib.redirect_stdout(io.StringIO()) as output:
                    pc.rekey()
                self.assertIn("blocked", output.getvalue())
                pc.session.assert_not_called()
                pc.new_recovery.assert_not_called()

    def test_phone_refuses_destructive_rekey_even_if_client_bypasses_menu(self):
        for profile in ("default", "personal"):
            phone = object.__new__(app.Phone)
            private = bytes([3]) * 32
            peer = app.pubkey(bytes([4]) * 32)
            phone.priv, phone.pub = private, app.pubkey(private)
            phone.d = {"peers": {peer.hex(): {"name": "test"}}, "servers": [], "recovery": None}
            before = copy.deepcopy(phone.d)
            phone.log, phone.ks, phone.save = Mock(), Mock(), Mock()
            channel = Mock()
            channel.recv.side_effect = [{"intent": "test"}, {"t": "rekey", "phone": True, "wipe": True}, ConnectionError()]
            with tempfile.TemporaryDirectory(prefix="sshstore-profile-refusal-") as root:
                app.create_personal_profile(root, phone=False)
                with self.subTest(profile=profile), patch.object(app, "PROFILE", profile), \
                        patch.object(app, "STATE_ROOT", root), patch.object(app, "Chan", return_value=channel), \
                        patch.object(app, "yes", return_value=True), patch.object(app, "Keystore") as hardware, \
                        patch.object(app.subprocess, "run"), \
                        contextlib.redirect_stdout(io.StringIO()):
                    phone.session(Mock(), {"id": peer.hex(), "e": peer.hex(), "profile": profile})
                hardware.assert_not_called()
            self.assertEqual(channel.send.call_args.args[0], {"ok": False})
            self.assertEqual(phone.d, before)
            phone.save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
