import contextlib
import copy
import io
import socket
import threading
import unittest
from unittest.mock import Mock, patch

from test_security import app


class AccessModeTests(unittest.TestCase):
    def setUp(self):
        self.pc = object.__new__(app.PC)
        self.pc.d = {"me": "pairing-secret", "phone": {"fp": "paired"}, "recovery": "",
                     "servers": [{"name": "existing"}], "rights": {"existing": "viewer"}}
        self.pc.save = Mock()
        self.before = copy.deepcopy(self.pc.d)
        self.channel = Mock()
        self.pc.session = Mock(return_value=self.channel)
        self.key = app.recovery_line(bytes(range(32)))
        self.channel.call.return_value = {"recovery": self.key}
        self.output = io.StringIO()
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(contextlib.redirect_stdout(self.output))
        self.stack.enter_context(patch.object(app, "pause"))
        self.stack.enter_context(patch.object(app.getpass, "getpass", return_value="owner-password"))
        self.seed = self.stack.enter_context(patch.object(app, "recovery_seed", return_value=bytes(range(32))))
        self.confirm = self.stack.enter_context(patch.object(app, "yes", return_value=True))

    def assert_unchanged(self):
        self.assertEqual(self.pc.d, self.before)
        self.pc.save.assert_not_called()

    def test_restore_requires_matching_password_and_changes_only_local_public_key(self):
        self.pc.repair_access()
        self.assertEqual(self.pc.d, {**self.before, "recovery": self.key})
        self.pc.save.assert_called_once_with()
        self.pc.session.assert_called_once_with(app.tr("Проверить режим доступа"), check_updates=False)
        self.channel.call.assert_called_once_with({"t": "list"})
        self.channel.close.assert_called_once_with()

    def test_team_phone_never_becomes_owner_or_generates_new_keys(self):
        for value in ("", None):
            with self.subTest(value=value):
                self.channel.call.return_value = {"recovery": value}
                self.pc.repair_access()
                self.assert_unchanged()
        self.seed.assert_not_called()

    def test_wrong_password_does_not_change_local_or_remote_state(self):
        self.seed.return_value = bytes([1]) * 32
        self.pc.repair_access()
        self.assert_unchanged()
        self.channel.call.assert_called_once_with({"t": "list"})
        self.channel.close.assert_called_once_with()

    def test_existing_different_recovery_key_is_not_overwritten(self):
        self.pc.d["recovery"] = app.recovery_line(bytes([2]) * 32)
        self.before = copy.deepcopy(self.pc.d)
        self.pc.repair_access()
        self.assert_unchanged()
        self.seed.assert_not_called()

    def test_existing_matching_key_needs_no_change_or_password(self):
        self.pc.d["recovery"] = self.key
        self.before = copy.deepcopy(self.pc.d)
        self.pc.repair_access()
        self.assert_unchanged()
        self.seed.assert_not_called()

    def test_pairing_menu_exposes_check_without_repairing_or_pairing_implicitly(self):
        self.pc.repair_access, self.pc.pair = Mock(), Mock()
        with patch.object(app, "menu", side_effect=["3", "5"]):
            self.pc.section_pairing()
        self.pc.repair_access.assert_called_once_with()
        self.pc.pair.assert_not_called()

    def test_declined_confirmation_preserves_state(self):
        self.confirm.return_value = False
        self.pc.repair_access()
        self.assert_unchanged()

    def test_empty_password_cancels(self):
        with patch.object(app.getpass, "getpass", return_value=""):
            self.pc.repair_access()
        self.assert_unchanged()
        self.seed.assert_not_called()

    def test_unpaired_computer_does_not_contact_phone(self):
        self.pc.d["phone"] = None
        self.before = copy.deepcopy(self.pc.d)
        self.pc.repair_access()
        self.assert_unchanged()
        self.pc.session.assert_not_called()

    def test_refused_session_preserves_state(self):
        self.pc.session.return_value = None
        self.pc.repair_access()
        self.assert_unchanged()

    def test_invalid_phone_response_fails_closed(self):
        for reply in ({}, {"recovery": []}, {"recovery": True}, {"recovery": "not-a-key"}, []):
            with self.subTest(reply=reply):
                self.channel.call.return_value = reply
                self.pc.repair_access()
                self.assert_unchanged()
        self.seed.assert_not_called()

    def test_disconnection_closes_channel_without_changing_state(self):
        self.channel.call.side_effect = ConnectionError("disconnected")
        self.pc.repair_access()
        self.assert_unchanged()
        self.channel.close.assert_called_once_with()

    def test_matching_but_malformed_key_does_not_report_success(self):
        for key in ("ssh-ed25519 = ssh-storage-recovery", "ssh-ed25519 YWJj ssh-storage-recovery"):
            with self.subTest(key=key):
                self.pc.d["recovery"] = key
                self.before = copy.deepcopy(self.pc.d)
                self.channel.call.return_value = {"recovery": key}
                self.pc.repair_access()
                self.assert_unchanged()
        self.assertNotIn(app.tr("Резервный ключ ПК совпадает с телефоном. Изменения не нужны; права на серверах проверяются отдельно."), self.output.getvalue())

    def test_interrupted_password_or_confirmation_does_not_change_state(self):
        for error in (KeyboardInterrupt, EOFError):
            with self.subTest(error=error):
                with patch.object(app.getpass, "getpass", side_effect=error), self.assertRaises(error):
                    self.pc.repair_access()
                self.assert_unchanged()
                with patch.object(app, "yes", side_effect=error), self.assertRaises(error):
                    self.pc.repair_access()
                self.assert_unchanged()
        self.assertEqual(self.channel.close.call_count, 4)

    def test_save_failure_restores_in_memory_mode(self):
        self.pc.save.side_effect = OSError("write failed")
        self.pc.repair_access()
        self.assertEqual(self.pc.d, self.before)
        self.channel.close.assert_called_once_with()

    def test_paired_team_vps_error_does_not_suggest_pairing_again(self):
        with patch.object(app, "edit_server") as edit:
            self.pc.new_vps()
        self.assertNotIn(app.tr("Настройка VPS доступна владельцу резервного доступа. Сначала выполните сопряжение."), self.output.getvalue())
        self.assertIn(app.tr("Проверить режим доступа"), self.output.getvalue())
        edit.assert_not_called()
        self.assert_unchanged()


class AccessSessionTests(unittest.TestCase):
    def test_real_encrypted_session_only_reads_phone_and_keeps_audit_log(self):
        self.run_session(allow=True)

    def test_denied_phone_session_never_requests_state(self):
        self.run_session(allow=False)

    def run_session(self, allow):
        pc = object.__new__(app.PC)
        private = bytes(range(32))
        phone = object.__new__(app.Phone)
        phone.priv = bytes([7]) * 32
        phone.pub = app.pubkey(phone.priv)
        phone.d = {"peers": {app.pubkey(private).hex(): {"name": "test"}}, "servers": [], "recovery": ""}
        phone.ks = Mock()
        phone.ks.line.return_value = "phone-public-key"
        phone.save = Mock()
        before = copy.deepcopy(phone.d)
        pc.d = {"me": private.hex(), "phone": {"pub": phone.pub.hex(), "fp": app.fingerprint(phone.pub)},
                "servers": [], "recovery": ""}
        pc.save, pc.offer_update = Mock(), Mock()
        client, server = socket.socketpair()
        server.settimeout(5)
        errors, messages = [], []
        original_receive = app.Chan.recv

        def receive(channel):
            message = original_receive(channel)
            messages.append(message)
            return message

        def serve():
            try:
                with server:
                    phone.session(server, app.recv_raw(server))
            except BaseException as e:
                errors.append(e)

        with patch.object(app, "find_phone", return_value=("localhost", 1)), \
                patch.object(app.socket, "create_connection", return_value=client), \
                patch.object(app, "yes", return_value=allow), patch.object(app, "pause"), \
                patch.object(app.Chan, "recv", receive), contextlib.redirect_stdout(io.StringIO()):
            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            try:
                pc.repair_access()
            finally:
                client.close()
                worker.join(timeout=6)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual([m["t"] for m in messages if "t" in m], ["list"] if allow else [])
        pc.offer_update.assert_not_called()
        pc.save.assert_not_called()
        self.assertEqual({k: v for k, v in phone.d.items() if k != "log"}, before)
        self.assertEqual(len(phone.d["log"]), 1)
        phone.save.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
