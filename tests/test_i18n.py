import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_security import app


class LanguageTests(unittest.TestCase):
    def tearDown(self):
        app.set_language("en")

    def test_default_is_english(self):
        app.load_language({})
        self.assertEqual(app.tr("Назад"), "Back")

    def test_russian_is_preserved(self):
        app.load_language({"language": "ru"})
        self.assertEqual(app.tr("Назад"), "Назад")

    def test_invalid_saved_language_uses_english(self):
        app.load_language({"language": "invalid"})
        self.assertEqual(app.tr("Назад"), "Back")

    def test_language_setting_survives_reload_without_losing_other_state(self):
        with tempfile.TemporaryDirectory(prefix="sshstore-language-") as directory:
            path = Path(directory) / "pc.json"
            state = {"me": "pairing-key", "servers": [{"name": "test"}]}
            with patch.object(app, "menu", return_value="2"), contextlib.redirect_stdout(io.StringIO()):
                app.language_settings(state, lambda: app.save_json(str(path), state), apply=lambda: None)
            saved = json.loads(path.read_text())
            self.assertEqual(saved, {**state, "language": "ru"})
            app.set_language("en")
            app.load_language(saved)
            self.assertEqual(app.tr("Назад"), "Назад")

    def test_computer_and_phone_languages_are_independent(self):
        app.load_language({"language": "ru"})
        app.load_language({"language": "en"})
        self.assertEqual(app.tr("Назад"), "Back")


if __name__ == "__main__":
    unittest.main()


import ast
import os
import re
import subprocess
import sys

from test_security import ROOT

CYRILLIC = re.compile("[А-Яа-яЁё]")
UNTRANSLATED_LITERALS = {"д", "да", "Русский", "СТЕРЕТЬ", "ПЕРЕВЫПУСК", "разрешено", "отклонено", "выполнен", "не удался"}


def parse_source():
    source = (ROOT / "sshstore.py").read_text()
    tree = ast.parse(source)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    return tree, parents


def is_tr_call(node):
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "tr"


class CatalogueTests(unittest.TestCase):
    def test_every_translated_message_has_an_english_entry(self):
        tree, _ = parse_source()
        missing = []
        for node in ast.walk(tree):
            if is_tr_call(node) and node.args and isinstance(node.args[0], ast.Constant):
                key = node.args[0].value
                if CYRILLIC.search(key) and key not in app.EN_MESSAGES:
                    missing.append(key[:80])
        self.assertEqual(missing, [])

    def test_no_user_facing_russian_literal_bypasses_translation(self):
        tree, parents = parse_source()
        bypassed = []
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str) and CYRILLIC.search(node.value)):
                continue
            parent = parents[node]
            if isinstance(parent, ast.Expr):
                continue
            catalogue, inside = node, False
            while catalogue in parents:
                catalogue = parents[catalogue]
                if isinstance(catalogue, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "EN_MESSAGES" for t in catalogue.targets):
                    inside = True
            if inside:
                continue
            if is_tr_call(parent) and parent.args[0] is node:
                continue
            if node.value in UNTRANSLATED_LITERALS:
                continue
            ancestor, in_log = node, False
            while ancestor in parents:
                up = parents[ancestor]
                if isinstance(up, ast.Call) and isinstance(up.func, ast.Attribute) and up.func.attr == "log" and len(up.args) >= 3 and up.args[2] is ancestor:
                    in_log = True
                ancestor = up
            if not in_log:
                bypassed.append((node.lineno, node.value[:60]))
        self.assertEqual(bypassed, [])

    def test_english_entries_keep_placeholders_and_contain_no_russian(self):
        for key, value in app.EN_MESSAGES.items():
            with self.subTest(key=key[:60]):
                self.assertEqual(sorted(re.findall(r"\{p\d+\}", key)), sorted(re.findall(r"\{p\d+\}", value)))
                self.assertEqual((key.count("{{"), key.count("}}")), (value.count("{{"), value.count("}}")))
                if key != "Language / Язык":
                    self.assertFalse(CYRILLIC.search(value))

    def test_formatted_messages_can_be_rendered_in_both_languages(self):
        tree, _ = parse_source()
        for node in ast.walk(tree):
            if is_tr_call(node) and node.args and isinstance(node.args[0], ast.Constant) and node.keywords:
                values = {keyword.arg: "X" for keyword in node.keywords}
                for language in ("en", "ru"):
                    app.set_language(language)
                    with self.subTest(line=node.lineno, language=language):
                        app.tr(node.args[0].value, **values)


def run_program(state, *arguments, stdin=""):
    with tempfile.TemporaryDirectory(prefix="sshstore-language-") as directory:
        for name, content in state.items():
            (Path(directory) / name).write_text(json.dumps(content))
        environment = {**os.environ, "SSHSTORE_DIR": directory, "NO_COLOR": "1"}
        result = subprocess.run([sys.executable, str(ROOT / "sshstore.py"), *arguments], input=stdin,
                                env=environment, capture_output=True, text=True, timeout=20)
        files = {path.name: path.read_text() for path in Path(directory).iterdir() if path.is_file()}
        return result, files


class ProgramLanguageTests(unittest.TestCase):
    def test_computer_defaults_to_english(self):
        result, _ = run_program({}, stdin="7\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Connect to a server", result.stdout)
        self.assertNotRegex(result.stdout.replace("Language / Язык", ""), CYRILLIC)

    def test_computer_uses_saved_russian_and_keeps_it(self):
        state = {"pc.json": {"me": "00" * 32, "phone": None, "recovery": None, "servers": [], "language": "ru"}}
        result, files = run_program(state, stdin="7\n")
        self.assertIn("Подключиться к серверу", result.stdout)
        self.assertEqual(json.loads(files["pc.json"])["language"], "ru")

    def test_switching_restarts_in_russian_and_persists(self):
        result, files = run_program({}, stdin="6\n2\n7\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Connect to a server", result.stdout)
        self.assertIn("Подключиться к серверу", result.stdout)
        self.assertEqual(json.loads(files["pc.json"])["language"], "ru")
        again, _ = run_program({"pc.json": json.loads(files["pc.json"])}, stdin="7\n")
        self.assertIn("Подключиться к серверу", again.stdout)

    def test_phone_language_is_separate_and_loaded_from_phone_state(self):
        english, _ = run_program({}, "--phone")
        russian, _ = run_program({"phone.json": {"language": "ru"}}, "--phone")
        self.assertIn("termux-keystore is missing", english.stdout)
        self.assertIn("Нет termux-keystore", russian.stdout)
        computer, _ = run_program({"pc.json": {"me": "00" * 32, "phone": None, "recovery": None, "servers": [], "language": "ru"}}, "--phone")
        self.assertIn("termux-keystore is missing", computer.stdout)
