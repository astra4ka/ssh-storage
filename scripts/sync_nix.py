#!/usr/bin/env python3
"""Regenerate the standalone Nix module's embedded Python after source changes."""
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
path = root / "ssh-storage.nix"
source = (root / "sshstore.py").read_text()
nix = path.read_text()
start = 'script = pkgs.writeText "sshstore.py" \'\'\n'
before, rest = nix.split(start, 1)
_, after = rest.split("  '';\n", 1)
escaped = source.replace("''", "'''").replace("${", "''${")
embedded = "".join("    " + line if line.strip() else line for line in escaped.splitlines(keepends=True))
generated = before + start + embedded + "  '';\n" + after
if "--check" in sys.argv:
    if generated != nix:
        sys.exit("Nix source is out of sync: run python3 scripts/sync_nix.py")
else:
    path.write_text(generated)
