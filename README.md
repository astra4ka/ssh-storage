# SSH Storage

SSH authentication with an Android phone. The phone holds an ECDSA key in Android Keystore and signs login requests after confirmation. The computer runs a temporary SSH agent and does not receive the phone's SSH private key.

**Experimental and unaudited. Keep a separate recovery path.** Android Keystore, VPS provisioning, migration and team administration still need real-device testing. Team administration is not hardened for untrusted members. Read [SECURITY.md](SECURITY.md) before using it.

The terminal interface is in English by default. Choose `Language / Язык` in the main menu on the computer and on the phone to switch to Russian. Each device stores its own choice in its state file (`pc.json` or `phone.json`), so it survives restarts, pairing and program updates. Choosing Erase all data also removes the saved language. See the [full English manual](README.en.md) or the [Russian manual](README.ru.md).

## Requirements

- Computer: Linux or macOS, Python 3.9 or newer with `hashlib.scrypt`, and an OpenSSH client. macOS has not been tested on real hardware.
- Phone: Android, Termux and Termux:API from F-Droid, and the `python`, `termux-api` and `openssh` Termux packages.
- Phone and computer on a network where they can reach each other. There is no relay service.
- An existing way into each server, such as a password, SSH key or provider console.

Hardware-backed Keystore support depends on the phone. The program reports what Android provides; a separate secure chip is not assumed.

## Install on the computer

To inspect the files before running the installer:

```sh
git clone https://github.com/astra4ka/ssh-storage.git
cd ssh-storage
sh install.sh
```

Or run the installer directly from the current branch:

```sh
curl -fsSL https://raw.githubusercontent.com/astra4ka/ssh-storage/main/install.sh | sh
```

The second command executes downloaded code. The installer's Python syntax check is not an authenticity check.

The installer copies the program into `~/.local/share/ssh-storage/` and adds an `ssh-storage` command to your shell configuration. It can install missing packages through your package manager. It does not replace the normal `ssh` command.

On NixOS, run `sh install.sh`, select your configuration directory, add `./ssh-storage.nix` to `imports`, and rebuild. The module also works with home-manager. The installer copies the module; it does not edit your Nix configuration.

## Set up the phone

1. Install Termux and Termux:API from F-Droid.
2. Open `ssh-storage` on the computer. Choose Pairing, then Install / update the phone app.
3. Run the displayed command in Termux. It installs the packages and waits for the computer to transfer the program.
4. Compare the 16-character hexadecimal code on both devices before pressing Enter on the phone. If it differs, stop the installation.
5. Start `ssh-storage` on the phone and choose Pairing, then Start pairing. On the computer choose Pair with phone.
6. For personal use, answer no when asked whether this computer belongs to a member of someone else's team. Write down the generated recovery password and complete the input check.
7. Enter the phone's six-digit pairing code on the computer. Approve pairing on the phone only after the computer reports that the code matches.

Do not share or commit `pc.json`, `phone.json`, private keys or recovery passwords. Both state files contain private pairing keys.

## Add a server and connect

1. Put the phone in Wait for computer requests.
2. On the computer, open Servers, then Add server. Enter the host, port, login and a label.
3. Choose your existing login method. The program adds the phone's public key and your recovery public key to `authorized_keys`.
4. Keep existing server keys until you have verified access with the phone. Never remove your only working recovery method.
5. To connect later, choose Connect to a server, compare the session code and approve it on the phone. Select the server and approve that server separately on the phone.

The phone can also connect without the computer: Servers, select a server, then Connect. Both devices offer a Web panel tunnel menu item, which forwards a server port to `127.0.0.1` on the local device. Close the tunnel when finished.

## Recovery

Use Special, then Recovery with the recovery password. On a fresh computer, do this before generating a different recovery password through pairing.

To replace a lost phone, install and pair the new phone, then choose Bind the paired phone for each server. Select the old phone key to revoke. The program adds the new key, checks a login through the new phone, and only then removes the selected old key. If the check fails, the old key stays. Choosing Only add leaves old keys authorized.

If you lose both the phone and recovery password, use your hosting provider's console or another access method you kept.

## Other operations

The [full English manual](README.en.md) covers bulk imports, key rotation, team accounts, audit logging, diagnostics, metrics, VPS setup and uninstalling. These operations can change server access or remove users and files. Test them on a disposable server first.

**VPS setup:** Servers → Add server offers “Connect an existing server” or “Set up a new VPS”. The setup wizard also works from a saved server's menu. Each change has a Run/Skip choice; it can create a named sudo user, install your existing phone/recovery public keys and verify a separate connection before offering to remove the old list entry. Keep your provider console available when changing SSH settings.

For source changes, regenerate the standalone Nix module with `python3 scripts/sync_nix.py`; `python3 -m unittest discover -s tests -v` verifies that its embedded program matches `sshstore.py`.

## Development checks

No third-party Python packages are required:

```sh
python3 -m unittest discover -s tests -v
sh -n install.sh
```

Tests use temporary files, loopback sockets and phone stubs. They include recovery ordering, key replacement, signing-request validation, shell escaping, encrypted-message integrity, state-file permissions, menu startup and consistency of the embedded Nix script. GitHub Actions runs the suite on Linux and macOS with Python 3.10 and 3.14.

A local SSH login through the application agent was also checked against a real OpenSSH server with a temporary test key, including OpenSSH hostbound requests. That test used a native SSH agent as the signer, not Android Keystore.

See [CHANGELOG.md](CHANGELOG.md) for changes and [TASKS.md](TASKS.md) for remaining work.
