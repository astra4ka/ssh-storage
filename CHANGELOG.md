# Changelog

## 2026.11.01

### Added
- A guided VPS setup with an explanation and Run/Skip choice for each change: package lists, a named new user, sudo privileges, terminal colors, application keys, SSH port and login restrictions.
- Choose between connecting an existing server and setting up a new VPS when adding a server. Run the same wizard from a saved server's menu or Server actions.
- Save a separate connection for a new login or port, verify fresh phone-key access, then optionally remove only the old connection entry from the phone and computer.

### Safety
- Back up the pre-run SSH configuration in a root-only per-run directory and schedule independent rollback before changing it. Block overlapping setup transactions and verify effective SSH settings before restarting.
- Preserve skipped settings, other authorized keys, server accounts and files. Passwords and SSH private keys are not added to application state.
- Synchronize the standalone application and the Python embedded in the NixOS/home-manager module.
- The wizard remains experimental: automated tests are not a substitute for disposable VPS and real Android testing. Keep a provider console and a separate recovery path available.

### Fixed
- Keep the active application state directory out of startup temporary-directory cleanup, including when it is stored in the macOS temporary directory.
- Use portable stream editing for the SSH port transaction, preserving existing file permissions without depending on GNU `sed -i` syntax.

## 2026.10.31

### Interface
- The terminal interface is English by default. `Language / Язык` in the main menu switches to Russian on the computer and on the phone.
- Each device stores its choice in `pc.json` or `phone.json`. The setting survives restarts, pairing, server synchronization and program updates; Erase all data removes it.
- Remove the decorative emoji from the interface.

### Security
- Quote process names in diagnostic shell commands. Reject PID 0, PID 1 and negative PIDs.
- Reject network messages with unexpected JSON types.
- Require separate phone approval for the selected server. Validate the SSH signing request's format, username and key, including OpenSSH hostbound requests. This does not verify the server address.
- Let recovery select an old phone key to revoke, and remove it only after verifying a login with the new phone.
- Preserve other phones' keys with the legacy `ssh-storage-phone` tag during installation.
- Replace a member's previously tagged key when adding the same member with a new key.
- Save JSON state through an unpredictable temporary file with mode 600.
- Correct claims that `pc.json` contains no secrets or that Android Keystore always has hardware backing.

### Tests
- Add regression tests using Python's standard library, including translation coverage and language persistence on the computer and the phone.
- Check a real local SSH login through the application agent, including OpenSSH hostbound requests. A native SSH agent provided the test signature, not Android Keystore.
- Add GitHub Actions checks for Linux/macOS and Python 3.10/3.14.
- Real Android Keystore, VPS operations, existing-installation migrations and macOS still need testing. Pairing formats and update message types are unchanged; this is not a compatibility guarantee without device testing.
