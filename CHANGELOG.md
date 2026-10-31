# Changelog

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
