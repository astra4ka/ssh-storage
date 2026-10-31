# Security

SSH Storage is experimental and has not had an independent security audit. Passing local tests is not a security certification. Keep your provider console and another recovery path available.

## Trust boundaries

- `pc.json` and `phone.json` contain **private pairing keys**. Never publish these files, recovery passwords, `vault.json` or SSH private keys. `.gitignore` does not remove secrets already in Git history.
- Android Keystore holds the phone's SSH key. Hardware backing depends on the device. An infected phone can use the key and bypass application prompts.
- The session code verifies the PC–phone channel. SSH signing-request validation checks the username and key, not the server address or the commands run after login. Hostbound requests are accepted, but the phone does not independently authenticate the supplied host key.
- An infected computer can abuse an approved session or capture recovery input. Updating the phone from a computer executes code supplied by that computer; a SHA-256 checksum does not establish that the author is trusted.
- The network protocol and Python cryptographic implementations have not had an independent cryptographic audit. Side-channel resistance is not claimed.

## Before using important servers

- Test on real Android hardware: Keystore, a real SSH login, denied approval, tunnels, updates and key rotation.
- Test on a disposable VPS: recovery, failed new-key login, member revocation and re-enrollment, role reduction, deletion, disabling passwords and rollback.
- Team administration runs privileged shell commands over files in members' home directories. It is not proven safe against malicious file changes, symlinks or races. **Do not use it for untrusted members** until this has been hardened and tested separately.
- Operators can restart or reload any service, not a restricted allowlist. This role can disrupt the server and is not suitable for untrusted users.
- Changing groups does not immediately remove privileges from already running processes. Revocation and role changes need separate live tests.
- On systems without `/dev/shm`, temporary private keys may be written to disk. Memory can also be swapped out. Storage exclusively in RAM is not guaranteed on every operating system.
- Concurrent instances are not tested. Startup cleanup of old temporary directories may interfere with another instance.
- Test migrations from earlier `pc.json`/`phone.json` files and legacy key comments before updating an existing installation.

## Reporting a problem

Do not attach private keys, tokens, recovery passwords or real state files to public issues. Use synthetic data for a public reproduction. If a secret has already been published, revoke or rotate it first; deleting the file is not enough.
