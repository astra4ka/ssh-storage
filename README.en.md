# SSH Storage

The SSH key lives in Android Keystore on your phone; hardware backing depends on the device. The computer never gets that key. When you log in to a server, the computer asks the phone to sign the login, and you confirm it on the phone.

**Experimental software without an independent audit.** Real Android Keystore, recovery, and VPS configuration changes still need testing on real test equipment. Do not use this as your only way into important servers. See [SECURITY.md](SECURITY.md).

Русская версия: [README.ru.md](README.ru.md).

| Where | What is there | How it is installed |
|---|---|---|
| Computer | the program and `pc.json` in `~/.local/share/ssh-storage/`. The file contains a private pairing key: never publish it | one command or `install.sh`, on NixOS a `.nix` module |
| Phone (Termux) | the program, private pairing key and server list in `~/.ssh-storage/`, the SSH key in Android Keystore | one command in Termux |
| Server | the phone key and the recovery key in `~/.ssh/authorized_keys` | the computer adds them for you |
| A sheet of paper | the 20-character recovery password | you write it down during pairing |

Open the program with `ssh-storage` on the computer and on the phone. The normal `ssh` command is not changed.

First setup order: computer, then phone, pairing, servers.

The interface is in English by default. Open `Language / Язык` in the main menu on the computer and on the phone to switch to Russian. Each device saves its own choice in `pc.json` or `phone.json`, so the language is kept after restarts, pairing and updates. The program restarts itself when you switch, so some server-side messages change only after that restart. Erasing all data also removes the saved language. Source comments and the Russian manual are not translated.

---

## 1. Computer

### One-line install (Linux and macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/astra4ka/ssh-storage/main/install.sh | sh
```

The script downloads `sshstore.py`, checks its Python syntax, and installs it. This is not an authenticity check: the command runs code from the current GitHub branch. To review before running, download the repository and inspect its files first.

### Install from the project folder

```bash
git clone https://github.com/astra4ka/ssh-storage && cd ssh-storage && sh install.sh
```

Supported: Arch and derivatives (CachyOS, Manjaro, EndeavourOS), Debian, Ubuntu, Mint, Fedora, openSUSE, Alpine, Void and macOS.

What the installer does:
- installs `python3` and the ssh client only if they are missing, and never upgrades the system;
- copies the program to `~/.local/share/ssh-storage/` with mode `600`;
- adds the `ssh-storage` command to `~/.bashrc` and `~/.zshrc` between `# >>> ssh-storage >>>` markers and keeps a `*.ssh-storage.bak` copy. For fish it creates `~/.config/fish/functions/ssh-storage.fish`;
- runs as your normal user. It asks for sudo only to install missing packages.

Open a new terminal after installing. To remove the program, run `sh install.sh --uninstall`. Your data stays.

### NixOS

```bash
sh install.sh
```

The script asks for your config folder, copies `ssh-storage.nix` there and runs `git add` for flakes. It does not edit your config files. Add `./ssh-storage.nix` to `imports` and run `sudo nixos-rebuild switch` (or `home-manager switch`).

### Computer menu

```
1 Connect to a server
2 Servers                 list, add, new VPS, bulk actions, key reissue, team members
3 Pairing                 with the phone, install or update the phone app
4 Server actions          history, break-in attempts, diagnostics, process check, web panel tunnel
5 Advanced options        recovery, vault.json import, approval log, erase data
6 Language / Язык
7 Exit
```

On every login the program detects your rights on the server: root, passwordless sudo, sudo with password, log access, or a plain user. Items that need more rights are marked. The server always checks the real rights.

---

## 2. Phone

### Install

You need Termux and Termux:API, both from F-Droid. The phone and the computer must be on the same Wi-Fi, with VPN off on the phone.

1. On the phone, in Termux (send the command to yourself in a messenger to copy it):
   ```bash
   pkg install -y python termux-api openssh && python -c "import socket,hashlib,os;c=socket.create_server(('',47232)).accept()[0];c.send(b'R');d=c.makefile('rb').read();print(hashlib.sha256(d).hexdigest()[:16]);input('OK? Enter');p=os.path.expanduser('~/.ssh-storage');os.makedirs(p,0o700,1);f=p+'/sshstore.py';open(f+'.n','wb').write(d);os.replace(f+'.n',f);os.execvp('python',['python',f,'--install'])"
   ```
2. On the computer: `ssh-storage`, Pairing, "Install / update the phone app", pick the phone.
3. Both screens show a 16-digit code. If the codes match, press Enter on the phone. If they differ, press nothing and close Termux: the file was tampered with.

On first start the phone creates the key in Keystore. The main screen shows whether Android reports hardware backing. A separate secure chip is not available on every device.

The `openssh` package lets you log in to servers directly from the phone. Everything else works without it.

### Update

Update the program on the computer (`sh install.sh` or `sudo nixos-rebuild switch`). At the next session with the computer, the phone asks whether to update itself. Answer yes only if you updated the computer yourself. The program travels over the encrypted pairing channel, the phone checks its checksum and never installs a version older than its own. After the session the phone restarts with the new version. Pairing, the server list and the key are kept.

If the phone runs a version without auto-update (before October 2026), update it once by hand with the same install command.

### Pairing and the recovery password

1. Phone: `ssh-storage`, Pairing, "Start pairing".
2. Computer: `ssh-storage`, Pairing, "Pair with phone".
3. On first pairing the computer asks whether it belongs to a member of someone else's team. On your own computer answer "no". The computer then shows a 20-character recovery password. Write it on paper, keep it away from the phone, and type it back to check. The program does not store it.
4. The phone shows 6 digits. Type them on the computer.
5. Press `y` on the phone only after the computer says the code is correct.

One recovery password covers all your servers. Adding a server does not create a new one. The same recovery key goes to every server.

### Phone menu

- "Wait for computer requests": the phone waits for the computer to ask for a signature or a list change.
- "Servers": the server list. Each server has Connect, Edit, Install command, Delete and Web panel tunnel. Below the list are "+ Add manually" and, if you are the team admin, "Revoke member".
- "Advanced options": approval log, your public key for a team admin, erase data.
- "Language / Язык": switch between English and Russian.

---

## 3. Servers

### Add a server you can already log in to

1. Phone: "Wait for computer requests".
2. Computer: Servers, "Add server". Enter a name, IP, port and user.
3. Compare the 4-digit session code on both screens and press `y` on the phone.
4. Choose how to log in the first time: the server password, your current SSH key (a file path or the key text), or automatically with keys from `~/.ssh`. Key text is not shown on screen and stays in memory only until the login ends.
5. Choose what to do with the old keys on the server. "Keep" only adds the phone key. "Disable" comments out every other line in `authorized_keys`, and only after the phone key login is confirmed. A copy is kept in `authorized_keys.ssh-storage.bak`.

The program adds the phone key and the recovery key and prints `SSH-STORAGE-OK`. It does not change sshd settings here.

### Set up a VPS

**Servers → Add server** offers **Connect an existing server** (install application keys without system configuration) and **Set up a new VPS**. For a saved connection, use **Servers → List → your server → Set up VPS**, or **Server actions → Set up VPS**.

The setup wizard requires Ubuntu/Debian, root or sudo for the original login, and a paired phone with recovery access. Each change has an explanation and its own **Run / Skip** choice:
1. refresh package lists (`apt update`, without installing updates);
2. create a new user with the login you enter, or keep the original user;
3. grant that user administrator privileges through password-protected sudo;
4. add terminal colors (`TERM=xterm-256color`) to that user's `~/.profile`;
5. install the existing phone public key and recovery key, preserving other keys;
6. change the SSH port;
7. disable direct root SSH login;
8. disable SSH password and keyboard-interactive login, not the sudo password.

Review the plan before execution. No private key is generated on the VPS. Passwords are entered in the SSH terminal and are not saved by the program. A login already used by another account is not silently repurposed.

For SSH changes, the wizard saves the original configuration, starts an independent three-minute rollback and keeps the old port available until a separate phone-key login on the target port succeeds. Only then are the selected access restrictions applied. A second fresh login confirms the result. If verification fails, the original SSH configuration is restored; user creation and other completed preparation steps are not undone. The timer starts **before the first SSH change**, not after the final restrictions, so approve phone prompts promptly.

The managed drop-in is `/etc/ssh/sshd_config.d/00-ssh-storage.conf`; the main config includes it first, and explicit ports in other standard drop-ins are commented only when changing ports. Root-only per-run backups and transaction logs live under `/var/lib/ssh-storage/vps-*`. Pending setup blocks another setup from overwriting its rollback. Open a selected port in the provider's firewall yourself and keep the provider console available.

The new connection is synchronized to the phone and computer and remains marked unverified until a fresh login succeeds. After success, you may remove the old connection **from the list only**; its server user, files and keys are not deleted. Keeping the old entry is the default. Skipped key installation may leave a newly created user without application access; SSH restrictions cannot be applied in that combination.

**Personal account without root:** use **Connect an existing server**, not VPS setup; ask the server owner to change system settings.

### Connect to a server

From the computer: phone in "Wait for computer requests", run `ssh-storage` on the computer and press Enter, compare the session code, press `y` on the phone, pick the server and approve that server separately on the phone. Administrative actions opening another connection require another approval.

From the phone: Servers, pick the server, Connect. No computer needed.

### Web panel tunnel (3x-ui and others)

This opens a server's web panel without exposing it to the internet. On the computer: Server actions, "Web panel tunnel". On the phone: Servers, the server, "Web panel tunnel". Enter the panel port (2053 by default) and open `http://127.0.0.1:2053/` plus the panel path in a browser. Ctrl+C closes the tunnel.

You can then set 3x-ui to listen only on `127.0.0.1`, so nobody outside can see it. While the tunnel is open, other programs on the same device can also reach the port, so close it when you are done.

---

## 4. Team mode

For teams of up to 10 people. There is one admin, who holds the recovery password. Everyone else logs in only with their own phone.

### Roles

| Role | Rights | For whom |
|---|---|---|
| administrator | sudo and log access | a developer who installs packages and edits configs |
| operator | log access and only `sudo systemctl restart/reload` | a helper who restarts services, reads logs and works in the web panel through the tunnel |
| viewer | log access, no sudo | someone who only checks things |

Each member has their own user and key on the server, so the logs show who did what.

An administrator gets a temporary sudo password when created. The server asks them to change it at first login. If the server cannot do that, the program warns you, and the member should run `passwd`.

### Add a member

1. The member installs the same program on their computer and phone and pairs them. When asked "Is this a team member's computer?", they answer "yes". They get no recovery password.
2. The member sends you their phone's public key. On the phone it is in Advanced options, "My public key". The line starts with `ecdsa-sha2-nistp256`. It is not secret and can be sent in a messenger.
3. You: Servers, "Team members", "Add member to servers". Enter login, nick, key and role, then pick the servers.

The member list is stored on your phone, with a copy on the computer. They sync after every add and delete.

### Revoke or delete a member

Servers, "Team members", "Revoke or delete member". Pick the member from the list, then the servers (Enter picks all).

- "Only remove keys": the member's keys are removed, the account is locked, open sessions are closed, and sudo is taken away. The user and their files stay. Add the member again to give access back.
- "Delete completely": the user and their home folder are deleted. You confirm by typing the nick.

From the phone without the computer: Servers, "Revoke member". Use it to cut access at night if a member is compromised. Full deletion is only on the computer.

Your own user and root are never locked or deleted. The program touches only users it created. They are listed in `/var/lib/ssh-storage/members`, which only root can read.

### Role change and a member's lost phone

- To change a role, add the member again with the new role. Moving down from administrator removes sudo.
- If a member loses their phone, revoke them, then add them again with the new phone key. Their files are kept.

### What a member sees

Team management items are hidden for members. Recovery by password is not available to them, the admin gives new access.

A member with the administrator role has sudo and can technically do anything on the server. Hidden buttons do not limit that. Give this role only to people you trust.

---

## 5. Lost phone

Your phone:
1. On any computer with the program: Advanced options, "Recover with backup password", enter the password from paper.
2. Pick a server, "Connect with the recovery key".
3. New phone: install and pair. Then in Recovery choose "Bind the paired phone" for each server and explicitly select the lost phone's key to revoke. The program adds the new key, verifies a login with it, then removes the selected old key. If verification fails, the old key stays; retry recovery. Choosing "Only add" does not revoke old keys.

A member's phone: revoke the member and add them again with the new phone key.

If both the phone and the paper are lost, the only way in is the console in your hoster's panel.

---

## 6. Security

| Situation | Result |
|---|---|
| Malware on the computer | The phone's SSH key is not copied, but malware can abuse an approved login, steal the session or offer a malicious update |
| Stolen `pc.json` | The private pairing key has leaked; remove pairing on the phone and pair again |
| Malware on the phone, especially with root | May bypass approvals and use the key. Hardware backing does not make an infected phone safe |
| Stolen phone | Log in with the recovery password and bind a new phone |
| Interception during pairing | The 6-digit code reveals it |
| Someone else's request during your login | The session code on the phone will not match the computer |
| Tampering during the phone install | The 16-digit code reveals it |
| Guessing the recovery password | 20 random characters, brute force would take billions of years |

There is no telemetry. The program connects only to the phone on the local network (port 47232), to your servers over SSH, and to `127.0.0.1` for the tunnel.

What remains:
- Malware on the computer can read and alter your terminal and commands. Recovery also enters the recovery password on the computer, where malware could steal it.
- The phone checks the SSH signing request format and username, not the server address: the address is absent from the signed data. The session code verifies the PC–phone channel, not the safety of the PC or server commands.
- Press `y` on the phone only for your own requests and only when the code matches.
- The recovery password opens all servers. If it may have leaked, use Servers, "Key reissue" with a new recovery key.
- Command recording (auditd) saves every command of every user with arguments. A password typed inside a command ends up in the log. Tell your members.
- The protocol uses standard parts (X25519, SHA-512, HMAC, ECDSA through Android) and has had no independent audit.

---

## 7. FAQ

**How many recovery passwords does a team need?** One, held by the admin. Members have none, the admin restores their access.

**What if another person answers "no, not a member" during pairing?** They get their own recovery password for their own servers. Yours does not change, and they get no access to your servers.

**Where is the member list stored?** On your phone. The copy on the computer updates with every add and delete.

**Can I log in without the computer?** Yes, from the phone: Servers, the server, Connect. Termux needs the `openssh` package.

**Can I still use plain `ssh`?** Yes, the program does not change it. Plain `ssh` just does not have the phone key.

**What does the program leave on a server?** `authorized_keys` (key-management actions may also create `.ssh-storage.bak`). VPS setup adds `/etc/ssh/sshd_config.d/00-ssh-storage.conf`, its early Include in the main configuration, root-only transaction backups under `/var/lib/ssh-storage/vps-*`, and a verification marker in the target user's home. Selected user, sudo, profile and UFW changes remain. In team mode, the registry is `/var/lib/ssh-storage/members`. With metrics on, `~/.ssh-storage-metrics` and a crontab line; "Turn off" removes metrics.

---

## 8. Troubleshooting

| Problem | What to do |
|---|---|
| The computer cannot find the phone | The phone must be in "Wait for computer requests" and awake. Check that both are on the same network and VPN is off. Guest networks may isolate devices, then type the IP shown on the phone |
| "termux-keystore is missing" | Install Termux:API from F-Droid and run `pkg install termux-api` |
| "ssh is missing: run pkg install openssh" | Run `pkg install openssh` in Termux |
| "no SSH server found on this port" | Check the IP and port. The hoster firewall may block the port |
| Adding a server failed | Run the command the computer shows on the server, or take it from the phone: the server, Install command |
| VPS setup stopped | Some preparation steps may have completed. Read the output; do not assume the server was unchanged. The old connection entry is kept |
| No login after VPS SSH changes | Allow 3 minutes from the first SSH change for rollback to the pre-run configuration. If needed, use the provider console; check the root-only transaction status and watcher log under `/var/lib/ssh-storage/vps-*` |
| Member: "user already exists and is not this member" | That login on the server is not your member. Choose another login |
| Revoke: "failed (unreachable or sudo denied) - try again" | The server was unreachable or the sudo password was not entered. Retry for that server |
| `ssh-storage: command not found` on the computer | Open a new terminal. Fallback: `python3 ~/.local/share/ssh-storage/sshstore.py` |
| `ssh-storage: command not found` on the phone | Reinstall the app (section 2). Fallback: `python ~/.ssh-storage/sshstore.py` |
| Installer: "Set your GitHub name in REPO_RAW" | Replace `OWNER` in the URL with the account name, or run with `SSH_STORAGE_RAW=https://raw.githubusercontent.com/NAME/ssh-storage/main` |
| Installer: "sshstore.py is damaged" | The download was incomplete. Run the install again |

Limits: the real `termux-keystore` and team mode have not yet been tested on live devices and servers. The installer was tested on Linux, not live on macOS. The interface is English by default with a Russian option; source code comments are in Russian.

## Developer checks

No third-party Python dependencies: `python3 -m unittest discover -s tests -v` and `sh -n install.sh`. Tests use temporary directories and phone stubs, not your servers. They do not replace real SSH login and Android Keystore tests.
