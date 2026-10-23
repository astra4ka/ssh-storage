# SSH Storage

The SSH key lives only on your phone, in the Android Keystore secure chip. The computer never gets the key. When you log in to a server, the computer asks the phone to sign the login, and you confirm it on the phone.

Русская версия: [README.ru.md](README.ru.md).

| Where | What is there | How it is installed |
|---|---|---|
| Computer | the program and `pc.json` settings in `~/.local/share/ssh-storage/`. `pc.json` holds no secrets | one command or `install.sh`, on NixOS a `.nix` module |
| Phone (Termux) | the program and the server list in `~/.ssh-storage/`, the SSH key in Android Keystore (it cannot be extracted) | one command in Termux |
| Server | the phone key and the recovery key in `~/.ssh/authorized_keys` | the computer adds them for you |
| A sheet of paper | the 20-character recovery password | you write it down during pairing |

Open the program with `ssh-storage` on the computer and on the phone. The normal `ssh` command is not changed.

First setup order: computer, then phone, pairing, servers.

The program interface is in Russian. Menu names below are given in English with the Russian text in quotes where it helps.

---

## 1. Computer

### One-line install (Linux and macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/ssh-storage/main/install.sh | sh
```

Replace `OWNER` with the GitHub account that hosts the project. The script downloads `sshstore.py`, checks that the file is valid Python, and installs the program. If `OWNER` is still in the script, it stops and changes nothing.

### Install from the project folder

```bash
git clone https://github.com/OWNER/ssh-storage && cd ssh-storage && sh install.sh
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
5 Special                 recovery, vault.json import, erase data
6 Exit
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
2. On the computer: `ssh-storage`, Pairing ("Сопряжение"), "Install / update the phone app", pick the phone.
3. Both screens show a 16-digit code. If the codes match, press Enter on the phone. If they differ, press nothing and close Termux: the file was tampered with.

On first start the phone creates the key in Keystore. The main screen then says the SSH key is in the secure chip.

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
- "Special": approval log, your public key for a team admin, erase data.

---

## 3. Servers

### Add a server you can already log in to

1. Phone: "Wait for computer requests".
2. Computer: Servers, "Add server". Enter a name, IP, port and user.
3. Compare the 4-digit session code on both screens and press `y` on the phone.
4. Choose how to log in the first time: the server password, your current SSH key (a file path or the key text), or automatically with keys from `~/.ssh`. Key text is not shown on screen and stays in memory only until the login ends.
5. Choose what to do with the old keys on the server. "Keep" only adds the phone key. "Disable" comments out every other line in `authorized_keys`, and only after the phone key login is confirmed. A copy is kept in `authorized_keys.ssh-storage.bak`.

The program adds the phone key and the recovery key and prints `SSH-STORAGE-OK`. It does not change sshd settings here.

### New VPS from scratch

Servers, "New VPS: set up from scratch". There are two options.

**I just bought a server.** You need the IP, root (or a sudo user) and the hoster password. The server must run Ubuntu or Debian. The program:
1. updates the package list and creates your user with sudo (you choose the sudo password);
2. adds the phone key and the recovery key;
3. makes SSH listen on the old and the new port, with password login still on;
4. checks the phone key login on the new port;
5. only then turns off the old port, root login and password login.

If the new login is not confirmed within 3 minutes after step 5, the server restores the step 3 settings by itself. The sshd changes live in one file, `/etc/ssh/sshd_config.d/00-ssh-storage.conf`. Backups are named `*.ssh-storage.bak`, and each run overwrites the single copy.

**I was given a personal user on someone else's server.** You have no root. The program installs only your keys and `TERM` in `~/.profile`. The server owner controls the port, root login and passwords.

### Connect to a server

From the computer: phone in "Wait for computer requests", run `ssh-storage` on the computer and press Enter, compare the session code, press `y` on the phone, pick the server.

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
2. The member sends you their phone's public key. On the phone it is in Special, "My public key". The line starts with `ecdsa-sha2-nistp256`. It is not secret and can be sent in a messenger.
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
1. On any computer with the program: Special, "Recovery with the recovery password", enter the password from paper.
2. Pick a server, "Connect with the recovery key".
3. New phone: install and pair. Then in Recovery choose "Bind the paired phone" for each server. The old phone key is replaced.

A member's phone: revoke the member and add them again with the new phone key.

If both the phone and the paper are lost, the only way in is the console in your hoster's panel.

---

## 6. Security

| Situation | Result |
|---|---|
| Malware on the computer | There is no key on the computer. Logging in as you needs confirmation on the phone with a matching code |
| A file stolen from the computer | `pc.json` holds no secrets |
| Malware on the phone, even with root | The key cannot be extracted from the chip. Malware can use it only while running on the phone |
| Stolen phone | Log in with the recovery password and bind a new phone |
| Interception during pairing | The 6-digit code reveals it |
| Someone else's request during your login | The session code on the phone will not match the computer |
| Tampering during the phone install | The 16-digit code reveals it |
| Guessing the recovery password | 20 random characters, brute force would take billions of years |

There is no telemetry. The program connects only to the phone on the local network (port 47232), to your servers over SSH, and to `127.0.0.1` for the tunnel.

What remains:
- Malware on the computer during your session sees the terminal. It does not get the key.
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

**What does the program leave on a server?** `authorized_keys` and its `.ssh-storage.bak` copy. After "New VPS", the file `/etc/ssh/sshd_config.d/00-ssh-storage.conf`. In team mode, the registry `/var/lib/ssh-storage/members`. With metrics on, `~/.ssh-storage-metrics` and a crontab line. The "Turn off" item removes the metrics.

---

## 8. Troubleshooting

| Problem | What to do |
|---|---|
| The computer cannot find the phone | The phone must be in "Wait for computer requests" and awake. Check that both are on the same network and VPN is off. Guest networks may isolate devices, then type the IP shown on the phone |
| "Нет termux-keystore" (no termux-keystore) | Install Termux:API from F-Droid and run `pkg install termux-api` |
| "Нет ssh: выполните pkg install openssh" | Run `pkg install openssh` in Termux |
| "не нашёл SSH-сервер на этом порту" (no SSH server on this port) | Check the IP and port. The hoster firewall may block the port |
| Adding a server failed | Run the command the computer shows on the server, or take it from the phone: the server, Install command |
| "New VPS" stopped at steps 1 to 3 | Password login still works. Fix the reason from the message and retry |
| No login after "New VPS" | Wait 3 minutes. The server restores the old port and password login by itself |
| Member: "user already exists and is not this member" | That login on the server is not your member. Choose another login |
| Revoke: "не выполнено" (not done) | The server was unreachable or the sudo password was not entered. Retry for that server |
| `ssh-storage: command not found` on the computer | Open a new terminal. Fallback: `python3 ~/.local/share/ssh-storage/sshstore.py` |
| `ssh-storage: command not found` on the phone | Reinstall the app (section 2). Fallback: `python ~/.ssh-storage/sshstore.py` |
| Installer: "Set your GitHub name in REPO_RAW" | Replace `OWNER` in the URL with the account name, or run with `SSH_STORAGE_RAW=https://raw.githubusercontent.com/NAME/ssh-storage/main` |
| Installer: "sshstore.py is damaged" | The download was incomplete. Run the install again |

Limits: the real `termux-keystore` and team mode have not yet been tested on live devices and servers. The installer was tested on Linux, not live on macOS. The program interface is Russian only.
