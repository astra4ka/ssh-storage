# SSH Storage — guide

**Main idea:** your SSH key lives **only on your phone**, in the secure Android Keystore chip. The computer never gets it. When you log in to a server, the computer asks the phone to "sign the login", and you confirm it on the phone.

> The program's menus are currently in Russian only. Menu item names are given below in Russian with a translation.

The system has **three parts**:

| Part | What is there | How it is installed |
|---|---|---|
| **1. Computer** | program in `~/.local/share/ssh-storage/` (on NixOS: inside the module), settings `pc.json` in the same folder (**no secrets**) | `install.sh` / `.nix` |
| **2. Phone** (Termux) | program and server list in `~/.ssh-storage/`, SSH key in Android Keystore (cannot be extracted) | one command in Termux |
| **3. Server** | in `~/.ssh/authorized_keys`: the phone key and the recovery key | one command; the computer runs it for you |
| Your piece of paper | 20-character recovery password | — |

The manager is opened with **`ssh-storage`** (on the computer and on the phone). The normal `ssh` command is not changed.

First-time setup order: **computer → phone → pairing → servers**.

---

# Part 1. Computer

Project files:

| File | Purpose |
|---|---|
| `sshstore.py` | the program itself (one file for computer and phone) |
| `install.sh` | installer for Linux and macOS |
| `ssh-storage.nix` | NixOS / home-manager module (the program is embedded in it) |
| `README.ru.md`, `README.en.md` | this guide in Russian and English |

## Linux and macOS

In the project folder:

```bash
sh install.sh
```

Supported: Arch and derivatives (CachyOS, Manjaro, EndeavourOS), Debian/Ubuntu/Mint, Fedora, openSUSE, Alpine, Void, and macOS.

To avoid breaking anything, the installer:
- installs `python3` and the ssh client **only if they are missing** and **never upgrades the system** (no `pacman -Sy` on Arch, so no partial upgrades);
- copies the program to `~/.local/share/ssh-storage/`;
- adds an `ssh-storage` alias to `~/.bashrc` / `~/.zshrc` between `# >>> ssh-storage >>>` markers and keeps a `*.ssh-storage.bak` backup; for fish it creates `~/.config/fish/functions/ssh-storage.fish`;
- does not touch the system `ssh` and runs as your normal user (sudo is asked only to install packages).

Uninstall (your data is kept): `sh install.sh --uninstall`. Open a new terminal after installing.

## NixOS

```bash
sh install.sh
```

The script copies `ssh-storage.nix` into your config folder (it asks which one) and runs `git add` for flakes. **It does not edit your config files.** Add one line to `imports`:

```nix
./ssh-storage.nix
```

The module works both as a NixOS module and as a home-manager module. Then run `sudo nixos-rebuild switch` (or `home-manager switch`).


Root is needed only for installation. No firewall ports are opened: the computer itself connects to the phone and the servers.

---

# Part 2. Phone

## 2.1. Installation

You need **Termux** and **Termux:API**, both from F-Droid. The phone and computer must be on the same Wi-Fi network, with VPN off on the phone.

1. **Phone**, in Termux (it is handy to send the command to yourself in a messenger):
   ```bash
   pkg install -y python termux-api && python -c "import socket,hashlib,os;c=socket.create_server(('',47232)).accept()[0];c.send(b'R');d=c.makefile('rb').read();print(hashlib.sha256(d).hexdigest()[:16]);input('OK? Enter');p=os.path.expanduser('~/.ssh-storage');os.makedirs(p,0o700,1);f=p+'/sshstore.py';open(f+'.n','wb').write(d);os.replace(f+'.n',f);os.execvp('python',['python',f,'--install'])"
   ```
2. **Computer**: `ssh-storage` → **«Сопряжение» → «Установить / обновить приложение на телефоне»** (Pairing → Install / update phone app) → Enter → choose the phone.
3. Both screens show a **16-character code**. If it matches, press Enter on the phone.
   **If it does not match, press nothing and close Termux**: the file was tampered with.

On first start the phone creates its key in Keystore. The phone's main screen will say «ключ SSH: в защищённом чипе» (SSH key: in secure chip).

## Updating the app on the phone

Use the same installation (2.1): the same command in Termux, then «Сопряжение» → «Установить / обновить приложение на телефоне» on the computer and compare the 16-character code. Only the program is replaced. Pairing, the server list (`~/.ssh-storage/phone.json`) and the SSH key in Keystore **are kept**, so nothing needs to be set up again.

Update the computer first (`sudo nixos-rebuild switch` or `sh install.sh`): the phone gets the program from the computer.

## 2.2. Pairing and recovery password

1. **Phone**: `ssh-storage` → **«Начать сопряжение»** (Start pairing).
2. **Computer**: `ssh-storage` → **«Сопряжение» → «Сопряжение с телефоном»** (Pairing → Pair with phone).
3. On the first pairing the computer shows a **recovery password** (20 characters).
   **Write it on paper**, keep it away from the phone, then type it in to confirm. It is not stored anywhere else.
4. The phone shows **6 digits**. Type them on the computer.
5. Press `y` on the phone only after the computer says **«✓ Код верный»** (Code correct).

## 2.3. Editing servers

Only non-secret data can be changed: name, IP/host, port, user. Passwords and the first-login method are **not stored anywhere**.

- **On the phone:** `ssh-storage` → **«Серверы»** (Servers) → choose a server → edit / install command / delete.
- **On the computer:** phone in «Ожидать запросы компьютера» mode, then on the PC `ssh-storage` → **«Серверы» → «Список серверов»** (Servers → Server list) → choose a server → edit / install command / delete. The list lives on the phone, so the phone shows "old → new" and the change is saved only after `y` on the phone.

## 2.4. Erase all data

- **Computer:** `ssh-storage` → **«Специальные возможности» → «Стереть все данные»** (Special → Erase all data) → type `СТЕРЕТЬ`. Deletes `pc.json` (pairing and server list; no secrets). A **new** recovery password is created at the next pairing.
- **Phone:** `ssh-storage` → **«Стереть все данные»**:
  - **«Стереть серверы и сопряжение»** (erase servers and pairing) — the SSH key stays; servers keep accepting the phone after a new pairing;
  - **«Стереть всё»** (erase everything) — deletes the SSH key from Keystore, the data and the app itself. ⚠ **No server will accept this phone anymore**; access is restored only with the recovery password.

---

# Part 3. Server

Nothing is installed on the server and sshd settings are not changed. The server script is a single command. It:

- creates `~/.ssh/authorized_keys` if it does not exist;
- **replaces** the old phone key (tag `ssh-storage-phone`) with the new one;
- **adds** the recovery key if it is not there yet;
- **does not touch** any other keys;
- prints `SSH-STORAGE-OK` at the end.

## 3.1. Automatically (usual way)

1. **Phone**: `ssh-storage` → **«Ожидать запросы компьютера»** (Wait for computer requests).
2. **Computer**: `ssh-storage` → **«Серверы» → «Добавить сервер»** (Servers → Add server) → name, IP, port, user.
3. Compare the **4-digit session code** on both screens → `y` on the phone → confirm.
4. The computer asks **how to log in to the server the first time** (the phone key is not there yet):
   - **Пароль сервера** (server password) — if the server allows password login;
   - **SSH-ключ** (SSH key) — path to the key you use now (e.g. `~/.ssh/1/vpn`), **or paste the key text** starting with the `-----BEGIN … PRIVATE KEY-----` line. The text is not shown on screen; the key is kept only in RAM and erased right after login;
   - **Автоматически** (automatic) — regular keys from `~/.ssh` and the agent.

5. Then the computer asks what to do with **old keys** on the server:
   - **Оставить как есть** (keep) — only the phone key is added;
   - **Отключить** (disable) — every line in `~/.ssh/authorized_keys` and `authorized_keys2` except the phone and recovery keys is **commented out (not deleted)**. This happens **only after login with the phone key is verified**: if the phone could not log in, old keys are untouched. Backup: `authorized_keys.ssh-storage.bak`; to restore, on the server `cp ~/.ssh/authorized_keys.ssh-storage.bak ~/.ssh/authorized_keys`. Other files in `~/.ssh` (config, known_hosts, server keys) are not touched.

   The computer does everything on the server itself. This old way is needed **once**; after checking login via the phone you can remove it (see 3.4).

## 3.2. Manually (no existing login, e.g. only a hosting web console)

1. **Phone**: `ssh-storage` → **«Серверы» → «+ Добавить вручную»** (Servers → + Add manually), or choose an existing server → "show install command".
2. The phone shows the command. Copy it and run it on the server as the target user.
3. You should see `SSH-STORAGE-OK`.

If automatic adding fails, the computer shows the same command.

## 3.3. Connecting to a server

1. **Phone**: `ssh-storage` → **«Ожидать запросы компьютера»**.
2. **Computer**: `ssh-storage` → Enter (**«Подключиться к серверу»**, Connect to server).
3. If the session code matches, press `y` on the phone.
4. Choose the server. The phone signs the login and you are in.

The phone shows how the login went:
- **«✓ сервер принял ключ телефона — подпись выдана»** (server accepted the phone key, signature given) — the phone knows this itself: a server asks for a signature only if it accepts the phone key;
- **«✓ вход выполнен, сеанс закрыт»** (login done, session closed) or **«✗ вход не удался»** (login failed) — the result after you leave the server. It is reported by the computer, so it is information only: the phone does not allow anything based on it.

## Computer menu and rights

```
1 Connect to server
2 Servers            — list (edit / install command / delete), add
3 Pairing            — pair with phone, install / update phone app
4 Server actions     — check rights (other items in development)
5 Special            — recovery, vault.json migration, erase all data
6 Exit
```

On every login the program detects your rights on the server: **root**, **passwordless sudo**, **sudo with password**, **log access** (groups `adm`/`systemd-journal`) or **regular user**. Nothing on the server is changed. The level is shown in the server list; "Server actions" items you lack rights for are marked with what is needed. This is only a menu hint: the server always enforces real rights. The check and the command share one login, so the phone signs once.

With password sudo, the check (`sudo -n`) may leave a "denied" line in the server log. That is expected.

## 3.4. Close the old way in

While old keys remain on the server, it can be entered without the phone. After checking login via the phone (3.3), run on the server:

```bash
grep -E 'ssh-storage-(phone|recovery)$' ~/.ssh/authorized_keys > ~/.ssh/ak.new && mv ~/.ssh/ak.new ~/.ssh/authorized_keys
```

and on the computer `ssh-add -D` (clear the agent). If the server allows password login, that is also a way around (`PasswordAuthentication no` in sshd — your call).

---

# If the phone is lost or broken

1. **Computer** (any one with this program): `ssh-storage` → **«Специальные возможности» → «Восстановление по резервному паролю»** (Special → Recovery by password) → enter the password.
2. Choose a server → **«Подключиться резервным ключом»** (Connect with recovery key). You are on the server without the phone.
3. New phone: **install (2.1) → pair (2.2)**. Then in Recovery choose **«Привязать сопряжённый телефон»** (Bind paired phone) for each server. The old phone's key on the server is replaced and the lost phone can no longer log in.

# Migrating old connections

If an old `vault.json` remains, the computer menu (**«Специальные возможности»**) has **«Перенести старые подключения»** (Migrate old connections). It asks for the old admin password, logs in to each server with the old key and adds the phone key. After checking, you can delete `~/.local/share/ssh-storage/vault.json` and the old keys in `~/.ssh/`. *(This item has not been tested yet.)*

---

# What is protected

| Situation | Result |
|---|---|
| **Malware on the computer** | No key on the computer, nothing to steal. Malware can only try to log in as you, which needs `y` on the phone with a matching code |
| **File stolen from the computer** | `pc.json` has no secrets |
| **Malware on the phone, even with root** | The key cannot be extracted from the secure chip. Malware can use it only while running on your phone |
| **Phone stolen** | Log in with the recovery password and bind a new phone: the old key is removed |
| **Man in the middle** (café) during pairing | Exposed by the 6-digit code |
| **Man in the middle** during login | Devices verify each other by keys, all traffic is encrypted, plus the session code |
| Someone else's request **while you log in** | The session code on the phone will not match the computer |
| **Tampering during phone install** | Exposed by the 16-character check code |
| **Guessing the recovery password** | 20 random characters: brute force would take billions of years |

## What remains (honestly)

- **Malware on the computer during your session** sees everything you do on the server, because it is your terminal. It will not get the key, but it sees the session.
- **Pressing `y` without looking.** Approve only your own requests and only when the code matches.
- **The recovery password is full access to all servers.** Keep the paper away from the phone. There is no "change recovery password" menu item yet.
- The protocol is built from standard parts (X25519, SHA-512, HMAC, ECDSA via Android) but **has not been independently audited**.
- The real `termux-keystore` has not been tested on a phone yet.
- The installer was tested on Linux; it has not been run live on macOS or every distro.

# Troubleshooting

- **Phone not found**: same Wi-Fi? VPN off? Café networks often isolate devices; then enter the IP shown on the phone.
- **"Нет termux-keystore"** (no termux-keystore): install Termux:API from F-Droid and run `pkg install termux-api`.
- **Adding a server failed**: run the command the computer shows on the server (see 3.2).
- **`ssh-storage` does not work on the phone**: it is lowercase with a hyphen. If you get "command not found", an old version is installed: reinstall the app (computer → «Сопряжение» → «Установить / обновить приложение на телефоне»); pairing and key are kept. Fallback: `python ~/.ssh-storage/sshstore.py`.
