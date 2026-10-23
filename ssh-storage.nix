# SSH Storage: SSH keys live only on the phone (Android Keystore); the PC signs
# logins through the phone; 20-character recovery password.
# Command: `ssh-storage` opens the manager; the normal `ssh` is not touched.
# Works both as a NixOS module and as a home-manager module: add it to `imports`.
# Data: ~/.local/share/ssh-storage/ (no secrets). No firewall ports are opened.
# This file is generated from sshstore.py — the Python script is embedded below.
{ pkgs, lib, options, ... }:
let
  script = pkgs.writeText "sshstore.py" ''
    #!/usr/bin/env python3
    """SSH Storage — SSH-ключи живут только на телефоне, компьютер их никогда не видит.

    Один файл для компьютера и для телефона (Termux). Только стандартная библиотека
    (+ termux-api на телефоне).

    Телефон (Termux, ~/.ssh-storage/):
      * SSH-ключ ECDSA P-256 в Android Keystore — неизвлекаемый, даже с root.
      * Список серверов, редактирование, команда установки для сервера.
      * Каждый вход подтверждается на телефоне по коду сеанса.
    Компьютер (~/.local/share/ssh-storage/pc.json) — секретов нет:
      * Временный ssh-agent: подписи запрашиваются у телефона.
      * Добавление сервера: сам заходит на сервер и прописывает ключи.
    Резервный пароль (20 символов): из него выводится резервный ключ Ed25519,
      прописанный на каждом сервере. Телефон потерян — вход по паролю с любого
      компьютера и привязка нового телефона. Пароль нигде не хранится.
    Сеть: сопряжение — X25519 + commit-reveal + 6-значный код (телефон показывает,
      вводите на компьютере); сеансы — как Noise KK + 4-значный код сеанса.
    Цвета — стандартные 16 ANSI-цветов, т.е. палитра вашего терминала.
    """
    import base64, getpass, hashlib, hmac, json, os, re, secrets, shlex, shutil, socket, struct
    import concurrent.futures, subprocess, sys, tempfile, threading, time

    HERE = os.environ.get("SSHSTORE_DIR") or os.path.dirname(os.path.abspath(__file__))
    os.makedirs(HERE, mode=0o700, exist_ok=True)
    SSH = os.environ.get("SSHSTORE_SSH", "ssh")
    PC_STATE = os.path.join(HERE, "pc.json")
    LEGACY_VAULT = os.path.join(HERE, "vault.json")
    PHONE = os.path.join(HERE, "phone.json")
    TCP_PORT = 47232
    RAM = "/dev/shm" if os.path.isdir("/dev/shm") else None
    IS_PHONE = "com.termux" in os.environ.get("PREFIX", "") or "--phone" in sys.argv
    PHONE_TAG, RECOVERY_TAG = "ssh-storage-phone", "ssh-storage-recovery"
    NICK_RE = r"[A-Za-z0-9_-]{1,32}"  # ник в подписи ключа: ssh-storage-phone:<ник>
    ANY_PHONE_TAG = PHONE_TAG + r"\(:[A-Za-z0-9_:-]*\)\{0,1\}"  # sed: старая подпись и с именем:ID:датой

    # ---------- цвета (палитра терминала) ----------
    USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    def c(code, s): return f"\033[{code}m{s}\033[0m" if USE_COLOR else s
    dim    = lambda s: c("2", s)
    bold   = lambda s: c("1", s)
    red    = lambda s: c("31", s)
    green  = lambda s: c("32", s)
    yellow = lambda s: c("33", s)
    blue   = lambda s: c("34", s)
    mag    = lambda s: c("35", s)
    cyan   = lambda s: c("36", s)

    def clear(): print("\033[2J\033[H", end="") if USE_COLOR else None

    def header(title):
        clear()
        w = min(shutil.get_terminal_size().columns, 60)
        print(cyan("╭" + "─" * (w - 2) + "╮"))
        t = f" ⚿  SSH Storage · {title}"
        print(cyan("│") + bold(t.ljust(w - 2)) + cyan("│"))
        print(cyan("╰" + "─" * (w - 2) + "╯"))
        print()

    def menu(items, default=1):
        for i, it in enumerate(items, 1):
            mark = green("›") if i == default else " "
            print(f" {mark} {yellow(str(i))}  {it}")
        print()
        ans = input(blue(f"Выбор [{default}]: ")).strip()
        return ans if ans else str(default)

    def pause(msg="Enter — продолжить"): input(dim(msg))
    def yes(q, default=False):
        a = input(q + (" [Y/n]: " if default else " [y/N]: ")).strip().lower()
        return default if not a else a in ("y", "yes", "д", "да")
    def bell(): return "\a" if USE_COLOR else ""

    # ---------- X25519 + симметричное шифрование ----------
    P = 2**255 - 19

    def x25519(k, u):
        """RFC 7748, scalar multiplication on Curve25519."""
        k = bytearray(k); k[0] &= 248; k[31] &= 127; k[31] |= 64
        k = int.from_bytes(k, "little")
        x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
        x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
        for t in reversed(range(255)):
            kt = (k >> t) & 1
            swap ^= kt
            if swap: x2, x3, z2, z3 = x3, x2, z3, z2
            swap = kt
            A, B = x2 + z2, x2 - z2
            AA, BB = A * A % P, B * B % P
            E = AA - BB
            C, D = x3 + z3, x3 - z3
            DA, CB = D * A % P, C * B % P
            x3 = (DA + CB) ** 2 % P
            z3 = x1 * (DA - CB) ** 2 % P
            x2 = AA * BB % P
            z2 = E * (AA + 121665 * E) % P
        if swap: x2, x3, z2, z3 = x3, x2, z3, z2
        out = (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")
        if out == bytes(32): raise ValueError("bad point")
        return out

    BASE = (9).to_bytes(32, "little")
    pubkey = lambda priv: x25519(priv, BASE)
    H = lambda *parts: hashlib.sha512(b"".join(parts)).digest()
    fingerprint = lambda pub: "-".join(hashlib.sha256(pub).hexdigest()[i:i + 4] for i in (0, 4, 8, 12)).upper()

    def _stream(key, nonce, n):
        out, ctr = bytearray(), 0
        while len(out) < n:
            out += hmac.new(key, nonce + ctr.to_bytes(8, "big"), hashlib.sha256).digest()
            ctr += 1
        return bytes(out[:n])

    def seal_sym(k64, data, aad=b""):
        ek, mk = k64[:32], k64[32:]
        nonce = secrets.token_bytes(16)
        ct = bytes(a ^ b for a, b in zip(data, _stream(ek, nonce, len(data))))
        return nonce + ct + hmac.new(mk, aad + nonce + ct, hashlib.sha256).digest()

    def open_sym(k64, blob, aad=b""):
        ek, mk = k64[:32], k64[32:]
        nonce, ct, tag = blob[:16], blob[16:-32], blob[-32:]
        if not hmac.compare_digest(tag, hmac.new(mk, aad + nonce + ct, hashlib.sha256).digest()):
            raise ValueError("bad tag")
        return bytes(a ^ b for a, b in zip(ct, _stream(ek, nonce, len(ct))))

    def sas(*parts):
        n = int.from_bytes(H(b"sas", *parts)[:8], "big") % 1_000_000
        return f"{n:06d}"[:3] + " " + f"{n:06d}"[3:]

    def session_code(k):
        """4 цифры сеанса: совпадают на обоих экранах, только если соединение не подменено."""
        return f"{int.from_bytes(H(b'session', k)[:8], 'big') % 10000:04d}"

    # ---------- форматы SSH ----------
    def sstr(b): return struct.pack(">I", len(b)) + b

    def mpint(n):
        b = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
        return sstr(b"\0" + b if b and b[0] & 0x80 else b)

    def read_str(buf, off):
        n = struct.unpack(">I", buf[off:off + 4])[0]
        return buf[off + 4:off + 4 + n], off + 4 + n

    def der_to_rs(der):
        """ECDSA-подпись Java (DER SEQUENCE{INTEGER r, INTEGER s}) → (r, s)."""
        def length(i):
            n = der[i]
            if n < 0x80: return n, i + 1
            k = n & 0x7F
            return int.from_bytes(der[i + 1:i + 1 + k], "big"), i + 1 + k
        if der[0] != 0x30: raise ValueError("не DER")
        _, i = length(1)
        out = []
        for _ in range(2):
            if der[i] != 0x02: raise ValueError("не DER")
            n, i = length(i + 1)
            out.append(int.from_bytes(der[i:i + n], "big")); i += n
        return out

    def ecdsa_blob(x, y):
        q = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
        return sstr(b"ecdsa-sha2-nistp256") + sstr(b"nistp256") + sstr(q)

    def ecdsa_sig(der):
        r, s = der_to_rs(der)
        return sstr(b"ecdsa-sha2-nistp256") + sstr(mpint(r) + mpint(s))

    # ---------- Ed25519 (резервный ключ из пароля) ----------
    _d = -121665 * pow(121666, P - 2, P) % P
    _I = pow(2, (P - 1) // 4, P)

    def _ed_add(A, B):
        a = (A[1] - A[0]) * (B[1] - B[0]) % P
        b = (A[1] + A[0]) * (B[1] + B[0]) % P
        cc = 2 * A[3] * B[3] * _d % P
        dd = 2 * A[2] * B[2] % P
        e, f, g, h = b - a, dd - cc, dd + cc, b + a
        return (e * f % P, g * h % P, f * g % P, e * h % P)

    def _ed_mul(s, Q):
        R = (0, 1, 1, 0)
        while s:
            if s & 1: R = _ed_add(R, Q)
            Q = _ed_add(Q, Q); s >>= 1
        return R

    def _ed_base():
        y = 4 * pow(5, P - 2, P) % P
        x2 = (y * y - 1) * pow(_d * y * y + 1, P - 2, P) % P
        x = pow(x2, (P + 3) // 8, P)
        if (x * x - x2) % P: x = x * _I % P
        if x & 1: x = P - x
        return (x, y, 1, x * y % P)

    def ed25519_pub(seed):
        h = hashlib.sha512(seed).digest()
        a = int.from_bytes(h[:32], "little") & ((1 << 254) - 8) | (1 << 254)
        X, Y, Z, _ = _ed_mul(a, _ed_base())
        zi = pow(Z, P - 2, P)
        x, y = X * zi % P, Y * zi % P
        return (y | ((x & 1) << 255)).to_bytes(32, "little")

    def openssh_ed25519_private(seed, comment):
        """Незашифрованный ключ в формате OpenSSH — для ssh -i (только во временной памяти)."""
        pk = ed25519_pub(seed)
        pub = sstr(b"ssh-ed25519") + sstr(pk)
        chk = secrets.token_bytes(4)
        priv = chk + chk + pub + sstr(seed + pk) + sstr(comment.encode())
        priv += bytes(range(1, 1 + (-len(priv) % 8)))
        blob = b"openssh-key-v1\0" + sstr(b"none") + sstr(b"none") + sstr(b"") + \
               struct.pack(">I", 1) + sstr(pub) + sstr(priv)
        b64 = base64.b64encode(blob).decode()
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + \
               "\n".join(b64[i:i + 70] for i in range(0, len(b64), 70)) + \
               "\n-----END OPENSSH PRIVATE KEY-----\n"

    RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"  # без 0/O/1/l/I

    def new_recovery_password():
        raw = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(20))
        return "-".join(raw[i:i + 5] for i in range(0, 20, 5))

    def recovery_seed(pw):
        raw = re.sub(r"[\s-]", "", pw)
        return hashlib.scrypt(raw.encode(), salt=b"ssh-storage-recovery-v1",
                              n=2**17, r=8, p=1, maxmem=2**28, dklen=32)

    def recovery_line(seed):
        blob = sstr(b"ssh-ed25519") + sstr(ed25519_pub(seed))
        return f"ssh-ed25519 {base64.b64encode(blob).decode()} {RECOVERY_TAG}"

    # ---------- установка ключей на сервер ----------
    def server_tag(s):
        """Подпись ключа для сервера: <имя>:<ID>:<дата добавления> (у старых записей — только имя или ничего)."""
        return ":".join(str(s[k]) for k in ("nick", "id", "added") if s.get(k)) or None

    def new_id(s):
        """ID и дата добавления — по ним на сервере видно, откуда строка ключа (и лишние строки)."""
        return dict(s, id=secrets.token_hex(3), added=time.strftime("%Y%m%d"))

    def with_nick(line, nick):
        """Ключ телефона с подписью для сервера: ssh-storage-phone[:<ник>]."""
        return line.rsplit(" ", 1)[0] + " " + (f"{PHONE_TAG}:{nick}" if nick else PHONE_TAG)

    def install_cmd(phone_line, rec_line):
        """Команда для сервера: заменить свой ключ телефона (тот же ключ с любым именем или старая подпись),
        добавить резервный; ключи других участников и прочее не трогать."""
        return ("umask 077; mkdir -p ~/.ssh && f=~/.ssh/authorized_keys && touch \"$f\" && "
                f"{{ grep -vF '{phone_line.split()[1]}' \"$f\" | grep -v ' {PHONE_TAG}$'; echo '{phone_line}'; }} > \"$f.new\" && "
                + (f"{{ grep -qF '{rec_line.split()[1]}' \"$f.new\" || echo '{rec_line}' >> \"$f.new\"; }} && " if rec_line else "") +
                "cat \"$f.new\" > \"$f\" && rm -f \"$f.new\" && echo SSH-STORAGE-OK")

    TERM_CMD = "grep -qs 'TERM=xterm-256color' ~/.profile || echo 'export TERM=xterm-256color' >> ~/.profile"

    # Новый VPS: свой drop-in sshd (00- — читается первым, первое значение побеждает, в т.ч. над 50-cloud-init.conf).
    VPS_CONF = "/etc/ssh/sshd_config.d/00-ssh-storage.conf"
    SSHD_RESTART = ("if systemctl is-active -q ssh.socket 2>/dev/null; then systemctl daemon-reload && systemctl restart ssh.socket; "
                    "else systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || service ssh restart; fi")

    def vps_step1(user, old_port, port, install):
        """Шаг 1 (вход паролем, root или sudo): пользователь, ключи телефона, оба порта. Пароль и root пока работают."""
        assert re.fullmatch(LOGIN_RE, user) and port_ok(str(port)) and port_ok(str(old_port))
        root = (f'set -e; command -v apt-get >/dev/null || {{ echo "Нужна Ubuntu / Debian (apt)"; exit 5; }}; '
                f'grep -qsi "^Include /etc/ssh/sshd_config.d/" /etc/ssh/sshd_config || {{ echo "В sshd_config нет Include sshd_config.d"; exit 6; }}; '
                f'apt-get update -qq || true; '
                f'if ! id {user} >/dev/null 2>&1; then adduser --disabled-password --gecos "" {user}; '
                f'echo "Придумайте пароль для sudo пользователя {user}:"; passwd {user}; fi; usermod -aG sudo {user}; '
                f'su - {user} -s /bin/sh -c {shlex.quote(TERM_CMD + "; " + install)}; '
                # чужие строки Port (sshd_config и другие *.conf) — в комментарий с копией *.ssh-storage.bak, иначе старый порт остался бы открыт
                f'for c in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do if [ -f "$c" ] && [ "$c" != {VPS_CONF} ] && '
                f'grep -qi "^[[:space:]]*port[[:space:]]" "$c"; then sed -i.ssh-storage.bak "s/^[[:space:]]*[Pp]ort[[:space:]]/#&/" "$c"; fi; done; '
                f'printf "Port {old_port}\nPort {port}\n" > {VPS_CONF}; sshd -t || {{ rm -f {VPS_CONF}; '
                f'for c in /etc/ssh/sshd_config.ssh-storage.bak /etc/ssh/sshd_config.d/*.ssh-storage.bak; do '
                f'if [ -f "$c" ]; then mv "$c" "''${{c%.ssh-storage.bak}}"; fi; done; exit 7; }}; '
                f'if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then ufw allow {port}/tcp; fi; '
                f'{SSHD_RESTART}')
        return f'S=""; [ "$(id -u)" = 0 ] || S=sudo; $S sh -c {shlex.quote(root)}'

    def vps_step2(port):
        """Шаг 2 (уже ключом телефона на новом порту): только новый порт, без root и паролей.
        Если через 3 мин нет метки ~/.ssh-storage-ok (её ставит следующий вход ключом) — откат к шагу 1."""
        assert port_ok(str(port))
        back = f"sleep 180; [ -f \"$H/.ssh-storage-ok\" ] || {{ mv {VPS_CONF}.bak {VPS_CONF}; {SSHD_RESTART}; }}"
        root = (f'set -e; cp {VPS_CONF} {VPS_CONF}.bak; printf "Port {port}\nPermitRootLogin no\nPubkeyAuthentication yes\n'
                f'PasswordAuthentication no\nKbdInteractiveAuthentication no\n" > {VPS_CONF}; '
                f'sshd -t || {{ mv {VPS_CONF}.bak {VPS_CONF}; exit 7; }}; '
                f'H="$H" setsid nohup sh -c {shlex.quote(back)} >/dev/null 2>&1 </dev/null & sleep 1; {SSHD_RESTART}')
        return f'H=$HOME; rm -f ~/.ssh-storage-ok; S=""; [ "$(id -u)" = 0 ] || S=sudo; $S env H="$H" sh -c {shlex.quote(root)}'

    def keys_cmd(add=(), drop=(), keep=None, backup=True):
        """Команда для сервера: убрать строки с ключами drop; при keep — оставить только строки с этими ключами;
        дописать строки add. Копия — authorized_keys.ssh-storage.bak, запись одной заменой файла."""
        opt = lambda bs: " ".join(f"-e '{b}'" for b in bs)
        drop = list(drop) + [l.split()[1] for l in add]  # без дублей добавляемых ключей
        filt = (f" | grep -vF {opt(drop)}" if drop else "") + (f" | grep -F {opt(keep)}" if keep else "")
        lines = " ".join(shlex.quote(l) for l in add)
        return ("umask 077; mkdir -p ~/.ssh && f=~/.ssh/authorized_keys && touch \"$f\" && "
                + ("cp \"$f\" \"$f.ssh-storage.bak\" && " if backup else "")
                + f"{{ cat \"$f\"{filt}; true; }} > \"$f.new\" && "
                + (f"printf '%s\\n' {lines} >> \"$f.new\" && " if add else "")
                + "cat \"$f.new\" > \"$f\" && rm -f \"$f.new\" && echo SSH-STORAGE-OK")

    def remove_keys_cmd(phone_line, rec_line):
        """Снять ключ телефона (с любым именем) и резервный; остальное не трогать."""
        return keys_cmd(drop=[l.split()[1] for l in (phone_line, rec_line) if l])

    # Отключить на сервере все прочие ключи: закомментировать (не удалять) строки в authorized_keys
    # и authorized_keys2, кроме ключей телефона, резервного и участников команды (S.2: чужие — только через отзыв участника). Копия — *.ssh-storage.bak.
    DISABLE_OLD_CMD = (
        "for f in ~/.ssh/authorized_keys ~/.ssh/authorized_keys2; do [ -f \"$f\" ] || continue; "
        "cp \"$f\" \"$f.ssh-storage.bak\" && "
        f"sed -e '/ {ANY_PHONE_TAG}$/b' -e '/ {RECOVERY_TAG}$/b' -e '/ ssh-storage-member:[^ ]*$/b' -e '/^[[:space:]]*#/b' -e '/^[[:space:]]*$/b' "
        "-e 's/^/# /' \"$f.ssh-storage.bak\" > \"$f.new\" && cat \"$f.new\" > \"$f\" && rm -f \"$f.new\" || exit 1; "
        "done; echo SSH-STORAGE-OK")

    # История сервера (2.1), только чтение. IP вырезаются на сервере и на компьютер не попадают.
    # Ключи → имена: только имя из подписи ssh-storage-phone:<имя>:…, чужие комментарии не передаются.
    LOG_SH = r''''S=""; [ "$(id -u)" = 0 ] || { sudo -n true 2>/dev/null && S="sudo -n"; }
    noip() { sed -E '/a password is required ; .*COMMAND=[^ ]*\/true$/d; s/ from [0-9A-Fa-f.:]+( port [0-9]+)?//; s/ rhost=[^ ]*//; s/^([^ ]+) [^ ]+ /\1 /; s/([0-9]{1,3}\.){3}[0-9]{1,3}/<ip>/g; s/[0-9A-Fa-f:]*::[0-9A-Fa-f:]+/<ip>/g; s/([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}/<ip>/g'; }
    J() { $S journalctl --since "-''${D}d" -o short-iso --no-pager -q "$@" 2>/dev/null; }
    F() { $S cat /var/log/auth.log /var/log/secure 2>/dev/null; }
    A=$(J _COMM=sshd _COMM=sshd-session _COMM=sudo _COMM=su); [ -n "$A" ] || A=$(F)
    echo "==ACCESS=="; [ -n "$S" ] && echo SUDO-NOPW || id -Gn
    ''''
    HISTORY_SH = LOG_SH + r''''echo "==KEYS=="
    for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys ~/.ssh/authorized_keys; do
      $S ssh-keygen -lf "$f" 2>/dev/null | awk '{n="-"; for(i=3;i<=NF;i++) if($i ~ /^ssh-storage-phone:/){split($i,a,":"); n=a[2]} print $2, n}'
    done | sort -u
    echo "==LOGINS=="; printf '%s\n' "$A" | grep -E 'Accepted (publickey|password|keyboard-interactive)' | noip | tail -n $N
    echo "==SUDO=="; printf '%s\n' "$A" | grep -E 'sudo(\[[0-9]+\])?: .*COMMAND=' | noip | tail -n $N
    echo "==SU=="; printf '%s\n' "$A" | grep -E 'su(\[[0-9]+\])?: (\(to |pam_unix\(su(-l)?:session\): session opened)' | noip | tail -n $N
    echo "==PKG=="
    { grep -hE ' (install|upgrade|remove|purge) ' /var/log/dpkg.log 2>/dev/null
      grep -hE '(Installed|Upgraded|Erased|Removed):' /var/log/dnf.rpm.log /var/log/yum.log 2>/dev/null
      grep -hE '\[ALPM\] (installed|upgraded|removed)' /var/log/pacman.log 2>/dev/null; } | tail -n $N
    echo "==ETC=="; $S find /etc -xdev -type f -mtime -$D -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort | tail -n $N
    echo "==END=="''''

    # Попытки взлома (2.3). IP уходят с сервера только у источников с ≥5 неудачными входами или
    # с попытками под несуществующим логином; остальные неудачи — по пользователям, без IP.
    ATTACKS_SH = LOG_SH + r''''echo "==ATTACKS=="
    printf '%s\n' "$A" | awk '
    function add(ip, u, inv) { c[ip]++; if (inv) bad[ip] = 1; if (index(" " us[ip] " ", " " u " ") == 0) us[ip] = us[ip] " " u
      last[ip] = ts; uc[u]++; ul[u] = ts }
    { ts = ($1 ~ /^[0-9]/) ? $1 : $1 "_" $2 "_" $3; pid = match($0, /\[[0-9]+\]:/) ? substr($0, RSTART, RLENGTH) : "" }  # journal (ISO) или auth.log («Oct 23 10:00:00»)
    /Invalid user [^ ]+ from / { match($0, /Invalid user [^ ]+ from [^ ]+/); split(substr($0, RSTART, RLENGTH), w, " ")
      add(w[5], w[3], 1); next }
    /(Connection closed by|Disconnected from) authenticating user [^ ]+ [^ ]+/ { if (pid != "" && pid in fl) next
      match($0, /authenticating user [^ ]+ [^ ]+/); split(substr($0, RSTART, RLENGTH), w, " "); add(w[4], w[3], 0); next }
    /Failed (password|publickey|keyboard-interactive)/ && !/invalid user/ {
      if (match($0, /for [^ ]+ from [^ ]+/)) { split(substr($0, RSTART, RLENGTH), w, " "); add(w[4], w[2], 0); fl[pid] = 1 } }
    END { for (ip in c) if (c[ip] >= 5 || bad[ip]) print "IP", c[ip], ip, (bad[ip] ? "invalid" : "-"), last[ip], us[ip]
          for (u in uc) print "USER", uc[u], u, ul[u] }' | sort -k1,1 -k2,2nr | awk -v N=$N '{ if (++n[$1] <= N) print }'
    echo "==END=="''''

    # Диагностика (2.5), только чтение. Процессы — без аргументов командной строки (там бывают пароли).
    # Не предлагаются: PID 1, sshd, процессы своего сеанса.
    DIAG_SH = LOG_SH + r''''echo "==FAILED=="
    systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}'
    echo "==ERRORS=="; J -p err | noip | tail -n $N
    echo "==PROCS=="
    me=$(ps -o sid= -p $$ | tr -d ' ')
    ps -eo pid=,sid=,user=,pcpu=,pmem=,comm= --sort=-pcpu 2>/dev/null |
      awk -v me="$me" '$1 != 1 && $2 != me && $6 !~ /^sshd/ { print $1, $3, $4, $5, $6 }' | head -n 10
    echo "==END=="''''

    # Проверка процессов, только чтение (нужен root: иначе видны только свои процессы). Аргументы команд не передаются
    # (там бывают пароли) — только имя (comm), argv[0] без пути и настоящий файл программы (/proc/PID/exe).
    # P|pid|ppid|uid|comm|argv0|exe   E|exe|sha256|md5   K|путь из пакета|md5 из dpkg   H|pid|comm (скрыт от ps)
    # L|протокол|порт|процесс   U|uid|имя
    PROC_SH = r''''t=$(mktemp -d) || exit 1; cd /proc || exit 1
    for p in [0-9]*; do
      [ -r "$p/status" ] || continue
      e=$(readlink "$p/exe" 2>/dev/null); [ -n "$e" ] || e=-
      pp=0; u=0; while read -r k v x; do case $k in PPid:) pp=$v;; Uid:) u=$v; break;; esac; done < "$p/status" 2>/dev/null
      read -r c < "$p/comm" 2>/dev/null; a=$(tr '\0' '\n' < "$p/cmdline" 2>/dev/null | head -n 1); a=''${a##*/}
      case "$c$a" in *"|"*) c=$(printf %s "$c" | tr -d '|'); a=$(printf %s "$a" | tr -d '|');; esac
      echo "P|$p|$pp|$u|$c|$a|$e"; [ "$e" = - ] || echo "$e" >> "$t/exe"
    done
    sort -u "$t/exe" 2>/dev/null | while IFS= read -r e; do
      f=''${e% (deleted)}; [ -f "$f" ] || { echo "E|$e|-|-"; continue; }
      echo "E|$e|$(sha256sum < "$f" | cut -c1-64)|$(md5sum < "$f" | cut -c1-32)"; r=''${f#/}; echo "$r"; echo "''${r#usr/}"
    done > "$t/out"
    grep '^E|' "$t/out"; grep -v '^E|' "$t/out" > "$t/want"
    [ -d /var/lib/dpkg/info ] && awk 'NR == FNR { w[$0] = 1; next } ($2 in w) { print "K|" $2 "|" $1 }' "$t/want" /var/lib/dpkg/info/*.md5sums 2>/dev/null
    ps -eo pid= 2>/dev/null | tr -d ' ' | sort > "$t/ps"; ls /proc | grep -E '^[0-9]+$' | sort > "$t/proc"
    comm -13 "$t/ps" "$t/proc" | while read -r p; do
      [ -d "/proc/$p" ] && ! ps -p "$p" >/dev/null 2>&1 && echo "H|$p|$(tr -d '|\n' < "/proc/$p/comm" 2>/dev/null)"
    done
    ss -tulnpH 2>/dev/null | awk '{ n = split($5, a, ":"); m = ""; if (match($0, /\(\("[^"]+"/)) m = substr($0, RSTART + 3, RLENGTH - 4); print "L|" $1 "|" a[n] "|" m }' | sort -u
    awk -F: '{ print "U|" $3 "|" $1 }' /etc/passwd
    rm -rf "$t"; echo "==END=="''''
    SUSPECT_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/", "/home/", "/root/")

    def analyze_procs(out, base):
        """→ (находки [(уровень, exe, текст, [процессы])], скрытые, порты, exe→sha). base: exe→sha256 из «доверять»."""
        rows = [l.split("|") for l in out.splitlines()]
        procs = [f[1:] for f in rows if f[0] == "P" and len(f) == 7]
        exes = {f[1]: (f[2], f[3]) for f in rows if f[0] == "E" and len(f) == 4}
        pkg = {}
        for f in rows:
            if f[0] == "K" and len(f) == 3: pkg.setdefault(f[1], set()).add(f[2])
        users = {f[1]: f[2] for f in rows if f[0] == "U" and len(f) == 3}
        def status(e):
            f = e.removesuffix(" (deleted)").lstrip("/")
            sums = set().union(*(pkg.get(v, set()) for v in (f, f.removeprefix("usr/"), "usr/" + f)))
            return "nopkg" if not sums else "pkg" if exes.get(e, ("-", "-"))[1] in sums else "mod"
        found = {}
        def add(lv, e, why, pr): found.setdefault((e, why), [lv, e, why, []])[3].append(pr)
        for pid, ppid, uid, comm, argv0, e in procs:
            pr = f"{comm} (pid {pid}, {users.get(uid, uid)})"
            if e == "-":
                # настоящий поток ядра: файла программы нет, родитель kthreadd (2); иначе — просто не хватило прав
                continue
            st = status(e)
            if argv0.startswith("[") or comm.startswith("kworker") and st != "pkg":
                add("crit", e, "выдаёт себя за поток ядра (у настоящих нет файла программы)", pr)
            if st == "mod": add("crit", e, "файл программы из пакета изменён — не совпадает с контрольной суммой пакета", pr)
            if e.endswith(" (deleted)"): add("warn", e, "файл программы удалён после запуска (после обновления — норма до перезапуска)", pr)
            if e.startswith(SUSPECT_DIRS): add("warn", e, "запущена из временной / домашней папки", pr)
            name = e.removesuffix(" (deleted)").rsplit("/", 1)[-1]
            if st != "pkg" and comm != name[:15]:
                add("warn", e, f"имя «{comm}» не совпадает с файлом программы «{name}» и программа не из пакета", pr)
            if base is not None:
                sha = exes.get(e, ("-",))[0]
                if e not in base: add("info", e, "новая программа (не было при «доверять»)" + ("" if st == "pkg" else ", не из пакета"), pr)
                elif sha != "-" and base[e] != sha: add("warn", e, "файл программы изменился с момента «доверять»", pr)
        hidden = [f[1:] for f in rows if f[0] == "H" and len(f) == 3]
        ports = [f[1:] for f in rows if f[0] == "L" and len(f) == 4]
        order = {"crit": 0, "warn": 1, "info": 2}
        return sorted(found.values(), key=lambda f: order[f[0]]), hidden, ports, {e: v[0] for e, v in exes.items() if v[0] != "-"}

    # Зачатки неисправностей (2.6), только чтение. Строки «статус|что|подробно», статус ok / warn / crit.
    # Быстрая: диск, inode, только-чтение, память, swap, нагрузка, время. Полная (FULL=1): + OOM, рост ошибок, SSL, обновления.
    HEALTH_SH = r''''o() { echo "$1|$2|$3"; }
    df -P -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null | awk 'NR>1 { u = $5 + 0; s = (u >= 95 ? "crit" : u >= 85 ? "warn" : "ok"); print s "|диск " $6 "|занято " u "%" }'
    df -Pi -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null | awk 'NR>1 && $5 != "-" { u = $5 + 0; if (u >= 85) print (u >= 95 ? "crit" : "warn") "|inode " $6 "|занято " u "% inode" }'
    # только чтение — если у устройства нет ни одного rw-монтирования (bind-ro вроде /nix/store — норма)
    awk '$3 ~ /^(ext[234]|xfs|btrfs|f2fs)$/ { if ($4 ~ /^rw/) rw[$1] = 1; else if ($4 ~ /^ro(,|$)/) ro[$1] = $2 }
      END { for (d in ro) if (!(d in rw)) print "crit|ФС " ro[d] "|смонтирована только на чтение (часто — ошибки диска)" }' /proc/mounts
    awk '/^MemTotal/ { t = $2 } /^MemAvailable/ { a = $2 } /^SwapTotal/ { st = $2 } /^SwapFree/ { sf = $2 }
      END { p = 100 - a * 100 / t; printf "%s|память|занято %d%%\n", (p >= 95 ? "crit" : p >= 85 ? "warn" : "ok"), p
            if (st > 0) { q = 100 - sf * 100 / st; printf "%s|swap|занято %d%%\n", (q >= 80 ? "warn" : "ok"), q } }' /proc/meminfo
    n=$(nproc 2>/dev/null || echo 1); read l1 l5 rest < /proc/loadavg
    awk -v l="$l5" -v n="$n" 'BEGIN { printf "%s|нагрузка|%s за 5 мин на %d ядер\n", (l >= 2 * n ? "crit" : l >= n ? "warn" : "ok"), l, n }'
    if command -v timedatectl >/dev/null 2>&1; then
      [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = yes ] && o ok время "синхронизировано (NTP)" || o warn время "не синхронизировано с NTP — расходятся журналы, TLS, 2FA"
    fi
    if [ "$FULL" = 1 ]; then
      S=""; [ "$(id -u)" = 0 ] || { sudo -n true 2>/dev/null && S="sudo -n"; }
      oom=$($S journalctl -k --since -7d -q --no-pager 2>/dev/null | grep -ci "out of memory")
      [ "''${oom:-0}" -gt 0 ] && o crit OOM "процессы убиты из-за нехватки памяти за 7 дней: $oom" || o ok OOM "за 7 дней не было"
      t=$($S journalctl -p err --since today -q --no-pager 2>/dev/null | wc -l)
      w=$($S journalctl -p err --since -7d --until today -q --no-pager 2>/dev/null | wc -l); avg=$((w / 6))
      [ "$t" -gt $((avg * 2 + 10)) ] && o warn "рост ошибок" "сегодня $t, обычно ~$avg в день" || o ok "ошибки журнала" "сегодня $t, обычно ~$avg в день"
      if command -v openssl >/dev/null 2>&1; then
        for c in $($S sh -c 'ls /etc/letsencrypt/live/*/cert.pem' 2>/dev/null); do
          e=$($S openssl x509 -enddate -noout -in "$c" 2>/dev/null | cut -d= -f2); [ -n "$e" ] || continue
          x=$(date -d "$e" +%s 2>/dev/null); [ -n "$x" ] || continue; d=$(( (x - $(date +%s)) / 86400 ))
          o "$([ $d -lt 3 ] && echo crit || { [ $d -lt 14 ] && echo warn || echo ok; })" "SSL $(basename "$(dirname "$c")")" "истекает через $d дн."
        done
      fi
      u=""
      if command -v apt >/dev/null 2>&1; then u=$(apt list --upgradable 2>/dev/null | grep -ci -- "-security")
      elif command -v dnf >/dev/null 2>&1; then u=$(dnf -q updateinfo list --security 2>/dev/null | wc -l)
      elif command -v checkupdates >/dev/null 2>&1; then u=$(checkupdates 2>/dev/null | wc -l); fi
      [ -n "$u" ] && { [ "$u" -gt 0 ] && o warn "обновления безопасности" "доступно: $u" || o ok "обновления безопасности" "нет"; }
    fi
    echo "==END=="''''

    # Сборщик истории нагрузки: cron раз в 5 мин дописывает строку «время диск% память% swap% нагрузка5мин»
    # в ~/.ssh-storage-metrics. Без sudo и пакетов: два awk и read — доли миллисекунды. Хранится 31 день
    # (~270 КБ): когда первая строка старше 32 дней, файл обрезается до 31 дня (раз в сутки).
    COLLECT_SH = r''''f="$HOME/.ssh-storage-metrics"; n=$(date +%s)
    d=$(df -P / | awk 'NR==2{print $5+0}')
    m=$(awk '/^MemTotal:/{t=$2}/^MemAvailable:/{a=$2}/^SwapTotal:/{st=$2}/^SwapFree:/{sf=$2}END{printf "%d %d", t?100-a*100/t:0, st?100-sf*100/st:0}' /proc/meminfo)
    read l1 l5 x < /proc/loadavg
    echo "$n $d $m $l5" >> "$f"
    read t x < "$f"; if [ $((n - t)) -gt 2764800 ]; then awk -v c=$((n - 2678400)) '$1 >= c' "$f" > "$f.n" && mv "$f.n" "$f"; fi
    ''''
    COLLECT_ON = ('umask 077; c="$HOME/.ssh-storage-collect.sh"; printf "%s" ' + shlex.quote(COLLECT_SH) + ' > "$c" && '
                  '{ crontab -l 2>/dev/null | grep -v ssh-storage-collect; echo "*/5 * * * * sh $c >/dev/null 2>&1"; } | crontab - '
                  '&& sh "$c" && echo SSH-STORAGE-OK')
    COLLECT_OFF = ('{ crontab -l 2>/dev/null | grep -v ssh-storage-collect; true; } | crontab - && '
                   'rm -f "$HOME/.ssh-storage-collect.sh" "$HOME/.ssh-storage-metrics" "$HOME/.ssh-storage-metrics.n" && echo SSH-STORAGE-OK')
    METRICS = ("диск /", "память", "swap", "нагрузка")  # столбцы 1..4 в строке истории

    def show_metric(pts, i, span, cores=1, now=None, width=60, height=8):
        """График столбца i за последние span секунд: в столбце графика — максимум (пики видны); пик, среднее, минимум."""
        now = now or time.time(); t0 = now - span
        v = [(f[0], f[i]) for f in pts if f[0] >= t0]
        print(bold(f"{METRICS[i - 1]} · " + {3600: "последний час", 86400: "сутки"}.get(span, "месяц")))
        if not v: print(yellow("  Нет данных за этот период.")); return
        col = [None] * width
        for t, x in v:
            for k in range(max(0, int((t - 300 - t0) * width / span) + 1), min(width - 1, int((t - t0) * width / span)) + 1):
                col[k] = x if col[k] is None else max(col[k], x)  # точка покрывает свои 5 минут
        top = max(cores, max(x for _, x in v)) if i == 4 else 100
        unit = "" if i == 4 else "%"
        for row in range(height, 0, -1):
            line = "".join(" " if c is None else "█" if c / top * height >= row else
                           ("▁▂▃▄▅▆▇"[min(6, int((c / top * height - row + 1) * 7))] if c / top * height > row - 1 else " ") for c in col)
            print(f"  {top * row / height:>6.1f}{unit} │{line}")
        fmt = "%H:%M" if span <= 86400 else "%d.%m"
        print(f"  {''':>7} └{time.strftime(fmt, time.localtime(t0)):<{width - 5}}{time.strftime(fmt, time.localtime(now))}")
        pk = max(v, key=lambda f: f[1]); xs = [x for _, x in v]
        print(f"\n  Пик:     {bold(f'{pk[1]:g}{unit}')}  {dim(time.strftime('%d.%m %H:%M', time.localtime(pk[0])))}")
        print(f"  Среднее: {sum(xs) / len(xs):.1f}{unit}")
        print(f"  Минимум: {min(xs):g}{unit}")
        if i == 4: print(dim(f"  Нагрузка — средняя за 5 мин; {cores} ядер = загрузка 100%."))
        print(dim(f"  Точек: {len(v)} из ~{span // 300} (пустые места — сервер был выключен или сборщика ещё не было)."))

    def show_health(out):
        icon = {"ok": green("✓"), "warn": yellow("⚠"), "crit": red("✗")}
        rows = [l.split("|", 2) for l in out.splitlines() if l.count("|") >= 2]
        for st, what, info in sorted(rows, key=lambda f: {"crit": 0, "warn": 1}.get(f[0], 2)):
            print(f"  {icon.get(st, '?')} {what:<24} {info}")
        bad = sum(f[0] != "ok" for f in rows)
        print("\n" + (green("Всё в порядке.") if not bad else yellow(f"Требуют внимания: {bad}.")))

    def diag_action_cmd(kind, items):
        """kind: restart (юниты) | TERM | KILL (пары pid, имя). Перед kill — проверка, что PID всё ещё тот же процесс."""
        pre = 'S=""; [ "$(id -u)" = 0 ] || S=sudo; '
        if kind == "restart":
            return pre + "$S systemctl restart " + " ".join(shlex.quote(u) for u in items) + " && echo '✓ перезапущено'"
        return pre + "; ".join(
            f'if [ "$(ps -o comm= -p {int(pid)})" = {shlex.quote(name)} ]; then $S kill -{kind} {int(pid)} && echo "✓ {int(pid)} {name}"; '
            f'else echo "— {int(pid)} {name}: процесс уже завершён или сменился"; fi' for pid, name in items)

    def history_cmd(days=7, n=50, script=None):
        return f"D={int(days)}; N={int(n)}\n" + (script or HISTORY_SH)

    def warn_access(sec):
        if not ({"SUDO-NOPW", "root", "adm", "systemd-journal"} & set(" ".join(sec.get("ACCESS", [])).split())):
            print(yellow("  ⚠ Нет доступа к журналам (нужны группа adm / systemd-journal или sudo без пароля) — данные могут быть неполными.\n"))

    def show_attacks(sec):
        rows = [l.split() for l in sec.get("ATTACKS", [])]
        warn_access(sec)
        t = lambda v: v.replace("T", " ").replace("_", " ")[:16]
        print(bold("Источники атак") + dim("  (IP — только при ≥5 неудачных входах или входе под несуществующим логином)"))
        ips = [f for f in rows if f[0] == "IP"]
        for f in ips or [None]:
            if not f: print("  " + dim("—")); break
            mark = red("несуществующий логин") if f[3] == "invalid" else yellow("≥5 неудач")
            print(f"  {bold(f[2]):<20} {red(f[1] + ' попыт.')}  {mark}  {dim('последняя ' + t(f[4]))}  логины: {' '.join(f[5:])[:80]}")
        print("\n" + bold("Неудачные входы по пользователям") + dim("  (без IP)"))
        for f in [f for f in rows if f[0] == "USER"] or [None]:
            if not f: print("  " + dim("—")); break
            print(f"  {bold(f[2]):<20} {f[1]} попыт.  {dim('последняя ' + t(f[3]))}")

    def parse_history(out):
        """Вывод HISTORY_SH → {раздел: [строки]}."""
        sec, cur = {}, None
        for l in out.splitlines():
            m = re.fullmatch(r"==(\w+)==", l)
            if m: cur = m.group(1); sec[cur] = []
            elif cur and l.strip(): sec[cur].append(l)
        return sec

    def show_history(sec):
        keys = dict(l.split(" ", 1) for l in sec.get("KEYS", []) if " " in l)
        t = lambda l: l.split(" ", 1)[0].replace("T", " ")[:16]
        warn_access(sec)
        print(bold("Входы") + dim("  (кто, когда, чем; без IP)"))
        for l in sec.get("LOGINS", []) or [dim("—")]:
            m = re.search(r"Accepted (\S+) for (\S+)", l)
            if not m: print("  " + l); continue
            fp = re.search(r"(SHA256:\S+)", l)
            nick = keys.get(fp.group(1), "-") if fp else "-"
            how = {"publickey": "ключ", "password": "пароль"}.get(m.group(1), m.group(1))
            who = (cyan(nick) if nick != "-" else dim(fp.group(1)[:20] + "…")) if fp else ""
            print(f"  {dim(t(l))}  {bold(m.group(2))}  {how} {who}")
        print("\n" + bold("sudo-команды"))
        for l in sec.get("SUDO", []) or [dim("—")]:
            m = re.search(r":\s+(\S+) : .*?USER=(\S+) ; COMMAND=(.*)", l)
            print(f"  {dim(t(l))}  {bold(m.group(1))} → {m.group(2)}: {m.group(3)}" if m else "  " + l)
        print("\n" + bold("Смены пользователя (su)"))
        for l in sec.get("SU", []) or [dim("—")]: print(f"  {dim(t(l))}  {l.split(': ', 1)[-1]}" if ": " in l else "  " + l)
        print("\n" + bold("Пакеты"))
        for l in sec.get("PKG", []) or [dim("—")]: print("  " + l)
        print("\n" + bold("Изменённые файлы /etc"))
        for l in sec.get("ETC", []) or [dim("—")]: print("  " + l)

    # auditd (2.2): запись всех запущенных команд с исходным пользователем входа (auid) — видно и после sudo -i/su.
    # Включение: копия /etc/audit, прежнее состояние службы, свои правила в отдельном файле; выключение — откат.
    _AUDIT_PRE = ('S=""; [ "$(id -u)" = 0 ] || S=sudo; '
                  'command -v auditctl >/dev/null 2>&1 || { echo "auditd не установлен. Установите: '
                  'apt install auditd | dnf install audit | pacman -S audit"; exit 3; }; ')
    AUDIT_ON_CMD = _AUDIT_PRE + """$S sh -c 'set -e
    B=/var/lib/ssh-storage; mkdir -p $B
    [ -f $B/auditd.prev ] || { systemctl is-active auditd >/dev/null 2>&1 && echo active || echo inactive; } > $B/auditd.prev
    tar czf $B/audit-backup-$(date +%Y%m%d%H%M%S).tgz -C /etc audit
    echo "копия настроек: $(ls -t $B/audit-backup-*.tgz | head -n 1)"
    printf "%s\\n" "-a always,exit -F arch=b64 -S execve -F auid!=4294967295 -k ssh-storage" "-a always,exit -F arch=b32 -S execve -F auid!=4294967295 -k ssh-storage" > /etc/audit/rules.d/ssh-storage.rules
    systemctl enable --now auditd
    augenrules --load >/dev/null 2>&1 || auditctl -R /etc/audit/rules.d/ssh-storage.rules >/dev/null
    auditctl -l | grep -q ssh-storage
    echo "✓ запись команд включена"'"""
    AUDIT_OFF_CMD = _AUDIT_PRE + """$S sh -c 'B=/var/lib/ssh-storage
    rm -f /etc/audit/rules.d/ssh-storage.rules
    auditctl -D -k ssh-storage >/dev/null 2>&1; augenrules --load >/dev/null 2>&1
    if [ "$(cat $B/auditd.prev 2>/dev/null)" = inactive ]; then
      systemctl disable --now auditd 2>/dev/null || { systemctl disable auditd; service auditd stop; }
      echo "auditd остановлен (был выключен до ssh-storage)"
    fi
    rm -f $B/auditd.prev
    ! auditctl -l 2>/dev/null | grep -q ssh-storage && echo "✓ запись команд выключена, правила ssh-storage сняты"'"""

    def audit_history_cmd(start="week-ago", n=100):
        """Команды из auditd: время, исходный пользователь входа → от чьего имени, команда. Форматирует сервер."""
        return (_AUDIT_PRE + f"$S ausearch -i -k ssh-storage --start {start} 2>/dev/null | awk '"
                r"""/^----/ { if (c != "") print t "  " a " -> " u ":  " c; t = a = u = c = ""; next }
    /type=SYSCALL/ { if (match($0, /audit\([^ ]+ [^.]+/)) t = substr($0, RSTART + 6, RLENGTH - 6)
      for (i = 1; i <= NF; i++) { if ($i ~ /^auid=/) a = substr($i, 6); if ($i ~ /^uid=/) u = substr($i, 5) } }
    /type=PROCTITLE/ { sub(/.*proctitle=/, ""); c = $0 }
    END { if (c != "") print t "  " a " -> " u ":  " c }"""
                + f"' | tail -n {int(n)}")

    # Уровень прав на сервере: печатает одну строку RIGHTS=<уровень>. Ничего не меняет.
    # sudo -n не спрашивает пароль (при отказе sudo пишет строку в журнал сервера — это нормально).
    RIGHTS_CMD = (
        'g=" $(id -Gn 2>/dev/null) "; '
        'if [ "$(id -u)" = 0 ]; then r=root; '
        'elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then r=sudo-nopw; '
        'else case "$g" in *" sudo "*|*" wheel "*|*" admin "*) r=sudo ;; '
        '*" adm "*|*" systemd-journal "*) r=logs ;; *) r=user ;; esac; fi; echo "RIGHTS=$r"')
    RIGHTS = {  # уровень → (название, ранг)
        "root": ("root", 4), "sudo-nopw": ("sudo без пароля", 4), "sudo": ("sudo с паролем", 3),
        "logs": ("доступ к журналам", 2), "user": ("обычный пользователь", 1)}
    NEED = {1: "любые права", 2: "доступ к журналам (группа adm или systemd-journal) или sudo", 3: "root или sudo"}

    # ---------- файлы ----------
    def save_json(path, obj):
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)

    def load_json(path, default):
        if os.path.exists(path):
            with open(path) as f: return json.load(f)
        save_json(path, default)
        return default

    # ---------- сеть ----------
    def send_raw(sock, obj):
        b = json.dumps(obj).encode()
        sock.sendall(struct.pack(">I", len(b)) + b)

    def recv_raw(sock):
        def exact(n):
            buf = b""
            while len(buf) < n:
                ch = sock.recv(n - len(buf))
                if not ch: raise ConnectionError("соединение закрыто")
                buf += ch
            return buf
        n = struct.unpack(">I", exact(4))[0]
        if n > 1 << 20: raise ConnectionError("слишком большое сообщение")
        return json.loads(exact(n))

    class Chan:
        """Зашифрованный канал с номерами сообщений (защита от повтора/перестановки)."""
        def __init__(self, sock, k, me):
            self.sock, self.k, self.me, self.tx, self.rx = sock, k, me, 0, 0
            self.lock = threading.Lock()
        def send(self, obj):
            aad = f"{self.me}{self.tx}".encode(); self.tx += 1
            send_raw(self.sock, {"c": seal_sym(self.k, json.dumps(obj).encode(), aad).hex()})
        def recv(self):
            other = "p" if self.me == "c" else "c"
            aad = f"{other}{self.rx}".encode(); self.rx += 1
            try:
                return json.loads(open_sym(self.k, bytes.fromhex(recv_raw(self.sock)["c"]), aad))
            except (ValueError, KeyError):
                raise ConnectionError("подделка или чужое устройство — соединение разорвано")
        def call(self, obj):
            with self.lock:
                self.send(obj); return self.recv()
        def close(self):
            try: self.sock.close()
            except OSError: pass

    def local_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("10.255.255.255", 1)); return s.getsockname()[0]
        except OSError:
            return "?"
        finally:
            s.close()

    def scan(probe):
        """Параллельно стучится на TCP_PORT всех адресов своей /24 (исходящие соединения)."""
        ip = local_ip()
        if ip == "?": return []
        net = ip.rsplit(".", 1)[0]
        found, lock = [], threading.Lock()
        def run(host):
            r = probe(host)
            if r is not None:
                with lock: found.append(r)
        ts = [threading.Thread(target=run, args=(f"{net}.{i}",), daemon=True)
              for i in range(1, 255) if f"{net}.{i}" != ip]
        for t in ts: t.start()
        for t in ts: t.join()
        return found

    def discover():
        def probe(host):
            try:
                # 3 с: Wi-Fi спящего телефона отвечает на первый пакет (ARP) с задержкой, 1 с часто не хватало
                with socket.create_connection((host, TCP_PORT), timeout=3.0) as sk:
                    sk.settimeout(3.0)
                    send_raw(sk, {"t": "probe"})
                    d = recv_raw(sk)
                    if d.get("app") == "sshstore": d["ip"] = host; return d
            except (OSError, ConnectionError, ValueError):
                return None
        return scan(probe)

    def find_phone(want_fp=None, mode=None):
        for left in (3, 2, 1, 0):  # Enter — искать снова: введённое до этого не теряется
            print(dim("Ищу телефон в сети…"))
            for _ in range(3):  # первый проход часто будит Wi-Fi телефона, отвечает он на следующем
                phones = [p for p in discover() if (not want_fp or p["fp"] == want_fp) and (not mode or p["mode"] == mode)]
                if phones: break
            if len(phones) == 1:
                return phones[0]["ip"], TCP_PORT
            if phones:
                ch = menu([f"{p['name']}  {dim(p['ip'] + '  ' + p['fp'])}" for p in phones])
                if ch.isdigit() and 1 <= int(ch) <= len(phones): return phones[int(ch) - 1]["ip"], TCP_PORT
                return None
            print(yellow("Телефон не найден (та же сеть Wi-Fi? в кафе устройства бывают изолированы)."))
            ip = input(blue("IP телефона (виден на его экране), " +
                            (f"Enter — искать снова (осталось {left}): " if left else "Enter — отмена: "))).strip()
            if ip: return ip, TCP_PORT
        return None

    # ---------- ввод ----------
    host_ok = lambda v: bool(re.fullmatch(r"[A-Za-z0-9\[][A-Za-z0-9.:\[\]_-]*", v))
    user_ok = lambda v: bool(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]*", v))
    port_ok = lambda v: v.isdigit() and 0 < int(v) < 65536

    def ask(label, default=None, required=True, validate=None):
        while True:
            hint = dim(f" [{default}]") if default not in (None, "") else ""
            v = input(f"  {cyan(label)}{hint}: ").strip()
            if not v and default is not None: v = str(default)
            if not v and required: print(red("    обязательное поле")); continue
            if v and validate and not validate(v): print(red("    неверное значение")); continue
            return v

    FIELDS = ("name", "host", "port", "user", "nick", "id", "added", "pending")

    def edit_server(cur=None, servers=()):
        cur = cur or {}
        s = {"name": ask("Название", cur.get("name")),
             "host": ask("IP / хост", cur.get("host"), validate=host_ok),
             "port": int(ask("Порт", cur.get("port", 22), validate=port_ok)),
             "user": ask("Пользователь", cur.get("user", "root"), validate=user_ok)}
        # подпись ключа на сервере: ssh-storage-phone:<имя>:<ID>:<дата>; ID и дата — при создании, дальше не меняются
        s["nick"] = pick_nick(cur, servers)
        return dict(s, id=cur["id"], added=cur["added"]) if cur.get("id") else new_id(s)

    def pick_nick(cur, servers):
        """Имя (обязательно): при изменении — текущее, иначе последнее использованное, или новое."""
        last = next((x["nick"] for x in reversed(servers) if x.get("nick")), None)
        opts = []
        if cur.get("nick"): opts.append((f"Оставить «{cur['nick']}»", cur["nick"]))
        if last and last != cur.get("nick"): opts.append((f"Последнее: «{last}»", last))
        if not opts: return ask("Имя (латиница, цифры, _ -; видно в подписи ключа на сервере)",
                                validate=lambda v: re.fullmatch(NICK_RE, v))
        print(f"  {cyan('Имя (видно в подписи ключа на сервере)')}")
        opts.append(("Новое имя", ""))
        a = menu([o[0] for o in opts], default=1)
        nick = opts[int(a) - 1][1] if a.isdigit() and 1 <= int(a) <= len(opts) else opts[0][1]
        if nick == "": nick = ask("Имя (латиница, цифры, _ -)", validate=lambda v: re.fullmatch(NICK_RE, v))
        return nick

    def parse_servers(text):
        """Строки «имя хост [порт] [пользователь]» → (серверы, ошибки). Пустые и # — пропуск."""
        out, bad = [], []
        for n, line in enumerate(text.splitlines(), 1):
            f = line.split("#", 1)[0].split()
            if not f: continue
            s = {"name": f[0], "host": f[1] if len(f) > 1 else "",
                 "port": int(f[2]) if len(f) > 2 and port_ok(f[2]) else (22 if len(f) < 3 else -1),
                 "user": f[3] if len(f) > 3 else "root"}
            if len(f) > 4 or not server_ok(s): bad.append(f"строка {n}: «{line.strip()}»")
            else: out.append(s)
        return out, bad

    def ssh_config_servers(path="~/.ssh/config"):
        """Хосты из ~/.ssh/config (без шаблонов *?), адрес/порт/пользователь — через ssh -G."""
        path = os.path.expanduser(path)
        if not os.path.isfile(path): return [], [f"нет файла {path}"]
        names = []
        for line in open(path, errors="replace"):
            f = line.split()
            if len(f) > 1 and f[0].lower() == "host":
                names += [h for h in f[1:] if not set("*?!") & set(h) and h not in names]
        lines = []
        for h in names:
            p = subprocess.run([SSH, "-F", path, "-G", h], capture_output=True, text=True)
            g = dict(l.split(" ", 1) for l in p.stdout.splitlines() if " " in l)
            lines.append(f"{h} {h} {g.get('port', 22)} {g.get('user', 'root')}")
        return parse_servers("\n".join(lines))

    def confirm_wipe():
        return input(red("Для подтверждения введите СТЕРЕТЬ: ")).strip().upper() == "СТЕРЕТЬ"

    def first_login():
        """Как один раз зайти на новый сервер, чтобы прописать ключ телефона.
        Возвращает (опции ssh, временная папка для удаления) или (None, None) — отмена.
        Вставленный текстом ключ лежит только в RAM и удаляется сразу после входа."""
        print("\nКак зайти на сервер " + bold("в первый раз") + " (ключа телефона там ещё нет)?")
        ch = menu(["Пароль сервера", "SSH-ключ: путь к файлу или вставить текст ключа",
                   "Автоматически (ключи из ~/.ssh и агента)", "Отмена"])
        if ch == "1":
            return ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive"], None
        if ch == "3": return [], None
        if ch != "2": return None, None
        print(dim("Путь к закрытому ключу (например ~/.ssh/id_ed25519) или вставьте ключ целиком,"))
        print(dim("начиная со строки -----BEGIN … PRIVATE KEY----- (текст ключа на экране не показывается)."))
        key_opts = lambda f: ["-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-i", f]
        while True:
            first = input(blue("Путь или ключ (Enter — отмена): ")).strip()
            if not first: return None, None
            if first.startswith("-----BEGIN") and "PRIVATE KEY" in first:
                lines = [first]
                while not lines[-1].startswith("-----END"):
                    lines.append(getpass.getpass("").strip())
                tmp = tempfile.mkdtemp(prefix="sshstore-", dir=RAM)
                f = os.path.join(tmp, "key")
                with open(os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as fh:
                    fh.write("\n".join(lines) + "\n")
                print(green(f"✓ Ключ принят ({len(lines)} строк), будет удалён после входа"))
                return key_opts(f), tmp
            path = os.path.expanduser(first)
            if os.path.isfile(path): return key_opts(path), None
            print(red("✗ Файл не найден (или вставьте ключ, начиная со строки -----BEGIN)"))

    def reachable(s, timeout=4):
        """До входа: отвечает ли на host:port именно SSH. Возвращает None (всё в порядке) или причину."""
        # адрес — как его увидит ssh (алиасы ~/.ssh/config); через ProxyJump/ProxyCommand напрямую не проверить
        g = subprocess.run([SSH, "-G", "-p", str(s["port"]), s["host"]], capture_output=True, text=True).stdout
        g = dict(l.split(" ", 1) for l in g.splitlines() if " " in l)
        if g.get("proxyjump", "none") != "none" or g.get("proxycommand", "none") != "none": return None
        try:
            with socket.create_connection((g.get("hostname", s["host"]), int(g.get("port", s["port"]))), timeout=timeout) as c:
                c.settimeout(timeout)
                if not c.recv(64).startswith(b"SSH-"): return "не нашёл SSH-сервер на этом порту"
        except socket.gaierror: return "хост не найден (ошибка в имени или DNS)"
        except ConnectionRefusedError: return "порт закрыт (SSH не запущен или другой порт)"
        except (socket.timeout, TimeoutError): return "нет ответа (сервер выключен, файрвол или другая сеть)"
        except OSError as e: return f"нет связи: {e.strerror or e}"
        return None

    def check_reach(s):
        """Проверить доступность с понятным сообщением; при недоступности спросить, продолжать ли."""
        print(dim(f"Проверяю {s['host']}:{s['port']}…"), end=" ", flush=True)
        why = reachable(s)
        if not why: print(green("✓ SSH отвечает")); return True
        print(red(f"✗ {why}"))
        return yes(yellow("Всё равно продолжить?"))

    def server_ok(s):
        return isinstance(s, dict) and host_ok(str(s.get("host", ""))) and user_ok(str(s.get("user", ""))) \
            and port_ok(str(s.get("port", ""))) and isinstance(s.get("name"), str) \
            and ("nick" not in s or bool(re.fullmatch(NICK_RE, str(s["nick"])))) \
            and ("id" not in s or bool(re.fullmatch(r"[0-9a-f]{1,8}", str(s["id"])))) \
            and ("added" not in s or bool(re.fullmatch(r"\d{8}", str(s["added"]))))

    server_line = lambda s: f"{bold(s['name'])}  {dim(s['user'] + '@' + s['host'] + ':' + str(s['port']))}" \
        + (f"  {cyan(s['nick'])}" if s.get("nick") else "") + (dim(f"  #{s['id']}") if s.get("id") else "") \
        + (red("  [ключи не установлены]") if s.get("pending") else "")

    # =====================================================================
    #                              ТЕЛЕФОН
    # =====================================================================
    class Keystore:
        """SSH-ключ в Android Keystore через termux-api: закрытая часть не покидает чип."""
        ALIAS = "ssh-storage"

        @staticmethod
        def available(): return bool(shutil.which("termux-keystore"))

        def _list(self):
            r = subprocess.run(["termux-keystore", "list", "-d"], capture_output=True, text=True, timeout=30)
            try: return {k["alias"]: k for k in json.loads(r.stdout or "[]")}
            except ValueError: return {}

        def ensure(self):
            if self.ALIAS not in self._list():
                print(dim("Создаю ключ в Android Keystore…"))
                subprocess.run(["termux-keystore", "generate", self.ALIAS, "-a", "EC", "-s", "256"],
                               capture_output=True, timeout=60)
            k = self._list().get(self.ALIAS)
            if not k or "x" not in k: raise RuntimeError("Keystore не создал ключ")
            self.blob = ecdsa_blob(int(k["x"], 16), int(k["y"], 16))
            self.hardware = k.get("inside_secure_hardware")

        def sign(self, data):
            r = subprocess.run(["termux-keystore", "sign", self.ALIAS, "SHA256withECDSA"],
                               input=data, capture_output=True, timeout=60)
            if r.returncode or not r.stdout: raise RuntimeError("Keystore не подписал")
            return r.stdout  # DER

        def line(self):
            return f"ecdsa-sha2-nistp256 {base64.b64encode(self.blob).decode()} {PHONE_TAG}"

    class Phone:
        def __init__(self, ks):
            self.d = load_json(PHONE, {"priv": secrets.token_bytes(32).hex(), "peers": {},
                                       "servers": [], "recovery": None})
            self.priv = bytes.fromhex(self.d["priv"])
            self.pub = pubkey(self.priv)
            self.ks, self.mode = ks, "idle"
            ks.ALIAS = self.d.get("alias", Keystore.ALIAS)  # после перевыпуска — новый alias

        def save(self): save_json(PHONE, self.d)

        def log(self, pc, what, result, server=""):
            """Журнал одобрений: последние 500 записей в phone.json."""
            j = self.d.setdefault("log", [])
            j.append({"t": time.strftime("%Y-%m-%d %H:%M"), "pc": pc, "server": server, "what": what, "result": result})
            del j[:-500]; self.save()

        def info(self):
            return {"app": "sshstore", "name": socket.gethostname() or "phone",
                    "fp": fingerprint(self.pub), "mode": self.mode}

        def serve(self, mode):
            self.mode = mode
            srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("", TCP_PORT)); srv.listen(4)
            try:
                while True:
                    what = "сопряжения" if mode == "pair" else "запросы компьютера"
                    print(cyan(f"Жду {what}…  IP: {bold(local_ip())}"))
                    print(dim("Ctrl+C — назад\n"))
                    while True:
                        conn, _ = srv.accept()
                        conn.settimeout(5)  # молчащий клиент не занимает телефон
                        try:
                            msg = recv_raw(conn); conn.settimeout(300)
                        except (ConnectionError, OSError, ValueError):
                            conn.close(); continue
                        if msg.get("t") != "probe": break
                        try: send_raw(conn, self.info())
                        except OSError: pass
                        conn.close()
                    try:
                        if mode == "pair" and msg.get("t") == "pair":
                            if self.pair(conn, msg): return
                        elif mode == "wait" and msg.get("t") == "hello":
                            self.session(conn, msg)
                    except (ConnectionError, OSError, ValueError, KeyError, TypeError, IndexError, RuntimeError) as e:
                        print(red(f"✗ {e}\n"))
                    finally:
                        conn.close()
            except KeyboardInterrupt:
                print()
            finally:
                srv.close(); self.mode = "idle"

        def pair(self, conn, msg):
            cpub, commit = bytes.fromhex(msg["pub"]), bytes.fromhex(msg["commit"])
            name = str(msg.get("name", "компьютер"))[:40]
            nP = secrets.token_bytes(32)
            send_raw(conn, {"pub": self.pub.hex(), "n": nP.hex()})
            nC = bytes.fromhex(recv_raw(conn)["n"])
            if not hmac.compare_digest(H(b"commit", nC), commit):
                raise ConnectionError("нарушен протокол — возможна атака")
            header("сопряжение")
            print(f"  Компьютер: {bold(name)}  {dim(fingerprint(cpub))}\n")
            print(f"  Введите на компьютере код:  {mag(bold(sas(cpub, self.pub, nC, nP)))}\n")
            ok = yes(blue("Компьютер написал «✓ Код верный»?"))
            send_raw(conn, {"ok": ok})
            if not ok or not recv_raw(conn).get("ok"):
                print(red("✗ Сопряжение отменено")); pause(); return False
            ch = Chan(conn, H(b"pair", x25519(self.priv, cpub), nC, nP), "p")
            rec = ch.recv()["recovery"]
            if rec and not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+ " + RECOVERY_TAG, rec): raise ValueError("bad recovery")
            ch.send({"line": self.ks.line()})
            self.d["peers"] = {cpub.hex(): {"name": name}}
            self.d["recovery"] = rec
            self.save()
            print(green(f"\n✓ Сопряжено с «{name}»")); pause()
            return True

        def session(self, conn, msg):
            cpub = bytes.fromhex(msg["id"])
            peer = self.d["peers"].get(cpub.hex())
            if not peer:
                print(yellow("Запрос от незнакомого компьютера — отклонён.\n")); return
            ce = bytes.fromhex(msg["e"])
            pe_priv = secrets.token_bytes(32); pe = pubkey(pe_priv)
            send_raw(conn, {"e": pe.hex()})
            k = H(b"kk", x25519(pe_priv, ce), x25519(pe_priv, cpub), x25519(self.priv, ce), ce, pe)
            ch = Chan(conn, k, "p")
            hello = ch.recv()
            intent, danger = str(hello.get("intent", "?"))[:120], bool(hello.get("danger"))
            print(bell() + bold(f"🔔 «{peer['name']}»: {intent}"))
            if danger: print(red(bold("   ⚠ ОПАСНОЕ ДЕЙСТВИЕ — подтверждайте, только если запускали его сами.")))
            print(f"   Код сеанса:  {mag(bold(session_code(k)))}")
            print(dim("   Разрешайте, только если на компьютере тот же код."))
            allow = yes(blue("Код совпадает, разрешить?"))
            ch.send({"allow": allow})
            pc = peer["name"]
            self.log(pc, intent, "разрешено" if allow else "отклонено")
            if not allow: print(); return
            signs, signed, target, approved, to_delete, pending = 0, False, None, set(), [], None
            while True:
                try: m = ch.recv()
                except (ConnectionError, OSError):
                    if pending and pending["ks"]:  # перевыпуск не завершён — новый ключ не нужен
                        subprocess.run(["termux-keystore", "delete", pending["ks"].ALIAS], capture_output=True, timeout=30)
                    print(dim("  сеанс завершён\n")); return
                t = m.get("t")
                if t == "list":
                    ch.send({"servers": self.d["servers"], "line": self.ks.line(), "recovery": self.d["recovery"],
                             "members": self.d.get("members", [])})
                elif t == "members":
                    mem = [x for x in m.get("members", []) if isinstance(x, str) and re.fullmatch(NICK_RE, x)]
                    self.d["members"] = mem; self.save(); ch.send({"ok": True})
                elif t == "report":
                    # отчёт опасного действия — от компьютера, только для журнала
                    ok, text = bool(m.get("ok")), str(m.get("text", ""))[:200]
                    self.log(pc, f"{intent}: {text}" if text else intent, "выполнен" if ok else "не удался", target or "")
                    print((green("  ✓ ") if ok else red("  ✗ ")) + (text or intent))
                    ch.send({"ok": True})
                elif t == "rekey":
                    new_rec = m.get("recovery")
                    if pending or new_rec and not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+ " + RECOVERY_TAG, new_rec):
                        ch.send({"ok": False}); continue
                    what = ", ".join(w for w, on in (("ключ телефона", m.get("phone")), ("резервный ключ", new_rec)) if on)
                    if not what: ch.send({"ok": False}); continue
                    print(red(bold(f"  ⚠ Перевыпуск: {what} — на всех серверах ({len(self.d['servers'])})")))
                    if m.get("wipe"): print(red("  ⚠ Затереть: на серверах останутся только ключи ssh-storage этого телефона"))
                    for w in m.get("warn", [])[:20]: print(yellow("    ⚠ " + str(w)[:120]))
                    if new_rec: print(yellow("  Старый резервный пароль перестанет работать."))
                    ok = yes(red("  Перевыпустить?"))
                    self.log(pc, f"перевыпуск: {what}" + (", затереть" if m.get("wipe") else ""),
                             "разрешено" if ok else "отклонено")
                    if not ok: ch.send({"ok": False}); continue
                    nks = None
                    if m.get("phone"):
                        nks = Keystore(); nks.ALIAS = f"ssh-storage-{secrets.token_hex(3)}"; nks.ensure()
                    pending = {"ks": nks, "recovery": new_rec}
                    ch.send({"ok": True, "line": nks.line() if nks else None})
                elif t == "rekey_commit":
                    if not pending: ch.send({"ok": False}); continue
                    old = self.ks
                    if pending["ks"]: self.ks = pending["ks"]; self.d["alias"] = self.ks.ALIAS
                    if pending["recovery"]: self.d["recovery"] = pending["recovery"]
                    self.save()
                    if pending["ks"]:
                        subprocess.run(["termux-keystore", "delete", old.ALIAS], capture_output=True, timeout=30)
                    pending = None
                    self.log(pc, "перевыпуск: новые ключи действуют", "выполнен")
                    print(green("  ✓ новые ключи действуют"))
                    ch.send({"ok": True})
                elif t == "journal":
                    ch.send({"log": self.d.get("log", [])})
                elif t == "use":
                    s = self.d["servers"][int(m["i"])]
                    signs = 3; conn.settimeout(60); target = s['name']
                    print(green(f"  → вход на {s['name']} ({s['user']}@{s['host']})"))
                    ch.send({"ok": True})
                elif t == "sign":
                    if signs <= 0: ch.send({"ok": False}); continue
                    signs -= 1
                    ch.send({"ok": True, "sig": self.ks.sign(bytes.fromhex(m["data"])).hex()})
                    if not signed:
                        # сервер просит подпись только если уже согласился принять ключ телефона
                        print(green("  ✓ сервер принял ключ телефона — подпись выдана"))
                        signed = True; conn.settimeout(12 * 3600)  # ждём итог, пока идёт сеанс
                elif t == "add_many":
                    sv = [x for x in m["servers"] if server_ok(x)]
                    print(yellow(f"  Добавить серверы ({len(sv)}):"))
                    for x in sv: print("    " + server_line(x))
                    ok = yes(blue("  Разрешить добавление всех?"), True)
                    if ok: approved = {(x["host"], x["port"], x["user"]) for x in sv}
                    self.log(pc, f"добавить серверы ({len(sv)})", "разрешено" if ok else "отклонено")
                    ch.send({"ok": ok})
                elif t == "delete_many":
                    sv = [x for x in m["servers"] if x in self.d["servers"]]
                    how = "из списка и снять ключи с серверов" if m.get("keys") else "только из списка"
                    print(red(f"  Удалить серверы ({len(sv)}), {how}:"))
                    for x in sv: print("    " + server_line(x))
                    ok = bool(sv) and yes(red("  Удалить?"))
                    to_delete = sv if ok else []
                    self.log(pc, f"удалить серверы ({len(sv)}), {how}", "разрешено" if ok else "отклонено")
                    ch.send({"ok": ok})
                elif t == "delete_done":
                    # удаляем только одобренные в delete_many
                    gone = [x for x in m["servers"] if x in to_delete and x in self.d["servers"]]
                    to_delete = []  # одобрение одноразовое
                    self.d["servers"] = [x for x in self.d["servers"] if x not in gone]; self.save()
                    for x in gone: self.log(pc, "удалить сервер", "выполнен", x["name"])
                    print(green(f"  ✓ удалено из списка: {len(gone)}"))
                    ch.send({"ok": True, "n": len(gone)})
                elif t == "add":
                    s = m["server"]
                    if not server_ok(s): ch.send({"ok": False}); continue
                    ok = (s["host"], s["port"], s["user"]) in approved or yes(blue(f"  Добавить сервер «{s['name']}» ({s['user']}@{s['host']}:{s['port']})?"), True)
                    self.log(pc, "добавить сервер", "разрешено" if ok else "отклонено", s["name"])
                    ch.send({"ok": ok, "line": self.ks.line(), "recovery": self.d["recovery"]})
                elif t in ("edit", "delete"):
                    i, old, sv = int(m["i"]), m.get("old"), self.d["servers"]
                    if not (0 <= i < len(sv)) or sv[i] != old: ch.send({"ok": False}); continue
                    if t == "edit":
                        new = m["server"]
                        if not server_ok(new): ch.send({"ok": False}); continue
                        print(yellow(f"  Изменить сервер с компьютера:"))
                        for k in FIELDS:
                            o, n = old.get(k, "—"), new.get(k, "—")
                            mark = bold(yellow("→ " + str(n))) if n != o else dim("без изменений")
                            print(f"    {k:5} {o}  {mark}")
                        ok = yes(blue("  Сохранить?"), True)
                        if ok: sv[i] = {k: new[k] for k in FIELDS if k in new}; self.save()
                    else:
                        ok = yes(red(f"  Удалить «{old['name']}» ({old['user']}@{old['host']}) из списка?"))
                        if ok: sv.pop(i); self.save()
                    self.log(pc, "изменить сервер" if t == "edit" else "удалить сервер",
                             "разрешено" if ok else "отклонено", old["name"])
                    print(green("  ✓ сохранено") if ok else dim("  отменено"))
                    ch.send({"ok": ok})
                elif t == "result":
                    # сообщает компьютер — только для информации, телефон ничего на этом не разрешает
                    self.log(pc, "вход", "выполнен" if m.get("ok") else "не удался", target or "")
                    if m.get("ok"): print(green(f"  ✓ вход на «{target}» выполнен, сеанс закрыт"))
                    elif not signed: print(red(f"  ✗ вход на «{target}» не удался: сервер не принял ключ телефона или нет связи"))
                    else: print(red(f"  ✗ вход на «{target}» не удался"))
                    ch.send({"ok": True})
                elif t == "added":
                    s = m["server"]
                    if server_ok(s):
                        self.d["servers"] = [x for x in self.d["servers"]
                                             if (x["host"], x["port"], x["user"]) != (s["host"], s["port"], s["user"])]
                        self.d["servers"].append(s); self.save()
                        print(green(f"  ✓ сервер «{s['name']}» сохранён"))
                    ch.send({"ok": True})
                else:
                    ch.send({"ok": False})

        # --- редактирование на телефоне ---
        def servers_menu(self):
            while True:
                header("серверы")
                sv = self.d["servers"]
                adm = self.d["recovery"] != ""  # у участника команды (recovery == "") отзыва нет — это делает админ
                extra = [green("+ Добавить вручную")] + ([red("Отозвать участника (снять ключи)")] if adm else [])
                ch = menu([server_line(s) for s in sv] + extra + [dim("Назад")], default=len(sv) + len(extra) + 1)
                if ch == str(len(sv) + len(extra) + 1): return
                if adm and ch == str(len(sv) + 2): self.revoke_member()
                elif ch == str(len(sv) + 1):
                    header("новый сервер"); s = dict(edit_server(servers=sv), pending=True)
                    sv.append(s); self.save(); self.show_cmd(s)
                elif ch.isdigit() and 1 <= int(ch) <= len(sv):
                    i = int(ch) - 1
                    header(sv[i]["name"])
                    a = menu(["Подключиться", "Изменить", "Команда установки для сервера", "Удалить",
                              "Туннель к веб-панели (3x-ui и др.)", "Назад"], default=1)
                    if a == "1": clear(); self.ssh(sv[i])
                    elif a == "5":
                        port = int(ask("Порт панели на сервере", 2053, validate=port_ok))
                        print(green(f"Откройте в браузере телефона http://127.0.0.1:{port}/  Ctrl+C — закрыть."))
                        print(yellow("Пока туннель открыт, порт доступен и другим приложениям телефона — закройте сразу после работы."))
                        try: self.ssh(sv[i], opts=("-N", "-L", f"127.0.0.1:{port}:127.0.0.1:{port}"))
                        except KeyboardInterrupt: pass
                    elif a == "2": header("изменить"); sv[i] = dict(edit_server(sv[i], sv), **({"pending": True} if sv[i].get("pending") else {})); self.save()
                    elif a == "3": self.show_cmd(sv[i])
                    elif a == "4" and yes(red(f"Удалить «{sv[i]['name']}» из списка?")):
                        sv.pop(i); self.save()

        def ssh(self, s, *cmd, opts=()):
            """Вход прямо с телефона: тот же агент, что и на ПК, но подписывает свой Keystore."""
            if not shutil.which(SSH): print(red("Нет ssh: выполните pkg install openssh")); pause(); return 255
            a = Agent(self.ks.blob, lambda d: ecdsa_sig(self.ks.sign(d)))
            try: return subprocess.call(ssh_cmd(s, "-o", f"IdentityAgent={a.path}", "-o", "IdentitiesOnly=yes",
                                                "-i", a.pubfile(), *(["-t"] if cmd else []), *opts) + list(cmd))
            finally: a.close()

        def revoke_member(self):
            header("отозвать участника")
            sv = [x for x in self.d["servers"] if server_ok(x) and not x.get("pending")]
            known = self.d.get("members", [])
            if not sv: print(yellow("Список серверов пуст.")); pause(); return
            for n, k in enumerate(known, 1): print(f"  {n}. {k}")
            nick = ask("Ник участника (или номер)", validate=lambda v: bool(re.fullmatch(NICK_RE, v)) or v.isdigit() and 1 <= int(v) <= len(known))
            if nick.isdigit() and 1 <= int(nick) <= len(known): nick = known[int(nick) - 1]
            sv = pick_many(sv, "Где отозвать")
            if not sv: return
            print(yellow(f"\nУчастник {nick}: ключи снять, вход заблокировать, сеансы закрыть на: {', '.join(x['name'] for x in sv)}. "
                         "Полное удаление — с компьютера."))
            if not yes(red("Отозвать?")): return
            res = []
            for x in sv:
                print(bold(f"\n→ {x['name']}"))
                res.append((x, {0: "снято", 3: "участника не было"}.get(self.ssh(x, "sh -c " + shlex.quote(revoke_cmd(nick))))))
            self.log("телефон", f"отзыв {nick}", "выполнен" if all(w for _, w in res) else "не удался", "")
            header(f"итог отзыва · {nick}")
            for x, w in res: print(f"  {server_line(x)}  " + (green(w) if w else red("не выполнено — повторите")))
            pause()

        def show_cmd(self, s):
            header("установка на сервер")
            if self.d["recovery"] is None:
                print(yellow("Сначала сопряжение с компьютером (там создаётся резервный пароль).")); pause(); return
            print(f"Выполните на сервере {bold(s['user'] + '@' + s['host'])} (консоль хостинга или текущий вход):\n")
            print(cyan(install_cmd(with_nick(self.ks.line(), server_tag(s)), self.d["recovery"])) + "\n")
            print(dim("Проще: на компьютере ssh-storage → «Серверы» → «Добавить сервер» сделает это сам."))
            pause()

    # Команда ssh-storage — файл в $PREFIX/bin Termux: работает сразу, в любой оболочке, без root
    PHONE_BIN = os.path.join(os.environ.get("PREFIX", "/data/data/com.termux/files/usr"), "bin", "ssh-storage")

    def strip_bashrc():
        """Убрать строки старых версий (обёртка ssh() / alias) из ~/.bashrc."""
        rc = os.path.expanduser("~/.bashrc")
        if not os.path.exists(rc): return
        old = open(rc).read().splitlines()
        lines = [l for l in old if not l.endswith("# ssh-storage")]
        if lines != old:
            with open(rc, "w") as f: f.write("\n".join(lines) + ("\n" if lines else ""))

    def phone_install():
        me = os.path.abspath(__file__)
        os.chmod(HERE, 0o700); os.chmod(me, 0o400)
        strip_bashrc()
        with open(PHONE_BIN, "w") as f:
            f.write(f"#!{os.path.dirname(PHONE_BIN)}/sh\nexec python {shlex.quote(me)} \"$@\"\n")
        os.chmod(PHONE_BIN, 0o755)
        print(green("✓ Установлено. Дальше на телефоне команда ") + bold("ssh-storage"))
        pause()

    def phone_main():
        if "--install" in sys.argv: phone_install()
        if not Keystore.available():
            print(red("Нет termux-keystore."))
            print("Установите приложение " + bold("Termux:API") + " из F-Droid и выполните: " + bold("pkg install termux-api"))
            sys.exit(1)
        ks = Keystore()
        ph = Phone(ks); ks.ensure()
        while True:
            header("телефон")
            print(f"  {dim('отпечаток')}  {fingerprint(ph.pub)}")
            print(f"  {dim('IP')}         {local_ip()}")
            print(f"  {dim('ключ SSH')}   " + (green("в защищённом чипе") if ph.ks.hardware else yellow("в Keystore (без отдельного чипа)")))
            peers = ph.d["peers"]
            for p in peers.values(): print(f"  {dim('сопряжён')}   {green(p['name'])}")
            if not peers: print(f"  {yellow('не сопряжён')}")
            print(f"  {dim('серверов')}   {len(ph.d['servers'])}\n")
            # разделы — как на ПК (кроме «Действий на сервере»: они выполняются с компьютера)
            ch = menu(["Ожидать запросы компьютера", "Серверы", "Сопряжение", "Специальные возможности", "Выход"],
                      default=1 if peers else 3)
            if ch == "1":
                if not peers: print(yellow("Сначала сопряжение.")); pause(); continue
                header("ожидание"); ph.serve("wait")
            elif ch == "2": ph.servers_menu()
            elif ch == "3":
                header("сопряжение")
                a = menu(["Начать сопряжение", "Отменить сопряжение", "Назад"], default=3 if peers else 1)
                if a == "1": header("сопряжение"); ph.serve("pair")
                elif a == "2" and peers and yes(red("Удалить сопряжение с компьютером?")):
                    ph.d["peers"] = {}; ph.save()
            elif ch == "4":
                header("специальные возможности")
                a = menu(["Журнал одобрений", "Мой публичный ключ (отправить админу команды)", "Стереть все данные", "Назад"], default=4)
                if a == "1": header("журнал одобрений"); show_journal(ph.d.get("log", [])); pause()
                elif a == "2": header("публичный ключ"); print(cyan(ph.ks.line()) + "\n"); print(dim("Это не секрет: скопируйте и отправьте админу.")); pause()
                elif a == "3" and phone_wipe(ph.ks): return
            elif ch == "5": clear(); return

    def show_journal(log):
        if not log: print(dim("  Журнал пуст.")); return
        for e in log[-50:]:
            ok = e["result"] in ("разрешено", "выполнен")
            srv = f" · {e['server']}" if e.get("server") else ""
            print(f"  {dim(e['t'])}  {e['pc']}{srv}: {e['what']} — " + (green if ok else red)(e["result"]))
        if len(log) > 50: print(dim(f"  …показаны последние 50 из {len(log)}"))

    def phone_wipe(ks):
        header("стереть данные")
        a = menu(["Стереть серверы и сопряжение (ключ SSH остаётся — серверы будут пускать телефон)",
                  "Стереть всё: и ключ SSH, и приложение",
                  "Назад"], default=3)
        if a == "1":
            print(yellow("\nУдалится список серверов и сопряжение. Потом — новое сопряжение с компьютером."))
            if not confirm_wipe(): return False
            if os.path.exists(PHONE): os.remove(PHONE)
            print(green("✓ Стёрто. Запустите ssh-storage заново.")); return True
        if a == "2":
            print(red(bold("\n⚠ Ключ SSH будет удалён навсегда: НИ ОДИН сервер больше не пустит этот телефон.")))
            print(yellow("  Вернуть доступ можно только резервным паролем (на компьютере → «Специальные возможности» → «Восстановление»)."))
            if not confirm_wipe(): return False
            subprocess.run(["termux-keystore", "delete", ks.ALIAS], capture_output=True, timeout=30)
            if os.path.exists(PHONE): os.remove(PHONE)
            strip_bashrc()
            if os.path.exists(PHONE_BIN): os.remove(PHONE_BIN)
            me = os.path.abspath(__file__)
            if os.path.dirname(me) == HERE:
                os.remove(me)
                try: os.rmdir(HERE)
                except OSError: pass
            print(green("✓ Всё стёрто: ключ, данные и приложение.")); return True
        return False

    # =====================================================================
    #                             КОМПЬЮТЕР
    # =====================================================================
    PHONE_CMD = ("pkg install -y python termux-api && python -c \"import socket,hashlib,os;"
                 "c=socket.create_server((''',47232)).accept()[0];c.send(b'R');d=c.makefile('rb').read();"
                 "print(hashlib.sha256(d).hexdigest()[:16]);input('OK? Enter');"
                 "p=os.path.expanduser('~/.ssh-storage');os.makedirs(p,0o700,1);f=p+'/sshstore.py';"
                 "open(f+'.n','wb').write(d);os.replace(f+'.n',f);os.execvp('python',['python',f,'--install'])\"")

    def install_phone():
        """Передать программу на телефон: компьютер сам подключается (исходящее TCP,
        без открытия портов и без root). Подлинность — 16-значный код на обоих экранах."""
        header("установка на телефон")
        with open(os.path.abspath(__file__), "rb") as f: data = f.read()
        print("Нужно: Termux и " + bold("Termux:API") + " из F-Droid.")
        print("В Termux выполните " + dim("(можно переслать себе в мессенджер)") + ":\n")
        print(cyan(PHONE_CMD) + "\n")
        if shutil.which("qrencode"):  # QR: камерой телефона → «Копировать» → вставить в Termux
            print("Или наведите камеру телефона на QR, скопируйте текст и вставьте в Termux:\n")
            subprocess.run(["qrencode", "-t", "ANSIUTF8", "-m", "2", PHONE_CMD]); print()
        input(blue("Когда телефон ждёт — Enter: "))
        def probe(host):
            try:
                sk = socket.create_connection((host, TCP_PORT), timeout=1.0); sk.settimeout(1.0)
                if sk.recv(1) == b"R": return host, sk
                sk.close()
            except OSError:
                pass
            return None
        while True:
            print(dim("Ищу устройства…"))
            found = scan(probe)
            if found: break
            if not yes(yellow("Устройства не найдены. Искать снова?"), True): return
        header("установка на телефон")
        names = []
        for host, _ in found:
            try: names.append(socket.gethostbyaddr(host)[0])
            except OSError: names.append("устройство")
        ch = menu([f"{n}  {dim(h)}" for n, (h, _) in zip(names, found)] + [dim("Отмена")])
        pick = int(ch) - 1 if ch.isdigit() and 1 <= int(ch) <= len(found) else None
        for i, (_, sk) in enumerate(found):
            if i != pick: sk.close()
        if pick is None: return
        sk = found[pick][1]
        sk.settimeout(30); sk.sendall(data); sk.close()
        print(f"\n  Код проверки:  {mag(bold(hashlib.sha256(data).hexdigest()[:16]))}\n")
        print("Если на телефоне тот же код — нажмите там Enter.")
        print(red("Если код другой — НЕ нажимайте, закройте Termux: файл подменили."))
        pause()

    class Agent:
        """Временный ssh-agent: список ключей и подписи берёт у телефона."""
        def __init__(self, blob, signer):
            self.blob, self.signer = blob, signer
            self.dir = tempfile.mkdtemp(prefix="sshstore-", dir=RAM)
            self.path = os.path.join(self.dir, "agent")
            self.srv = socket.socket(socket.AF_UNIX); self.srv.bind(self.path); self.srv.listen(2)
            os.chmod(self.path, 0o600)
            threading.Thread(target=self._loop, daemon=True).start()

        def _loop(self):
            while True:
                try: conn, _ = self.srv.accept()
                except OSError: return
                threading.Thread(target=self._client, args=(conn,), daemon=True).start()

        def _client(self, conn):
            try:
                while True:
                    hdr = conn.recv(4, socket.MSG_WAITALL)
                    if len(hdr) < 4: return
                    n = struct.unpack(">I", hdr)[0]
                    if n > 1 << 18: return
                    msg = conn.recv(n, socket.MSG_WAITALL)
                    if not msg: return
                    conn.sendall(self._handle(msg))
            except (OSError, struct.error, IndexError):
                pass
            finally:
                conn.close()

        def _handle(self, msg):
            fail = struct.pack(">IB", 1, 5)
            if msg[0] == 11:  # REQUEST_IDENTITIES
                body = struct.pack(">BI", 12, 1) + sstr(self.blob) + sstr(PHONE_TAG.encode())
                return struct.pack(">I", len(body)) + body
            if msg[0] == 13:  # SIGN_REQUEST
                blob, off = read_str(msg, 1)
                data, off = read_str(msg, off)
                if blob != self.blob: return fail
                try: sig = self.signer(data)
                except Exception: return fail
                if not sig: return fail
                body = b"\x0e" + sstr(sig)
                return struct.pack(">I", len(body)) + body
            return fail

        def pubfile(self):
            p = os.path.join(self.dir, "id.pub")
            with open(p, "w") as f:
                f.write(f"ecdsa-sha2-nistp256 {base64.b64encode(self.blob).decode()} {PHONE_TAG}\n")
            return p

        def close(self):
            self.srv.close(); shutil.rmtree(self.dir, ignore_errors=True)

    def pick_many(sv, what):
        """Номера серверов; Enter — все. Пустой список — отмена."""
        for n, x in enumerate(sv, 1): print(f"  {n}. {server_line(x)}")
        while True:
            a = input(blue(f"\n{what}: номера через запятую или пробел (Enter — все, 0 — отмена): ")).strip()
            if not a: return list(sv)
            nums = {int(n) if n.isdigit() else -1 for n in re.split(r"[\s,]+", a)}
            if 0 in nums: return []
            if all(1 <= n <= len(sv) for n in nums): return [sv[n - 1] for n in sorted(nums)]
            print(yellow(f"Только номера от 1 до {len(sv)}."))

    def ssh_cmd(s, *opts):
        return [SSH, "-p", str(s["port"]), "-o", "ForwardAgent=no", *opts, "--", f"{s['user']}@{s['host']}"]

    # Командный режим (S.1): свой Unix-пользователь на человека. Логин — строго по правилам useradd.
    LOGIN_RE = r"[a-z_][a-z0-9_-]{0,31}"
    PUBKEY_RE = r"(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|ssh-rsa|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/]+=*"

    # S.6: роль = группа ssh-storage-<роль> + права: admin — sudo (свой пароль, сменить при первом входе) и журналы;
    # operator / viewer — только чтение журналов (adm, systemd-journal), без sudo.
    ROLES = {"admin": "администратор — sudo и журналы", "operator": "оператор — журналы и sudo systemctl restart/reload",
             "viewer": "наблюдатель — журналы, без sudo"}

    # Общие куски shell для участников (под root, нужны L, N, T, U). Без set -e: busybox (Alpine) не знает usermod/gpasswd/
    # passwd -e, поэтому у шагов запасной вариант, а важные шаги проверяются явно.
    # Реестр /var/lib/ssh-storage/members/<логин> = ник (только root): чей это пользователь, даже если участник стёр метку ключа;
    # <логин>.locked — заблокирован нашим отзывом (снимаем только свою блокировку).
    MEMBER_SH = (
        'R=/var/lib/ssh-storage/members; mkdir -p "$R" && chmod 700 /var/lib/ssh-storage "$R" || exit 1; '
        'grp() { getent group "$1" >/dev/null || groupadd "$1" 2>/dev/null || addgroup "$1" >/dev/null 2>&1; }; '
        'join() { usermod -aG "$1" "$L" 2>/dev/null || addgroup "$L" "$1" >/dev/null 2>&1; }; '
        'leave() { gpasswd -d "$L" "$1" >/dev/null 2>&1 || delgroup "$L" "$1" >/dev/null 2>&1; true; }; '
        'pw() { awk -F: -v u="$L" \'$1==u{print $2}\' /etc/shadow; }; '
        'home() { h=$(getent passwd "$L" | cut -d: -f6); f="$h/.ssh/authorized_keys"; }; '
        'ours() { [ "$L" != root ] && [ "$L" != "$U" ] && id -nG "$L" | grep -Eq "(^| )ssh-storage-(admin|operator|viewer)( |$)"; }; '
        'mine() { [ "$(cat "$R/$L" 2>/dev/null)" = "$N" ] || { [ ! -f "$R/$L" ] && grep -q "$T" "$f" 2>/dev/null; }; }; ')
    LOCK_SH = ('pkill -KILL -u "$L" 2>/dev/null; usermod -L -e 1 "$L" 2>/dev/null || passwd -l "$L" >/dev/null 2>&1; '
               'leave sudo; leave wheel; echo "$N" > "$R/$L"; : > "$R/$L.locked"; pkill -KILL -u "$L" 2>/dev/null; ')
    UNLOCK_SH = ('usermod -U -e "" "$L" 2>/dev/null || usermod -e "" "$L" 2>/dev/null '
                 '|| case "$(pw)" in "!"?*) passwd -u "$L" >/dev/null 2>&1;; esac; ')  # одиночный "!" не трогаем: busybox сделал бы пустой пароль
    STRIP_SH = ('cp "$f" "$f.ssh-storage.bak" && { grep -v "$T" "$f.ssh-storage.bak"; true; } > "$f.new" '
                '&& cat "$f.new" > "$f" && rm -f "$f.new" || exit 1; ')

    # Группа операторов: sudo только на systemctl restart/reload (любой сервис). Файл ставится один раз, проверяется visudo.
    OPERATOR_SUDO_SH = (
        'O=/etc/sudoers.d/ssh-storage-operator; C=$(command -v systemctl); '
        'if [ -n "$C" ] && [ -d /etc/sudoers.d ] && [ ! -f "$O" ]; then '
        'printf "%%ssh-storage-operator ALL=(root) %s restart *, %s reload *\\n" "$C" "$C" > "$O.new" && chmod 440 "$O.new" '
        '&& visudo -cf "$O.new" >/dev/null 2>&1 && mv "$O.new" "$O" || rm -f "$O.new"; fi; ')

    def as_root(script):
        """Выполнить под root (или через sudo); U — кто вызывает, его никогда не трогаем."""
        return f'U=$(id -un); S=""; [ "$(id -u)" = 0 ] || S=sudo; $S env U="$U" sh -c {shlex.quote(script)}'

    def member_vars(nick, login=None):
        assert re.fullmatch(NICK_RE, nick) and (login is None or re.fullmatch(LOGIN_RE, login))
        return (f'L={login}; ' if login else ''') + f'N={nick}; T=" ssh-storage-member:{nick}:"; ' + MEMBER_SH

    def member_cmd(login, key, nick, role="viewer"):
        """Создать участника или обновить своего (тот же ник в реестре): ключ с меткой ssh-storage-member:<ник>, роль
        (группы, sudo только у admin), снять нашу блокировку после отзыва. Чужого пользователя не трогает (exit 4)."""
        assert re.fullmatch(PUBKEY_RE, key) and role in ROLES
        line = f"{key} ssh-storage-member:{nick}:{time.strftime('%Y%m%d')}"  # символы проверены — кавычки не нужны
        sh = (member_vars(nick, login) +
              'if id "$L" >/dev/null 2>&1; then home; ours && mine || { echo "✗ пользователь $L уже есть и это не участник $N — не трогаю"; exit 4; }; new=0; '
              'else useradd -m -s /bin/sh "$L" 2>/dev/null || adduser -D -s /bin/sh "$L" || exit 1; new=1; home; '
              # "!" = заблокирован (sshd без PAM не пустит и по ключу); "*" = пароля нет, вход по ключу работает
              'case "$(pw)" in "!"|"!!") usermod -p "*" "$L" 2>/dev/null || sed -i "s/^$L:!*:/$L:*:/" /etc/shadow;; esac; fi; '
              'echo "$N" > "$R/$L"; mkdir -p "$h/.ssh" || exit 1; '
              f'grep -qF "{key.split()[1]}" "$f" 2>/dev/null || printf "%s\\n" "{line}" >> "$f" || exit 1; '
              'chmod 700 "$h/.ssh"; chmod 600 "$f"; chown -R "$L": "$h/.ssh"; '
              'if [ -f "$R/$L.locked" ]; then ' + UNLOCK_SH + 'rm -f "$R/$L.locked"; fi; '
              f'for g in admin operator viewer; do [ "$g" = {role} ] || leave ssh-storage-$g; done; '
              f'grp ssh-storage-{role}; join ssh-storage-{role}; '
              'for g in adm systemd-journal; do getent group $g >/dev/null && join $g; done; ' + OPERATOR_SUDO_SH +
              # пароль — до выдачи sudo: прерванный ввод не оставит sudo без пароля
              ('case "$(pw)" in ""|"!"*|"*"*) echo "Временный пароль sudo для $L:"; passwd "$L" || exit 1; '
               'if passwd -e "$L" >/dev/null 2>&1 || chage -d 0 "$L" 2>/dev/null; then echo "  $L сменит его при первом входе"; '
               'else echo "  ⚠ сервер не умеет просить смену — попросите $L выполнить passwd"; fi;; esac; '
               'SG=$(getent group sudo >/dev/null && echo sudo || echo wheel); grp $SG; join $SG; '
               # на Arch группа wheel в sudoers часто закомментирована — проверяем, что sudo действительно разрешён
               'sudo -l -U "$L" 2>/dev/null | grep -q "may run" || echo "  ⚠ sudo для $L не работает: в /etc/sudoers не разрешена группа $SG (visudo)"; '
               if role == "admin" else 'leave sudo; leave wheel; ') +
              f'id -nG "$L" | grep -Eq "(^| )ssh-storage-{role}( |$)" || {{ echo "✗ не удалось выдать роль"; exit 1; }}; '
              '[ $new = 1 ] && w=создан || w=обновлён; echo "✓ $w $L ($N): ключ на месте, группы: $(id -nG "$L")"')
        return as_root(sh)

    def revoke_cmd(nick):
        """Отозвать участника: снять ключи с меткой ника у всех (копия *.ssh-storage.bak). Его пользователя (реестр или метка,
        группа ssh-storage-*, не root и не вы) ещё и заблокировать, убрать из sudo, выгнать из сеансов. Файлы остаются."""
        sh = (member_vars(nick) + 'n=0; for L in $(getent passwd | cut -d: -f1); do home; m=0; ours && mine && m=1; t=0; '
              'grep -q "$T" "$f" 2>/dev/null && { ' + STRIP_SH + 't=1; }; '
              'if [ $m = 1 ]; then ' + LOCK_SH + 'echo "✓ $L: ключи сняты, вход заблокирован, сеансы закрыты, sudo снят"; '
              'elif [ $t = 1 ]; then echo "✓ у $L снят только ключ"; else continue; fi; n=$((n+1)); done; [ $n -gt 0 ] || exit 3')
        return as_root(sh)

    def delete_member_cmd(nick):
        """Удалить участника полностью: его пользователя (реестр или метка, группа ssh-storage-*) с домашней папкой —
        в том числе уже отозванного. root и того, кто удаляет, не трогает: у них только снимает ключ."""
        sh = (member_vars(nick) + 'n=0; for L in $(getent passwd | cut -d: -f1); do home; m=0; ours && mine && m=1; '
              'if [ $m = 1 ]; then pkill -KILL -u "$L" 2>/dev/null; sleep 1; userdel -r "$L" 2>/dev/null; '
              'if id "$L" >/dev/null 2>&1; then deluser --remove-home "$L" || exit 1; fi; rm -f "$R/$L" "$R/$L.locked"; '
              'echo "✓ удалён пользователь $L и его папка"; '
              'elif grep -q "$T" "$f" 2>/dev/null; then ' + STRIP_SH + 'echo "✓ у $L снят только ключ (не участник — не удаляю)"; '
              'else continue; fi; n=$((n+1)); done; [ $n -gt 0 ] || exit 3')
        return as_root(sh)

    def ssh_alive(s):
        """Отвечает ли sshd — через сам ssh (работает и с ProxyJump), без входа. Жив — только при явном ответе sshd
        (отказ во входе, нет методов, disconnect, ключ хоста); любая иная ошибка — пока недоступен."""
        p = subprocess.run(ssh_cmd(s, "-o", "BatchMode=yes", "-o", "PreferredAuthentications=none", "-o", "IdentityAgent=none",
                                   "-o", "ConnectTimeout=3") + ["true"], capture_output=True, text=True, timeout=20)
        alive = ("Permission denied", "no supported authentication methods", "Received disconnect", "Disconnected from",
                 "Too many authentication failures", "Host key verification failed", "REMOTE HOST IDENTIFICATION HAS CHANGED")
        return p.returncode != 255 or any(m in p.stderr for m in alive)

    def cleanup_stale():
        base = RAM or tempfile.gettempdir()
        for n in os.listdir(base):
            p = os.path.join(base, n)
            try:
                if n.startswith("sshstore-") and os.path.isdir(p) and os.stat(p).st_uid == os.getuid():
                    shutil.rmtree(p, ignore_errors=True)
            except OSError:
                pass

    class PC:
        def __init__(self):
            self.d = load_json(PC_STATE, {"me": secrets.token_bytes(32).hex(), "phone": None,
                                          "recovery": None, "servers": []})
        def save(self): save_json(PC_STATE, self.d)
        @property
        def me(self): return bytes.fromhex(self.d["me"])

        def sync_members(self, ch, add=None, drop=None):
            m = [x for x in ch.call({"t": "list"}).get("members", []) if re.fullmatch(NICK_RE, x)]
            m += [x for x in self.d.get("members", []) + [add] if x and x not in m and x != drop]
            if drop in m: m.remove(drop)
            ch.call({"t": "members", "members": m}); self.d["members"] = m; self.save()

        def cache(self, servers):
            self.d["servers"] = [s for s in servers if server_ok(s)]; self.save()

        # --- сеанс с телефоном ---
        def session(self, intent, danger=False):
            if not self.d["phone"]:
                print(yellow("Телефон не сопряжён: пункт «Сопряжение» → «Сопряжение с телефоном».")); pause(); return None
            print(dim("На телефоне: ssh-storage → «Ожидать запросы компьютера»."))
            try:
                addr = find_phone(self.d["phone"]["fp"], "wait")
                if not addr: return None
                sock = socket.create_connection(addr, timeout=10); sock.settimeout(300)
                ce_priv = secrets.token_bytes(32); ce = pubkey(ce_priv)
                send_raw(sock, {"t": "hello", "id": pubkey(self.me).hex(), "e": ce.hex()})
                pe = bytes.fromhex(recv_raw(sock)["e"])
                ppub = bytes.fromhex(self.d["phone"]["pub"])
                k = H(b"kk", x25519(ce_priv, pe), x25519(self.me, pe), x25519(ce_priv, ppub), ce, pe)
                ch = Chan(sock, k, "c")
                ch.send({"intent": intent, "danger": danger})
                print(f"\n  Код сеанса:  {mag(bold(session_code(k)))}")
                print(cyan("  Подтвердите на телефоне, если там тот же код…"))
                if not ch.recv().get("allow"):
                    print(red("✗ Отклонено на телефоне")); ch.close(); pause(); return None
                return ch
            except (OSError, ConnectionError, ValueError, KeyError) as e:
                print(red(f"✗ {e}")); pause(); return None

        def ensure_recovery(self):
            if self.d["recovery"] is not None: return
            # S.3: в командном режиме резервный пароль только у админа, участник восстанавливается через админа
            print(dim("«Да» — только если админ команды сам выдал вам доступ. Иначе ответьте «нет»."))
            if yes("Это компьютер участника команды (резервный пароль хранит админ)?", False):
                self.d["recovery"] = ""; self.save(); return
            self.d["recovery"] = self.new_recovery(); self.save()

        def new_recovery(self):
            """Показать новый резервный пароль, проверить ввод; вернуть строку резервного ключа."""
            header("резервный пароль")
            pw = new_recovery_password()
            print("Это единственный способ вернуть доступ, если телефон потеряется или сломается.")
            print("Запишите его на бумагу и храните отдельно. Он больше нигде не сохраняется.\n")
            print(f"     {mag(bold(pw))}\n")
            while True:
                again = getpass.getpass(blue("Введите его для проверки: "))
                if re.sub(r"[\s-]", "", again) == pw.replace("-", ""): break
                print(red("  Не совпадает."))
            clear()
            if USE_COLOR: print("\033[3J", end="", flush=True)
            print(dim("Вычисляю резервный ключ…"))
            return recovery_line(recovery_seed(pw))

        def pair(self):
            self.ensure_recovery()
            header("сопряжение с телефоном")
            print(dim("На телефоне: ssh-storage → «Начать сопряжение».\n"))
            input(blue("Enter — искать телефон: "))
            try:
                addr = find_phone(mode="pair")
                if not addr: return
                sock = socket.create_connection(addr, timeout=10); sock.settimeout(300)
                nC = secrets.token_bytes(32)
                send_raw(sock, {"t": "pair", "pub": pubkey(self.me).hex(), "commit": H(b"commit", nC).hex(),
                                "name": socket.gethostname()})
                r = recv_raw(sock)
                ppub, nP = bytes.fromhex(r["pub"]), bytes.fromhex(r["n"])
                send_raw(sock, {"n": nC.hex()})
                code = sas(pubkey(self.me), ppub, nC, nP)
                header("сопряжение с телефоном")
                print(f"  Телефон: {dim(fingerprint(ppub))}\n")
                ok = False
                for _ in range(3):
                    if re.sub(r"\D", "", input(blue("Код с экрана телефона: "))) == code.replace(" ", ""):
                        ok = True; print(green(bold("✓ Код верный")) + dim("  — подтвердите на телефоне")); break
                    print(red("✗ Не совпадает"))
                if not ok: print(red("Если вводили правильно — кто-то вмешивается в соединение."))
                send_raw(sock, {"ok": ok})
                if not ok or not recv_raw(sock).get("ok"):
                    print(red("✗ Сопряжение отменено")); pause(); return
                ch = Chan(sock, H(b"pair", x25519(self.me, ppub), nC, nP), "c")
                ch.send({"recovery": self.d["recovery"]})
                ch.recv()
                self.d["phone"] = {"pub": ppub.hex(), "fp": fingerprint(ppub)}; self.save()
                sock.close()
                print(green("\n✓ Телефон сопряжён"))
                print("Дальше: «Серверы» → «Добавить сервер» — ключ телефона пропишется на сервер."); pause()
            except (OSError, ConnectionError, ValueError, KeyError) as e:
                print(red(f"✗ {e}")); pause()

        # --- подключение ---
        def connect(self):
            header("подключение")
            ch = self.session("вход на сервер")
            if not ch: return
            try:
                r = ch.call({"t": "list"})
                servers = [s for s in r["servers"] if server_ok(s)]
                self.cache(servers)
                if not servers:
                    print(yellow("На телефоне нет серверов. Добавьте: «Серверы» → «Добавить сервер».")); pause(); return
                header("серверы")
                pick = menu([server_line(s) for s in servers] + [dim("Отмена")])
                if not (pick.isdigit() and 1 <= int(pick) <= len(servers)): return
                s = servers[int(pick) - 1]
                if not check_reach(s): return
                clear(); print(green(f"→ {s['user']}@{s['host']}:{s['port']}  {dim('(подпись — на телефоне)')}\n"))
                rc, _ = self.phone_ssh(ch, s)
                try: ch.call({"t": "result", "ok": rc != 255})  # 255 — ошибка самого ssh (вход/связь)
                except (OSError, ConnectionError, ValueError): pass
                pause()
            except (OSError, ConnectionError, ValueError, KeyError) as e:
                print(red(f"✗ {e}")); pause()
            finally:
                ch.close()

        # --- серверы: правка несекретных данных (сохраняет телефон, после подтверждения) ---
        def servers(self):
            header("серверы")
            ch = self.session("изменить список серверов")
            if not ch: return
            try:
                while True:
                    r = ch.call({"t": "list"})
                    sv = r["servers"]; self.cache(sv)
                    header("серверы")
                    pick = menu([server_line(x) for x in sv] + [dim("Назад")], default=len(sv) + 1)
                    if not (pick.isdigit() and 1 <= int(pick) <= len(sv)): return
                    i = int(pick) - 1; s = sv[i]
                    header(s["name"])
                    a = menu(["Изменить (название, хост, порт, пользователь, имя)", "Команда установки для сервера",
                              "Удалить из списка", "Обновить ключи на сервере (имя в подписи, резервный ключ)",
                              "Назад"], default=5)
                    if a == "1":
                        header("изменить"); new = edit_server(s, sv)
                        if s.get("pending"): new["pending"] = True
                        print(cyan("Подтвердите изменение на телефоне…"))
                        ok = ch.call({"t": "edit", "i": i, "old": s, "server": new}).get("ok")
                        print(green("✓ Сохранено") if ok else red("✗ Не сохранено (отклонено на телефоне)"))
                        if ok and new.get("nick") != s.get("nick"):
                            print(dim("Имя в подписи ключа на сервере сменится после «Обновить ключи на сервере»."))
                        pause()
                    elif a == "2":
                        header("установка на сервер")
                        print(f"Выполните на сервере {bold(s['user'] + '@' + s['host'])}:\n")
                        print(cyan(install_cmd(with_nick(r["line"], server_tag(s)), r["recovery"])) + "\n"); pause()
                    elif a == "4":
                        # вход ключом телефона и та же команда установки: ключ с текущим именем, резервный — если нет
                        cmd = install_cmd(with_nick(r["line"], server_tag(s)), r["recovery"])
                        rc, out = self.phone_ssh(ch, s, "sh -c " + shlex.quote(cmd))
                        ok = "SSH-STORAGE-OK" in (out or "")
                        if ok and s.get("pending"):
                            s = {k: v for k, v in s.items() if k != "pending"}
                            ch.call({"t": "added", "server": s})
                        try: ch.call({"t": "report", "ok": ok, "text": "обновить ключи на сервере"})
                        except (OSError, ConnectionError, ValueError): pass
                        print(green("✓ Ключи на сервере обновлены") if ok else red("✗ Не удалось (вход или запись ключей)"))
                        pause()
                    elif a == "3" and yes(red(f"Удалить «{s['name']}» из списка?")):
                        print(cyan("Подтвердите удаление на телефоне…"))
                        ok = ch.call({"t": "delete", "i": i, "old": s}).get("ok")
                        print(green("✓ Удалено") if ok else red("✗ Отклонено на телефоне")); pause()
            except (OSError, ConnectionError, ValueError, KeyError) as e:
                print(red(f"✗ {e}")); pause()
            finally:
                ch.close()

        # --- разделы меню ---
        def pick_server(self, title):
            """Выбор сервера из сохранённого списка (копия с телефона) с отметкой прав."""
            sv = [x for x in self.d["servers"] if server_ok(x)]
            if not sv:
                print(yellow("Список серверов пуст. Добавьте: «Серверы» → «Добавить сервер».")); pause(); return None
            header(title)
            pick = menu([f"{server_line(x)}  {dim('[' + self.rights_label(x) + ']')}" for x in sv] + [dim("Назад")],
                        default=len(sv) + 1)
            return sv[int(pick) - 1] if pick.isdigit() and 1 <= int(pick) <= len(sv) else None

        def section_servers(self):
            while True:
                header("серверы")
                # участнику команды (recovery == "") управление участниками не показываем — это делает админ
                # участнику команды (recovery == "") не показываем «Новый VPS» (у него нет резервного ключа — при потере телефона
                # сервер без паролей закроется насовсем) и управление участниками (это делает админ)
                adm = self.d["recovery"] != ""
                items = [("Список серверов (изменить / команда установки / удалить)", self.servers), ("Добавить сервер", self.add)] \
                    + ([("Новый VPS: настроить с нуля", self.new_vps)] if adm else []) \
                    + [("Массовое добавление", self.bulk_add), ("Массовое удаление", self.bulk_delete),
                       ("Перевыпуск ключей (на всех серверах)", self.rekey)] \
                    + ([("Участники серверов (командный режим)", self.members_menu)] if adm else [])
                a = menu([t for t, _ in items] + ["Назад"], default=1)
                if not (a.isdigit() and 1 <= int(a) <= len(items)): return
                items[int(a) - 1][1]()

        def members_menu(self):
            b = menu(["Добавить участника на серверы", "Отозвать или удалить участника", "Назад"], default=1)
            if b == "1": self.add_member_many()
            elif b == "2": self.revoke_member()

        def section_pairing(self):
            while True:
                header("сопряжение")
                a = menu(["Сопряжение с телефоном", "Установить / обновить приложение на телефоне", "Назад"], default=1)
                if a == "1": self.pair()
                elif a == "2": install_phone()
                else: return

        ACTIONS = [  # (название, нужный ранг прав)
            ("История (входы, sudo-команды, пакеты, изменения /etc)", 2),
            ("Запись команд auditd (включить / история / выключить)", 3),
            ("Попытки взлома (неверные входы, несуществующие логины, частые IP)", 2),
            ("Диагностика (упавшие сервисы, ошибки журнала, процессы)", 1),
            ("Проверка на зачатки неисправностей (быстрая / полная)", 1),
            ("Перезагрузить сервер", 3),
            ("Создать пользователя для участника (командный режим)", 3),
            ("Проверка процессов (подмена системных, новые программы, скрытые процессы)", 1),
            ("Туннель к веб-панели (3x-ui и др.) — панель не торчит в интернет", 1)]

        def section_actions(self):
            s = self.pick_server("действия на сервере")
            if not s: return
            while True:
                lv = self.rights(s); rank = RIGHTS[lv][1] if lv else 0
                header(f"действия · {s['name']}")
                print(f"  {dim(self.skey(s))} · права: {bold(self.rights_label(s))}\n")
                items = []
                for name, need in self.ACTIONS:
                    mark = "" if rank >= need or not lv else yellow(f"  (нужно: {NEED[need]})")
                    items.append(name + mark + ("" if name.startswith(("История", "Запись", "Попытки", "Диагностика", "Проверка", "Перезагрузить", "Создать", "Туннель")) else dim("  — в разработке")))
                items += ["Проверить права на сервере", "Назад"]
                a = menu(items, default=len(items) - 1)
                if a == str(len(items) - 1):
                    ch = self.session(f"проверить права на {s['name']}")
                    if not ch: continue
                    try:
                        rc, _ = self.phone_ssh(ch, s, "true")
                        try: ch.call({"t": "result", "ok": rc != 255})
                        except (OSError, ConnectionError, ValueError): pass
                        print(green(f"✓ Права: {self.rights_label(s)}") if rc != 255 else red("✗ Вход не удался"))
                    except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e:
                        print(red(f"✗ {e or 'сервер не найден в списке телефона'}"))
                    finally: ch.close()
                    pause()
                elif a.isdigit() and 1 <= int(a) <= len(self.ACTIONS):
                    need = self.ACTIONS[int(a) - 1][1]
                    if lv and rank < need:
                        print(yellow(f"Недостаточно прав. Нужно: {NEED[need]}."))
                        print(dim("Права определяются при каждом входе; если их добавили — «Проверить права»."))
                    elif a == "1": self.history(s)
                    elif a == "2": self.audit(s); continue
                    elif a == "3": self.history(s, ATTACKS_SH, show_attacks, "попытки взлома")
                    elif a == "4": self.diagnose(s); continue
                    elif a == "5": self.health(s); continue
                    elif a == "6": self.reboot(s); continue
                    elif a == "7" and self.d["recovery"] == "": print(yellow("Участников добавляет админ команды."))
                    elif a == "7": self.add_member(s); continue
                    elif a == "8": self.check_procs(s); continue
                    elif a == "9": self.tunnel(s); continue
                    else:
                        print(yellow("Этот пункт в разработке (этап 2)."))
                    pause()
                else: return

        def history(self, s, script=None, show=None, title="история"):
            days = ask("За сколько дней", 7, validate=lambda v: v.isdigit() and 0 < int(v) <= 365)
            ch = self.session(f"{title} {s['name']} (только чтение)")
            if not ch: return
            try:
                rc, out = self.phone_ssh(ch, s, "sh -c " + shlex.quote(history_cmd(days, script=script)))
                try: ch.call({"t": "result", "ok": rc != 255})
                except (OSError, ConnectionError, ValueError): pass
                if rc == 255 or "==END==" not in (out or ""): print(red("✗ Не удалось получить историю")); return
                header(f"{title} · {s['name']} · {days} дн.")
                (show or show_history)(parse_history(out))
            except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e: print(red(f"✗ {e}"))
            finally: ch.close()

        def audit(self, s):
            while True:
                header(f"запись команд · {s['name']}")
                print(dim("  auditd записывает каждую запущенную команду с исходным пользователем входа —"))
                print(dim("  видно, кто на самом деле работал, даже после sudo -i / su. Нужен root или sudo.\n"))
                a = menu(["Включить запись команд", "История команд", "Выключить (откат к прежним настройкам)", "Назад"],
                         default=2)
                if a == "1":
                    print(yellow("Будут записываться команды ВСЕХ пользователей сервера с аргументами (в т.ч. пароль, если его набрать\n"
                                 "прямо в команде: mysql -pПАРОЛЬ). Читать журнал может любой с sudo. Предупредите участников."))
                    if not yes("Включить?"): continue
                    self.danger("включить запись команд (auditd)", s,
                                lambda ch: (self.phone_ssh(ch, s, "sh -c " + shlex.quote(AUDIT_ON_CMD), tty=True)[0] == 0,
                                            "запись команд включена"))
                elif a == "3":
                    self.danger("выключить запись команд (auditd), откат", s,
                                lambda ch: (self.phone_ssh(ch, s, "sh -c " + shlex.quote(AUDIT_OFF_CMD), tty=True)[0] == 0,
                                            "запись команд выключена"))
                elif a == "2":
                    p = menu(["Сегодня", "Неделя", "Месяц"], default=2)
                    start = {"1": "today", "3": "this-month"}.get(p, "week-ago")
                    ch = self.session(f"история команд {s['name']} (только чтение)")
                    if not ch: continue
                    try:
                        header(f"история команд · {s['name']}")
                        print(dim("время  исходный пользователь -> от чьего имени:  команда\n"))
                        rc, _ = self.phone_ssh(ch, s, "sh -c " + shlex.quote(audit_history_cmd(start)), tty=True)
                        try: ch.call({"t": "result", "ok": rc != 255})
                        except (OSError, ConnectionError, ValueError): pass
                    except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e: print(red(f"✗ {e}"))
                    finally: ch.close()
                    pause()
                else: return

        def health(self, s):
            full = menu(["Быстрая (диск, память, нагрузка, время)",
                         "Полная (+ OOM, рост ошибок, SSL-сертификаты, обновления безопасности)"], default=1) == "2"
            ch = self.session(f"проверка {s['name']} (только чтение)")
            if not ch: return
            try:
                rc, out = self.phone_ssh(ch, s, "sh -c " + shlex.quote(f"FULL={int(full)}\n" + HEALTH_SH +
                                                                       "\ncat ~/.ssh-storage-metrics 2>/dev/null; echo ==METRICS=="))
                try: ch.call({"t": "result", "ok": rc != 255})
                except (OSError, ConnectionError, ValueError): pass
                if rc == 255 or "==END==" not in (out or ""): print(red("✗ Не удалось выполнить проверку")); return
                header(f"проверка · {s['name']} · {'полная' if full else 'быстрая'}")
                out, hist = out.split("==END==", 1)
                show_health(out)
            except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e: print(red(f"✗ {e}")); return
            finally: ch.close()
            pts = [[float(x) for x in l.split()] for l in hist.splitlines() if re.fullmatch(r"\d+ \d+ \d+ \d+ [\d.]+", l)]
            m = re.search(r"на (\d+) ядер", out); cores = int(m[1]) if m else 1
            while True:
                print()
                a = menu([f"График: {x}" for x in METRICS] +
                         ["Сборщик истории: " + ("удалить (и всю историю)" if pts else "установить (графики за час / сутки / месяц)"), "Назад"],
                         default=6)
                if a in ("1", "2", "3", "4"):
                    if not pts: print(yellow("История пуста: установите сборщик (пункт 5). Первые точки — через 5 минут.")); continue
                    p = menu(["Последний час", "Сутки", "Месяц"], default=2)
                    header(f"история · {s['name']}")
                    show_metric(pts, int(a), {"1": 3600, "3": 31 * 86400}.get(p, 86400), cores); pause()
                elif a == "5":
                    on = not pts
                    if not on and not yes(red("Удалить сборщик и всю накопленную историю?")): continue
                    self.danger(("установить" if on else "удалить") + " сборщик истории нагрузки", s,
                                lambda ch: ("SSH-STORAGE-OK" in (self.phone_ssh(ch, s, "sh -c " + shlex.quote(COLLECT_ON if on else COLLECT_OFF))[1] or ""),
                                            "сборщик установлен: точка раз в 5 мин, хранится 31 день" if on else "сборщик и история удалены"))
                    return
                else: return

        def diagnose(self, s):
            ch = self.session(f"диагностика {s['name']} (только чтение)")
            if not ch: return
            try:
                rc, out = self.phone_ssh(ch, s, "sh -c " + shlex.quote(history_cmd(1, 30, script=DIAG_SH)))
                try: ch.call({"t": "result", "ok": rc != 255})
                except (OSError, ConnectionError, ValueError): pass
            except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e: print(red(f"✗ {e}")); pause(); return
            finally: ch.close()
            if rc == 255 or "==END==" not in (out or ""): print(red("✗ Не удалось получить данные")); pause(); return
            sec = parse_history(out)
            units = [u for u in sec.get("FAILED", []) if re.fullmatch(r"[\w@.:-]+", u) and not u.startswith(("sshd", "ssh."))]
            procs = [l.split() for l in sec.get("PROCS", [])]
            procs = [f for f in procs if len(f) == 5 and f[0].isdigit()]
            header(f"диагностика · {s['name']}")
            print(bold("Упавшие сервисы"))
            for n, u in enumerate(units, 1): print(f"  {n:>2}. {red(u)}")
            if not units: print(green("  нет"))
            print("\n" + bold("Ошибки журнала за сутки") + dim("  (последние 30, без IP)"))
            for l in sec.get("ERRORS", []) or [green("нет")]: print("  " + l[:160])
            print("\n" + bold("Процессы с наибольшей нагрузкой") + dim("  (PID 1, sshd и свой сеанс не показаны)"))
            for n, f in enumerate(procs, len(units) + 1):
                print(f"  {n:>2}. {f[4]:<20} {dim('pid')} {f[0]:<7} {dim('польз.')} {f[1]:<10} cpu {f[2]}%  mem {f[3]}%")
            print()
            a = menu(["Перезапустить сервисы (номера)", "Остановить процессы — SIGTERM (номера)",
                      "Убить процессы принудительно — SIGKILL (номера)", "Назад"], default=4)
            if a not in ("1", "2", "3"): return
            nums = {int(n) for n in re.split(r"[\s,]+", input(blue("Номера через запятую или пробел: ")).strip()) if n.isdigit()}
            if a == "1": items = [units[n - 1] for n in sorted(nums) if 1 <= n <= len(units)]
            else: items = [(procs[n - 1 - len(units)][0], procs[n - 1 - len(units)][4]) for n in sorted(nums)
                           if len(units) < n <= len(units) + len(procs)]
            if not items: print(yellow("Нет подходящих номеров.")); pause(); return
            kind = {"1": "restart", "2": "TERM", "3": "KILL"}[a]
            what = {"restart": "перезапустить", "TERM": "остановить (SIGTERM)", "KILL": "убить (SIGKILL)"}[kind]
            print(yellow(f"\nБудет {what}:"))
            for x in items: print("  " + (x if kind == "restart" else f"{x[1]} (pid {x[0]})"))
            if kind == "KILL": print(red("SIGKILL не даёт процессу сохранить данные — только если SIGTERM не помог."))
            if not yes(red("Выполнить?")): return
            names = ", ".join(x if kind == "restart" else x[1] for x in items)
            self.danger(f"{what}: {names}"[:100], s,
                        lambda ch: (self.phone_ssh(ch, s, "sh -c " + shlex.quote(diag_action_cmd(kind, items)), tty=True)[0] == 0,
                                    f"{what}: {names}"[:150]))

        def section_special(self):
            while True:
                header("специальные возможности")
                items = ["Восстановление по резервному паролю"]
                if os.path.exists(LEGACY_VAULT): items.append("Перенести старые подключения (vault.json)")
                items += ["Журнал одобрений (с телефона)", "Стереть все данные", "Назад"]
                a = menu(items, default=len(items))
                act = items[int(a) - 1] if a.isdigit() and 1 <= int(a) <= len(items) else "Назад"
                if act.startswith("Восстановление"):
                    if self.d["recovery"] == "": print(yellow("Вы участник команды: доступ восстанавливает админ (добавит ваш новый ключ).")); pause()
                    else: self.recovery()
                elif act.startswith("Перенести"): self.migrate()
                elif "Журнал" in act: self.journal()
                elif act == "Стереть все данные":
                    if pc_wipe(): return "wiped"
                else: return

        def ask_member(self):
            print(dim("  У каждого участника свой Unix-пользователь и свой ключ — в журналах видно, кто что делал.\n"))
            login = ask("Логин на сервере (a-z, 0-9, _ -)", validate=lambda v: bool(re.fullmatch(LOGIN_RE, v)))
            nick = ask("Ник участника (для метки ключа)", login, validate=lambda v: bool(re.fullmatch(NICK_RE, v)))
            key = " ".join(ask("Публичный ключ участника (строка ssh-ed25519 …)",
                               validate=lambda v: bool(re.fullmatch(PUBKEY_RE, " ".join(v.split()[:2])))).split()[:2])
            print(dim("  Роль задаёт права. Администратору sudo нужен только если он ставит пакеты и правит системные файлы."))
            a = menu(list(ROLES.values()), default=3)
            role = list(ROLES)[int(a) - 1] if a in ("1", "2", "3") else "viewer"
            return login, nick, key, role

        def add_member(self, s):
            header(f"новый пользователь · {s['name']}")
            login, nick, key, role = self.ask_member()
            print(yellow(f"\nБудет создан пользователь {login} на {s['name']} с ключом участника {nick}."))
            if not yes(red("Выполнить?")): return
            def run(ch):
                ok = self.phone_ssh(ch, s, "sh -c " + shlex.quote(member_cmd(login, key, nick, role)), tty=True)[0] == 0
                if ok: self.sync_members(ch, add=nick)
                return ok, f"создан пользователь {login} ({nick})"
            self.danger(f"создать пользователя {login} ({nick})", s, run)

        def check_procs(self, s):
            ch = self.session(f"проверка процессов {s['name']} (только чтение)")
            if not ch: return
            f = "~/.ssh-storage-proc.out"
            try:
                # sudo может спросить пароль — поэтому вывод в файл (umask 077), затем отдельным чтением без tty
                self.phone_ssh(ch, s, "sh -c " + shlex.quote(f'umask 077; S=""; [ "$(id -u)" = 0 ] || S=sudo; '
                                                              f'$S sh -c {shlex.quote(PROC_SH)} > {f}'), tty=True)
                rc, out = self.phone_ssh(ch, s, f"cat {f} 2>/dev/null; rm -f {f}")
                try: ch.call({"t": "result", "ok": rc != 255})
                except (OSError, ConnectionError, ValueError): pass
            except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e: print(red(f"✗ {e}")); pause(); return
            finally: ch.close()
            if "==END==" not in (out or ""): print(red("✗ Не удалось выполнить проверку (нужен root или sudo)")); pause(); return
            bases = self.d.setdefault("proc_base", {}); base = bases.get(self.skey(s))
            found, hidden, ports, shas = analyze_procs(out, base)
            header(f"проверка процессов · {s['name']}")
            icon = {"crit": red("✗"), "warn": yellow("⚠"), "info": cyan("•")}
            for lv, e, why, pr in found:
                print(f"  {icon[lv]} {bold(e)}\n      {why}\n      {dim(', '.join(pr[:5]) + (f' и ещё {len(pr) - 5}' if len(pr) > 5 else '''))}")
            for pid, comm in hidden: print(f"  {red('✗')} {bold(comm)} (pid {pid}) скрыт от ps — признак руткита")
            if not found and not hidden: print(green("  Подозрительного не найдено."))
            print("\n" + bold("Открытые порты") + dim("  (кто слушает входящие подключения)"))
            for proto, port, name in ports: print(f"  {proto:<4} {port:>6}  {name or dim('?')}")
            if base is None: print(yellow("\nЭталона ещё нет: если сейчас всё ваше — нажмите «Доверять», и в следующий раз будут видны новые программы."))
            print()
            a = menu(["Доверять: запомнить текущие программы как нормальные", "Назад"], default=2)
            if a == "1": bases[self.skey(s)] = shas; self.save(); print(green(f"✓ Запомнено программ: {len(shas)}")); pause()

        def reboot(self, s):
            if not yes(red(f"Перезагрузить {s['name']}? Все подключения и работающие программы прервутся.")): return
            # ssh обрывается вместе с сервером (код 255) — это не ошибка
            cmd = 'S=""; [ "$(id -u)" = 0 ] || S=sudo; $S systemctl reboot || $S reboot'
            if not self.danger("перезагрузить сервер", s, lambda ch: (
                    self.phone_ssh(ch, s, "sh -c " + shlex.quote(cmd), tty=True)[0] in (0, 255), "команда перезагрузки отправлена"), wait=False):
                pause(); return
            print(dim("Жду, пока сервер выключится и снова ответит по SSH… (Ctrl+C — перестать ждать)"))
            try:
                down = False; t = time.time()
                while time.time() - t < 600:
                    try: up = ssh_alive(s)
                    except subprocess.TimeoutExpired: up = False
                    if not up: down = True
                    elif down: print(green(f"✓ Сервер снова в сети ({int(time.time() - t)} с)")); break
                    elif time.time() - t > 90:  # команда принята (ssh оборвался или 0), а падение не застали — быстрая перезагрузка
                        print(green("✓ Сервер в сети") + dim(" (момент перезагрузки не застали — она была быстрой)")); break
                    time.sleep(3)
                else: print(red("✗ Сервер не вернулся за 10 минут. Проверьте его через панель хостинга."))
            except KeyboardInterrupt: print(yellow("\nОжидание прервано."))
            pause()

        def danger(self, reason, s, run, wait=True):
            """Опасное действие: отдельный сеанс с причиной на телефоне, run(ch) -> (ok, отчёт), отчёт — в журнал телефона."""
            header("опасное действие")
            print(yellow(f"  {reason} — {s['name']}\n"))
            ch = self.session(f"{reason} — {s['name']}", danger=True)
            if not ch: return False
            try:
                ok, text = run(ch)
                print((green("✓ ") if ok else red("✗ ")) + text)
                try: ch.call({"t": "report", "ok": ok, "text": text})
                except (OSError, ConnectionError, ValueError): pass
                return ok
            except (OSError, ConnectionError, ValueError, KeyError) as e:
                print(red(f"✗ {e}")); return False
            finally:
                ch.close()
                if wait: pause()

        def journal(self):
            header("журнал одобрений")
            ch = self.session("просмотр журнала одобрений")
            if not ch: return
            try:
                header("журнал одобрений"); show_journal(ch.call({"t": "journal"})["log"])
            except (OSError, ConnectionError, ValueError, KeyError) as e: print(red(f"✗ {e}"))
            finally: ch.close()
            pause()

        # --- добавление сервера ---
        def add_server(self, ch, s, identity=None, opts=None, extra=""):
            """Прописать ключ телефона и резервный ключ на сервер; при успехе сохранить на телефоне."""
            r = ch.call({"t": "add", "server": s})
            if not r.get("ok"): print(red("✗ Отклонено на телефоне")); return False
            cmd = extra + install_cmd(with_nick(r["line"], server_tag(s)), r["recovery"])
            if identity: opts = ["-o", "IdentitiesOnly=yes", "-i", identity]
            opts = opts or []
            print(dim(f"Захожу на {s['user']}@{s['host']}…"))
            p = subprocess.run(ssh_cmd(s, *opts) + ["sh -c " + shlex.quote(cmd)], stdout=subprocess.PIPE, text=True)
            if "SSH-STORAGE-OK" not in (p.stdout or ""):
                print(red("✗ Не удалось прописать ключи. Можно вручную — выполните на сервере:"))
                print(cyan(cmd))
                # сохранить с пометкой: по ID на сервере потом видно, установилась ли строка
                ch.call({"t": "added", "server": dict(s, pending=True)})
                self.cache([x for x in self.d["servers"] if (x["host"], x["user"]) != (s["host"], s["user"])]
                           + [dict(s, pending=True)])
                print(yellow(f"«{s['name']}» сохранён с пометкой «ключи не установлены» (#{s.get('id')})"))
                return False
            s.pop("pending", None)
            ch.call({"t": "added", "server": s})
            self.cache([x for x in self.d["servers"] if (x["host"], x["user"]) != (s["host"], s["user"])] + [s])
            print(green(f"✓ «{s['name']}»: ключ телефона и резервный ключ прописаны"))
            return True

        def tunnel(self, s):
            port = int(ask("Порт панели на сервере", 2053, validate=port_ok))
            ch = self.session(f"туннель к панели {s['name']}:{port}")
            if not ch: return
            try:
                print(green(f"Откройте в браузере http://127.0.0.1:{port}/ (путь панели — как обычно). Ctrl+C — закрыть туннель."))
                print(yellow("Пока туннель открыт, порт доступен и другим программам на этом компьютере — закройте сразу после работы."))
                print(dim("Подсказка: в 3x-ui можно оставить панель только на 127.0.0.1 — снаружи её не будет видно."))
                try: rc, _ = self.phone_ssh(ch, s, opts=("-N", "-L", f"127.0.0.1:{port}:127.0.0.1:{port}"))
                except KeyboardInterrupt: rc = 0
                try: ch.call({"t": "result", "ok": rc != 255})
                except (OSError, ConnectionError, ValueError): pass
            except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e: print(red(f"✗ {e}"))
            finally: ch.close()
            pause()

        def phone_ssh(self, ch, s, *cmd, tty=False, opts=()):
            """ssh на сервер ключом телефона (подписи — на телефоне). Возвращает (код, stdout|None).
            Один вход: первое соединение становится мастером (ControlMaster) и заодно проверяет права;
            команда или интерактивный сеанс идут через него без новых подписей."""
            r = ch.call({"t": "list"})
            i = next(n for n, x in enumerate(r["servers"]) if x == s)
            ch.call({"t": "use", "i": i})
            blob = base64.b64decode(r["line"].split()[1])
            def signer(data):
                resp = ch.call({"t": "sign", "data": data.hex()})
                return ecdsa_sig(bytes.fromhex(resp["sig"])) if resp.get("ok") else None
            agent = Agent(blob, signer)
            cm = os.path.join(agent.dir, "cm")
            base = ssh_cmd(s, "-o", f"IdentityAgent={agent.path}", "-o", "IdentitiesOnly=yes",
                           "-i", agent.pubfile(), "-o", "ControlMaster=auto",
                           "-o", f"ControlPath={cm}", "-o", "ControlPersist=120")
            try:
                p = subprocess.run(base + [RIGHTS_CMD], stdout=subprocess.PIPE, text=True)
                if p.returncode == 255: return 255, None  # вход не прошёл
                m = re.search(r"RIGHTS=([\w-]+)", p.stdout or "")
                if m and m.group(1) in RIGHTS: self.set_rights(s, m.group(1))
                if opts: return subprocess.call(base[:1] + list(opts) + base[1:]), None
                if not cmd: return subprocess.call(base), None
                # tty: вывод сразу на экран, sudo может спросить пароль (он не проходит через программу)
                if tty: return subprocess.call(base[:1] + ["-t"] + base[1:] + list(cmd)), None
                p = subprocess.run(base + list(cmd), stdout=subprocess.PIPE, text=True)
                return p.returncode, p.stdout
            finally:
                subprocess.run([SSH, "-o", f"ControlPath={cm}", "-O", "exit", f"{s['user']}@{s['host']}"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                agent.close()

        # --- права на серверах (только для удобства меню; реально права проверяет сервер) ---
        @staticmethod
        def skey(s): return f"{s['user']}@{s['host']}:{s['port']}"

        def set_rights(self, s, level):
            self.d.setdefault("rights", {})[self.skey(s)] = level; self.save()

        def rights(self, s):
            return self.d.get("rights", {}).get(self.skey(s))

        def rights_label(self, s):
            lv = self.rights(s)
            return RIGHTS[lv][0] if lv else "права не проверены"

        def disable_old(self, ch, s):
            print(dim("Проверяю вход ключом телефона и отключаю старые ключи…"))
            rc, out = self.phone_ssh(ch, s, "sh -c " + shlex.quote(DISABLE_OLD_CMD))
            ok = "SSH-STORAGE-OK" in (out or "")
            try: ch.call({"t": "result", "ok": rc != 255})
            except (OSError, ConnectionError, ValueError): pass
            if ok:
                print(green("✓ Вход телефоном работает; старые ключи закомментированы (копия: authorized_keys.ssh-storage.bak)"))
            elif rc == 255:
                print(red("✗ Вход ключом телефона не прошёл — старые ключи НЕ тронуты"))
            else:
                print(red("✗ Не удалось отключить старые ключи — на сервере выполните вручную:")); print(cyan(DISABLE_OLD_CMD))
            return ok

        def new_vps(self):
            header("новый VPS: настроить с нуля")
            a = menu(["Только купил сервер: есть root (или пользователь с sudo) и пароль от хостера",
                      "Мне дали личного пользователя на чужом сервере (без root)", "Назад"], default=1)
            if a == "2":
                print(dim("Без root можно только своё: ключ телефона, резервный ключ, TERM в ~/.profile и отключить старые ключи.\n"
                          "Порт, вход root и пароли сервера настраивает его владелец."))
                return self.add(extra=TERM_CMD + "; ")
            if a != "1": return
            host = ask("IP / хост", validate=host_ok)
            old = int(ask("Порт сейчас", 22, validate=port_ok))
            login = ask("Логин от хостера", "root", validate=user_ok)
            user = ask("Новый пользователь", validate=lambda v: re.fullmatch(LOGIN_RE, v) and v != "root")
            port = int(ask("Новый порт SSH", 1024 + secrets.randbelow(64000),
                           validate=lambda v: port_ok(v) and 1024 <= int(v) and int(v) != old))
            name = ask("Название", host)
            s1 = {"name": name, "host": host, "port": old, "user": login}
            if not check_reach(s1): return
            s = new_id({"name": name, "host": host, "port": port, "user": user, "nick": pick_nick({}, self.d["servers"])})
            print(f"\nПлан для {bold(host)}:\n"
                  f"  1. apt update; создать {user} (sudo с паролем), TERM в ~/.profile\n"
                  + dim("     свежий список пакетов; работать не под root; цвета в терминале") + "\n"
                  f"  2. {user}: ключ телефона и резервный ключ\n"
                  + dim("     вход с телефона; резервный — если телефон потерян") + "\n"
                  f"  3. SSH слушает порты {old} и {port} (пароль пока работает)\n"
                  + dim("     новый порт — меньше ботов; старый — чтобы не запереться") + "\n"
                  f"  4. проверить вход ключом телефона на порт {port}\n"
                  + dim("     убедиться, что новый вход работает") + "\n"
                  f"  5. только после этого: порт {old}, вход root и пароли — отключить\n"
                  + dim("     пароль не подобрать; войти можно только ключом") + "\n"
                  + dim("  Если после шага 5 вход ключом не подтвердится за 3 мин — сервер сам вернёт шаг 3."))
            if not yes("Продолжить?", True): return
            ch = self.session(f"новый VPS {name}", danger=True)
            if not ch: return
            try:
                r = ch.call({"t": "add", "server": s})
                if not r.get("ok"): print(red("✗ Отклонено на телефоне")); pause(); return
                inst = install_cmd(with_nick(r["line"], server_tag(s)), r["recovery"])
                print(dim(f"Захожу на {login}@{host}:{old} — пароль от хостера (и sudo) вводите здесь, программа их не хранит…"))
                rc = subprocess.call(ssh_cmd(s1, "-t", "-o", "PubkeyAuthentication=no") + [vps_step1(user, old, port, inst)])
                if rc: print(red(f"✗ Шаг 1–3 не выполнен (код {rc}). Сервер не изменён или изменён частично — вход паролем работает.")); pause(); return
                ch.call({"t": "added", "server": s})
                self.cache([x for x in self.d["servers"] if (x["host"], x["user"]) != (host, user)] + [s])
                print(green(f"✓ {user} создан, ключи прописаны, SSH слушает {old} и {port}"))
                print(dim(f"Шаг 4–5: вход {user}@{host}:{port} ключом телефона (sudo спросит пароль {user})…"))
                rc, _ = self.phone_ssh(ch, s, vps_step2(port), tty=True)
                if rc: print(red(f"✗ Вход ключом телефона или настройка не прошли (код {rc}). Старый вход паролем остался.")); pause(); return
                time.sleep(2)
                print(dim("Проверяю вход заново (новое подключение)…"))
                rc, out = self.phone_ssh(ch, s, "touch ~/.ssh-storage-ok && echo SSH-STORAGE-OK")
                try: ch.call({"t": "result", "ok": "SSH-STORAGE-OK" in (out or "")})
                except (OSError, ConnectionError, ValueError): pass
                if "SSH-STORAGE-OK" in (out or ""):
                    print(green(f"✓ Готово: вход только {user}@{host}:{port} ключом телефона (или резервным). Root и пароли отключены."))
                else:
                    print(red(f"✗ Новый вход не подтвердился — через 3 мин сервер сам вернёт порты {old}, {port} и вход паролем."))
            except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e: print(red(f"✗ {e}"))
            finally: ch.close()
            pause()

        def add(self, extra=""):
            header("новый сервер")
            s = edit_server(servers=self.d["servers"])
            if not check_reach(s): return
            opts, tmp = first_login()
            if opts is None: return
            print("\nДругие ключи в ~/.ssh/authorized_keys на сервере — те, которыми вы входили раньше")
            print(dim("(ключи с компьютеров, другие ssh-ключи; ключи телефонов, резервный и участников команды не затрагиваются):"))
            old = menu(["Оставить — они продолжат работать, просто добавится ключ телефона",
                        "Отключить — входить ими станет нельзя. Строки не удаляются: в начало ставится «#»,\n"
                        "      вернуть можно, убрав «#» или из копии authorized_keys.ssh-storage.bak.\n"
                        "      Делается только после того, как вход телефоном проверен."])
            disable_old = old == "2"
            try:
                ch = self.session(f"добавить сервер {s['name']}")
                if not ch: return
                try:
                    if self.add_server(ch, s, opts=opts, extra=extra) and disable_old: self.disable_old(ch, s)
                except (OSError, ConnectionError, ValueError, KeyError) as e: print(red(f"✗ {e}"))
                finally: ch.close()
                pause()
            finally:
                if tmp: shutil.rmtree(tmp, ignore_errors=True)

        def bulk_add(self):
            header("массовое добавление")
            a = menu(["Из файла (строки: имя хост [порт] [пользователь])", "Из ~/.ssh/config",
                      "Вставить списком", "Назад"], default=1)
            if a == "1":
                path = os.path.expanduser(ask("Путь к файлу"))
                if not os.path.isfile(path): print(red("✗ Файл не найден")); pause(); return
                sv, bad = parse_servers(open(path, errors="replace").read())
            elif a == "2": sv, bad = ssh_config_servers()
            elif a == "3":
                print(dim("Строки «имя хост [порт] [пользователь]», пустая строка — конец:"))
                lines = []
                while (l := input()).strip(): lines.append(l)
                sv, bad = parse_servers("\n".join(lines))
            else: return
            header("массовое добавление")
            print(dim("Проверяю доступность…"))
            down = {}
            with concurrent.futures.ThreadPoolExecutor(16) as ex:
                for x, why in zip(sv, ex.map(reachable, sv)):
                    if why: down[x["name"], x["host"]] = why
            for x in sv:
                why = down.get((x["name"], x["host"]))
                print("  " + server_line(x) + (red(f"  ✗ {why}") if why else green("  ✓")))
            for b in bad: print(red("  ✗ пропущено, неверный формат — " + b))
            if not sv: print(yellow("Нечего добавлять.")); pause(); return
            print(); nick = pick_nick({}, self.d["servers"])
            sv = [new_id(dict(x, nick=nick)) for x in sv]
            print("\nСпособ первого входа:")
            per = menu(["Общий для всех серверов", "Свой для каждого сервера"], default=1) == "2"
            if down and not yes(yellow(f"Недоступно: {len(down)}. Добавить их всё равно (сохранятся с пометкой)?")):
                sv = [x for x in sv if (x["name"], x["host"]) not in down]
                if not sv: return
            logins, tmps = {}, []
            try:
                common = None if per else first_login()
                if common and common[0] is None: return
                for x in sv:
                    if per: print(bold(f"\n{x['name']}") + dim(f"  {x['user']}@{x['host']}"))
                    o = first_login() if per else common
                    if o[1]: tmps.append(o[1])
                    logins[x["name"], x["host"]] = o[0]  # None — пропустить сервер
                ch = self.session(f"добавить серверы ({len(sv)})")
                if not ch: return
                done, fail = [], []
                try:
                    if not ch.call({"t": "add_many", "servers": sv}).get("ok"):
                        print(red("✗ Отклонено на телефоне")); pause(); return
                    for x in sv:
                        o = logins[x["name"], x["host"]]
                        if o is None: fail.append((x, "пропущен (отмена входа)")); continue
                        print(bold(f"\n→ {x['name']}"))
                        try:
                            if self.add_server(ch, x, opts=o): done.append(x)
                            else: fail.append((x, "не удалось прописать ключи (вход или права)"))
                        except (OSError, ConnectionError, ValueError, KeyError) as e: fail.append((x, str(e)))
                finally: ch.close()
                header("итог массового добавления")
                print(green(f"  Добавлено: {len(done)}"))
                for x in done: print("    " + server_line(x))
                if fail or bad: print(red(f"  Не добавлено: {len(fail) + len(bad)}"))
                for x, why in fail: print(f"    {server_line(x)}  {red(why)}")
                for b in bad: print(f"    {red(b)}  {dim('неверный формат')}")
            finally:
                for t in tmps: shutil.rmtree(t, ignore_errors=True)
            pause()

        def add_member_many(self):
            header("участник → серверы")
            sv = [x for x in self.d["servers"] if server_ok(x)]
            if not sv: print(yellow("Список серверов пуст.")); pause(); return
            login, nick, key, role = self.ask_member()
            for n, x in enumerate(sv, 1): print(f"  {n}. {server_line(x)}")
            nums = re.split(r"[\s,]+", input(blue("\nНомера серверов через запятую или пробел (Enter — отмена): ")).strip())
            sel = [sv[n - 1] for n in sorted({int(n) for n in nums if n.isdigit() and 1 <= int(n) <= len(sv)})]
            if not sel: return
            print(yellow(f"\nПользователь {login} (участник {nick}) на серверах: {', '.join(x['name'] for x in sel)}"))
            if not yes(red("Выполнить?")): return
            ch = self.session(f"добавить участника {nick} ({login}) на серверы ({len(sel)})", danger=True)
            if not ch: return
            done, fail = [], []
            try:
                for x in sel:
                    print(bold(f"\n→ {x['name']}"))
                    try: (done if self.phone_ssh(ch, x, "sh -c " + shlex.quote(member_cmd(login, key, nick, role)), tty=True)[0] == 0 else fail).append(x)
                    except (OSError, ConnectionError, ValueError, KeyError, StopIteration): fail.append(x)
                text = f"участник {nick} ({login}): добавлен на {len(done)}, не добавлен на {len(fail)}"
                try: ch.call({"t": "report", "ok": not fail, "text": text})
                except (OSError, ConnectionError, ValueError): pass
                if done: self.sync_members(ch, add=nick)
            finally: ch.close()
            header("итог")
            print(green(f"  Добавлен: {len(done)}")); [print("    " + server_line(x)) for x in done]
            if fail: print(red(f"  Не добавлен: {len(fail)} (недоступен, отказ sudo или логин занят)")); [print("    " + server_line(x)) for x in fail]
            pause()

        def revoke_member(self):
            header("отозвать участника")
            sv = [x for x in self.d["servers"] if server_ok(x) and not x.get("pending")]
            if not sv: print(yellow("Список серверов пуст.")); pause(); return
            known = self.d.get("members", [])
            if known: print(dim("Добавленные через это меню (можно ввести номер):")); [print(f"  {n}. {k}") for n, k in enumerate(known, 1)]
            nick = ask("Ник участника", validate=lambda v: bool(re.fullmatch(NICK_RE, v)) or v.isdigit() and 1 <= int(v) <= len(known))
            if nick.isdigit() and 1 <= int(nick) <= len(known): nick = known[int(nick) - 1]
            n_all = len(sv); sv = pick_many(sv, "Где")
            if not sv: return
            full = menu(["Только снять ключи — пользователь и его файлы останутся",
                         "Удалить полностью — пользователя, его папку и ключи (необратимо)", "Назад"], default=1)
            if full not in ("1", "2"): return
            full = full == "2"
            if full:
                print(red(f"\nНа {', '.join(x['name'] for x in sv)} будут удалены пользователи участника {nick} и все их файлы. Вернуть нельзя."))
                print(dim("Удаляются только созданные через меню участников; ваш пользователь и root — никогда."))
                if input(red(f"Для подтверждения введите ник {nick}: ")).strip() != nick: return
            else:
                print(yellow(f"\nУчастник {nick} на {', '.join(x['name'] for x in sv)}: ключи снять, вход заблокировать, "
                             "открытые сеансы закрыть, sudo снять. Пользователь и файлы останутся; вернуть — «Добавить участника»."))
                if not yes(red("Отозвать?")): return
            cmd = delete_member_cmd(nick) if full else revoke_cmd(nick)
            ch = self.session(f"{'удалить' if full else 'отозвать'} участника {nick} на серверах ({len(sv)})", danger=True)
            if not ch: return
            res = []
            try:
                for x in sv:
                    print(bold(f"\n→ {x['name']}"))
                    try:
                        rc = self.phone_ssh(ch, x, "sh -c " + shlex.quote(cmd), tty=True)[0]
                        res.append((x, {0: "удалено" if full else "снято", 3: "участника не было"}.get(rc)))
                    except (OSError, ConnectionError, ValueError, KeyError, StopIteration): res.append((x, None))
                bad = [x for x, w in res if w is None]
                try: ch.call({"t": "report", "ok": not bad, "text": f"отзыв {nick}: не выполнен на {len(bad)} из {len(res)}"})
                except (OSError, ConnectionError, ValueError): pass
                self.sync_members(ch, drop=nick if full and not bad and len(sv) == n_all else None)  # удалён не везде — ник остаётся
            finally: ch.close()
            header(f"итог отзыва · {nick}")
            for x, w in res: print(f"  {server_line(x)}  " + (green(w) if w else red("не выполнено (недоступен или отказ sudo) — повторите")))
            pause()

        def bulk_delete(self):
            header("массовое удаление")
            sv = [x for x in self.d["servers"] if server_ok(x)]
            if not sv: print(yellow("Список серверов пуст.")); pause(); return
            for n, x in enumerate(sv, 1): print(f"  {n}. {server_line(x)}")
            nums = re.split(r"[\s,]+", input(blue("\nНомера через запятую или пробел (Enter — отмена): ")).strip())
            pick = sorted({int(n) for n in nums if n.isdigit() and 1 <= int(n) <= len(sv)})
            if not pick: return
            sel = [sv[n - 1] for n in pick]
            header("массовое удаление")
            for x in sel: print("  " + server_line(x))
            mode = menu(["Только из списка (ключи на серверах остаются)",
                         "Из списка + снять ключ телефона и резервный с серверов", "Отмена"], default=1)
            if mode not in ("1", "2"): return
            keys = mode == "2"
            if keys: print(yellow("⚠ Ключ телефона и резервный будут сняты: войти на эти серверы через ssh-storage станет нельзя."))
            if not yes(red(f"Удалить серверов: {len(sel)}?")): return
            ch = self.session(f"удалить серверы ({len(sel)})" + (" и снять ключи" if keys else ""), danger=keys)
            if not ch: return
            done, fail = [], []
            try:
                r = ch.call({"t": "list"})
                sel = [x for x in sel if x in r["servers"]]  # список мог измениться на телефоне
                if not ch.call({"t": "delete_many", "servers": sel, "keys": keys}).get("ok"):
                    print(red("✗ Отклонено на телефоне")); pause(); return
                for x in sel:
                    if not keys: done.append(x); continue
                    print(bold(f"\n→ {x['name']}"))
                    try:
                        _, out = self.phone_ssh(ch, x, "sh -c " + shlex.quote(remove_keys_cmd(r["line"], r["recovery"])))
                        if "SSH-STORAGE-OK" in (out or ""): done.append(x)
                        else: fail.append((x, "ключи не сняты (сервер недоступен или вход не прошёл) — оставлен в списке"))
                    except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e: fail.append((x, str(e)))
                ch.call({"t": "delete_done", "servers": done})
                self.cache([x for x in r["servers"] if x not in done])
            except (OSError, ConnectionError, ValueError, KeyError) as e: print(red(f"✗ {e}"))
            finally: ch.close()
            header("итог массового удаления")
            print(green(f"  Удалено: {len(done)}"))
            for x in done: print("    " + server_line(x))
            if fail: print(red(f"  Не удалено: {len(fail)}"))
            for x, why in fail: print(f"    {server_line(x)}  {red(why)}")
            pause()

        def rekey(self):
            """Перевыпуск: 1) старым ключом дописать новые на все серверы; 2) телефон переключается на новые;
            3) новым ключом снять старые (это же проверка нового ключа)."""
            header("перевыпуск ключей")
            print(dim("Один ключ на устройство: перевыпуск действует сразу на всех серверах из списка.\n"))
            what = menu(["Ключ телефона", "Резервный ключ (новый резервный пароль)", "Оба", "Назад"], default=1)
            if what not in ("1", "2", "3"): return
            phone, rec = what in ("1", "3"), what in ("2", "3")
            if rec and self.d["recovery"] == "": print(yellow("Резервного ключа у участника команды нет — он у админа.")); pause(); return
            mode = menu(["Добавить: остальные ключи на серверах не трогать",
                         "Затереть: оставить на серверах только ключи ssh-storage этого телефона", "Назад"], default=1)
            if mode not in ("1", "2"): return
            wipe = mode == "2"
            sv = [x for x in self.d["servers"] if server_ok(x)]
            if not sv: print(yellow("Список серверов пуст.")); pause(); return
            header("перевыпуск ключей — сводка")
            print(f"  Перевыпустить: {bold(', '.join(w for w, on in (('ключ телефона', phone), ('резервный ключ', rec)) if on))}")
            print(f"  Режим: {red('затереть остальные ключи') if wipe else 'добавить'}")
            print(f"  Серверы ({len(sv)}):")
            for x in sv: print("    " + server_line(x))
            if rec: print(yellow("\n⚠ Старый резервный пароль перестанет работать — будет показан новый."))
            if wipe: print(red("⚠ Чужие ключи на серверах будут удалены (список — после проверки серверов)."))
            if input(red("\nДля подтверждения введите ПЕРЕВЫПУСК: ")).strip().upper() != "ПЕРЕВЫПУСК": return
            new_rec = self.new_recovery() if rec else None
            ch = self.session("перевыпуск ключей на всех серверах", danger=True)
            if not ch: return
            done, fail = [], []
            try:
                r = ch.call({"t": "list"})
                sv = [x for x in r["servers"] if server_ok(x)]
                ob, orb = r["line"].split()[1], (r["recovery"] or " -").split()[1]
                run = lambda x, cmd: (self.phone_ssh(ch, x, "sh -c " + shlex.quote(cmd))[1] or "")
                warn = []
                if wipe:  # кто потеряет доступ: имена ssh-storage и число прочих ключей (без комментариев — приватность)
                    for x in sv:
                        try: out = run(x, "cat ~/.ssh/authorized_keys 2>/dev/null")
                        except (OSError, ConnectionError, ValueError, KeyError, StopIteration): continue
                        other = [l.split() for l in out.splitlines() if l.strip() and not l.lstrip().startswith("#")]
                        other = [f for f in other if not {ob, orb} & set(f)]
                        if not other: continue
                        nicks = sorted({f[-1].split(":")[1] for f in other if f[-1].startswith(PHONE_TAG + ":")})
                        warn.append(f"{x['name']}: потеряют доступ ключей — {len(other)}"
                                    + (f" (участники: {', '.join(nicks)})" if nicks else ""))
                    for w in warn: print(red("  ⚠ " + w))
                    if warn and not yes(red("Участники выше потеряют доступ. Продолжить?")): return
                resp = ch.call({"t": "rekey", "phone": phone, "recovery": new_rec, "wipe": wipe, "warn": warn})
                if not resp.get("ok"):
                    print(red("✗ Отклонено на телефоне") + (yellow(" — новый резервный пароль не применён, действует старый") if rec else ""))
                    pause(); return
                new_line = resp.get("line") or r["line"]
                new_b = ([new_line.split()[1]] if phone else []) + ([new_rec.split()[1]] if rec else [])
                ok1 = []
                for x in sv:  # 1) старым ключом: дописать новые
                    print(bold(f"→ {x['name']}: новые ключи"))
                    add = ([with_nick(new_line, server_tag(x))] if phone else []) + ([new_rec] if rec else [])
                    try: res = run(x, keys_cmd(add=add, keep=[k for k in (ob, orb) if k != "-"] if wipe else None))
                    except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e: res = str(e)
                    (ok1.append(x) if "SSH-STORAGE-OK" in res else fail.append((x, "новые ключи не записаны (сервер недоступен?)")))
                if fail:
                    for x, why in fail: print(red(f"  ✗ {x['name']}: {why}"))
                    print(yellow("На них останутся только старые ключи" + (": вход телефоном туда пропадёт, останется резервный пароль" if phone else "") + "."))
                    if not yes(red("Всё равно перейти на новые ключи?")):
                        for x in ok1:  # откат: убрать дописанные новые ключи
                            try: run(x, keys_cmd(drop=new_b))
                            except (OSError, ConnectionError, ValueError, KeyError, StopIteration): pass
                        print(dim("Отменено, новые ключи убраны с серверов.")); pause(); return
                if not ch.call({"t": "rekey_commit"}).get("ok"): print(red("✗ Телефон не применил новые ключи")); pause(); return
                if rec: self.d["recovery"] = new_rec; self.save()
                r2 = ch.call({"t": "list"}); self.cache(r2["servers"])
                for x in ok1:  # 3) новым ключом: снять старые
                    print(bold(f"→ {x['name']}: снять старые ключи"))
                    drop = ([ob] if phone else []) + ([orb] if rec else [])
                    try: res = run(x, keys_cmd(drop=drop, backup=False))  # копия — состояние до перевыпуска
                    except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e: res = str(e)
                    (done.append(x) if "SSH-STORAGE-OK" in res
                     else fail.append((x, "новый ключ записан, но вход им не прошёл — старый не снят")))
                try: ch.call({"t": "report", "ok": not fail, "text": f"перевыпуск: готово {len(done)}, ошибок {len(fail)}"})
                except (OSError, ConnectionError, ValueError): pass
            except (OSError, ConnectionError, ValueError, KeyError) as e: print(red(f"✗ {e}"))
            finally: ch.close()
            header("итог перевыпуска")
            print(green(f"  Готово: {len(done)}"))
            for x in done: print("    " + server_line(x))
            if fail: print(red(f"  С ошибками: {len(fail)}"))
            for x, why in fail: print(f"    {server_line(x)}  {red(why)}")
            pause()

        # --- восстановление ---
        def recovery(self):
            header("восстановление")
            print("Вход резервным ключом из 20-символьного пароля.\n")
            while True:
                pw = getpass.getpass(blue("Резервный пароль (Enter — отмена): "))
                if not pw: return
                print(dim("Вычисляю ключ…"))
                seed = recovery_seed(pw)
                if self.d["recovery"] and recovery_line(seed) != self.d["recovery"]:
                    print(red("✗ Не тот пароль\n")); continue
                break
            if not self.d["recovery"]: self.d["recovery"] = recovery_line(seed); self.save()
            tmp = tempfile.mkdtemp(prefix="sshstore-", dir=RAM)
            key = os.path.join(tmp, "recovery")
            fd = os.open(key, os.O_WRONLY | os.O_CREAT, 0o600)
            with os.fdopen(fd, "w") as f: f.write(openssh_ed25519_private(seed, RECOVERY_TAG))
            try:
                while True:
                    header("восстановление")
                    sv = self.d["servers"]
                    ch = menu([server_line(s) for s in sv] + ["Другой сервер…", dim("Назад")])
                    if ch == str(len(sv) + 2): return
                    if ch == str(len(sv) + 1): header("сервер"); s = edit_server()
                    elif ch.isdigit() and 1 <= int(ch) <= len(sv): s = sv[int(ch) - 1]
                    else: continue
                    a = menu(["Подключиться резервным ключом", "Привязать сопряжённый телефон к этому серверу", "Назад"])
                    if a == "1":
                        clear(); subprocess.call(ssh_cmd(s, "-o", "IdentitiesOnly=yes", "-i", key)); pause()
                    elif a == "2":
                        c2 = self.session(f"привязать к серверу {s['name']}")
                        if c2:
                            try: self.add_server(c2, s, identity=key)
                            except (OSError, ConnectionError, ValueError, KeyError) as e: print(red(f"✗ {e}"))
                            finally: c2.close()
                            pause()
            finally:
                shutil.rmtree(tmp, ignore_errors=True)

        # --- перенос из старого хранилища (vault.json) ---
        def migrate(self):
            header("перенос старых подключений")
            with open(LEGACY_VAULT) as f: v = json.load(f)
            pw = getpass.getpass(blue("Пароль администратора старого хранилища: "))
            print(dim("Проверяю…"))
            try:
                k = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(v["salt"]), n=2**17, r=8, p=1, maxmem=2**28, dklen=64)
                M = open_sym(k, bytes.fromhex(v["admin"]))
                conns = []
                for b in v["conns"]:
                    b = bytes.fromhex(b); epub, rest = b[:32], b[32:]
                    conns.append(json.loads(open_sym(H(x25519(M, epub), epub, pubkey(M)), rest, epub)))
            except ValueError:
                print(red("✗ Неверный пароль")); pause(); return
            ch = self.session("перенос старых подключений")
            if not ch: return
            tmp = tempfile.mkdtemp(prefix="sshstore-", dir=RAM)
            try:
                for cn in conns:
                    s = {k2: cn[k2] for k2 in ("name", "host", "port", "user")}
                    print("\n" + server_line(s))
                    if not server_ok(s): print(red("  пропущен: недопустимый адрес")); continue
                    key = None
                    if cn.get("private_key"):
                        key = os.path.join(tmp, "old")
                        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                        with os.fdopen(fd, "w") as f: f.write(cn["private_key"])
                    self.add_server(ch, s, identity=key)
                print(yellow(f"\nКогда всё проверите, старое хранилище можно удалить: {LEGACY_VAULT}"))
            except (OSError, ConnectionError, ValueError, KeyError) as e:
                print(red(f"✗ {e}"))
            finally:
                shutil.rmtree(tmp, ignore_errors=True); ch.close()
            pause()

    def pc_wipe():
        header("стереть данные")
        print("Удалится " + bold(PC_STATE) + ": сопряжение и список серверов.")
        print(dim("Секретов там нет; ключ остаётся на телефоне, резервный пароль — у вас на бумаге."))
        print(yellow("Резервный пароль после этого здесь не будет известен: при новом сопряжении создастся новый."))
        if not confirm_wipe(): return False
        if os.path.exists(PC_STATE): os.remove(PC_STATE)
        if os.path.exists(LEGACY_VAULT) and yes(yellow("Удалить и старый vault.json?")): os.remove(LEGACY_VAULT)
        print(green("✓ Стёрто.")); return True

    def pc_main():
        if not shutil.which(SSH): print(red("ssh не найден")); sys.exit(1)
        cleanup_stale()
        pc = PC()
        while True:
            header("главное меню")
            phone = green("📱 " + pc.d["phone"]["fp"]) if pc.d["phone"] else yellow("📱 не сопряжён")
            rec = green("🔑 резерв есть") if pc.d["recovery"] else yellow("🔑 резерва нет")
            print(f"  {phone}   {rec}\n")
            ch = menu(["Подключиться к серверу", "Серверы", "Сопряжение", "Действия на сервере",
                       "Специальные возможности", "Выход"], default=1 if pc.d["phone"] else 3)
            if ch == "1": pc.connect()
            elif ch == "2": pc.section_servers()
            elif ch == "3": pc.section_pairing()
            elif ch == "4": pc.section_actions()
            elif ch == "5":
                if pc.section_special() == "wiped": return
            elif ch == "6": clear(); return

    if __name__ == "__main__":
        try: phone_main() if IS_PHONE else pc_main()
        except (KeyboardInterrupt, EOFError): print("\n" + dim("пока!"))
  '';

  ssh-storage = pkgs.writeShellApplication {
    name = "ssh-storage";
    runtimeInputs = [ pkgs.python3 pkgs.openssh pkgs.qrencode ];
    text = ''
      export SSHSTORE_DIR="''${XDG_DATA_HOME:-$HOME/.local/share}/ssh-storage"
      export SSHSTORE_SSH=${pkgs.openssh}/bin/ssh
      exec python3 ${script} "$@"
    '';
  };
  pkg = ssh-storage;
in
{
  config =
    if options ? home.packages
    then { home.packages = [ pkg ]; }
    else { environment.systemPackages = [ pkg ]; };
}
