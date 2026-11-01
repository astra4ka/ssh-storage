# SSH Storage: SSH keys live only on the phone (Android Keystore); the PC signs
# logins through the phone; 20-character recovery password.
# Command: `ssh-storage` opens the manager; the normal `ssh` is not touched.
# Works both as a NixOS module and as a home-manager module: add it to `imports`.
# Data: ~/.local/share/ssh-storage/ (includes a private pairing key). No firewall ports are opened.
# This file is generated from sshstore.py — the Python script is embedded below.
{ pkgs, lib, options, ... }:
let
  script = pkgs.writeText "sshstore.py" ''
    #!/usr/bin/env python3
    """SSH Storage — SSH-ключи живут только на телефоне, компьютер их никогда не видит.

    Один файл для компьютера и для телефона (Termux). Только стандартная библиотека
    (+ termux-api на телефоне).

    Телефон (Termux, ~/.ssh-storage/):
      * SSH-ключ ECDSA P-256 в Android Keystore; аппаратная защита зависит от устройства.
      * Список серверов, редактирование, команда установки для сервера.
      * Каждый вход подтверждается на телефоне по коду сеанса.
    Компьютер (~/.local/share/ssh-storage/pc.json) — SSH-ключа телефона нет:
      * pc.json содержит закрытый ключ сопряжения — файл нельзя публиковать.
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
    # Версия программы: ГГГГ.ММ.ДД[.N]. Поднимать при каждом выпуске — телефон не ставит версию старее своей.
    VERSION = "2026.11.01"
    # Автообновление телефона с ПК (сообщения version / update_part / update_done). Эти имена и поля НЕ менять и не удалять:
    # по ним обновляются телефоны со старыми версиями. Новое — только новыми полями/типами (неизвестное обе стороны игнорируют).
    UPD_CHUNK, UPD_MAX = 256 * 1024, 8 << 20

    def ver_key(v):
        return tuple(int(x) for x in re.findall(r"\d+", str(v))[:4])

    def self_bytes():
        with open(os.path.abspath(__file__), "rb") as f: return f.read()
    RAM = "/dev/shm" if os.path.isdir("/dev/shm") else None
    IS_PHONE = "com.termux" in os.environ.get("PREFIX", "") or "--phone" in sys.argv
    PHONE_TAG, RECOVERY_TAG = "ssh-storage-phone", "ssh-storage-recovery"
    NICK_RE = r"[A-Za-z0-9_-]{1,32}"  # ник в подписи ключа: ssh-storage-phone:<ник>
    ANY_PHONE_TAG = PHONE_TAG + r"\(:[A-Za-z0-9_:-]*\)\{0,1\}"  # sed: старая подпись и с именем:ID:датой

    # ---------- язык ----------
    # Язык хранится в phone.json / pc.json (ключ "language") отдельно на каждом устройстве и не сбрасывается
    # при перезапуске и обновлении. Ключ сообщения — русский текст; английский перевод — в EN_MESSAGES.
    LANGUAGES = ("en", "ru")

    def _saved_language():
        try:
            with open(PHONE if IS_PHONE else PC_STATE) as f: code = json.load(f).get("language")
        except (OSError, ValueError, AttributeError):
            return "en"
        return code if code in LANGUAGES else "en"

    LANG = _saved_language()

    def set_language(code):
        global LANG
        LANG = code if code in LANGUAGES else "en"

    def load_language(state):
        set_language(state.get("language") if isinstance(state, dict) else None)

    def tr(message, **values):
        text = message if LANG == "ru" else EN_MESSAGES.get(message, message)
        return text.format(**values) if values else text

    # BEGIN GENERATED TRANSLATIONS
    EN_MESSAGES = {
        "Ключом телефона": "Phone key",
        "Другим способом (пароль или SSH-ключ)": "Another method (password or SSH key)",
        "Настроить VPS": "Set up VPS",
        "Подключить существующий сервер": "Connect an existing server",
        "Настроить новый VPS": "Set up a new VPS",
        "Выполнить": "Run",
        "Пропустить": "Skip",
        "Отмена настройки": "Cancel setup",
        "Обновить список пакетов": "Refresh package lists",
        "apt update: только список доступных пакетов, без установки обновлений.": "apt update: refresh available package lists without installing updates.",
        "Создать нового пользователя": "Create a new user",
        "Отдельный логин для входа вместо root. При пропуске остаётся текущий пользователь.": "A separate login instead of root. Skip to keep using the current user.",
        "Логин нового пользователя": "New user's login",
        "Выдать права администратора": "Grant administrator privileges",
        "Добавить пользователя в sudo: административные команды с паролем. Пароль программа не сохраняет.": "Add the user to sudo: administrative commands with a password. The program does not save the password.",
        "Настроить цвета терминала": "Set up terminal colors",
        "Добавить export TERM=xterm-256color в ~/.profile выбранного пользователя для следующих входов.": "Add export TERM=xterm-256color to the target user's ~/.profile for subsequent logins.",
        "Настроить вход ключами приложения": "Set up application key login",
        "Добавить публичный ключ телефона и резервный ключ. Чужие ключи сохраняются; приватный ключ на VPS не создаётся.": "Add the phone public key and recovery key. Preserve other keys; no private key is generated on the VPS.",
        "Изменить порт SSH": "Change the SSH port",
        "Новый порт уменьшает шум от ботов, но не заменяет защиту ключами. Откройте его также в firewall хостера.": "A new port reduces bot noise but does not replace key security. Also open it in your provider's firewall.",
        "Запретить вход root по SSH": "Disable root SSH login",
        "Прямой SSH-вход под root перестанет работать. Права sudo у обычного пользователя сохраняются.": "Direct SSH login as root will stop working. A regular user's sudo privileges remain.",
        "Отключить вход по паролю SSH": "Disable SSH password login",
        "Вход только ключами, включая отключение интерактивного пароля. Пароль для sudo остаётся.": "Key-only login, also disabling keyboard-interactive passwords. The sudo password remains.",
        "Нельзя запретить root-вход, оставив root целевым пользователем. Запустите мастер заново и измените выбор.": "Cannot disable root login while root is the target user. Restart setup and change your selection.",
        "Для нового пользователя без ключей нельзя проверить вход перед изменением SSH. Выберите установку ключей или пропустите изменения SSH.": "Cannot verify a new user without keys before changing SSH. Select key installation or skip SSH changes.",
        "Удаляется только запись на ПК и телефоне. Пользователь, файлы и ключи на VPS остаются.": "Only remove the entry on the computer and phone. The user, files and keys on the VPS remain.",
        "Удалить старое подключение из списка?": "Remove the old connection from the list?",
        "Старое подключение оставлено в списке.": "The old connection was kept in the list.",
        "Настройка VPS доступна владельцу резервного доступа. Сначала выполните сопряжение.": "VPS setup is available to the recovery key owner. Pair your phone first.",
        "Все действия пропущены. Сервер не изменён.": "All actions skipped. The server was not changed.",
        "\nЦелевое подключение: {p0}": "\nTarget connection: {p0}",
        "  Порт SSH: {p0} → {p1}": "  SSH port: {p0} → {p1}",
        "Нужны Ubuntu/Debian и root или sudo у исходного пользователя. Сохраните доступ к консоли хостера.": "Requires Ubuntu/Debian and root or sudo for the original user. Keep access to your provider's console.",
        "Выполнить выбранные действия?": "Run the selected actions?",
        "Настройка не завершена. Изменения могли выполниться частично; старое подключение не удалено. Если SSH уже менялся, дождитесь отката через 3 минуты.": "Setup is incomplete. Some changes may have been applied; the old connection was not deleted. If SSH was changed, allow 3 minutes for rollback.",
        "Целевое подключение уже есть. Использовать его запись?": "The target connection already exists. Use its entry?",
        "SSH: включён независимый откат через 3 минуты до подтверждения нового входа.": "SSH: independent rollback in 3 minutes unless the new login is verified.",
        "Готово: выбранные действия выполнены, новый вход ключом телефона проверен.": "Done: selected actions applied and a fresh phone-key login verified.",
        "o() { echo \"$1|$2|$3\"; }\ndf -P -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null | awk 'NR>1 { u = $5 + 0; s = (u >= 95 ? \"crit\" : u >= 85 ? \"warn\" : \"ok\"); print s \"|диск \" $6 \"|занято \" u \"%\" }'\ndf -Pi -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null | awk 'NR>1 && $5 != \"-\" { u = $5 + 0; if (u >= 85) print (u >= 95 ? \"crit\" : \"warn\") \"|inode \" $6 \"|занято \" u \"% inode\" }'\n# только чтение — если у устройства нет ни одного rw-монтирования (bind-ro вроде /nix/store — норма)\nawk '$3 ~ /^(ext[234]|xfs|btrfs|f2fs)$/ { if ($4 ~ /^rw/) rw[$1] = 1; else if ($4 ~ /^ro(,|$)/) ro[$1] = $2 }\n  END { for (d in ro) if (!(d in rw)) print \"crit|ФС \" ro[d] \"|смонтирована только на чтение (часто — ошибки диска)\" }' /proc/mounts\nawk '/^MemTotal/ { t = $2 } /^MemAvailable/ { a = $2 } /^SwapTotal/ { st = $2 } /^SwapFree/ { sf = $2 }\n  END { p = 100 - a * 100 / t; printf \"%s|память|занято %d%%\\n\", (p >= 95 ? \"crit\" : p >= 85 ? \"warn\" : \"ok\"), p\n        if (st > 0) { q = 100 - sf * 100 / st; printf \"%s|swap|занято %d%%\\n\", (q >= 80 ? \"warn\" : \"ok\"), q } }' /proc/meminfo\nn=$(nproc 2>/dev/null || echo 1); read l1 l5 rest < /proc/loadavg\nawk -v l=\"$l5\" -v n=\"$n\" 'BEGIN { printf \"%s|нагрузка|%s за 5 мин на %d ядер\\n\", (l >= 2 * n ? \"crit\" : l >= n ? \"warn\" : \"ok\"), l, n }'\nif command -v timedatectl >/dev/null 2>&1; then\n  [ \"$(timedatectl show -p NTPSynchronized --value 2>/dev/null)\" = yes ] && o ok время \"синхронизировано (NTP)\" || o warn время \"не синхронизировано с NTP — расходятся журналы, TLS, 2FA\"\nfi\nif [ \"$FULL\" = 1 ]; then\n  S=\"\"; [ \"$(id -u)\" = 0 ] || { sudo -n true 2>/dev/null && S=\"sudo -n\"; }\n  oom=$($S journalctl -k --since -7d -q --no-pager 2>/dev/null | grep -ci \"out of memory\")\n  [ \"''${oom:-0}\" -gt 0 ] && o crit OOM \"процессы убиты из-за нехватки памяти за 7 дней: $oom\" || o ok OOM \"за 7 дней не было\"\n  t=$($S journalctl -p err --since today -q --no-pager 2>/dev/null | wc -l)\n  w=$($S journalctl -p err --since -7d --until today -q --no-pager 2>/dev/null | wc -l); avg=$((w / 6))\n  [ \"$t\" -gt $((avg * 2 + 10)) ] && o warn \"рост ошибок\" \"сегодня $t, обычно ~$avg в день\" || o ok \"ошибки журнала\" \"сегодня $t, обычно ~$avg в день\"\n  if command -v openssl >/dev/null 2>&1; then\n    for c in $($S sh -c 'ls /etc/letsencrypt/live/*/cert.pem' 2>/dev/null); do\n      e=$($S openssl x509 -enddate -noout -in \"$c\" 2>/dev/null | cut -d= -f2); [ -n \"$e\" ] || continue\n      x=$(date -d \"$e\" +%s 2>/dev/null); [ -n \"$x\" ] || continue; d=$(( (x - $(date +%s)) / 86400 ))\n      o \"$([ $d -lt 3 ] && echo crit || { [ $d -lt 14 ] && echo warn || echo ok; })\" \"SSL $(basename \"$(dirname \"$c\")\")\" \"истекает через $d дн.\"\n    done\n  fi\n  u=\"\"\n  if command -v apt >/dev/null 2>&1; then u=$(apt list --upgradable 2>/dev/null | grep -ci -- \"-security\")\n  elif command -v dnf >/dev/null 2>&1; then u=$(dnf -q updateinfo list --security 2>/dev/null | wc -l)\n  elif command -v checkupdates >/dev/null 2>&1; then u=$(checkupdates 2>/dev/null | wc -l); fi\n  [ -n \"$u\" ] && { [ \"$u\" -gt 0 ] && o warn \"обновления безопасности\" \"доступно: $u\" || o ok \"обновления безопасности\" \"нет\"; }\nfi\necho \"==END==\"": "o() { echo \"$1|$2|$3\"; }\ndf -P -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null | awk 'NR>1 { u = $5 + 0; s = (u >= 95 ? \"crit\" : u >= 85 ? \"warn\" : \"ok\"); print s \"|disk \" $6 \"|used \" u \"%\" }'\ndf -Pi -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null | awk 'NR>1 && $5 != \"-\" { u = $5 + 0; if (u >= 85) print (u >= 95 ? \"crit\" : \"warn\") \"|inode \" $6 \"|used \" u \"% inode\" }'\n# read-only: only when the device has no rw mount (a bind-ro mount such as /nix/store is normal)\nawk '$3 ~ /^(ext[234]|xfs|btrfs|f2fs)$/ { if ($4 ~ /^rw/) rw[$1] = 1; else if ($4 ~ /^ro(,|$)/) ro[$1] = $2 }\n  END { for (d in ro) if (!(d in rw)) print \"crit|FS \" ro[d] \"|mounted read-only (often a disk error)\" }' /proc/mounts\nawk '/^MemTotal/ { t = $2 } /^MemAvailable/ { a = $2 } /^SwapTotal/ { st = $2 } /^SwapFree/ { sf = $2 }\n  END { p = 100 - a * 100 / t; printf \"%s|memory|used %d%%\\n\", (p >= 95 ? \"crit\" : p >= 85 ? \"warn\" : \"ok\"), p\n        if (st > 0) { q = 100 - sf * 100 / st; printf \"%s|swap|used %d%%\\n\", (q >= 80 ? \"warn\" : \"ok\"), q } }' /proc/meminfo\nn=$(nproc 2>/dev/null || echo 1); read l1 l5 rest < /proc/loadavg\nawk -v l=\"$l5\" -v n=\"$n\" 'BEGIN { printf \"%s|load|%s in 5 min on %d cores\\n\", (l >= 2 * n ? \"crit\" : l >= n ? \"warn\" : \"ok\"), l, n }'\nif command -v timedatectl >/dev/null 2>&1; then\n  [ \"$(timedatectl show -p NTPSynchronized --value 2>/dev/null)\" = yes ] && o ok time \"synchronized (NTP)\" || o warn time \"not synchronized with NTP: logs, TLS and 2FA will drift\"\nfi\nif [ \"$FULL\" = 1 ]; then\n  S=\"\"; [ \"$(id -u)\" = 0 ] || { sudo -n true 2>/dev/null && S=\"sudo -n\"; }\n  oom=$($S journalctl -k --since -7d -q --no-pager 2>/dev/null | grep -ci \"out of memory\")\n  [ \"''${oom:-0}\" -gt 0 ] && o crit OOM \"processes killed for lack of memory in 7 days: $oom\" || o ok OOM \"none in 7 days\"\n  t=$($S journalctl -p err --since today -q --no-pager 2>/dev/null | wc -l)\n  w=$($S journalctl -p err --since -7d --until today -q --no-pager 2>/dev/null | wc -l); avg=$((w / 6))\n  [ \"$t\" -gt $((avg * 2 + 10)) ] && o warn \"error growth\" \"today $t, usually ~$avg per day\" || o ok \"journal errors\" \"today $t, usually ~$avg per day\"\n  if command -v openssl >/dev/null 2>&1; then\n    for c in $($S sh -c 'ls /etc/letsencrypt/live/*/cert.pem' 2>/dev/null); do\n      e=$($S openssl x509 -enddate -noout -in \"$c\" 2>/dev/null | cut -d= -f2); [ -n \"$e\" ] || continue\n      x=$(date -d \"$e\" +%s 2>/dev/null); [ -n \"$x\" ] || continue; d=$(( (x - $(date +%s)) / 86400 ))\n      o \"$([ $d -lt 3 ] && echo crit || { [ $d -lt 14 ] && echo warn || echo ok; })\" \"SSL $(basename \"$(dirname \"$c\")\")\" \"expires in $d days\"\n    done\n  fi\n  u=\"\"\n  if command -v apt >/dev/null 2>&1; then u=$(apt list --upgradable 2>/dev/null | grep -ci -- \"-security\")\n  elif command -v dnf >/dev/null 2>&1; then u=$(dnf -q updateinfo list --security 2>/dev/null | wc -l)\n  elif command -v checkupdates >/dev/null 2>&1; then u=$(checkupdates 2>/dev/null | wc -l); fi\n  [ -n \"$u\" ] && { [ \"$u\" -gt 0 ] && o warn \"security updates\" \"available: $u\" || o ok \"security updates\" \"none\"; }\nfi\necho \"==END==\"",
        "S=\"\"; [ \"$(id -u)\" = 0 ] || S=sudo; command -v auditctl >/dev/null 2>&1 || { echo \"auditd не установлен. Установите: apt install auditd | dnf install audit | pacman -S audit\"; exit 3; }; ": "S=\"\"; [ \"$(id -u)\" = 0 ] || S=sudo; command -v auditctl >/dev/null 2>&1 || { echo \"auditd is not installed. Install: apt install auditd | dnf install audit | pacman -S audit\"; exit 3; }; ",
        "Enter — продолжить": "Enter — continue",
        "set -e; command -v apt-get >/dev/null || {{ echo \"Нужна Ubuntu / Debian (apt)\"; exit 5; }}; grep -qsi \"^Include /etc/ssh/sshd_config.d/\" /etc/ssh/sshd_config || {{ echo \"В sshd_config нет Include sshd_config.d\"; exit 6; }}; apt-get update -qq || true; if ! id {p0} >/dev/null 2>&1; then adduser --disabled-password --gecos \"\" {p1}; echo \"Придумайте пароль для sudo пользователя {p2}:\"; passwd {p3}; fi; usermod -aG sudo {p4}; su - {p5} -s /bin/sh -c {p6}; for c in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do if [ -f \"$c\" ] && [ \"$c\" != {p7} ] && grep -qi \"^[[:space:]]*port[[:space:]]\" \"$c\"; then sed -i.ssh-storage.bak \"s/^[[:space:]]*[Pp]ort[[:space:]]/#&/\" \"$c\"; fi; done; printf \"Port {p8}\nPort {p9}\n\" > {p10}; sshd -t || {{ rm -f {p11}; for c in /etc/ssh/sshd_config.ssh-storage.bak /etc/ssh/sshd_config.d/*.ssh-storage.bak; do if [ -f \"$c\" ]; then mv \"$c\" \"''${{c%.ssh-storage.bak}}\"; fi; done; exit 7; }}; if command -v ufw >/dev/null && ufw status | grep -q \"Status: active\"; then ufw allow {p12}/tcp; fi; {p13}": "set -e; command -v apt-get >/dev/null || {{ echo \"Ubuntu / Debian (apt) required\"; exit 5; }}; grep -qsi \"^Include /etc/ssh/sshd_config.d/\" /etc/ssh/sshd_config || {{ echo \"sshd_config has no Include for sshd_config.d\"; exit 6; }}; apt-get update -qq || true; if ! id {p0} >/dev/null 2>&1; then adduser --disabled-password --gecos \"\" {p1}; echo \"Choose a password for sudo user {p2}:\"; passwd {p3}; fi; usermod -aG sudo {p4}; su - {p5} -s /bin/sh -c {p6}; for c in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do if [ -f \"$c\" ] && [ \"$c\" != {p7} ] && grep -qi \"^[[:space:]]*port[[:space:]]\" \"$c\"; then sed -i.ssh-storage.bak \"s/^[[:space:]]*[Pp]ort[[:space:]]/#&/\" \"$c\"; fi; done; printf \"Port {p8}\nPort {p9}\n\" > {p10}; sshd -t || {{ rm -f {p11}; for c in /etc/ssh/sshd_config.ssh-storage.bak /etc/ssh/sshd_config.d/*.ssh-storage.bak; do if [ -f \"$c\" ]; then mv \"$c\" \"''${{c%.ssh-storage.bak}}\"; fi; done; exit 7; }}; if command -v ufw >/dev/null && ufw status | grep -q \"Status: active\"; then ufw allow {p12}/tcp; fi; {p13}",
        "echo \"==ATTACKS==\"\nprintf '%s\\n' \"$A\" | awk '\nfunction add(ip, u, inv) { c[ip]++; if (inv) bad[ip] = 1; if (index(\" \" us[ip] \" \", \" \" u \" \") == 0) us[ip] = us[ip] \" \" u\n  last[ip] = ts; uc[u]++; ul[u] = ts }\n{ ts = ($1 ~ /^[0-9]/) ? $1 : $1 \"_\" $2 \"_\" $3; pid = match($0, /\\[[0-9]+\\]:/) ? substr($0, RSTART, RLENGTH) : \"\" }  # journal (ISO) или auth.log («Oct 23 10:00:00»)\n/Invalid user [^ ]+ from / { match($0, /Invalid user [^ ]+ from [^ ]+/); split(substr($0, RSTART, RLENGTH), w, \" \")\n  add(w[5], w[3], 1); next }\n/(Connection closed by|Disconnected from) authenticating user [^ ]+ [^ ]+/ { if (pid != \"\" && pid in fl) next\n  match($0, /authenticating user [^ ]+ [^ ]+/); split(substr($0, RSTART, RLENGTH), w, \" \"); add(w[4], w[3], 0); next }\n/Failed (password|publickey|keyboard-interactive)/ && !/invalid user/ {\n  if (match($0, /for [^ ]+ from [^ ]+/)) { split(substr($0, RSTART, RLENGTH), w, \" \"); add(w[4], w[2], 0); fl[pid] = 1 } }\nEND { for (ip in c) if (c[ip] >= 5 || bad[ip]) print \"IP\", c[ip], ip, (bad[ip] ? \"invalid\" : \"-\"), last[ip], us[ip]\n      for (u in uc) print \"USER\", uc[u], u, ul[u] }' | sort -k1,1 -k2,2nr | awk -v N=$N '{ if (++n[$1] <= N) print }'\necho \"==END==\"": "echo \"==ATTACKS==\"\nprintf '%s\\n' \"$A\" | awk '\nfunction add(ip, u, inv) { c[ip]++; if (inv) bad[ip] = 1; if (index(\" \" us[ip] \" \", \" \" u \" \") == 0) us[ip] = us[ip] \" \" u\n  last[ip] = ts; uc[u]++; ul[u] = ts }\n{ ts = ($1 ~ /^[0-9]/) ? $1 : $1 \"_\" $2 \"_\" $3; pid = match($0, /\\[[0-9]+\\]:/) ? substr($0, RSTART, RLENGTH) : \"\" }  # journal (ISO) or auth.log (\"Oct 23 10:00:00\")\n/Invalid user [^ ]+ from / { match($0, /Invalid user [^ ]+ from [^ ]+/); split(substr($0, RSTART, RLENGTH), w, \" \")\n  add(w[5], w[3], 1); next }\n/(Connection closed by|Disconnected from) authenticating user [^ ]+ [^ ]+/ { if (pid != \"\" && pid in fl) next\n  match($0, /authenticating user [^ ]+ [^ ]+/); split(substr($0, RSTART, RLENGTH), w, \" \"); add(w[4], w[3], 0); next }\n/Failed (password|publickey|keyboard-interactive)/ && !/invalid user/ {\n  if (match($0, /for [^ ]+ from [^ ]+/)) { split(substr($0, RSTART, RLENGTH), w, \" \"); add(w[4], w[2], 0); fl[pid] = 1 } }\nEND { for (ip in c) if (c[ip] >= 5 || bad[ip]) print \"IP\", c[ip], ip, (bad[ip] ? \"invalid\" : \"-\"), last[ip], us[ip]\n      for (u in uc) print \"USER\", uc[u], u, ul[u] }' | sort -k1,1 -k2,2nr | awk -v N=$N '{ if (++n[$1] <= N) print }'\necho \"==END==\"",
        "диск /": "disk /",
        "память": "memory",
        "нагрузка": "load",
        "$S sh -c 'set -e\nB=/var/lib/ssh-storage; mkdir -p $B\n[ -f $B/auditd.prev ] || { systemctl is-active auditd >/dev/null 2>&1 && echo active || echo inactive; } > $B/auditd.prev\ntar czf $B/audit-backup-$(date +%Y%m%d%H%M%S).tgz -C /etc audit\necho \"копия настроек: $(ls -t $B/audit-backup-*.tgz | head -n 1)\"\nprintf \"%s\\n\" \"-a always,exit -F arch=b64 -S execve -F auid!=4294967295 -k ssh-storage\" \"-a always,exit -F arch=b32 -S execve -F auid!=4294967295 -k ssh-storage\" > /etc/audit/rules.d/ssh-storage.rules\nsystemctl enable --now auditd\naugenrules --load >/dev/null 2>&1 || auditctl -R /etc/audit/rules.d/ssh-storage.rules >/dev/null\nauditctl -l | grep -q ssh-storage\necho \"✓ запись команд включена\"'": "$S sh -c 'set -e\nB=/var/lib/ssh-storage; mkdir -p $B\n[ -f $B/auditd.prev ] || { systemctl is-active auditd >/dev/null 2>&1 && echo active || echo inactive; } > $B/auditd.prev\ntar czf $B/audit-backup-$(date +%Y%m%d%H%M%S).tgz -C /etc audit\necho \"settings backup: $(ls -t $B/audit-backup-*.tgz | head -n 1)\"\nprintf \"%s\\n\" \"-a always,exit -F arch=b64 -S execve -F auid!=4294967295 -k ssh-storage\" \"-a always,exit -F arch=b32 -S execve -F auid!=4294967295 -k ssh-storage\" > /etc/audit/rules.d/ssh-storage.rules\nsystemctl enable --now auditd\naugenrules --load >/dev/null 2>&1 || auditctl -R /etc/audit/rules.d/ssh-storage.rules >/dev/null\nauditctl -l | grep -q ssh-storage\necho \"command logging enabled\"'",
        "$S sh -c 'B=/var/lib/ssh-storage\nrm -f /etc/audit/rules.d/ssh-storage.rules\nauditctl -D -k ssh-storage >/dev/null 2>&1; augenrules --load >/dev/null 2>&1\nif [ \"$(cat $B/auditd.prev 2>/dev/null)\" = inactive ]; then\n  systemctl disable --now auditd 2>/dev/null || { systemctl disable auditd; service auditd stop; }\n  echo \"auditd остановлен (был выключен до ssh-storage)\"\nfi\nrm -f $B/auditd.prev\n! auditctl -l 2>/dev/null | grep -q ssh-storage && echo \"✓ запись команд выключена, правила ssh-storage сняты\"'": "$S sh -c 'B=/var/lib/ssh-storage\nrm -f /etc/audit/rules.d/ssh-storage.rules\nauditctl -D -k ssh-storage >/dev/null 2>&1; augenrules --load >/dev/null 2>&1\nif [ \"$(cat $B/auditd.prev 2>/dev/null)\" = inactive ]; then\n  systemctl disable --now auditd 2>/dev/null || { systemctl disable auditd; service auditd stop; }\n  echo \"auditd stopped (was disabled before ssh-storage)\"\nfi\nrm -f $B/auditd.prev\n! auditctl -l 2>/dev/null | grep -q ssh-storage && echo \"command logging disabled, ssh-storage rules removed\"'",
        "любые права": "any privileges",
        "доступ к журналам (группа adm или systemd-journal) или sudo": "log access (adm or systemd-journal group) or sudo",
        "root или sudo": "root or sudo",
        "СТЕРЕТЬ": "ERASE",
        "администратор — sudo и журналы": "administrator — sudo and logs",
        "оператор — журналы и sudo systemctl restart/reload": "operator — logs and sudo systemctl restart/reload",
        "наблюдатель — журналы, без sudo": "observer — logs, no sudo",
        "Language / Язык": "Language / Язык",
        "\n  Пик:     {p0}  {p1}": "\n  Peak:    {p0}  {p1}",
        "  Среднее: {p0}{p1}": "  Average: {p0}{p1}",
        "  Минимум: {p0}{p1}": "  Minimum: {p0}{p1}",
        "sudo без пароля": "passwordless sudo",
        "sudo с паролем": "sudo with password",
        "доступ к журналам": "log access",
        "обычный пользователь": "regular user",
        "стереть данные": "erase data",
        "установка на телефон": "phone installation",
        "\n  Код проверки:  {p0}\n": "\n  Verification code:  {p0}\n",
        "Если на телефоне тот же код — нажмите там Enter.": "If the phone shows the same code, press Enter there.",
        "id -nG \"$L\" | grep -Eq \"(^| )ssh-storage-{p0}( |$)\" || {{ echo \"✗ не удалось выдать роль\"; exit 1; }}; [ $new = 1 ] && w=создан || w=обновлён; echo \"✓ $w $L ($N): ключ на месте, группы: $(id -nG \"$L\")\"": "id -nG \"$L\" | grep -Eq \"(^| )ssh-storage-{p0}( |$)\" || {{ echo \"failed to assign role\"; exit 1; }}; [ $new = 1 ] && w=created || w=updated; echo \"$w $L ($N): key installed, groups: $(id -nG \"$L\")\"",
        "echo \"✓ $L: ключи сняты, вход заблокирован, сеансы закрыты, sudo снят\"; elif [ $t = 1 ]; then echo \"✓ у $L снят только ключ\"; else continue; fi; n=$((n+1)); done; [ $n -gt 0 ] || exit 3": "echo \"$L: keys removed, login blocked, sessions closed, sudo revoked\"; elif [ $t = 1 ]; then echo \"only the key was removed for $L\"; else continue; fi; n=$((n+1)); done; [ $n -gt 0 ] || exit 3",
        "echo \"✓ у $L снят только ключ (не участник — не удаляю)\"; else continue; fi; n=$((n+1)); done; [ $n -gt 0 ] || exit 3": "echo \"only the key was removed for $L (not a member — account left intact)\"; else continue; fi; n=$((n+1)); done; [ $n -gt 0 ] || exit 3",
        "история": "history",
        "обрезанная SSH-строка": "truncated SSH string",
        "не DER": "not DER",
        "  Точек: {p0} из ~{p1} (пустые места — сервер был выключен или сборщика ещё не было).": "  Samples: {p0} of ~{p1} (gaps mean the server was off or the collector was not yet installed).",
        " && echo '✓ перезапущено'": " && echo 'restarted'",
        "недопустимый сигнал или PID": "invalid signal or PID",
        "— {p0} {p1}: процесс уже завершён или сменился": "— {p0} {p1}: process has already exited or changed",
        "  {p0} {p1}  {p2}  {p3}  логины: {p4}": "  {p0} {p1}  {p2}  {p3}  usernames: {p4}",
        "  {p0} {p1} попыт.  {p2}": "  {p0} {p1} attempts  {p2}",
        "слишком большое сообщение": "message too large",
        "ожидался объект сообщения": "expected a message object",
        "Название": "Name",
        "IP / хост": "IP / host",
        "Пользователь": "User",
        "Имя (латиница, цифры, _ -; видно в подписи ключа на сервере)": "Name (Latin letters, digits, _ -; shown in the key comment on the server)",
        "Новое имя": "New name",
        "Имя (латиница, цифры, _ -)": "Name (Latin letters, digits, _ -)",
        " (ключа телефона там ещё нет)?": " (the phone's key is not there yet)?",
        "Пароль сервера": "Server password",
        "SSH-ключ: путь к файлу или вставить текст ключа": "SSH key: file path or pasted key text",
        "Автоматически (ключи из ~/.ssh и агента)": "Automatic (keys from ~/.ssh and the agent)",
        "Отмена": "Cancel",
        "Путь к закрытому ключу (например ~/.ssh/id_ed25519) или вставьте ключ целиком,": "Enter the private key path (e.g. ~/.ssh/id_ed25519) or paste the entire key,",
        "начиная со строки -----BEGIN … PRIVATE KEY----- (текст ключа на экране не показывается).": "starting with -----BEGIN … PRIVATE KEY----- (the key text is hidden).",
        "хост не найден (ошибка в имени или DNS)": "host not found (incorrect name or DNS error)",
        "порт закрыт (SSH не запущен или другой порт)": "port closed (SSH not running or using another port)",
        "нет ответа (сервер выключен, файрвол или другая сеть)": "no response (server off, firewall, or different network)",
        "нет связи: {p0}": "cannot connect: {p0}",
        "Проверяю {p0}:{p1}…": "Checking {p0}:{p1}…",
        "Всё равно продолжить?": "Continue anyway?",
        "сопряжение": "pairing",
        "  Компьютер: {p0}  {p1}\n": "  Computer: {p0}  {p1}\n",
        "  Введите на компьютере код:  {p0}\n": "  Enter this code on the computer:  {p0}\n",
        "   Код сеанса:  {p0}": "   Session code:  {p0}",
        "отозвать участника": "revoke member access",
        "Ник участника (или номер)": "Member nickname (or number)",
        "Где отозвать": "Where to revoke access",
        "телефон": "phone",
        "отзыв {p0}": "revoking access: {p0}",
        "итог отзыва · {p0}": "revocation summary · {p0}",
        "установка на сервер": "server installation",
        "Выполните на сервере {p0} (консоль хостинга или текущий вход):\n": "Run on server {p0} (via the hosting console or an existing session):\n",
        "Стереть серверы и сопряжение (ключ SSH остаётся — серверы будут пускать телефон)": "Erase servers and pairing (keep SSH key — servers will still accept this phone)",
        "Стереть всё: и ключ SSH, и приложение": "Erase everything: SSH key and app too",
        "Назад": "Back",
        " из F-Droid.": " from F-Droid.",
        "Или наведите камеру телефона на QR, скопируйте текст и вставьте в Termux:\n": "Or scan the QR code with your phone's camera, copy the text and paste it into Termux:\n",
        "Когда телефон ждёт — Enter: ": "When the phone is waiting, press Enter: ",
        "Если код другой — НЕ нажимайте, закройте Termux: файл подменили.": "If the code differs, do NOT press Enter. Close Termux: the file has been tampered with.",
        "недопустимый ключ или ник": "invalid key or nickname",
        "Это компьютер участника команды (резервный пароль хранит админ)?": "Is this a team member's computer (the admin keeps the recovery password)?",
        "резервный пароль": "recovery password",
        "Это единственный способ вернуть доступ, если телефон потеряется или сломается.": "This is the only way to regain access if the phone is lost or breaks.",
        "Запишите его на бумагу и храните отдельно. Он больше нигде не сохраняется.\n": "Write it on paper and keep it separately. It is not saved anywhere else.\n",
        "сопряжение с телефоном": "pair with phone",
        "подключение": "connection",
        "вход на сервер": "server login",
        "серверы": "servers",
        "изменить список серверов": "edit server list",
        "История (входы, sudo-команды, пакеты, изменения /etc)": "History (logins, sudo commands, packages, /etc changes)",
        "Запись команд auditd (включить / история / выключить)": "auditd command logging (enable / history / disable)",
        "Попытки взлома (неверные входы, несуществующие логины, частые IP)": "Break-in attempts (failed logins, unknown users, frequent IPs)",
        "Диагностика (упавшие сервисы, ошибки журнала, процессы)": "Diagnostics (failed services, journal errors, processes)",
        "Проверка на зачатки неисправностей (быстрая / полная)": "Check for early warning signs (quick / full)",
        "Перезагрузить сервер": "Reboot server",
        "Создать пользователя для участника (командный режим)": "Create a user for a member (team mode)",
        "Проверка процессов (подмена системных, новые программы, скрытые процессы)": "Process check (system process impersonation, new programs, hidden processes)",
        "Туннель к веб-панели (3x-ui и др.) — панель не торчит в интернет": "Tunnel to web panel (3x-ui, etc.) — keep the panel off the public internet",
        "действия на сервере": "server actions",
        "За сколько дней": "Number of days",
        "{p0} {p1} (только чтение)": "{p0} {p1} (read-only)",
        "проверка {p0} (только чтение)": "check {p0} (read-only)",
        "на (\\d+) ядер": "on (\\d+) cores",
        "диагностика {p0} (только чтение)": "diagnostics {p0} (read-only)",
        "диагностика · {p0}": "diagnostics · {p0}",
        "Логин на сервере (a-z, 0-9, _ -)": "Server username (a-z, 0-9, _ -)",
        "Ник участника (для метки ключа)": "Member nickname (for the key label)",
        "новый пользователь · {p0}": "new user · {p0}",
        "создать пользователя {p0} ({p1})": "create user {p0} ({p1})",
        "проверка процессов {p0} (только чтение)": "process check {p0} (read-only)",
        "проверка процессов · {p0}": "process check · {p0}",
        "опасное действие": "dangerous action",
        "журнал одобрений": "approval log",
        "просмотр журнала одобрений": "view approval log",
        "туннель к панели {p0}:{p1}": "tunnel to panel {p0}:{p1}",
        "права не проверены": "permissions not checked",
        "новый VPS: настроить с нуля": "new VPS: set up from scratch",
        "Логин от хостера": "Username from the provider",
        "Новый пользователь": "New user",
        "новый VPS {p0}": "new VPS {p0}",
        "новый сервер": "new server",
        "\nДругие ключи в ~/.ssh/authorized_keys на сервере — те, которыми вы входили раньше": "\nOther keys in ~/.ssh/authorized_keys on the server — keys you used before",
        "массовое добавление": "bulk add",
        "\nСпособ первого входа:": "\nInitial login method:",
        "участник → серверы": "member → servers",
        "добавить участника {p0} ({p1}) на серверы ({p2})": "add member {p0} ({p1}) to servers ({p2})",
        "участник {p0} ({p1}): добавлен на {p2}, не добавлен на {p3}": "member {p0} ({p1}): added to {p2}, not added to {p3}",
        "итог": "results",
        "Ник участника": "Member nickname",
        "Где": "Where",
        "{p0} участника {p1} на серверах ({p2})": "{p0} member {p1} on servers ({p2})",
        "массовое удаление": "bulk removal",
        "итог массового удаления": "bulk removal results",
        "перевыпуск ключей": "key rotation",
        "перевыпуск ключей — сводка": "key rotation — summary",
        "  Перевыпустить: {p0}": "  Rotate: {p0}",
        "  Режим: {p0}": "  Mode: {p0}",
        "  Серверы ({p0}):": "  Servers ({p0}):",
        "перевыпуск ключей на всех серверах": "rotate keys on all servers",
        "итог перевыпуска": "rotation results",
        "восстановление": "recovery",
        "Вход резервным ключом из 20-символьного пароля.\n": "Log in with a backup key derived from a 20-character password.\n",
        "перенос старых подключений": "migrate old connections",
        ": сопряжение и список серверов.": ": pairing and server list.",
        "Удалится закрытый ключ сопряжения; SSH-ключ остаётся на телефоне, резервный пароль — на бумаге.": "The private pairing key will be deleted; the SSH key stays on the phone, and the backup password stays on paper.",
        "Резервный пароль после этого здесь не будет известен: при новом сопряжении создастся новый.": "The backup password will no longer be available here: pairing again will create a new one.",
        "✓ Стёрто.": "Erased.",
        "главное меню": "main menu",
        "выдаёт себя за поток ядра (у настоящих нет файла программы)": "posing as a kernel thread (real ones have no executable file)",
        "файл программы из пакета изменён — не совпадает с контрольной суммой пакета": "package executable modified — does not match the package checksum",
        "файл программы удалён после запуска (после обновления — норма до перезапуска)": "executable deleted after launch (normal after an update until restarted)",
        "запущена из временной / домашней папки": "running from a temporary / home directory",
        "имя «{p0}» не совпадает с файлом программы «{p1}» и программа не из пакета": "name “{p0}” differs from executable “{p1}” and the program is not from a package",
        "  Нет данных за этот период.": "  No data for this period.",
        "  Нагрузка — средняя за 5 мин; {p0} ядер = загрузка 100%.": "  Load is the 5-minute average; {p0} cores = 100% load.",
        "  ⚠ Нет доступа к журналам (нужны группа adm / systemd-journal или sudo без пароля) — данные могут быть неполными.\n": "  No log access (requires the adm / systemd-journal group or passwordless sudo) — data may be incomplete.\n",
        "Источники атак": "Attack sources",
        "  (IP — только при ≥5 неудачных входах или входе под несуществующим логином)": "  (IP shown only for ≥5 failed logins or an attempt with a nonexistent username)",
        "несуществующий логин": "nonexistent username",
        "≥5 неудач": "≥5 failures",
        "  (без IP)": "  (no IP)",
        "Входы": "Logins",
        "  (кто, когда, чем; без IP)": "  (who, when, how; no IP)",
        "sudo-команды": "sudo commands",
        "Смены пользователя (su)": "User switches (su)",
        "Пакеты": "Packages",
        "Изменённые файлы /etc": "Modified /etc files",
        "Ищу телефон в сети…": "Looking for the phone on the network…",
        "Телефон не найден (та же сеть Wi-Fi? в кафе устройства бывают изолированы).": "Phone not found (same Wi-Fi network? Public Wi-Fi may isolate devices).",
        "Порт": "Port",
        "Оставить «{p0}»": "Keep “{p0}”",
        "Последнее: «{p0}»": "Last: “{p0}”",
        "строка {p0}: «{p1}»": "line {p0}: “{p1}”",
        "нет файла {p0}": "file not found: {p0}",
        "\nКак зайти на сервер ": "\nHow should we log in to the server ",
        "✗ Файл не найден (или вставьте ключ, начиная со строки -----BEGIN)": "File not found (or paste a key starting with -----BEGIN)",
        "не нашёл SSH-сервер на этом порту": "no SSH server found on this port",
        "✓ SSH отвечает": "SSH responds",
        "  [ключи не установлены]": "  [keys not installed]",
        "Keystore не создал ключ": "Keystore failed to create a key",
        "Keystore не подписал": "Keystore failed to sign",
        "нарушен протокол — возможна атака": "protocol violation — possible attack",
        "Компьютер написал «✓ Код верный»?": "Did the computer show “Code correct”?",
        "\n✓ Сопряжено с «{p0}»": "\nPaired with “{p0}”",
        "   Разрешайте, только если на компьютере тот же код.": "   Approve only if the computer shows the same code.",
        "Код совпадает, разрешить?": "Does the code match? Allow?",
        "\nУчастник {p0}: ключи снять, вход заблокировать, сеансы закрыть на: {p1}. Полное удаление — с компьютера.": "\nMember {p0}: remove keys, block login and close sessions on: {p1}. Use the computer to delete the account entirely.",
        "Проще: на компьютере ssh-storage → «Серверы» → «Добавить сервер» сделает это сам.": "Easier: on the computer, ssh-storage → “Servers” → “Add server” does this automatically.",
        "✓ Установлено. Дальше на телефоне команда ": "Installed. Next, on the phone run ",
        "Нет termux-keystore.": "termux-keystore is missing.",
        "Ожидать запросы компьютера": "Wait for computer requests",
        "Серверы": "Servers",
        "Сопряжение": "Pairing",
        "Специальные возможности": "Advanced options",
        "Выход": "Exit",
        "ожидание": "waiting",
        "  Журнал пуст.": "  Log is empty.",
        "  …показаны последние 50 из {p0}": "  …showing the latest 50 of {p0}",
        "\nУдалится список серверов и сопряжение. Потом — новое сопряжение с компьютером.": "\nThe server list and pairing will be erased. You will need to pair with a computer again.",
        "✓ Стёрто. Запустите ssh-storage заново.": "Erased. Restart ssh-storage.",
        "  Вернуть доступ можно только резервным паролем (на компьютере → «Специальные возможности» → «Восстановление»).": "  Access can only be restored with the recovery password (on the computer → “Advanced options” → “Recovery”).",
        "✓ Всё стёрто: ключ, данные и приложение.": "Everything erased: key, data and app.",
        "Нужно: Termux и ": "Required: Termux and ",
        "В Termux выполните ": "In Termux, run ",
        "Ищу устройства…": "Searching for devices…",
        "Только номера от 1 до {p0}.": "Only numbers from 1 to {p0}.",
        "case \"$(pw)\" in \"\"|\"!\"*|\"*\"*) echo \"Временный пароль sudo для $L:\"; passwd \"$L\" || exit 1; if passwd -e \"$L\" >/dev/null 2>&1 || chage -d 0 \"$L\" 2>/dev/null; then echo \"  $L сменит его при первом входе\"; else echo \"  ⚠ сервер не умеет просить смену — попросите $L выполнить passwd\"; fi;; esac; SG=$(getent group sudo >/dev/null && echo sudo || echo wheel); grp $SG; join $SG; sudo -l -U \"$L\" 2>/dev/null | grep -q \"may run\" || echo \"  ⚠ sudo для $L не работает: в /etc/sudoers не разрешена группа $SG (visudo)\"; ": "case \"$(pw)\" in \"\"|\"!\"*|\"*\"*) echo \"Temporary sudo password for $L:\"; passwd \"$L\" || exit 1; if passwd -e \"$L\" >/dev/null 2>&1 || chage -d 0 \"$L\" 2>/dev/null; then echo \"  $L will change it on first login\"; else echo \"  server cannot require a password change — ask $L to run passwd\"; fi;; esac; SG=$(getent group sudo >/dev/null && echo sudo || echo wheel); grp $SG; join $SG; sudo -l -U \"$L\" 2>/dev/null | grep -q \"may run\" || echo \"  sudo does not work for $L: group $SG is not allowed in /etc/sudoers (visudo)\"; ",
        "n=0; for L in $(getent passwd | cut -d: -f1); do home; m=0; ours && mine && m=1; if [ $m = 1 ]; then pkill -KILL -u \"$L\" 2>/dev/null; sleep 1; userdel -r \"$L\" 2>/dev/null; if id \"$L\" >/dev/null 2>&1; then deluser --remove-home \"$L\" || exit 1; fi; rm -f \"$R/$L\" \"$R/$L.locked\"; echo \"✓ удалён пользователь $L и его папка\"; elif grep -q \"$T\" \"$f\" 2>/dev/null; then ": "n=0; for L in $(getent passwd | cut -d: -f1); do home; m=0; ours && mine && m=1; if [ $m = 1 ]; then pkill -KILL -u \"$L\" 2>/dev/null; sleep 1; userdel -r \"$L\" 2>/dev/null; if id \"$L\" >/dev/null 2>&1; then deluser --remove-home \"$L\" || exit 1; fi; rm -f \"$R/$L\" \"$R/$L.locked\"; echo \"user $L and their home directory deleted\"; elif grep -q \"$T\" \"$f\" 2>/dev/null; then ",
        "На телефоне: ssh-storage → «Ожидать запросы компьютера».": "On the phone: ssh-storage → “Wait for computer requests”.",
        "\n  Код сеанса:  {p0}": "\n  Session code:  {p0}",
        "Обновляю программу на телефоне ({p0} → {p1})…": "Updating the app on the phone ({p0} → {p1})…",
        "«Да» — только если админ команды сам выдал вам доступ. Иначе ответьте «нет».": "Answer “yes” only if the team admin personally granted you access. Otherwise, answer “no”.",
        "Вычисляю резервный ключ…": "Deriving recovery key…",
        "На телефоне: ssh-storage → «Начать сопряжение».\n": "On the phone: ssh-storage → “Start pairing”.\n",
        "Enter — искать телефон: ": "Press Enter to search for the phone: ",
        "  Телефон: {p0}\n": "  Phone: {p0}\n",
        "Дальше: «Серверы» → «Добавить сервер» — ключ телефона пропишется на сервер.": "Next: “Servers” → “Add server” to install the phone's key on the server.",
        "Добавить участника на серверы": "Add a member to servers",
        "Отозвать или удалить участника": "Revoke access or remove a member",
        "действия · {p0}": "actions · {p0}",
        "  {p0} · права: {p1}\n": "  {p0} · permissions: {p1}\n",
        "Проверить права на сервере": "Check server permissions",
        "{p0} · {p1} · {p2} дн.": "{p0} · {p1} · {p2} days",
        "запись команд · {p0}": "command logging · {p0}",
        "проверка · {p0} · {p1}": "check · {p0} · {p1}",
        "Упавшие сервисы": "Failed services",
        "Перезапустить сервисы (номера)": "Restart services (numbers)",
        "Остановить процессы — SIGTERM (номера)": "Stop processes — SIGTERM (numbers)",
        "Убить процессы принудительно — SIGKILL (номера)": "Force-kill processes — SIGKILL (numbers)",
        "перезапустить": "restart",
        "остановить (SIGTERM)": "stop (SIGTERM)",
        "убить (SIGKILL)": "kill (SIGKILL)",
        "\nБудет {p0}:": "\nAction: {p0}:",
        "специальные возможности": "advanced options",
        "  У каждого участника свой Unix-пользователь и свой ключ — в журналах видно, кто что делал.\n": "  Each member has their own Unix user and key — logs show who did what.\n",
        "  Роль задаёт права. Администратору sudo нужен только если он ставит пакеты и правит системные файлы.": "  The role defines permissions. An admin needs sudo only to install packages and edit system files.",
        "\nБудет создан пользователь {p0} на {p1} с ключом участника {p2}.": "\nUser {p0} will be created on {p1} with member {p2}'s key.",
        "создан пользователь {p0} ({p1})": "user {p0} created ({p1})",
        "  {p0} {p1} (pid {p2}) скрыт от ps — признак руткита": "  {p0} {p1} (pid {p2}) is hidden from ps — a sign of a rootkit",
        "Доверять: запомнить текущие программы как нормальные": "Trust: save current programs as the baseline",
        "перезагрузить сервер": "reboot server",
        "Жду, пока сервер выключится и снова ответит по SSH… (Ctrl+C — перестать ждать)": "Waiting for the server to shut down and respond over SSH again… (Ctrl+C to stop waiting)",
        "Захожу на {p0}@{p1}…": "Logging in to {p0}@{p1}…",
        "✓ «{p0}»: ключ телефона и резервный ключ прописаны": "“{p0}”: phone key and backup key installed",
        "Порт панели на сервере": "Panel port on server",
        "Проверяю вход ключом телефона и отключаю старые ключи…": "Checking login with the phone key and disabling old keys…",
        "Только купил сервер: есть root (или пользователь с sudo) и пароль от хостера": "I just bought a server: I have root (or a sudo user) and a password from the provider",
        "Мне дали личного пользователя на чужом сервере (без root)": "I was given my own account on someone else's server (no root)",
        "Порт сейчас": "Current port",
        "Новый порт SSH": "New SSH port",
        "Продолжить?": "Continue?",
        "(ключи с компьютеров, другие ssh-ключи; ключи телефонов, резервный и участников команды не затрагиваются):": "(computer keys and other SSH keys; phone, backup, and team member keys are not affected):",
        "Оставить — они продолжат работать, просто добавится ключ телефона": "Keep — they will still work; the phone key will simply be added",
        "Отключить — входить ими станет нельзя. Строки не удаляются: в начало ставится «#»,\n      вернуть можно, убрав «#» или из копии authorized_keys.ssh-storage.bak.\n      Делается только после того, как вход телефоном проверен.": "Disable — they will no longer allow login. Lines are not deleted: '#' is added at the start.\n      Restore them by removing '#' or using authorized_keys.ssh-storage.bak.\n      Done only after phone login has been verified.",
        "добавить сервер {p0}": "add server {p0}",
        "Из файла (строки: имя хост [порт] [пользователь])": "From a file (lines: name host [port] [user])",
        "Из ~/.ssh/config": "From ~/.ssh/config",
        "Вставить списком": "Paste a list",
        "Проверяю доступность…": "Checking reachability…",
        "добавить серверы ({p0})": "add servers ({p0})",
        "итог массового добавления": "bulk add results",
        "\nПользователь {p0} (участник {p1}) на серверах: {p2}": "\nUser {p0} (member {p1}) on servers: {p2}",
        "  Добавлен: {p0}": "  Added to: {p0}",
        "Только снять ключи — пользователь и его файлы останутся": "Remove keys only — keep the user and their files",
        "Удалить полностью — пользователя, его папку и ключи (необратимо)": "Delete completely — user, home directory, and keys (irreversible)",
        "Только из списка (ключи на серверах остаются)": "From the list only (keep keys on servers)",
        "Из списка + снять ключ телефона и резервный с серверов": "From the list and remove phone and backup keys from servers",
        "удалить серверы ({p0})": "remove servers ({p0})",
        "  Удалено: {p0}": "  Removed: {p0}",
        "Один ключ на устройство: перевыпуск действует сразу на всех серверах из списка.\n": "One key per device: rotation applies to all servers in the list at once.\n",
        "Ключ телефона": "Phone key",
        "Резервный ключ (новый резервный пароль)": "Backup key (new backup password)",
        "Оба": "Both",
        "Добавить: остальные ключи на серверах не трогать": "Add: leave other keys on servers unchanged",
        "Затереть: оставить на серверах только ключи ssh-storage этого телефона": "Overwrite: keep only this phone's ssh-storage keys on servers",
        "  Готово: {p0}": "  Done: {p0}",
        "Выберите ключ потерянного телефона для отзыва. Ключи других людей не выбирайте.": "Select the lost phone's key to revoke. Do not select other people's keys.",
        "⚠ Новый телефон проверен, но старые ключи остались действующими": "New phone verified, but old keys are still active",
        "Пароль администратора старого хранилища: ": "Old storage admin password: ",
        "Проверяю…": "Checking…",
        "Удалится ": "Will delete ",
        "Удалить и старый vault.json?": "Also delete the old vault.json?",
        "ssh не найден": "ssh not found",
        "Телефон не сопряжён": "Phone not paired",
        "Резервный ключ есть": "Recovery key present",
        "Резервного ключа нет": "No recovery key",
        "Подключиться к серверу": "Connect to a server",
        "Действия на сервере": "Server actions",
        "Выбор [{p0}]: ": "Choice [{p0}]: ",
        "месяц": "month",
        "Всё в порядке.": "All OK.",
        "Требуют внимания: {p0}.": "Need attention: {p0}.",
        "Неудачные входы по пользователям": "Failed logins by user",
        "ключ": "key",
        "пароль": "password",
        "соединение закрыто": "connection closed",
        "подделка или чужое устройство — соединение разорвано": "forgery or unknown device — connection closed",
        "    обязательное поле": "    required field",
        "    неверное значение": "    invalid value",
        "Имя (видно в подписи ключа на сервере)": "Name (shown in the key comment on the server)",
        "в первый раз": "for the first time",
        "✓ Ключ принят ({p0} строк), будет удалён после входа": "Key accepted ({p0} lines), will be deleted after login",
        "Создаю ключ в Android Keystore…": "Creating a key in Android Keystore…",
        "сопряжения": "pairing",
        "запросы компьютера": "computer requests",
        "компьютер": "computer",
        "✗ Сопряжение отменено": "Pairing cancelled",
        "Запрос от незнакомого компьютера — отклонён.\n": "Request from an unknown computer — rejected.\n",
        "Запрос от «{p0}»: {p1}": "Request from \"{p0}\": {p1}",
        "Нет ssh: выполните pkg install openssh": "ssh is missing: run pkg install openssh",
        "Список серверов пуст.": "Server list is empty.",
        "Отозвать?": "Revoke access?",
        "Сначала сопряжение с компьютером (там создаётся резервный пароль).": "Pair with a computer first (the recovery password is created there).",
        " из F-Droid и выполните: ": " from F-Droid and run: ",
        "\n⚠ Ключ SSH будет удалён навсегда: НИ ОДИН сервер больше не пустит этот телефон.": "\nThe SSH key will be permanently deleted: NO server will accept this phone anymore.",
        "(можно переслать себе в мессенджер)": "(you can send it to yourself in a messaging app)",
        "Устройства не найдены. Искать снова?": "No devices found. Search again?",
        "устройство": "device",
        "Телефон не сопряжён: пункт «Сопряжение» → «Сопряжение с телефоном».": "Phone is not paired: select “Pairing” → “Pair with phone”.",
        "  Подтвердите на телефоне, если там тот же код…": "  Confirm on the phone if it shows the same code…",
        "✓ Телефон обновлён (перезапустится после сеанса)": "Phone updated (app will restart after the session)",
        "✗ Обновление на телефоне не прошло проверку": "Update on the phone failed verification",
        "Введите его для проверки: ": "Enter it to verify: ",
        "  Не совпадает.": "  Does not match.",
        "\n✓ Телефон сопряжён": "\nPhone paired",
        "Список серверов пуст. Добавьте: «Серверы» → «Добавить сервер».": "Server list is empty. Add one: “Servers” → “Add server”.",
        "Сопряжение с телефоном": "Pair with phone",
        "Установить / обновить приложение на телефоне": "Install / update the phone app",
        "проверить права на {p0}": "check permissions on {p0}",
        "  auditd записывает каждую запущенную команду с исходным пользователем входа —": "  auditd logs every command with the original login user —",
        "  видно, кто на самом деле работал, даже после sudo -i / su. Нужен root или sudo.\n": "  see who actually ran it, even after sudo -i / su. Requires root or sudo.\n",
        "Включить запись команд": "Enable command logging",
        "История команд": "Command history",
        "Выключить (откат к прежним настройкам)": "Disable (restore previous settings)",
        "включить запись команд (auditd)": "enable command logging (auditd)",
        "Быстрая (диск, память, нагрузка, время)": "Quick (disk, memory, load, time)",
        "Полная (+ OOM, рост ошибок, SSL-сертификаты, обновления безопасности)": "Full (+ OOM, rising error counts, SSL certificates, security updates)",
        "история · {p0}": "history · {p0}",
        "✗ Не удалось получить данные": "Could not retrieve data",
        "  нет": "  none",
        "  (последние 30, без IP)": "  (last 30, IP addresses omitted)",
        "нет": "none",
        "  (PID 1, sshd и свой сеанс не показаны)": "  (PID 1, sshd and your session are omitted)",
        "Нет подходящих номеров.": "No valid numbers.",
        "SIGKILL не даёт процессу сохранить данные — только если SIGTERM не помог.": "SIGKILL prevents the process from saving data — use only if SIGTERM did not work.",
        "Выполнить?": "Proceed?",
        "Восстановление по резервному паролю": "Recover with backup password",
        "Журнал одобрений (с телефона)": "Approval log (from phone)",
        "Стереть все данные": "Erase all data",
        "✗ Не удалось выполнить проверку (нужен root или sudo)": "Could not run the check (requires root or sudo)",
        "  Подозрительного не найдено.": "  Nothing suspicious found.",
        "  (кто слушает входящие подключения)": "  (what is listening for incoming connections)",
        "\nЭталона ещё нет: если сейчас всё ваше — нажмите «Доверять», и в следующий раз будут видны новые программы.": "\nNo baseline yet: if you recognize everything here, select “Trust” to flag new programs next time.",
        "✓ Запомнено программ: {p0}": "Programs saved: {p0}",
        "Перезагрузить {p0}? Все подключения и работающие программы прервутся.": "Reboot {p0}? All connections and running programs will be interrupted.",
        "✗ Отклонено на телефоне": "Rejected on the phone",
        "✗ Не удалось прописать ключи. Можно вручную — выполните на сервере:": "Could not install keys. To install them manually, run on the server:",
        "«{p0}» сохранён с пометкой «ключи не установлены» (#{p1})": "“{p0}” saved with “keys not installed” status (#{p1})",
        "Откройте в браузере http://127.0.0.1:{p0}/ (путь панели — как обычно). Ctrl+C — закрыть туннель.": "Open http://127.0.0.1:{p0}/ in your browser (use the usual panel path). Ctrl+C to close the tunnel.",
        "Пока туннель открыт, порт доступен и другим программам на этом компьютере — закройте сразу после работы.": "While the tunnel is open, other programs on this computer can also access the port — close it as soon as you finish.",
        "Подсказка: в 3x-ui можно оставить панель только на 127.0.0.1 — снаружи её не будет видно.": "Tip: in 3x-ui, bind the panel only to 127.0.0.1 to keep it inaccessible from outside.",
        "✓ Вход телефоном работает; старые ключи закомментированы (копия: authorized_keys.ssh-storage.bak)": "Phone login works; old keys commented out (backup: authorized_keys.ssh-storage.bak)",
        "Без root можно только своё: ключ телефона, резервный ключ, TERM в ~/.profile и отключить старые ключи.\nПорт, вход root и пароли сервера настраивает его владелец.": "Without root, you can only manage your phone key, backup key, TERM in ~/.profile, and disable old keys.\nThe server owner manages the port, root login, and server passwords.",
        "  Если после шага 5 вход ключом не подтвердится за 3 мин — сервер сам вернёт шаг 3.": "  If key login is not confirmed within 3 minutes after step 5, the server automatically reverts to step 3.",
        "Захожу на {p0}@{p1}:{p2} — пароль от хостера (и sudo) вводите здесь, программа их не хранит…": "Connecting to {p0}@{p1}:{p2} — enter the provider password (and sudo password) here; the app does not store them…",
        "✓ {p0} создан, ключи прописаны, SSH слушает {p1} и {p2}": "{p0} created, keys installed, SSH listening on {p1} and {p2}",
        "Шаг 4–5: вход {p0}@{p1}:{p2} ключом телефона (sudo спросит пароль {p3})…": "Steps 4–5: logging in to {p0}@{p1}:{p2} with the phone key (sudo will ask for {p3}'s password)…",
        "Проверяю вход заново (новое подключение)…": "Testing login again (new connection)…",
        "Путь к файлу": "File path",
        "Нечего добавлять.": "Nothing to add.",
        "Общий для всех серверов": "Same for all servers",
        "Свой для каждого сервера": "Different for each server",
        "  Добавлено: {p0}": "  Added: {p0}",
        "  Не добавлен: {p0} (недоступен, отказ sudo или логин занят)": "  Not added to: {p0} (unreachable, sudo denied, or username taken)",
        "Добавленные через это меню (можно ввести номер):": "Added through this menu (you can enter a number):",
        "\nНа {p0} будут удалены пользователи участника {p1} и все их файлы. Вернуть нельзя.": "\nOn {p0}, member {p1}'s user accounts and all their files will be deleted. This cannot be undone.",
        "Удаляются только созданные через меню участников; ваш пользователь и root — никогда.": "Only accounts created through the members menu are deleted; your account and root are never deleted.",
        "\nУчастник {p0} на {p1}: ключи снять, вход заблокировать, открытые сеансы закрыть, sudo снять. Пользователь и файлы останутся; вернуть — «Добавить участника».": "\nMember {p0} on {p1}: remove keys, block login, close active sessions, and revoke sudo. The user and files will remain; restore access with 'Add member'.",
        "⚠ Ключ телефона и резервный будут сняты: войти на эти серверы через ssh-storage станет нельзя.": "Phone and backup keys will be removed: you will no longer be able to log in to these servers through ssh-storage.",
        "Удалить серверов: {p0}?": "Remove {p0} servers?",
        " и снять ключи": " and remove keys",
        "  Не удалено: {p0}": "  Not removed: {p0}",
        "Резервного ключа у участника команды нет — он у админа.": "Team members do not have a backup key — the admin has it.",
        "\n⚠ Старый резервный пароль перестанет работать — будет показан новый.": "\nThe old backup password will stop working — a new one will be shown.",
        "⚠ Чужие ключи на серверах будут удалены (список — после проверки серверов).": "Other people's keys will be deleted from servers (listed after checking servers).",
        "  С ошибками: {p0}": "  With errors: {p0}",
        "Резервный пароль (Enter — отмена): ": "Backup password (Enter to cancel): ",
        "Вычисляю ключ…": "Deriving key…",
        "✗ Не удалось прочитать ключи резервным ключом — ничего не изменено": "Could not read keys using the backup key — nothing changed",
        "Отозвать: {p0} ({p1}…)": "Revoke: {p0} ({p1}…)",
        "Только добавить новый телефон (старые ключи останутся)": "Only add the new phone (keep old keys)",
        "✗ Новый вход не прошёл проверку — старые ключи НЕ сняты": "New login failed verification — old keys were NOT removed",
        "\nКогда всё проверите, старое хранилище можно удалить: {p0}": "\nOnce you have checked everything, you can delete the old storage: {p0}",
        "Телефон: ": "Phone: ",
        "новая программа (не было при «доверять»)": "new program (not present when marked trusted)",
        "файл программы изменился с момента «доверять»": "executable changed since being marked trusted",
        "Путь или ключ (Enter — отмена): ": "Path or key (Enter — cancel): ",
        "Жду {p0}…  IP: {p1}": "Waiting for {p0}…  IP: {p1}",
        "Ctrl+C — назад\n": "Ctrl+C — back\n",
        "   ⚠ ОПАСНОЕ ДЕЙСТВИЕ — подтверждайте, только если запускали его сами.": "   DANGEROUS ACTION — approve only if you initiated it yourself.",
        "+ Добавить вручную": "+ Add manually",
        "Установите приложение ": "Install the app ",
        "отпечаток": "fingerprint",
        "в защищённом чипе": "in a secure chip",
        "в Keystore (без отдельного чипа)": "in Keystore (no dedicated chip)",
        "серверов": "servers",
        "Сначала сопряжение.": "Pair first.",
        "\n{p0}: номера через запятую или пробел (Enter — все, 0 — отмена): ": "\n{p0}: numbers separated by commas or spaces (Enter for all, 0 to cancel): ",
        "✗ Телефон отклонил обновление": "Phone rejected the update",
        "✗ Не совпадает": "Does not match",
        "Если вводили правильно — кто-то вмешивается в соединение.": "If you entered it correctly, someone is interfering with the connection.",
        "На телефоне нет серверов. Добавьте: «Серверы» → «Добавить сервер».": "No servers on the phone. Add one: “Servers” → “Add server”.",
        "Изменить (название, хост, порт, пользователь, имя)": "Edit (label, host, port, user, name)",
        "Команда установки для сервера": "Server installation command",
        "Удалить из списка": "Remove from list",
        "Обновить ключи на сервере (имя в подписи, резервный ключ)": "Update keys on server (name in key comment, recovery key)",
        "изменить": "edit",
        "  (нужно: {p0})": "  (required: {p0})",
        "✗ Не удалось получить историю": "Could not retrieve history",
        "Будут записываться команды ВСЕХ пользователей сервера с аргументами (в т.ч. пароль, если его набрать\nпрямо в команде: mysql -pПАРОЛЬ). Читать журнал может любой с sudo. Предупредите участников.": "Commands and arguments from ALL server users will be logged (including passwords entered\ndirectly in a command: mysql -pPASSWORD). Anyone with sudo can read the log. Notify members.",
        "Включить?": "Enable?",
        "выключить запись команд (auditd), откат": "disable command logging (auditd), restore settings",
        "✗ Не удалось выполнить проверку": "Could not run the check",
        "График: {p0}": "Chart: {p0}",
        "Последний час": "Last hour",
        "Сутки": "24 hours",
        "Месяц": "Month",
        "Ошибки журнала за сутки": "Journal errors in the last 24 hours",
        "Процессы с наибольшей нагрузкой": "Top resource-consuming processes",
        "Перенести старые подключения (vault.json)": "Import old connections (vault.json)",
        "Открытые порты": "Open ports",
        "команда перезагрузки отправлена": "reboot command sent",
        "✗ Сервер не вернулся за 10 минут. Проверьте его через панель хостинга.": "Server did not come back within 10 minutes. Check it in your hosting control panel.",
        "\nОжидание прервано.": "\nStopped waiting.",
        "✗ Вход ключом телефона не прошёл — старые ключи НЕ тронуты": "Phone key login failed — old keys were NOT changed",
        "✗ Не удалось отключить старые ключи — на сервере выполните вручную:": "Could not disable old keys — run manually on the server:",
        "✗ Шаг 1–3 не выполнен (код {p0}). Сервер не изменён или изменён частично — вход паролем работает.": "Steps 1–3 failed (code {p0}). The server is unchanged or partially changed — password login still works.",
        "✗ Вход ключом телефона или настройка не прошли (код {p0}). Старый вход паролем остался.": "Phone key login or setup failed (code {p0}). The old password login still works.",
        "✓ Готово: вход только {p0}@{p1}:{p2} ключом телефона (или резервным). Root и пароли отключены.": "Done: login only as {p0}@{p1}:{p2} with the phone key (or backup key). Root and password login disabled.",
        "✗ Новый вход не подтвердился — через 3 мин сервер сам вернёт порты {p0}, {p1} и вход паролем.": "New login not confirmed — in 3 minutes the server will automatically restore ports {p0}, {p1}, and password login.",
        "✗ Файл не найден": "File not found",
        "  ✗ пропущено, неверный формат — ": "  skipped, invalid format — ",
        "Недоступно: {p0}. Добавить их всё равно (сохранятся с пометкой)?": "Unreachable: {p0}. Add them anyway (saved with a warning)?",
        "  Не добавлено: {p0}": "  Not added: {p0}",
        "удалить": "remove",
        "отозвать": "revoke access for",
        "отзыв {p0}: не выполнен на {p1} из {p2}": "revoking access for {p0}: failed on {p1} of {p2}",
        "добавить": "add",
        "ПЕРЕВЫПУСК": "ROTATE",
        "→ {p0}: новые ключи": "→ {p0}: new keys",
        "✗ Телефон не применил новые ключи": "The phone did not apply the new keys",
        "→ {p0}: снять старые ключи": "→ {p0}: remove old keys",
        "перевыпуск: готово {p0}, ошибок {p1}": "rotation: {p0} done, {p1} errors",
        "✗ Не тот пароль\n": "Wrong password\n",
        "сервер": "server",
        "Подключиться резервным ключом": "Connect with the backup key",
        "Привязать сопряжённый телефон к этому серверу": "Link the paired phone to this server",
        "✓ Новый телефон проверен, выбранный старый ключ отозван": "New phone verified; selected old key revoked",
        "✗ Старый ключ НЕ отозван — повторите восстановление": "Old key NOT revoked — repeat recovery",
        "✗ Неверный пароль": "Incorrect password",
        "пока!": "bye!",
        ", не из пакета": ", not from a package",
        "последний час": "last hour",
        "сутки": "24 hours",
        " попыт.": " attempts",
        "последняя ": "last ",
        "IP телефона (виден на его экране), ": "Phone IP (shown on its screen), ",
        "  сеанс завершён\n": "  session ended\n",
        "Отозвать участника (снять ключи)": "Revoke member access (remove keys)",
        "не выполнено — повторите": "failed — try again",
        "ключ SSH": "SSH key",
        "сопряжён": "paired",
        "не сопряжён": "not paired",
        "Начать сопряжение": "Start pairing",
        "Отменить сопряжение": "Unpair",
        "Подтвердите изменение на телефоне…": "Confirm the change on the phone…",
        "Выполните на сервере {p0}:\n": "Run on server {p0}:\n",
        "Массовое добавление": "Bulk add",
        "Массовое удаление": "Bulk removal",
        "Перевыпуск ключей (на всех серверах)": "Rotate keys (on all servers)",
        "Участники серверов (командный режим)": "Server members (team mode)",
        "запись команд включена": "command logging enabled",
        "история команд {p0} (только чтение)": "command history {p0} (read-only)",
        "полная": "full",
        "быстрая": "quick",
        "Сборщик истории: ": "History collector: ",
        "История пуста: установите сборщик (пункт 5). Первые точки — через 5 минут.": "No history: install the collector (option 5). First data points in 5 minutes.",
        " сборщик истории нагрузки": " load history collector",
        "польз.": "user",
        "Вы участник команды: доступ восстанавливает админ (добавит ваш новый ключ).": "You are a team member: ask the admin to restore access by adding your new key.",
        "Публичный ключ участника (строка ssh-ed25519 …)": "Member's public key (ssh-ed25519 … line)",
        "\n  5. только после этого: порт {p0}, вход root и пароли — отключить\n": "\n  5. only then: disable port {p0}, root login, and password login\n",
        "     пароль не подобрать; войти можно только ключом": "     no passwords to guess; key-only login",
        "Строки «имя хост [порт] [пользователь]», пустая строка — конец:": "Enter lines as 'name host [port] [user]'; a blank line ends the list:",
        "\nНомера серверов через запятую или пробел (Enter — отмена): ": "\nServer numbers separated by commas or spaces (Enter to cancel): ",
        "не выполнено (недоступен или отказ sudo) — повторите": "failed (unreachable or sudo denied) — try again",
        "\nНомера через запятую или пробел (Enter — отмена): ": "\nNumbers separated by commas or spaces (Enter to cancel): ",
        "затереть остальные ключи": "overwrite other keys",
        "{p0}: потеряют доступ ключей — {p1}": "{p0}: keys losing access — {p1}",
        "новые ключи не записаны (сервер недоступен?)": "new keys not installed (server unreachable?)",
        "Всё равно перейти на новые ключи?": "Switch to the new keys anyway?",
        "Отменено, новые ключи убраны с серверов.": "Canceled; new keys removed from servers.",
        "новый ключ записан, но вход им не прошёл — старый не снят": "new key installed, but login with it failed — old key not removed",
        "Другой сервер…": "Another server…",
        "привязать к серверу {p0}": "link to server {p0}",
        "  пропущен: недопустимый адрес": "  skipped: invalid address",
        "Enter — искать снова (осталось {p0}): ": "Enter — search again ({p0} remaining): ",
        "Enter — отмена: ": "Enter — cancel: ",
        "Для подтверждения введите СТЕРЕТЬ: ": "Type ERASE to confirm: ",
        "  На компьютере «{p0}» другая версия программы: {p1} (на телефоне {p2}).": "  Computer “{p0}” has a different program version: {p1} (phone: {p2}).",
        "  Обновить телефон? Да — если вы сами обновляли программу на компьютере.": "  Update the phone? Say yes only if you updated the program on the computer yourself.",
        "Подключиться": "Connect",
        "Изменить": "Edit",
        "Удалить": "Remove",
        "Туннель к веб-панели (3x-ui и др.)": "Tunnel to web panel (3x-ui, etc.)",
        "снято": "revoked",
        "участника не было": "member was not present",
        "Журнал одобрений": "Approval log",
        "Мой публичный ключ (отправить админу команды)": "My public key (send to team admin)",
        "Код с экрана телефона: ": "Code shown on the phone: ",
        "  — подтвердите на телефоне": "  — confirm on the phone",
        "(подпись — на телефоне)": "(signing happens on the phone)",
        "✓ Сохранено": "Saved",
        "✗ Не сохранено (отклонено на телефоне)": "Not saved (rejected on the phone)",
        "Имя в подписи ключа на сервере сменится после «Обновить ключи на сервере».": "The name in the key comment on the server will change after “Update keys on server”.",
        "Список серверов (изменить / команда установки / удалить)": "Server list (edit / installation command / remove)",
        "Добавить сервер": "Add server",
        "✓ Права: {p0}": "Permissions: {p0}",
        "✗ Вход не удался": "Login failed",
        "Недостаточно прав. Нужно: {p0}.": "Insufficient permissions. Required: {p0}.",
        "Права определяются при каждом входе; если их добавили — «Проверить права».": "Permissions are checked at each login; if new permissions were granted, select “Check permissions”.",
        "запись команд выключена": "command logging disabled",
        "Сегодня": "Today",
        "Неделя": "Week",
        "история команд · {p0}": "command history · {p0}",
        "удалить (и всю историю)": "remove (including all history)",
        "установить (графики за час / сутки / месяц)": "install (hourly / daily / monthly charts)",
        "установить": "install",
        "✓ Сервер снова в сети ({p0} с)": "Server is back online ({p0} s)",
        "пропущен (отмена входа)": "skipped (login canceled)",
        "неверный формат": "invalid format",
        "Для подтверждения введите ник {p0}: ": "Type the nickname {p0} to confirm: ",
        "ключи не сняты (сервер недоступен или вход не прошёл) — оставлен в списке": "keys not removed (server unreachable or login failed) — kept in the list",
        " (участники: {p0})": " (members: {p0})",
        "Участники выше потеряют доступ. Продолжить?": "The members listed above will lose access. Continue?",
        " — новый резервный пароль не применён, действует старый": " — new backup password not applied; the old one still works",
        "На них останутся только старые ключи": "Only the old keys will remain on these servers",
        "обновление программы": "program update",
        "Удалить сопряжение с компьютером?": "Unpair from the computer?",
        "публичный ключ": "public key",
        "if id \"$L\" >/dev/null 2>&1; then home; ours && mine || { echo \"✗ пользователь $L уже есть и это не участник $N — не трогаю\"; exit 4; }; new=0; else useradd -m -s /bin/sh \"$L\" 2>/dev/null || adduser -D -s /bin/sh \"$L\" || exit 1; new=1; home; case \"$(pw)\" in \"!\"|\"!!\") usermod -p \"*\" \"$L\" 2>/dev/null || sed -i \"s/^$L:!*:/$L:*:/\" /etc/shadow;; esac; fi; echo \"$N\" > \"$R/$L\"; mkdir -p \"$h/.ssh\" || exit 1; ": "if id \"$L\" >/dev/null 2>&1; then home; ours && mine || { echo \"user $L already exists and is not member $N — leaving unchanged\"; exit 4; }; new=0; else useradd -m -s /bin/sh \"$L\" 2>/dev/null || adduser -D -s /bin/sh \"$L\" || exit 1; new=1; home; case \"$(pw)\" in \"!\"|\"!!\") usermod -p \"*\" \"$L\" 2>/dev/null || sed -i \"s/^$L:!*:/$L:*:/\" /etc/shadow;; esac; fi; echo \"$N\" > \"$R/$L\"; mkdir -p \"$h/.ssh\" || exit 1; ",
        "✓ Код верный": "Code is correct",
        "Новый VPS: настроить с нуля": "New VPS: set up from scratch",
        "время  исходный пользователь -> от чьего имени:  команда\n": "time  original user -> run as:  command\n",
        "Удалить сборщик и всю накопленную историю?": "Remove the collector and all collected history?",
        "сборщик установлен: точка раз в 5 мин, хранится 31 день": "collector installed: one data point every 5 min, retained for 31 days",
        "сборщик и история удалены": "collector and history removed",
        "Номера через запятую или пробел: ": "Numbers separated by commas or spaces: ",
        " и ещё {p0}": " and {p0} more",
        "\n  4. проверить вход ключом телефона на порт {p0}\n": "\n  4. test phone key login on port {p0}\n",
        "     убедиться, что новый вход работает": "     make sure the new login works",
        "не удалось прописать ключи (вход или права)": "could not install keys (login or permissions)",
        "\nДля подтверждения введите ПЕРЕВЫПУСК: ": "\nType ROTATE to confirm: ",
        ": вход телефоном туда пропадёт, останется резервный пароль": ": phone login will stop working there; the backup password will still work",
        "Перезапуск…": "Restarting…",
        "  ✓ Программа обновлена — перезапущу после сеанса": "  Program updated — will restart after the session",
        "Откройте в браузере телефона http://127.0.0.1:{p0}/  Ctrl+C — закрыть.": "Open http://127.0.0.1:{p0}/ in your phone's browser.  Ctrl+C to close.",
        "Пока туннель открыт, порт доступен и другим приложениям телефона — закройте сразу после работы.": "While the tunnel is open, other apps on your phone can access the port too. Close it as soon as you finish.",
        "Это не секрет: скопируйте и отправьте админу.": "This is not secret: copy it and send it to the admin.",
        "обновить ключи на сервере": "update keys on server",
        "✓ Ключи на сервере обновлены": "Keys on server updated",
        "✗ Не удалось (вход или запись ключей)": "Failed (login or writing keys)",
        "Удалить «{p0}» из списка?": "Remove “{p0}” from the list?",
        "Подтвердите удаление на телефоне…": "Confirm removal on the phone…",
        "попытки взлома": "break-in attempts",
        "✓ Сервер в сети": "Server is online",
        " (момент перезагрузки не застали — она была быстрой)": " (reboot was too fast to observe)",
        "  ✗ Обновление не прошло проверку — оставлена старая версия": "  Update failed verification — kept the old version",
        "✓ Удалено": "Removed",
        "сервер не найден в списке телефона": "server not found in the phone's list",
        "\n  3. SSH слушает порты {p0} и {p1} (пароль пока работает)\n": "\n  3. SSH listens on ports {p0} and {p1} (password login still works)\n",
        "     новый порт — меньше ботов; старый — чтобы не запереться": "     new port for fewer bots; old port to avoid locking yourself out",
        "удалено": "deleted",
        "ключ телефона": "phone key",
        "резервный ключ": "backup key",
        "  Перевыпустить?": "  Reissue?",
        "перевыпуск: {p0}": "reissue: {p0}",
        "перевыпуск: новые ключи действуют": "reissue: new keys are active",
        "  ⚠ Перевыпуск: {p0} — на всех серверах ({p1})": "  Reissue: {p0} — on all servers ({p1})",
        "  ⚠ Затереть: на серверах останутся только ключи ssh-storage этого телефона": "  Overwrite: only this phone's ssh-storage keys will remain on the servers",
        "  Старый резервный пароль перестанет работать.": "  The old backup password will stop working.",
        ", затереть": ", overwrite",
        "  ✓ новые ключи действуют": "  new keys are active",
        "\n  2. {p0}: ключ телефона и резервный ключ\n": "\n  2. {p0}: phone key and backup key\n",
        "     вход с телефона; резервный — если телефон потерян": "     log in from your phone; backup access if the phone is lost",
        "\nПлан для {p0}:\n  1. apt update; создать {p1} (sudo с паролем), TERM в ~/.profile\n": "\nPlan for {p0}:\n  1. apt update; create {p1} (password required for sudo), TERM in ~/.profile\n",
        "  Разрешить вход на {p0} ({p1}@{p2}:{p3})?": "  Allow login to {p0} ({p1}@{p2}:{p3})?",
        "Участников добавляет админ команды.": "The team admin adds members.",
        "     свежий список пакетов; работать не под root; цвета в терминале": "     refresh package lists; work without root; terminal colors",
        "  ✓ сервер принял ключ телефона — подпись выдана": "  server accepted the phone key — signature issued",
        "  Добавить серверы ({p0}):": "  Add servers ({p0}):",
        "  Разрешить добавление всех?": "  Allow adding all?",
        "из списка и снять ключи с серверов": "from the list and remove keys from the servers",
        "только из списка": "from the list only",
        "удалить серверы ({p0}), {p1}": "remove servers ({p0}), {p1}",
        "  Удалить серверы ({p0}), {p1}:": "  Remove servers ({p0}), {p1}:",
        "Этот пункт в разработке (этап 2).": "This feature is in development (phase 2).",
        "  Удалить?": "  Remove?",
        "удалить сервер": "remove server",
        "  ✓ удалено из списка: {p0}": "  removed from list: {p0}",
        "добавить сервер": "add server",
        "  Добавить сервер «{p0}» ({p1}@{p2}:{p3})?": "  Add server “{p0}” ({p1}@{p2}:{p3})?",
        "изменить сервер": "edit server",
        "вход": "login",
        "  Изменить сервер с компьютера:": "  Edit server from computer:",
        "  Сохранить?": "  Save?",
        "  Удалить «{p0}» ({p1}@{p2}) из списка?": "  Remove “{p0}” ({p1}@{p2}) from the list?",
        "  ✓ сохранено": "  saved",
        "  отменено": "  cancelled",
        "без изменений": "no changes",
        "  ✓ вход на «{p0}» выполнен, сеанс закрыт": "  logged in to “{p0}”, session closed",
        "  ✗ вход на «{p0}» не удался: сервер не принял ключ телефона или нет связи": "  login to “{p0}” failed: server rejected the phone's key or could not be reached",
        "  ✗ вход на «{p0}» не удался": "  login to “{p0}” failed",
        "  ✓ сервер «{p0}» сохранён": "  server “{p0}” saved",
        "разрешено": "allowed",
        "отклонено": "rejected",
        "выполнен": "completed",
        "не удался": "failed",
    }
    # END GENERATED TRANSLATIONS

    def restart_program():
        # Язык влияет и на модульные константы (тексты скриптов для сервера), поэтому применяется перезапуском.
        os.execv(sys.executable, [sys.executable, os.path.abspath(__file__)] + [a for a in sys.argv[1:] if a != "--install"])

    def language_settings(state, save, apply=None):
        header(tr("Language / Язык"))
        ch = menu(["English", "Русский"], default=2 if LANG == "ru" else 1)
        code = {"1": "en", "2": "ru"}.get(ch)
        if code is None or code == LANG: return
        state["language"] = code; save(); set_language(code)
        (apply or restart_program)()

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
        t = f" SSH Storage · {title}"
        print(cyan("│") + bold(t.ljust(w - 2)) + cyan("│"))
        print(cyan("╰" + "─" * (w - 2) + "╯"))
        print()

    def menu(items, default=1):
        for i, it in enumerate(items, 1):
            mark = green("›") if i == default else " "
            print(f" {mark} {yellow(str(i))}  {it}")
        print()
        ans = input(blue(tr('Выбор [{p0}]: ', p0=default))).strip()
        return ans if ans else str(default)

    def pause(msg=tr("Enter — продолжить")): input(dim(msg))
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
        if off < 0 or off + 4 > len(buf): raise ValueError(tr("обрезанная SSH-строка"))
        n = struct.unpack(">I", buf[off:off + 4])[0]
        if off + 4 + n > len(buf): raise ValueError(tr("обрезанная SSH-строка"))
        return buf[off + 4:off + 4 + n], off + 4 + n

    def valid_sign_request(data, user, blob):
        """RFC 4252 §7 + OpenSSH hostbound: вход выбранным пользователем и нашим ключом.
        Имя хоста в этих данных отсутствует: это не защита от заражённого сопряжённого ПК.
        """
        try:
            sid, off = read_str(data, 0)
            if not sid: return False
            tail = data[off:]
            for method in (b"publickey", b"publickey-hostbound-v00@openssh.com"):
                expected = (b"\x32" + sstr(user.encode()) + sstr(b"ssh-connection") + sstr(method)
                            + b"\x01" + sstr(b"ecdsa-sha2-nistp256") + sstr(blob))
                if method == b"publickey":
                    if tail == expected: return True
                elif tail.startswith(expected):
                    hostkey, end = read_str(tail, len(expected))
                    return bool(hostkey) and end == len(tail)
            return False
        except ValueError:
            return False

    def der_to_rs(der):
        """ECDSA-подпись Java (DER SEQUENCE{INTEGER r, INTEGER s}) → (r, s)."""
        def length(i):
            n = der[i]
            if n < 0x80: return n, i + 1
            k = n & 0x7F
            return int.from_bytes(der[i + 1:i + 1 + k], "big"), i + 1 + k
        if der[0] != 0x30: raise ValueError(tr("не DER"))
        _, i = length(1)
        out = []
        for _ in range(2):
            if der[i] != 0x02: raise ValueError(tr("не DER"))
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
        """Команда для сервера: обновить подпись своего ключа телефона (тот же ключ с любым именем),
        добавить резервный; ключи других участников и прочее не трогать."""
        return ("umask 077; mkdir -p ~/.ssh && f=~/.ssh/authorized_keys && touch \"$f\" && "
                f"{{ grep -vF {shlex.quote(phone_line.split()[1])} \"$f\"; printf '%s\\n' {shlex.quote(phone_line)}; }} > \"$f.new\" && "
                + (f"{{ grep -qF {shlex.quote(rec_line.split()[1])} \"$f.new\" || printf '%s\\n' {shlex.quote(rec_line)} >> \"$f.new\"; }} && " if rec_line else "") +
                "cat \"$f.new\" > \"$f\" && rm -f \"$f.new\" && echo SSH-STORAGE-OK")

    TERM_CMD = "grep -qs 'TERM=xterm-256color' ~/.profile || echo 'export TERM=xterm-256color' >> ~/.profile"

    # Новый VPS: свой drop-in sshd (00- — читается первым, первое значение побеждает, в т.ч. над 50-cloud-init.conf).
    VPS_CONF = "/etc/ssh/sshd_config.d/00-ssh-storage.conf"
    SSHD_RESTART = ("(if systemctl is-active -q ssh.socket 2>/dev/null; then systemctl daemon-reload && systemctl restart ssh.socket && systemctl restart ssh; "
                    "else systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || service ssh restart; fi) || exit 1")

    def vps_root(command):
        return 'S=""; [ "$(id -u)" = 0 ] || S=sudo; $S env SSH_CONNECTION="''${SSH_CONNECTION-}" sh -c ' + shlex.quote(
            'set -eu; PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH; export PATH; ' + command)


    def vps_prepare_cmd(user, *, create=False, admin=False, term=False, update=False, install=""):
        """Подготовка через исходную учётку: пропущенные действия не попадают в команду."""
        if not re.fullmatch(LOGIN_RE, user) or create and user == "root":
            raise ValueError("Invalid target login")
        admin = admin and user != "root"  # root уже администратор; не меняем его пароль ради sudo.
        steps = ['command -v apt-get >/dev/null || { echo "Ubuntu / Debian required"; exit 5; }']
        if create:
            steps.append(f'if id {user} >/dev/null 2>&1; then echo "Login already exists: {user}"; exit 4; fi')
        else:
            steps.append(f'id {user} >/dev/null')
        if admin: steps.append('command -v sudo >/dev/null; getent group sudo >/dev/null')
        if update: steps.append('apt-get update')
        if create: steps.append(f'adduser --disabled-password --gecos "" {user}')
        if admin:
            steps += [f'passwd -S {user} | grep -q " P " || passwd {user}', f'usermod -aG sudo {user}',
                      f'sudo -l -U {user}']
        personal = ([TERM_CMD] if term else []) + ([install] if install else [])
        if personal:
            steps.append(f'su - {user} -s /bin/sh -c ' + shlex.quote("set -e; " + "; ".join(personal)))
        steps.append('echo SSH-STORAGE-PREPARED')
        return vps_root("; ".join(steps))


    def vps_settings(old_port, port, *, stage=False, root=False, passwords=False, keys=False):
        if not port_ok(str(old_port)) or not port_ok(str(port)):
            raise ValueError("Invalid SSH port")
        lines = []
        if old_port != port:
            if stage: lines.append(f"Port {old_port}")
            lines.append(f"Port {port}")
        if root: lines.append("PermitRootLogin no")
        if passwords: lines += ["PasswordAuthentication no", "KbdInteractiveAuthentication no"]
        if keys: lines.append("PubkeyAuthentication yes")
        return "".join(line + "\n" for line in lines)


    def vps_ssh_cmd(token, phase, old_port, port, *, user="root", root=False, passwords=False, keys=False):
        """Root-копии и откат живут вне home; подтверждение — новый вход целевым пользователем."""
        if not re.fullmatch(r"[a-f0-9]{24}", token) or not re.fullmatch(LOGIN_RE, user):
            raise ValueError("Invalid setup transaction")
        settings = vps_settings(old_port, port, stage=phase == "stage", root=root and phase != "stage",
                                passwords=passwords and phase != "stage", keys=keys)
        if phase == "commit":
            return f'umask 077; touch ~/.ssh-storage-vps-{token}.ok && echo SSH-STORAGE-VERIFIED'
        if phase not in ("stage", "finish", "check"):
            raise ValueError("Invalid setup phase")
        preflight = ('command -v apt-get >/dev/null; command -v flock >/dev/null; command -v setsid >/dev/null; '
                     'command -v sshd >/dev/null; sshd -t; '
                     '[ -f /etc/ssh/sshd_config ] && [ ! -L /etc/ssh/sshd_config ]; '
                     '[ -d /etc/ssh/sshd_config.d ] && [ ! -L /etc/ssh/sshd_config.d ]; '
                     'for f in /etc/ssh/sshd_config.d/*.conf; do '
                     '[ -e "$f" ] || continue; [ -f "$f" ] && [ ! -L "$f" ] || exit 6; done')
        if phase == "check": return vps_root(preflight + '; echo SSH-STORAGE-CHECKED')
        prefix = (f'R=/var/lib/ssh-storage; B=$R/vps-{token}; C={VPS_CONF}; '
                  'umask 077; [ ! -L "$R" ]; mkdir -p "$R"; '
                  '[ "$(stat -c %u "$R")" = 0 ]; [ "$(stat -c %a "$R")" = 700 ] || chmod 700 "$R"; '
                  '[ ! -L "$R/vps.lock" ]; exec 9>"$R/vps.lock"; flock -x 9; ')
        if phase == "stage":
            # Откат и подтверждение берут тот же flock: таймер не может восстановить файлы посреди записи.
            rollback = (f'set -eu; R=/var/lib/ssh-storage; B=$R/vps-{token}; C={VPS_CONF}; '
                        'exec 9>"$R/vps.lock"; flock -x 9; '
                        f'[ "$(cat "$R/vps-active" 2>/dev/null)" = {token} ] || exit 0; '
                        'cp -p "$B/main" /etc/ssh/sshd_config; '
                        'for f in "$B"/conf/*.conf; do [ -f "$f" ] || continue; cp -p "$f" /etc/ssh/sshd_config.d/; done; '
                        '[ -f "$B/conf/00-ssh-storage.conf" ] || rm -f "$C"; '
                        'sshd -t; ' + SSHD_RESTART + '; rm -f "$R/vps-active"; echo rolled-back > "$B/status"')
            watcher = ('echo $$ > "$B/watcher.pid"; touch "$B/ready"; '
                       f'for n in $(seq 1 180); do sleep 1; '
                       'if [ -f "$B/final" ] && [ -f "$H/.ssh-storage-vps-' + token + '.ok" ]; then '
                       'exec 9>"$R/vps.lock"; flock -x 9; '
                       f'[ "$(cat "$R/vps-active" 2>/dev/null)" = {token} ] || exit 0; '
                       'rm -f "$R/vps-active"; echo committed > "$B/status"; exit 0; fi; done; '
                       'exec sh "$B/rollback.sh"')
            setup = (preflight + '; [ ! -e "$R/vps-active" ] || { echo "Another SSH setup is awaiting verification/rollback"; exit 8; }; '
                     'mkdir "$B"; mkdir "$B/conf"; cp -p /etc/ssh/sshd_config "$B/main"; '
                     'for f in /etc/ssh/sshd_config.d/*.conf; do [ -f "$f" ] || continue; cp -p "$f" "$B/conf/"; done; '
                     f'H=$(getent passwd {user} | cut -d: -f6); [ -n "$H" ]; '
                     f'printf "%s\\n" {shlex.quote(rollback)} > "$B/rollback.sh"; '
                     f'printf "%s\\n" {token} > "$R/vps-active"; '
                     'echo pending > "$B/status"; '
                     f'R="$R" B="$B" H="$H" setsid nohup sh -c {shlex.quote(watcher)} '
                     '>"$B/watcher.log" 2>&1 </dev/null 9>&- & '
                     'for n in 1 2 3 4 5; do [ -f "$B/ready" ] && break; sleep 1; done; '
                     'if [ ! -f "$B/ready" ] || ! kill -0 "$(cat "$B/watcher.pid" 2>/dev/null)" 2>/dev/null; then '
                     'echo timer-failed > "$B/status"; rm -f "$R/vps-active"; echo "Rollback watcher failed to start"; exit 8; fi; ')
        else:
            setup = f'[ "$(cat "$R/vps-active" 2>/dev/null)" = {token} ]; '
        # Перезаписываем только выбранные директивы, остальные настройки своего drop-in сохраняем.
        names = [line.split()[0].lower() for line in settings.splitlines()]
        pattern = "|".join(sorted(set(names)))
        write = '''
        if pattern:
            write = (f'if [ -f "$C" ]; then awk \'tolower($1) !~ /^({pattern})$/\' "$C" > "$B/keep"; '
                     'else : > "$B/keep"; fi; '
                     f'printf "%s" {shlex.quote(settings)} > "$C"; cat "$B/keep" >> "$C"; ')
        if old_port != port:
            # Port — накопительная директива: одного раннего drop-in недостаточно, нужен снимок всех затронутых файлов.
            write += ('for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do '
                      '[ "$f" = "$C" ] && continue; [ -f "$f" ] || continue; '
                      'sed "/^[[:space:]]*[Pp][Oo][Rr][Tt][[:space:]]/s/^/# ssh-storage: /" "$f" > "$B/port.new"; '
                      'cat "$B/port.new" > "$f"; done; ')
        # Явный Include раньше любых значений в main; повторное чтение через wildcard не меняет первые значения.
        write += ('{ printf "%s\\n" "Include $C"; awk -v line="Include $C" \'$0 != line\' /etc/ssh/sshd_config; } > "$B/main.new"; '
                  'cat "$B/main.new" > /etc/ssh/sshd_config; sshd -t; '
                  f'set -- $SSH_CONNECTION; E=$(sshd -T -C "user={user},addr=$1,host=$1,laddr=$3,lport={port}"); ')
        expected = settings.splitlines()
        for line in expected:
            write += f'printf "%s\\n" "$E" | grep -Fxi -- {shlex.quote(line)} >/dev/null; '
        if root and phase == "finish":
            write += (f'sshd -T -C "user=root,addr=$1,host=$1,laddr=$3,lport={port}" '
                      '| grep -Fxi "permitrootlogin no" >/dev/null; ')
        if old_port != port and phase == "finish":
            write += f'if printf "%s\\n" "$E" | grep -Ei "^port " | grep -Fvxi "port {port}"; then exit 7; fi; '
        if old_port != port and phase == "stage":
            write += (f'if command -v ufw >/dev/null && LC_ALL=C ufw status | grep -q "Status: active"; '
                      f'then ufw allow {port}/tcp; fi; ')
        if phase == "finish": write += 'touch "$B/final"; '
        write += SSHD_RESTART + '; echo SSH-STORAGE-CONFIGURED'
        # Ошибка возвращает исходную SSH-конфигурацию сразу; независимый таймер остаётся страховкой при обрыве процесса.
        return vps_root(prefix + setup + 'trap \'rc=$?; trap - EXIT; if [ "$rc" != 0 ]; then '
                        'flock -u 9; sh "$B/rollback.sh"; fi; exit "$rc"\' EXIT; ' + write)

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
    ATTACKS_SH = LOG_SH + tr(r''''echo "==ATTACKS=="
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
    echo "==END=="'''')

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
                add("crit", e, tr("выдаёт себя за поток ядра (у настоящих нет файла программы)"), pr)
            if st == "mod": add("crit", e, tr("файл программы из пакета изменён — не совпадает с контрольной суммой пакета"), pr)
            if e.endswith(" (deleted)"): add("warn", e, tr("файл программы удалён после запуска (после обновления — норма до перезапуска)"), pr)
            if e.startswith(SUSPECT_DIRS): add("warn", e, tr("запущена из временной / домашней папки"), pr)
            name = e.removesuffix(" (deleted)").rsplit("/", 1)[-1]
            if st != "pkg" and comm != name[:15]:
                add("warn", e, tr('имя «{p0}» не совпадает с файлом программы «{p1}» и программа не из пакета', p0=comm, p1=name), pr)
            if base is not None:
                sha = exes.get(e, ("-",))[0]
                if e not in base: add("info", e, tr("новая программа (не было при «доверять»)") + ("" if st == "pkg" else tr(", не из пакета")), pr)
                elif sha != "-" and base[e] != sha: add("warn", e, tr("файл программы изменился с момента «доверять»"), pr)
        hidden = [f[1:] for f in rows if f[0] == "H" and len(f) == 3]
        ports = [f[1:] for f in rows if f[0] == "L" and len(f) == 4]
        order = {"crit": 0, "warn": 1, "info": 2}
        return sorted(found.values(), key=lambda f: order[f[0]]), hidden, ports, {e: v[0] for e, v in exes.items() if v[0] != "-"}

    # Зачатки неисправностей (2.6), только чтение. Строки «статус|что|подробно», статус ok / warn / crit.
    # Быстрая: диск, inode, только-чтение, память, swap, нагрузка, время. Полная (FULL=1): + OOM, рост ошибок, SSL, обновления.
    HEALTH_SH = tr(r''''o() { echo "$1|$2|$3"; }
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
    echo "==END=="'''')

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
    METRICS = (tr("диск /"), tr("память"), "swap", tr("нагрузка"))  # столбцы 1..4 в строке истории

    def show_metric(pts, i, span, cores=1, now=None, width=60, height=8):
        """График столбца i за последние span секунд: в столбце графика — максимум (пики видны); пик, среднее, минимум."""
        now = now or time.time(); t0 = now - span
        v = [(f[0], f[i]) for f in pts if f[0] >= t0]
        print(bold(f"{METRICS[i - 1]} · " + {3600: tr("последний час"), 86400: tr("сутки")}.get(span, tr("месяц"))))
        if not v: print(yellow(tr("  Нет данных за этот период."))); return
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
        print(tr('\n  Пик:     {p0}  {p1}', p0=bold(f'{pk[1]:g}{unit}'), p1=dim(time.strftime('%d.%m %H:%M', time.localtime(pk[0])))))
        print(tr('  Среднее: {p0}{p1}', p0=format(sum(xs) / len(xs), '.1f'), p1=unit))
        print(tr('  Минимум: {p0}{p1}', p0=format(min(xs), 'g'), p1=unit))
        if i == 4: print(dim(tr('  Нагрузка — средняя за 5 мин; {p0} ядер = загрузка 100%.', p0=cores)))
        print(dim(tr('  Точек: {p0} из ~{p1} (пустые места — сервер был выключен или сборщика ещё не было).', p0=len(v), p1=span // 300)))

    def show_health(out):
        icon = {"ok": green("✓"), "warn": yellow("⚠"), "crit": red("✗")}
        rows = [l.split("|", 2) for l in out.splitlines() if l.count("|") >= 2]
        for st, what, info in sorted(rows, key=lambda f: {"crit": 0, "warn": 1}.get(f[0], 2)):
            print(f"  {icon.get(st, '?')} {what:<24} {info}")
        bad = sum(f[0] != "ok" for f in rows)
        print("\n" + (green(tr("Всё в порядке.")) if not bad else yellow(tr('Требуют внимания: {p0}.', p0=bad))))

    def diag_action_cmd(kind, items):
        """kind: restart (юниты) | TERM | KILL (пары pid, имя). Перед kill — проверка, что PID всё ещё тот же процесс."""
        pre = 'S=""; [ "$(id -u)" = 0 ] || S=sudo; '
        if kind == "restart":
            return pre + "$S systemctl restart " + " ".join(shlex.quote(u) for u in items) + tr(" && echo '✓ перезапущено'")
        if kind not in ("TERM", "KILL") or any(int(pid) <= 1 for pid, _ in items):
            raise ValueError(tr("недопустимый сигнал или PID"))
        def one(pid, name):
            done = shlex.quote(f"✓ {int(pid)} {name}")
            gone = shlex.quote(tr("— {p0} {p1}: процесс уже завершён или сменился", p0=int(pid), p1=name))
            return (f'if [ "$(ps -o comm= -p {int(pid)})" = {shlex.quote(name)} ]; then $S kill -{kind} {int(pid)} && '
                    f'printf "%s\\n" {done}; else printf "%s\\n" {gone}; fi')
        return pre + "; ".join(one(pid, name) for pid, name in items)

    def history_cmd(days=7, n=50, script=None):
        return f"D={int(days)}; N={int(n)}\n" + (script or HISTORY_SH)

    def warn_access(sec):
        if not ({"SUDO-NOPW", "root", "adm", "systemd-journal"} & set(" ".join(sec.get("ACCESS", [])).split())):
            print(yellow(tr("  ⚠ Нет доступа к журналам (нужны группа adm / systemd-journal или sudo без пароля) — данные могут быть неполными.\n")))

    def show_attacks(sec):
        rows = [l.split() for l in sec.get("ATTACKS", [])]
        warn_access(sec)
        t = lambda v: v.replace("T", " ").replace("_", " ")[:16]
        print(bold(tr("Источники атак")) + dim(tr("  (IP — только при ≥5 неудачных входах или входе под несуществующим логином)")))
        ips = [f for f in rows if f[0] == "IP"]
        for f in ips or [None]:
            if not f: print("  " + dim("—")); break
            mark = red(tr("несуществующий логин")) if f[3] == "invalid" else yellow(tr("≥5 неудач"))
            print(tr('  {p0} {p1}  {p2}  {p3}  логины: {p4}', p0=format(bold(f[2]), '<20'), p1=red(f[1] + tr(' попыт.')), p2=mark, p3=dim(tr('последняя ') + t(f[4])), p4=' '.join(f[5:])[:80]))
        print("\n" + bold(tr("Неудачные входы по пользователям")) + dim(tr("  (без IP)")))
        for f in [f for f in rows if f[0] == "USER"] or [None]:
            if not f: print("  " + dim("—")); break
            print(tr('  {p0} {p1} попыт.  {p2}', p0=format(bold(f[2]), '<20'), p1=f[1], p2=dim(tr('последняя ') + t(f[3]))))

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
        print(bold(tr("Входы")) + dim(tr("  (кто, когда, чем; без IP)")))
        for l in sec.get("LOGINS", []) or [dim("—")]:
            m = re.search(r"Accepted (\S+) for (\S+)", l)
            if not m: print("  " + l); continue
            fp = re.search(r"(SHA256:\S+)", l)
            nick = keys.get(fp.group(1), "-") if fp else "-"
            how = {"publickey": tr("ключ"), "password": tr("пароль")}.get(m.group(1), m.group(1))
            who = (cyan(nick) if nick != "-" else dim(fp.group(1)[:20] + "…")) if fp else ""
            print(f"  {dim(t(l))}  {bold(m.group(2))}  {how} {who}")
        print("\n" + bold(tr("sudo-команды")))
        for l in sec.get("SUDO", []) or [dim("—")]:
            m = re.search(r":\s+(\S+) : .*?USER=(\S+) ; COMMAND=(.*)", l)
            print(f"  {dim(t(l))}  {bold(m.group(1))} → {m.group(2)}: {m.group(3)}" if m else "  " + l)
        print("\n" + bold(tr("Смены пользователя (su)")))
        for l in sec.get("SU", []) or [dim("—")]: print(f"  {dim(t(l))}  {l.split(': ', 1)[-1]}" if ": " in l else "  " + l)
        print("\n" + bold(tr("Пакеты")))
        for l in sec.get("PKG", []) or [dim("—")]: print("  " + l)
        print("\n" + bold(tr("Изменённые файлы /etc")))
        for l in sec.get("ETC", []) or [dim("—")]: print("  " + l)

    # auditd (2.2): запись всех запущенных команд с исходным пользователем входа (auid) — видно и после sudo -i/su.
    # Включение: копия /etc/audit, прежнее состояние службы, свои правила в отдельном файле; выключение — откат.
    _AUDIT_PRE = (tr('S=""; [ "$(id -u)" = 0 ] || S=sudo; '
                  'command -v auditctl >/dev/null 2>&1 || { echo "auditd не установлен. Установите: '
                  'apt install auditd | dnf install audit | pacman -S audit"; exit 3; }; '))
    AUDIT_ON_CMD = _AUDIT_PRE + tr("""$S sh -c 'set -e
    B=/var/lib/ssh-storage; mkdir -p $B
    [ -f $B/auditd.prev ] || { systemctl is-active auditd >/dev/null 2>&1 && echo active || echo inactive; } > $B/auditd.prev
    tar czf $B/audit-backup-$(date +%Y%m%d%H%M%S).tgz -C /etc audit
    echo "копия настроек: $(ls -t $B/audit-backup-*.tgz | head -n 1)"
    printf "%s\\n" "-a always,exit -F arch=b64 -S execve -F auid!=4294967295 -k ssh-storage" "-a always,exit -F arch=b32 -S execve -F auid!=4294967295 -k ssh-storage" > /etc/audit/rules.d/ssh-storage.rules
    systemctl enable --now auditd
    augenrules --load >/dev/null 2>&1 || auditctl -R /etc/audit/rules.d/ssh-storage.rules >/dev/null
    auditctl -l | grep -q ssh-storage
    echo "✓ запись команд включена"'""")
    AUDIT_OFF_CMD = _AUDIT_PRE + tr("""$S sh -c 'B=/var/lib/ssh-storage
    rm -f /etc/audit/rules.d/ssh-storage.rules
    auditctl -D -k ssh-storage >/dev/null 2>&1; augenrules --load >/dev/null 2>&1
    if [ "$(cat $B/auditd.prev 2>/dev/null)" = inactive ]; then
      systemctl disable --now auditd 2>/dev/null || { systemctl disable auditd; service auditd stop; }
      echo "auditd остановлен (был выключен до ssh-storage)"
    fi
    rm -f $B/auditd.prev
    ! auditctl -l 2>/dev/null | grep -q ssh-storage && echo "✓ запись команд выключена, правила ssh-storage сняты"'""")

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
        "root": ("root", 4), "sudo-nopw": (tr("sudo без пароля"), 4), "sudo": (tr("sudo с паролем"), 3),
        "logs": (tr("доступ к журналам"), 2), "user": (tr("обычный пользователь"), 1)}
    NEED = {1: tr("любые права"), 2: tr("доступ к журналам (группа adm или systemd-journal) или sudo"), 3: tr("root или sudo")}

    # ---------- файлы ----------
    def save_json(path, obj):
        fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".", dir=os.path.dirname(os.path.abspath(path)))
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(obj, f); f.flush(); os.fsync(f.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)

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
                if not ch: raise ConnectionError(tr("соединение закрыто"))
                buf += ch
            return buf
        n = struct.unpack(">I", exact(4))[0]
        if n > 1 << 20: raise ConnectionError(tr("слишком большое сообщение"))
        obj = json.loads(exact(n))
        if not isinstance(obj, dict): raise ValueError(tr("ожидался объект сообщения"))
        return obj

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
                obj = json.loads(open_sym(self.k, bytes.fromhex(recv_raw(self.sock)["c"]), aad))
                if not isinstance(obj, dict): raise ValueError(tr("ожидался объект сообщения"))
                return obj
            except (ValueError, KeyError, TypeError):
                raise ConnectionError(tr("подделка или чужое устройство — соединение разорвано"))
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
            print(dim(tr("Ищу телефон в сети…")))
            for _ in range(3):  # первый проход часто будит Wi-Fi телефона, отвечает он на следующем
                phones = [p for p in discover() if (not want_fp or p["fp"] == want_fp) and (not mode or p["mode"] == mode)]
                if phones: break
            if len(phones) == 1:
                return phones[0]["ip"], TCP_PORT
            if phones:
                ch = menu([f"{p['name']}  {dim(p['ip'] + '  ' + p['fp'])}" for p in phones])
                if ch.isdigit() and 1 <= int(ch) <= len(phones): return phones[int(ch) - 1]["ip"], TCP_PORT
                return None
            print(yellow(tr("Телефон не найден (та же сеть Wi-Fi? в кафе устройства бывают изолированы).")))
            ip = input(blue(tr("IP телефона (виден на его экране), ") +
                            (tr('Enter — искать снова (осталось {p0}): ', p0=left) if left else tr("Enter — отмена: ")))).strip()
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
            if not v and required: print(red(tr("    обязательное поле"))); continue
            if v and validate and not validate(v): print(red(tr("    неверное значение"))); continue
            return v

    FIELDS = ("name", "host", "port", "user", "nick", "id", "added", "pending")

    def edit_server(cur=None, servers=()):
        cur = cur or {}
        s = {"name": ask(tr("Название"), cur.get("name")),
             "host": ask(tr("IP / хост"), cur.get("host"), validate=host_ok),
             "port": int(ask(tr("Порт"), cur.get("port", 22), validate=port_ok)),
             "user": ask(tr("Пользователь"), cur.get("user", "root"), validate=user_ok)}
        # подпись ключа на сервере: ssh-storage-phone:<имя>:<ID>:<дата>; ID и дата — при создании, дальше не меняются
        s["nick"] = pick_nick(cur, servers)
        return dict(s, id=cur["id"], added=cur["added"]) if cur.get("id") else new_id(s)

    def pick_nick(cur, servers):
        """Имя (обязательно): при изменении — текущее, иначе последнее использованное, или новое."""
        last = next((x["nick"] for x in reversed(servers) if x.get("nick")), None)
        opts = []
        if cur.get("nick"): opts.append((tr('Оставить «{p0}»', p0=cur['nick']), cur["nick"]))
        if last and last != cur.get("nick"): opts.append((tr('Последнее: «{p0}»', p0=last), last))
        if not opts: return ask(tr("Имя (латиница, цифры, _ -; видно в подписи ключа на сервере)"),
                                validate=lambda v: re.fullmatch(NICK_RE, v))
        print(f"  {cyan(tr('Имя (видно в подписи ключа на сервере)'))}")
        opts.append((tr("Новое имя"), ""))
        a = menu([o[0] for o in opts], default=1)
        nick = opts[int(a) - 1][1] if a.isdigit() and 1 <= int(a) <= len(opts) else opts[0][1]
        if nick == "": nick = ask(tr("Имя (латиница, цифры, _ -)"), validate=lambda v: re.fullmatch(NICK_RE, v))
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
            if len(f) > 4 or not server_ok(s): bad.append(tr('строка {p0}: «{p1}»', p0=n, p1=line.strip()))
            else: out.append(s)
        return out, bad

    def ssh_config_servers(path="~/.ssh/config"):
        """Хосты из ~/.ssh/config (без шаблонов *?), адрес/порт/пользователь — через ssh -G."""
        path = os.path.expanduser(path)
        if not os.path.isfile(path): return [], [tr('нет файла {p0}', p0=path)]
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
        word = tr("СТЕРЕТЬ")
        return input(red(tr("Для подтверждения введите СТЕРЕТЬ: "))).strip().upper() in (word.upper(), "СТЕРЕТЬ")

    def first_login():
        """Как один раз зайти на новый сервер, чтобы прописать ключ телефона.
        Возвращает (опции ssh, временная папка для удаления) или (None, None) — отмена.
        Вставленный текстом ключ лежит только в RAM и удаляется сразу после входа."""
        print(tr("\nКак зайти на сервер ") + bold(tr("в первый раз")) + tr(" (ключа телефона там ещё нет)?"))
        ch = menu([tr("Пароль сервера"), tr("SSH-ключ: путь к файлу или вставить текст ключа"),
                   tr("Автоматически (ключи из ~/.ssh и агента)"), tr("Отмена")])
        if ch == "1":
            return ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive"], None
        if ch == "3": return [], None
        if ch != "2": return None, None
        print(dim(tr("Путь к закрытому ключу (например ~/.ssh/id_ed25519) или вставьте ключ целиком,")))
        print(dim(tr("начиная со строки -----BEGIN … PRIVATE KEY----- (текст ключа на экране не показывается).")))
        key_opts = lambda f: ["-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-i", f]
        while True:
            first = input(blue(tr("Путь или ключ (Enter — отмена): "))).strip()
            if not first: return None, None
            if first.startswith("-----BEGIN") and "PRIVATE KEY" in first:
                lines = [first]
                while not lines[-1].startswith("-----END"):
                    lines.append(getpass.getpass("").strip())
                tmp = tempfile.mkdtemp(prefix="sshstore-", dir=RAM)
                f = os.path.join(tmp, "key")
                with open(os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as fh:
                    fh.write("\n".join(lines) + "\n")
                print(green(tr('✓ Ключ принят ({p0} строк), будет удалён после входа', p0=len(lines))))
                return key_opts(f), tmp
            path = os.path.expanduser(first)
            if os.path.isfile(path): return key_opts(path), None
            print(red(tr("✗ Файл не найден (или вставьте ключ, начиная со строки -----BEGIN)")))

    def reachable(s, timeout=4):
        """До входа: отвечает ли на host:port именно SSH. Возвращает None (всё в порядке) или причину."""
        # адрес — как его увидит ssh (алиасы ~/.ssh/config); через ProxyJump/ProxyCommand напрямую не проверить
        g = subprocess.run([SSH, "-G", "-p", str(s["port"]), s["host"]], capture_output=True, text=True).stdout
        g = dict(l.split(" ", 1) for l in g.splitlines() if " " in l)
        if g.get("proxyjump", "none") != "none" or g.get("proxycommand", "none") != "none": return None
        try:
            with socket.create_connection((g.get("hostname", s["host"]), int(g.get("port", s["port"]))), timeout=timeout) as c:
                c.settimeout(timeout)
                if not c.recv(64).startswith(b"SSH-"): return tr("не нашёл SSH-сервер на этом порту")
        except socket.gaierror: return tr("хост не найден (ошибка в имени или DNS)")
        except ConnectionRefusedError: return tr("порт закрыт (SSH не запущен или другой порт)")
        except (socket.timeout, TimeoutError): return tr("нет ответа (сервер выключен, файрвол или другая сеть)")
        except OSError as e: return tr('нет связи: {p0}', p0=e.strerror or e)
        return None

    def check_reach(s):
        """Проверить доступность с понятным сообщением; при недоступности спросить, продолжать ли."""
        print(dim(tr('Проверяю {p0}:{p1}…', p0=s['host'], p1=s['port'])), end=" ", flush=True)
        why = reachable(s)
        if not why: print(green(tr("✓ SSH отвечает"))); return True
        print(red(f"✗ {why}"))
        return yes(yellow(tr("Всё равно продолжить?")))

    def server_ok(s):
        return isinstance(s, dict) and host_ok(str(s.get("host", ""))) and user_ok(str(s.get("user", ""))) \
            and port_ok(str(s.get("port", ""))) and isinstance(s.get("name"), str) \
            and ("nick" not in s or bool(re.fullmatch(NICK_RE, str(s["nick"])))) \
            and ("id" not in s or bool(re.fullmatch(r"[0-9a-f]{1,8}", str(s["id"])))) \
            and ("added" not in s or bool(re.fullmatch(r"\d{8}", str(s["added"]))))

    server_line = lambda s: f"{bold(s['name'])}  {dim(s['user'] + '@' + s['host'] + ':' + str(s['port']))}" \
        + (f"  {cyan(s['nick'])}" if s.get("nick") else "") + (dim(f"  #{s['id']}") if s.get("id") else "") \
        + (red(tr("  [ключи не установлены]")) if s.get("pending") else "")

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
                print(dim(tr("Создаю ключ в Android Keystore…")))
                subprocess.run(["termux-keystore", "generate", self.ALIAS, "-a", "EC", "-s", "256"],
                               capture_output=True, timeout=60)
            k = self._list().get(self.ALIAS)
            if not k or "x" not in k: raise RuntimeError(tr("Keystore не создал ключ"))
            self.blob = ecdsa_blob(int(k["x"], 16), int(k["y"], 16))
            self.hardware = k.get("inside_secure_hardware")

        def sign(self, data):
            r = subprocess.run(["termux-keystore", "sign", self.ALIAS, "SHA256withECDSA"],
                               input=data, capture_output=True, timeout=60)
            if r.returncode or not r.stdout: raise RuntimeError(tr("Keystore не подписал"))
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
                    what = tr("сопряжения") if mode == "pair" else tr("запросы компьютера")
                    print(cyan(tr('Жду {p0}…  IP: {p1}', p0=what, p1=bold(local_ip()))))
                    print(dim(tr("Ctrl+C — назад\n")))
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
                            if getattr(self, "restart", False):  # новая версия уже на месте — запускаем её
                                conn.close(); srv.close()
                                print(dim(tr("Перезапуск…"))); os.execv(sys.executable, [sys.executable, os.path.abspath(__file__), "--install"])
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
            name = str(msg.get("name", tr("компьютер")))[:40]
            nP = secrets.token_bytes(32)
            send_raw(conn, {"pub": self.pub.hex(), "n": nP.hex()})
            nC = bytes.fromhex(recv_raw(conn)["n"])
            if not hmac.compare_digest(H(b"commit", nC), commit):
                raise ConnectionError(tr("нарушен протокол — возможна атака"))
            header(tr("сопряжение"))
            print(tr('  Компьютер: {p0}  {p1}\n', p0=bold(name), p1=dim(fingerprint(cpub))))
            print(tr('  Введите на компьютере код:  {p0}\n', p0=mag(bold(sas(cpub, self.pub, nC, nP)))))
            ok = yes(blue(tr("Компьютер написал «✓ Код верный»?")))
            send_raw(conn, {"ok": ok})
            if not ok or not recv_raw(conn).get("ok"):
                print(red(tr("✗ Сопряжение отменено"))); pause(); return False
            ch = Chan(conn, H(b"pair", x25519(self.priv, cpub), nC, nP), "p")
            rec = ch.recv()["recovery"]
            if rec and not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+ " + RECOVERY_TAG, rec): raise ValueError("bad recovery")
            ch.send({"line": self.ks.line()})
            self.d["peers"] = {cpub.hex(): {"name": name}}
            self.d["recovery"] = rec
            self.save()
            print(green(tr('\n✓ Сопряжено с «{p0}»', p0=name))); pause()
            return True

        def session(self, conn, msg):
            cpub = bytes.fromhex(msg["id"])
            peer = self.d["peers"].get(cpub.hex())
            if not peer:
                print(yellow(tr("Запрос от незнакомого компьютера — отклонён.\n"))); return
            ce = bytes.fromhex(msg["e"])
            pe_priv = secrets.token_bytes(32); pe = pubkey(pe_priv)
            send_raw(conn, {"e": pe.hex()})
            k = H(b"kk", x25519(pe_priv, ce), x25519(pe_priv, cpub), x25519(self.priv, ce), ce, pe)
            ch = Chan(conn, k, "p")
            hello = ch.recv()
            intent, danger = str(hello.get("intent", "?"))[:120], bool(hello.get("danger"))
            print(bell() + bold(tr('Запрос от «{p0}»: {p1}', p0=peer['name'], p1=intent)))
            if danger: print(red(bold(tr("   ⚠ ОПАСНОЕ ДЕЙСТВИЕ — подтверждайте, только если запускали его сами."))))
            print(tr('   Код сеанса:  {p0}', p0=mag(bold(session_code(k)))))
            print(dim(tr("   Разрешайте, только если на компьютере тот же код.")))
            allow = yes(blue(tr("Код совпадает, разрешить?")))
            ch.send({"allow": allow})
            pc = peer["name"]
            self.log(pc, intent, "разрешено" if allow else "отклонено")
            if not allow: print(); return
            signs, signed, target, approved, to_delete, pending, upd = 0, False, None, set(), [], None, None
            sign_user = None
            while True:
                try: m = ch.recv()
                except (ConnectionError, OSError):
                    if pending and pending["ks"]:  # перевыпуск не завершён — новый ключ не нужен
                        subprocess.run(["termux-keystore", "delete", pending["ks"].ALIAS], capture_output=True, timeout=30)
                    print(dim(tr("  сеанс завершён\n"))); return
                t = m.get("t")
                if t == "list":
                    ch.send({"servers": self.d["servers"], "line": self.ks.line(), "recovery": self.d["recovery"],
                             "members": self.d.get("members", [])})
                elif t == "version":
                    data, upd = self_bytes(), None
                    theirs, size = str(m.get("v", "")), m.get("size")
                    if (m.get("sha") != hashlib.sha256(data).hexdigest() and isinstance(size, int) and 0 < size <= UPD_MAX
                            and ver_key(theirs) >= ver_key(VERSION)):
                        print(yellow(tr('  На компьютере «{p0}» другая версия программы: {p1} (на телефоне {p2}).', p0=pc, p1=theirs or '?', p2=VERSION)))
                        if yes(blue(tr("  Обновить телефон? Да — если вы сами обновляли программу на компьютере.")), True):
                            upd = {"sha": m.get("sha"), "size": size, "buf": bytearray()}
                    ch.send({"ok": True, "want": upd is not None, "v": VERSION})
                elif t == "update_part":
                    b = base64.b64decode(str(m.get("b", ""))) if upd else b""
                    ok = bool(upd) and m.get("i") == len(upd["buf"]) and len(upd["buf"]) + len(b) <= upd["size"]
                    if ok: upd["buf"] += b
                    else: upd = None  # сбой порядка/размера — обновление отменяется целиком
                    ch.send({"ok": ok})
                elif t == "update_done":
                    ok = bool(upd) and hashlib.sha256(upd["buf"]).hexdigest() == upd["sha"]
                    if ok:
                        try: compile(bytes(upd["buf"]), "sshstore.py", "exec")
                        except (SyntaxError, ValueError): ok = False
                    if ok:
                        me = os.path.abspath(__file__); tmp = me + ".new"
                        with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
                            f.write(upd["buf"]); f.flush(); os.fsync(f.fileno())
                        os.chmod(tmp, 0o400); os.replace(tmp, me)
                        self.log(pc, tr("обновление программы"), "выполнен"); self.restart = True
                        print(green(tr("  ✓ Программа обновлена — перезапущу после сеанса")))
                    elif upd is not None or m.get("sha"):
                        print(red(tr("  ✗ Обновление не прошло проверку — оставлена старая версия")))
                    upd = None
                    ch.send({"ok": ok})
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
                    what = ", ".join(w for w, on in ((tr("ключ телефона"), m.get("phone")), (tr("резервный ключ"), new_rec)) if on)
                    if not what: ch.send({"ok": False}); continue
                    print(red(bold(tr('  ⚠ Перевыпуск: {p0} — на всех серверах ({p1})', p0=what, p1=len(self.d['servers'])))))
                    if m.get("wipe"): print(red(tr("  ⚠ Затереть: на серверах останутся только ключи ssh-storage этого телефона")))
                    for w in m.get("warn", [])[:20]: print(yellow("    ⚠ " + str(w)[:120]))
                    if new_rec: print(yellow(tr("  Старый резервный пароль перестанет работать.")))
                    ok = yes(red(tr("  Перевыпустить?")))
                    self.log(pc, tr('перевыпуск: {p0}', p0=what) + (tr(", затереть") if m.get("wipe") else ""),
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
                    self.log(pc, tr("перевыпуск: новые ключи действуют"), "выполнен")
                    print(green(tr("  ✓ новые ключи действуют")))
                    ch.send({"ok": True})
                elif t == "journal":
                    ch.send({"log": self.d.get("log", [])})
                elif t == "use":
                    signs, sign_user = 0, None
                    i = m.get("i")
                    if type(i) is not int or not 0 <= i < len(self.d["servers"]):
                        ch.send({"ok": False}); continue
                    s = self.d["servers"][i]
                    ok = yes(blue(tr('  Разрешить вход на {p0} ({p1}@{p2}:{p3})?', p0=s['name'], p1=s['user'], p2=s['host'], p3=s['port'])))
                    if ok:
                        signs, sign_user, signed = 3, s["user"], False
                        conn.settimeout(60); target = s['name']
                    ch.send({"ok": ok})
                elif t == "sign":
                    if signs <= 0: ch.send({"ok": False}); continue
                    signs -= 1
                    data = bytes.fromhex(m["data"])
                    if not valid_sign_request(data, sign_user, self.ks.blob):
                        ch.send({"ok": False}); continue
                    ch.send({"ok": True, "sig": self.ks.sign(data).hex()})
                    if not signed:
                        # сервер просит подпись только если уже согласился принять ключ телефона
                        print(green(tr("  ✓ сервер принял ключ телефона — подпись выдана")))
                        signed = True; conn.settimeout(12 * 3600)  # ждём итог, пока идёт сеанс
                elif t == "add_many":
                    sv = [x for x in m["servers"] if server_ok(x)]
                    print(yellow(tr('  Добавить серверы ({p0}):', p0=len(sv))))
                    for x in sv: print("    " + server_line(x))
                    ok = yes(blue(tr("  Разрешить добавление всех?")), True)
                    if ok: approved = {(x["host"], x["port"], x["user"]) for x in sv}
                    self.log(pc, tr('добавить серверы ({p0})', p0=len(sv)), "разрешено" if ok else "отклонено")
                    ch.send({"ok": ok})
                elif t == "delete_many":
                    sv = [x for x in m["servers"] if x in self.d["servers"]]
                    how = tr("из списка и снять ключи с серверов") if m.get("keys") else tr("только из списка")
                    print(red(tr('  Удалить серверы ({p0}), {p1}:', p0=len(sv), p1=how)))
                    for x in sv: print("    " + server_line(x))
                    ok = bool(sv) and yes(red(tr("  Удалить?")))
                    to_delete = sv if ok else []
                    self.log(pc, tr('удалить серверы ({p0}), {p1}', p0=len(sv), p1=how), "разрешено" if ok else "отклонено")
                    ch.send({"ok": ok})
                elif t == "delete_done":
                    # удаляем только одобренные в delete_many
                    gone = [x for x in m["servers"] if x in to_delete and x in self.d["servers"]]
                    to_delete = []  # одобрение одноразовое
                    self.d["servers"] = [x for x in self.d["servers"] if x not in gone]; self.save()
                    for x in gone: self.log(pc, tr("удалить сервер"), "выполнен", x["name"])
                    print(green(tr('  ✓ удалено из списка: {p0}', p0=len(gone))))
                    ch.send({"ok": True, "n": len(gone)})
                elif t == "add":
                    s = m["server"]
                    if not server_ok(s): ch.send({"ok": False}); continue
                    ok = (s["host"], s["port"], s["user"]) in approved or yes(blue(tr('  Добавить сервер «{p0}» ({p1}@{p2}:{p3})?', p0=s['name'], p1=s['user'], p2=s['host'], p3=s['port'])), True)
                    self.log(pc, tr("добавить сервер"), "разрешено" if ok else "отклонено", s["name"])
                    ch.send({"ok": ok, "line": self.ks.line(), "recovery": self.d["recovery"]})
                elif t in ("edit", "delete"):
                    i, old, sv = int(m["i"]), m.get("old"), self.d["servers"]
                    if not (0 <= i < len(sv)) or sv[i] != old: ch.send({"ok": False}); continue
                    if t == "edit":
                        new = m["server"]
                        if not server_ok(new): ch.send({"ok": False}); continue
                        print(yellow(tr('  Изменить сервер с компьютера:')))
                        for k in FIELDS:
                            o, n = old.get(k, "—"), new.get(k, "—")
                            mark = bold(yellow("→ " + str(n))) if n != o else dim(tr("без изменений"))
                            print(f"    {k:5} {o}  {mark}")
                        ok = yes(blue(tr("  Сохранить?")), True)
                        if ok: sv[i] = {k: new[k] for k in FIELDS if k in new}; self.save()
                    else:
                        ok = yes(red(tr('  Удалить «{p0}» ({p1}@{p2}) из списка?', p0=old['name'], p1=old['user'], p2=old['host'])))
                        if ok: sv.pop(i); self.save()
                    self.log(pc, tr("изменить сервер") if t == "edit" else tr("удалить сервер"),
                             "разрешено" if ok else "отклонено", old["name"])
                    print(green(tr("  ✓ сохранено")) if ok else dim(tr("  отменено")))
                    ch.send({"ok": ok})
                elif t == "result":
                    # сообщает компьютер — только для информации, телефон ничего на этом не разрешает
                    self.log(pc, tr("вход"), "выполнен" if m.get("ok") else "не удался", target or "")
                    if m.get("ok"): print(green(tr('  ✓ вход на «{p0}» выполнен, сеанс закрыт', p0=target)))
                    elif not signed: print(red(tr('  ✗ вход на «{p0}» не удался: сервер не принял ключ телефона или нет связи', p0=target)))
                    else: print(red(tr('  ✗ вход на «{p0}» не удался', p0=target)))
                    ch.send({"ok": True})
                elif t == "added":
                    s = m["server"]
                    if server_ok(s):
                        self.d["servers"] = [x for x in self.d["servers"]
                                             if (x["host"], x["port"], x["user"]) != (s["host"], s["port"], s["user"])]
                        self.d["servers"].append(s); self.save()
                        print(green(tr('  ✓ сервер «{p0}» сохранён', p0=s['name'])))
                    ch.send({"ok": True})
                else:
                    ch.send({"ok": False})

        # --- редактирование на телефоне ---
        def servers_menu(self):
            while True:
                header(tr("серверы"))
                sv = self.d["servers"]
                adm = self.d["recovery"] != ""  # у участника команды (recovery == "") отзыва нет — это делает админ
                extra = [green(tr("+ Добавить вручную"))] + ([red(tr("Отозвать участника (снять ключи)"))] if adm else [])
                ch = menu([server_line(s) for s in sv] + extra + [dim(tr("Назад"))], default=len(sv) + len(extra) + 1)
                if ch == str(len(sv) + len(extra) + 1): return
                if adm and ch == str(len(sv) + 2): self.revoke_member()
                elif ch == str(len(sv) + 1):
                    header(tr("новый сервер")); s = dict(edit_server(servers=sv), pending=True)
                    sv.append(s); self.save(); self.show_cmd(s)
                elif ch.isdigit() and 1 <= int(ch) <= len(sv):
                    i = int(ch) - 1
                    header(sv[i]["name"])
                    a = menu([tr("Подключиться"), tr("Изменить"), tr("Команда установки для сервера"), tr("Удалить"),
                              tr("Туннель к веб-панели (3x-ui и др.)"), tr("Назад")], default=1)
                    if a == "1": clear(); self.ssh(sv[i])
                    elif a == "5":
                        port = int(ask(tr("Порт панели на сервере"), 2053, validate=port_ok))
                        print(green(tr('Откройте в браузере телефона http://127.0.0.1:{p0}/  Ctrl+C — закрыть.', p0=port)))
                        print(yellow(tr("Пока туннель открыт, порт доступен и другим приложениям телефона — закройте сразу после работы.")))
                        try: self.ssh(sv[i], opts=("-N", "-L", f"127.0.0.1:{port}:127.0.0.1:{port}"))
                        except KeyboardInterrupt: pass
                    elif a == "2": header(tr("изменить")); sv[i] = dict(edit_server(sv[i], sv), **({"pending": True} if sv[i].get("pending") else {})); self.save()
                    elif a == "3": self.show_cmd(sv[i])
                    elif a == "4" and yes(red(tr('Удалить «{p0}» из списка?', p0=sv[i]['name']))):
                        sv.pop(i); self.save()

        def ssh(self, s, *cmd, opts=()):
            """Вход прямо с телефона: тот же агент, что и на ПК, но подписывает свой Keystore."""
            if not shutil.which(SSH): print(red(tr("Нет ssh: выполните pkg install openssh"))); pause(); return 255
            a = Agent(self.ks.blob, lambda d: ecdsa_sig(self.ks.sign(d)))
            try: return subprocess.call(ssh_cmd(s, "-o", f"IdentityAgent={a.path}", "-o", "IdentitiesOnly=yes",
                                                "-i", a.pubfile(), *(["-t"] if cmd else []), *opts) + list(cmd))
            finally: a.close()

        def revoke_member(self):
            header(tr("отозвать участника"))
            sv = [x for x in self.d["servers"] if server_ok(x) and not x.get("pending")]
            known = self.d.get("members", [])
            if not sv: print(yellow(tr("Список серверов пуст."))); pause(); return
            for n, k in enumerate(known, 1): print(f"  {n}. {k}")
            nick = ask(tr("Ник участника (или номер)"), validate=lambda v: bool(re.fullmatch(NICK_RE, v)) or v.isdigit() and 1 <= int(v) <= len(known))
            if nick.isdigit() and 1 <= int(nick) <= len(known): nick = known[int(nick) - 1]
            sv = pick_many(sv, tr("Где отозвать"))
            if not sv: return
            print(yellow(tr('\nУчастник {p0}: ключи снять, вход заблокировать, сеансы закрыть на: {p1}. Полное удаление — с компьютера.', p0=nick, p1=', '.join(x['name'] for x in sv))))
            if not yes(red(tr("Отозвать?"))): return
            res = []
            for x in sv:
                print(bold(f"\n→ {x['name']}"))
                res.append((x, {0: tr("снято"), 3: tr("участника не было")}.get(self.ssh(x, "sh -c " + shlex.quote(revoke_cmd(nick))))))
            self.log(tr("телефон"), tr('отзыв {p0}', p0=nick), "выполнен" if all(w for _, w in res) else "не удался", "")
            header(tr('итог отзыва · {p0}', p0=nick))
            for x, w in res: print(f"  {server_line(x)}  " + (green(w) if w else red(tr("не выполнено — повторите"))))
            pause()

        def show_cmd(self, s):
            header(tr("установка на сервер"))
            if self.d["recovery"] is None:
                print(yellow(tr("Сначала сопряжение с компьютером (там создаётся резервный пароль)."))); pause(); return
            print(tr('Выполните на сервере {p0} (консоль хостинга или текущий вход):\n', p0=bold(s['user'] + '@' + s['host'])))
            print(cyan(install_cmd(with_nick(self.ks.line(), server_tag(s)), self.d["recovery"])) + "\n")
            print(dim(tr("Проще: на компьютере ssh-storage → «Серверы» → «Добавить сервер» сделает это сам.")))
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
        print(green(tr("✓ Установлено. Дальше на телефоне команда ")) + bold("ssh-storage"))
        pause()

    def phone_main():
        if "--install" in sys.argv: phone_install()
        if not Keystore.available():
            print(red(tr("Нет termux-keystore.")))
            print(tr("Установите приложение ") + bold("Termux:API") + tr(" из F-Droid и выполните: ") + bold("pkg install termux-api"))
            sys.exit(1)
        ks = Keystore()
        ph = Phone(ks); ks.ensure()
        while True:
            header(tr("телефон"))
            print(f"  {dim(tr('отпечаток'))}  {fingerprint(ph.pub)}")
            print(f"  {dim('IP')}         {local_ip()}")
            print(f"  {dim(tr('ключ SSH'))}   " + (green(tr("в защищённом чипе")) if ph.ks.hardware else yellow(tr("в Keystore (без отдельного чипа)"))))
            peers = ph.d["peers"]
            for p in peers.values(): print(f"  {dim(tr('сопряжён'))}   {green(p['name'])}")
            if not peers: print(f"  {yellow(tr('не сопряжён'))}")
            print(f"  {dim(tr('серверов'))}   {len(ph.d['servers'])}\n")
            # разделы — как на ПК (кроме «Действий на сервере»: они выполняются с компьютера)
            ch = menu([tr("Ожидать запросы компьютера"), tr("Серверы"), tr("Сопряжение"), tr("Специальные возможности"), tr("Language / Язык"), tr("Выход")],
                      default=1 if peers else 3)
            if ch == "1":
                if not peers: print(yellow(tr("Сначала сопряжение."))); pause(); continue
                header(tr("ожидание")); ph.serve("wait")
            elif ch == "2": ph.servers_menu()
            elif ch == "3":
                header(tr("сопряжение"))
                a = menu([tr("Начать сопряжение"), tr("Отменить сопряжение"), tr("Назад")], default=3 if peers else 1)
                if a == "1": header(tr("сопряжение")); ph.serve("pair")
                elif a == "2" and peers and yes(red(tr("Удалить сопряжение с компьютером?"))):
                    ph.d["peers"] = {}; ph.save()
            elif ch == "4":
                header(tr("специальные возможности"))
                a = menu([tr("Журнал одобрений"), tr("Мой публичный ключ (отправить админу команды)"), tr("Стереть все данные"), tr("Назад")], default=4)
                if a == "1": header(tr("журнал одобрений")); show_journal(ph.d.get("log", [])); pause()
                elif a == "2": header(tr("публичный ключ")); print(cyan(ph.ks.line()) + "\n"); print(dim(tr("Это не секрет: скопируйте и отправьте админу."))); pause()
                elif a == "3" and phone_wipe(ph.ks): return
            elif ch == "5": language_settings(ph.d, ph.save)
            elif ch == "6": clear(); return

    def show_journal(log):
        if not log: print(dim(tr("  Журнал пуст."))); return
        for e in log[-50:]:
            ok = e["result"] in ("разрешено", "выполнен")  # в журнале хранятся русские статусы; переводятся при показе
            srv = f" · {e['server']}" if e.get("server") else ""
            print(f"  {dim(e['t'])}  {e['pc']}{srv}: {e['what']} — " + (green if ok else red)(tr(e["result"])))
        if len(log) > 50: print(dim(tr('  …показаны последние 50 из {p0}', p0=len(log))))

    def phone_wipe(ks):
        header(tr("стереть данные"))
        a = menu([tr("Стереть серверы и сопряжение (ключ SSH остаётся — серверы будут пускать телефон)"),
                  tr("Стереть всё: и ключ SSH, и приложение"),
                  tr("Назад")], default=3)
        if a == "1":
            print(yellow(tr("\nУдалится список серверов и сопряжение. Потом — новое сопряжение с компьютером.")))
            if not confirm_wipe(): return False
            if os.path.exists(PHONE): os.remove(PHONE)
            print(green(tr("✓ Стёрто. Запустите ssh-storage заново."))); return True
        if a == "2":
            print(red(bold(tr("\n⚠ Ключ SSH будет удалён навсегда: НИ ОДИН сервер больше не пустит этот телефон."))))
            print(yellow(tr("  Вернуть доступ можно только резервным паролем (на компьютере → «Специальные возможности» → «Восстановление»).")))
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
            print(green(tr("✓ Всё стёрто: ключ, данные и приложение."))); return True
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
        header(tr("установка на телефон"))
        with open(os.path.abspath(__file__), "rb") as f: data = f.read()
        print(tr("Нужно: Termux и ") + bold("Termux:API") + tr(" из F-Droid."))
        print(tr("В Termux выполните ") + dim(tr("(можно переслать себе в мессенджер)")) + ":\n")
        print(cyan(PHONE_CMD) + "\n")
        if shutil.which("qrencode"):  # QR: камерой телефона → «Копировать» → вставить в Termux
            print(tr("Или наведите камеру телефона на QR, скопируйте текст и вставьте в Termux:\n"))
            subprocess.run(["qrencode", "-t", "ANSIUTF8", "-m", "2", PHONE_CMD]); print()
        input(blue(tr("Когда телефон ждёт — Enter: ")))
        def probe(host):
            try:
                sk = socket.create_connection((host, TCP_PORT), timeout=1.0); sk.settimeout(1.0)
                if sk.recv(1) == b"R": return host, sk
                sk.close()
            except OSError:
                pass
            return None
        while True:
            print(dim(tr("Ищу устройства…")))
            found = scan(probe)
            if found: break
            if not yes(yellow(tr("Устройства не найдены. Искать снова?")), True): return
        header(tr("установка на телефон"))
        names = []
        for host, _ in found:
            try: names.append(socket.gethostbyaddr(host)[0])
            except OSError: names.append(tr("устройство"))
        ch = menu([f"{n}  {dim(h)}" for n, (h, _) in zip(names, found)] + [dim(tr("Отмена"))])
        pick = int(ch) - 1 if ch.isdigit() and 1 <= int(ch) <= len(found) else None
        for i, (_, sk) in enumerate(found):
            if i != pick: sk.close()
        if pick is None: return
        sk = found[pick][1]
        sk.settimeout(30); sk.sendall(data); sk.close()
        print(tr('\n  Код проверки:  {p0}\n', p0=mag(bold(hashlib.sha256(data).hexdigest()[:16]))))
        print(tr("Если на телефоне тот же код — нажмите там Enter."))
        print(red(tr("Если код другой — НЕ нажимайте, закройте Termux: файл подменили.")))
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
            except (OSError, struct.error, IndexError, ValueError):
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
            a = input(blue(tr('\n{p0}: номера через запятую или пробел (Enter — все, 0 — отмена): ', p0=what))).strip()
            if not a: return list(sv)
            nums = {int(n) if n.isdigit() else -1 for n in re.split(r"[\s,]+", a)}
            if 0 in nums: return []
            if all(1 <= n <= len(sv) for n in nums): return [sv[n - 1] for n in sorted(nums)]
            print(yellow(tr('Только номера от 1 до {p0}.', p0=len(sv))))

    def ssh_cmd(s, *opts):
        return [SSH, "-p", str(s["port"]), "-o", "ForwardAgent=no", *opts, "--", f"{s['user']}@{s['host']}"]

    # Командный режим (S.1): свой Unix-пользователь на человека. Логин — строго по правилам useradd.
    LOGIN_RE = r"[a-z_][a-z0-9_-]{0,31}"
    PUBKEY_RE = r"(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|ssh-rsa|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/]+=*"

    # S.6: роль = группа ssh-storage-<роль> + права: admin — sudo (свой пароль, сменить при первом входе) и журналы;
    # operator / viewer — только чтение журналов (adm, systemd-journal), без sudo.
    ROLES = {"admin": tr("администратор — sudo и журналы"), "operator": tr("оператор — журналы и sudo systemctl restart/reload"),
             "viewer": tr("наблюдатель — журналы, без sudo")}

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

    def member_key_cmd(key, nick):
        if not re.fullmatch(PUBKEY_RE, key) or not re.fullmatch(NICK_RE, nick):
            raise ValueError(tr("недопустимый ключ или ник"))
        line = f"{key} ssh-storage-member:{nick}:{time.strftime('%Y%m%d')}"
        return ('if [ -f "$f" ]; then ' + STRIP_SH + 'fi; '
                + f'printf "%s\\n" {shlex.quote(line)} >> "$f" || exit 1; ')

    def member_cmd(login, key, nick, role="viewer"):
        """Создать участника или обновить своего (тот же ник в реестре): ключ с меткой ssh-storage-member:<ник>, роль
        (группы, sudo только у admin), снять нашу блокировку после отзыва. Чужого пользователя не трогает (exit 4)."""
        assert re.fullmatch(PUBKEY_RE, key) and role in ROLES
        sh = (member_vars(nick, login) +
              tr('if id "$L" >/dev/null 2>&1; then home; ours && mine || { echo "✗ пользователь $L уже есть и это не участник $N — не трогаю"; exit 4; }; new=0; '
              'else useradd -m -s /bin/sh "$L" 2>/dev/null || adduser -D -s /bin/sh "$L" || exit 1; new=1; home; '
              # "!" = заблокирован (sshd без PAM не пустит и по ключу); "*" = пароля нет, вход по ключу работает
              'case "$(pw)" in "!"|"!!") usermod -p "*" "$L" 2>/dev/null || sed -i "s/^$L:!*:/$L:*:/" /etc/shadow;; esac; fi; '
              'echo "$N" > "$R/$L"; mkdir -p "$h/.ssh" || exit 1; ')
              + member_key_cmd(key, nick) +
              'chmod 700 "$h/.ssh"; chmod 600 "$f"; chown -R "$L": "$h/.ssh"; '
              'if [ -f "$R/$L.locked" ]; then ' + UNLOCK_SH + 'rm -f "$R/$L.locked"; fi; '
              f'for g in admin operator viewer; do [ "$g" = {role} ] || leave ssh-storage-$g; done; '
              f'grp ssh-storage-{role}; join ssh-storage-{role}; '
              'for g in adm systemd-journal; do getent group $g >/dev/null && join $g; done; ' + OPERATOR_SUDO_SH +
              # пароль — до выдачи sudo: прерванный ввод не оставит sudo без пароля
              (tr('case "$(pw)" in ""|"!"*|"*"*) echo "Временный пароль sudo для $L:"; passwd "$L" || exit 1; '
               'if passwd -e "$L" >/dev/null 2>&1 || chage -d 0 "$L" 2>/dev/null; then echo "  $L сменит его при первом входе"; '
               'else echo "  ⚠ сервер не умеет просить смену — попросите $L выполнить passwd"; fi;; esac; '
               'SG=$(getent group sudo >/dev/null && echo sudo || echo wheel); grp $SG; join $SG; '
               # на Arch группа wheel в sudoers часто закомментирована — проверяем, что sudo действительно разрешён
               'sudo -l -U "$L" 2>/dev/null | grep -q "may run" || echo "  ⚠ sudo для $L не работает: в /etc/sudoers не разрешена группа $SG (visudo)"; ')
               if role == "admin" else 'leave sudo; leave wheel; ') +
              tr('id -nG "$L" | grep -Eq "(^| )ssh-storage-{p0}( |$)" || {{ echo "✗ не удалось выдать роль"; exit 1; }}; [ $new = 1 ] && w=создан || w=обновлён; echo "✓ $w $L ($N): ключ на месте, группы: $(id -nG "$L")"', p0=role))
        return as_root(sh)

    def revoke_cmd(nick):
        """Отозвать участника: снять ключи с меткой ника у всех (копия *.ssh-storage.bak). Его пользователя (реестр или метка,
        группа ssh-storage-*, не root и не вы) ещё и заблокировать, убрать из sudo, выгнать из сеансов. Файлы остаются."""
        sh = (member_vars(nick) + 'n=0; for L in $(getent passwd | cut -d: -f1); do home; m=0; ours && mine && m=1; t=0; '
              'grep -q "$T" "$f" 2>/dev/null && { ' + STRIP_SH + 't=1; }; '
              'if [ $m = 1 ]; then ' + LOCK_SH + tr('echo "✓ $L: ключи сняты, вход заблокирован, сеансы закрыты, sudo снят"; '
              'elif [ $t = 1 ]; then echo "✓ у $L снят только ключ"; else continue; fi; n=$((n+1)); done; [ $n -gt 0 ] || exit 3'))
        return as_root(sh)

    def delete_member_cmd(nick):
        """Удалить участника полностью: его пользователя (реестр или метка, группа ssh-storage-*) с домашней папкой —
        в том числе уже отозванного. root и того, кто удаляет, не трогает: у них только снимает ключ."""
        sh = (member_vars(nick) + tr('n=0; for L in $(getent passwd | cut -d: -f1); do home; m=0; ours && mine && m=1; '
              'if [ $m = 1 ]; then pkill -KILL -u "$L" 2>/dev/null; sleep 1; userdel -r "$L" 2>/dev/null; '
              'if id "$L" >/dev/null 2>&1; then deluser --remove-home "$L" || exit 1; fi; rm -f "$R/$L" "$R/$L.locked"; '
              'echo "✓ удалён пользователь $L и его папка"; '
              'elif grep -q "$T" "$f" 2>/dev/null; then ') + STRIP_SH + tr('echo "✓ у $L снят только ключ (не участник — не удаляю)"; '
              'else continue; fi; n=$((n+1)); done; [ $n -gt 0 ] || exit 3'))
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
                # SSHSTORE_DIR может находиться в системном temp (например на macOS). Это состояние, не мусор сеанса.
                if os.path.commonpath([os.path.realpath(p), os.path.realpath(HERE)]) == os.path.realpath(p): continue
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
                print(yellow(tr("Телефон не сопряжён: пункт «Сопряжение» → «Сопряжение с телефоном»."))); pause(); return None
            print(dim(tr("На телефоне: ssh-storage → «Ожидать запросы компьютера».")))
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
                print(tr('\n  Код сеанса:  {p0}', p0=mag(bold(session_code(k)))))
                print(cyan(tr("  Подтвердите на телефоне, если там тот же код…")))
                if not ch.recv().get("allow"):
                    print(red(tr("✗ Отклонено на телефоне"))); ch.close(); pause(); return None
                self.offer_update(ch)
                return ch
            except (OSError, ConnectionError, ValueError, KeyError) as e:
                print(red(f"✗ {e}")); pause(); return None

        def offer_update(self, ch):
            """Телефон сам решает, нужна ли ему эта версия; старый телефон ответит {"ok": False} — тогда ничего."""
            data = self_bytes()
            r = ch.call({"t": "version", "v": VERSION, "sha": hashlib.sha256(data).hexdigest(), "size": len(data)})
            if not r.get("want"): return
            print(dim(tr('Обновляю программу на телефоне ({p0} → {p1})…', p0=r.get('v', '?'), p1=VERSION)))
            for i in range(0, len(data), UPD_CHUNK):
                if not ch.call({"t": "update_part", "i": i, "b": base64.b64encode(data[i:i + UPD_CHUNK]).decode()}).get("ok"):
                    ch.call({"t": "update_done"}); print(red(tr("✗ Телефон отклонил обновление"))); return
            print(green(tr("✓ Телефон обновлён (перезапустится после сеанса)")) if ch.call({"t": "update_done"}).get("ok")
                  else red(tr("✗ Обновление на телефоне не прошло проверку")))

        def ensure_recovery(self):
            if self.d["recovery"] is not None: return
            # S.3: в командном режиме резервный пароль только у админа, участник восстанавливается через админа
            print(dim(tr("«Да» — только если админ команды сам выдал вам доступ. Иначе ответьте «нет».")))
            if yes(tr("Это компьютер участника команды (резервный пароль хранит админ)?"), False):
                self.d["recovery"] = ""; self.save(); return
            self.d["recovery"] = self.new_recovery(); self.save()

        def new_recovery(self):
            """Показать новый резервный пароль, проверить ввод; вернуть строку резервного ключа."""
            header(tr("резервный пароль"))
            pw = new_recovery_password()
            print(tr("Это единственный способ вернуть доступ, если телефон потеряется или сломается."))
            print(tr("Запишите его на бумагу и храните отдельно. Он больше нигде не сохраняется.\n"))
            print(f"     {mag(bold(pw))}\n")
            while True:
                again = getpass.getpass(blue(tr("Введите его для проверки: ")))
                if re.sub(r"[\s-]", "", again) == pw.replace("-", ""): break
                print(red(tr("  Не совпадает.")))
            clear()
            if USE_COLOR: print("\033[3J", end="", flush=True)
            print(dim(tr("Вычисляю резервный ключ…")))
            return recovery_line(recovery_seed(pw))

        def pair(self):
            self.ensure_recovery()
            header(tr("сопряжение с телефоном"))
            print(dim(tr("На телефоне: ssh-storage → «Начать сопряжение».\n")))
            input(blue(tr("Enter — искать телефон: ")))
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
                header(tr("сопряжение с телефоном"))
                print(tr('  Телефон: {p0}\n', p0=dim(fingerprint(ppub))))
                ok = False
                for _ in range(3):
                    if re.sub(r"\D", "", input(blue(tr("Код с экрана телефона: ")))) == code.replace(" ", ""):
                        ok = True; print(green(bold(tr("✓ Код верный"))) + dim(tr("  — подтвердите на телефоне"))); break
                    print(red(tr("✗ Не совпадает")))
                if not ok: print(red(tr("Если вводили правильно — кто-то вмешивается в соединение.")))
                send_raw(sock, {"ok": ok})
                if not ok or not recv_raw(sock).get("ok"):
                    print(red(tr("✗ Сопряжение отменено"))); pause(); return
                ch = Chan(sock, H(b"pair", x25519(self.me, ppub), nC, nP), "c")
                ch.send({"recovery": self.d["recovery"]})
                ch.recv()
                self.d["phone"] = {"pub": ppub.hex(), "fp": fingerprint(ppub)}; self.save()
                sock.close()
                print(green(tr("\n✓ Телефон сопряжён")))
                print(tr("Дальше: «Серверы» → «Добавить сервер» — ключ телефона пропишется на сервер.")); pause()
            except (OSError, ConnectionError, ValueError, KeyError) as e:
                print(red(f"✗ {e}")); pause()

        # --- подключение ---
        def connect(self):
            header(tr("подключение"))
            ch = self.session(tr("вход на сервер"))
            if not ch: return
            try:
                r = ch.call({"t": "list"})
                servers = [s for s in r["servers"] if server_ok(s)]
                self.cache(servers)
                if not servers:
                    print(yellow(tr("На телефоне нет серверов. Добавьте: «Серверы» → «Добавить сервер»."))); pause(); return
                header(tr("серверы"))
                pick = menu([server_line(s) for s in servers] + [dim(tr("Отмена"))])
                if not (pick.isdigit() and 1 <= int(pick) <= len(servers)): return
                s = servers[int(pick) - 1]
                if not check_reach(s): return
                clear(); print(green(f"→ {s['user']}@{s['host']}:{s['port']}  {dim(tr('(подпись — на телефоне)'))}\n"))
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
            header(tr("серверы"))
            ch = self.session(tr("изменить список серверов"))
            if not ch: return
            try:
                while True:
                    r = ch.call({"t": "list"})
                    sv = r["servers"]; self.cache(sv)
                    header(tr("серверы"))
                    pick = menu([server_line(x) for x in sv] + [dim(tr("Назад"))], default=len(sv) + 1)
                    if not (pick.isdigit() and 1 <= int(pick) <= len(sv)): return
                    i = int(pick) - 1; s = sv[i]
                    header(s["name"])
                    a = menu([tr("Изменить (название, хост, порт, пользователь, имя)"), tr("Команда установки для сервера"),
                              tr("Удалить из списка"), tr("Обновить ключи на сервере (имя в подписи, резервный ключ)"),
                              tr("Настроить VPS"), tr("Назад")], default=6)
                    if a == "1":
                        header(tr("изменить")); new = edit_server(s, sv)
                        if s.get("pending"): new["pending"] = True
                        print(cyan(tr("Подтвердите изменение на телефоне…")))
                        ok = ch.call({"t": "edit", "i": i, "old": s, "server": new}).get("ok")
                        print(green(tr("✓ Сохранено")) if ok else red(tr("✗ Не сохранено (отклонено на телефоне)")))
                        if ok and new.get("nick") != s.get("nick"):
                            print(dim(tr("Имя в подписи ключа на сервере сменится после «Обновить ключи на сервере».")))
                        pause()
                    elif a == "2":
                        header(tr("установка на сервер"))
                        print(tr('Выполните на сервере {p0}:\n', p0=bold(s['user'] + '@' + s['host'])))
                        print(cyan(install_cmd(with_nick(r["line"], server_tag(s)), r["recovery"])) + "\n"); pause()
                    elif a == "4":
                        # вход ключом телефона и та же команда установки: ключ с текущим именем, резервный — если нет
                        cmd = install_cmd(with_nick(r["line"], server_tag(s)), r["recovery"])
                        rc, out = self.phone_ssh(ch, s, "sh -c " + shlex.quote(cmd))
                        ok = "SSH-STORAGE-OK" in (out or "")
                        if ok and s.get("pending"):
                            s = {k: v for k, v in s.items() if k != "pending"}
                            ch.call({"t": "added", "server": s})
                        try: ch.call({"t": "report", "ok": ok, "text": tr("обновить ключи на сервере")})
                        except (OSError, ConnectionError, ValueError): pass
                        print(green(tr("✓ Ключи на сервере обновлены")) if ok else red(tr("✗ Не удалось (вход или запись ключей)")))
                        pause()
                    elif a == "5":
                        # Настройка требует собственного опасного сеанса, а не разрешения на правку списка.
                        ch.close(); ch = None
                        self.new_vps(s)
                        return
                    elif a == "6": return
                    elif a == "3" and yes(red(tr('Удалить «{p0}» из списка?', p0=s['name']))):
                        print(cyan(tr("Подтвердите удаление на телефоне…")))
                        ok = ch.call({"t": "delete", "i": i, "old": s}).get("ok")
                        print(green(tr("✓ Удалено")) if ok else red(tr("✗ Отклонено на телефоне"))); pause()
            except (OSError, ConnectionError, ValueError, KeyError) as e:
                print(red(f"✗ {e}")); pause()
            finally:
                if ch: ch.close()

        # --- разделы меню ---
        def pick_server(self, title):
            """Выбор сервера из сохранённого списка (копия с телефона) с отметкой прав."""
            sv = [x for x in self.d["servers"] if server_ok(x)]
            if not sv:
                print(yellow(tr("Список серверов пуст. Добавьте: «Серверы» → «Добавить сервер»."))); pause(); return None
            header(title)
            pick = menu([f"{server_line(x)}  {dim('[' + self.rights_label(x) + ']')}" for x in sv] + [dim(tr("Назад"))],
                        default=len(sv) + 1)
            return sv[int(pick) - 1] if pick.isdigit() and 1 <= int(pick) <= len(sv) else None

        def section_servers(self):
            while True:
                header(tr("серверы"))
                # участнику команды (recovery == "") управление участниками не показываем — это делает админ
                # участнику команды (recovery == "") не показываем «Новый VPS» (у него нет резервного ключа — при потере телефона
                # сервер без паролей закроется насовсем) и управление участниками (это делает админ)
                adm = self.d["recovery"] != ""
                items = [(tr("Список серверов (изменить / команда установки / удалить)"), self.servers), (tr("Добавить сервер"), self.add_menu)] \
                    + [(tr("Массовое добавление"), self.bulk_add), (tr("Массовое удаление"), self.bulk_delete),
                       (tr("Перевыпуск ключей (на всех серверах)"), self.rekey)] \
                    + ([(tr("Участники серверов (командный режим)"), self.members_menu)] if adm else [])
                a = menu([t for t, _ in items] + [tr("Назад")], default=1)
                if not (a.isdigit() and 1 <= int(a) <= len(items)): return
                items[int(a) - 1][1]()

        def members_menu(self):
            b = menu([tr("Добавить участника на серверы"), tr("Отозвать или удалить участника"), tr("Назад")], default=1)
            if b == "1": self.add_member_many()
            elif b == "2": self.revoke_member()

        def section_pairing(self):
            while True:
                header(tr("сопряжение"))
                a = menu([tr("Сопряжение с телефоном"), tr("Установить / обновить приложение на телефоне"), tr("Назад")], default=1)
                if a == "1": self.pair()
                elif a == "2": install_phone()
                else: return

        ACTIONS = [  # (название, нужный ранг прав)
            (tr("История (входы, sudo-команды, пакеты, изменения /etc)"), 2),
            (tr("Запись команд auditd (включить / история / выключить)"), 3),
            (tr("Попытки взлома (неверные входы, несуществующие логины, частые IP)"), 2),
            (tr("Диагностика (упавшие сервисы, ошибки журнала, процессы)"), 1),
            (tr("Проверка на зачатки неисправностей (быстрая / полная)"), 1),
            (tr("Перезагрузить сервер"), 3),
            (tr("Создать пользователя для участника (командный режим)"), 3),
            (tr("Проверка процессов (подмена системных, новые программы, скрытые процессы)"), 1),
            (tr("Туннель к веб-панели (3x-ui и др.) — панель не торчит в интернет"), 1),
            (tr("Настроить VPS"), 3)]

        def section_actions(self):
            s = self.pick_server(tr("действия на сервере"))
            if not s: return
            while True:
                lv = self.rights(s); rank = RIGHTS[lv][1] if lv else 0
                header(tr('действия · {p0}', p0=s['name']))
                print(tr('  {p0} · права: {p1}\n', p0=dim(self.skey(s)), p1=bold(self.rights_label(s))))
                items = []
                for name, need in self.ACTIONS:
                    mark = "" if rank >= need or not lv else yellow(tr('  (нужно: {p0})', p0=NEED[need]))
                    items.append(name + mark)
                items += [tr("Проверить права на сервере"), tr("Назад")]
                a = menu(items, default=len(items) - 1)
                if a == str(len(items) - 1):
                    ch = self.session(tr('проверить права на {p0}', p0=s['name']))
                    if not ch: continue
                    try:
                        rc, _ = self.phone_ssh(ch, s, "true")
                        try: ch.call({"t": "result", "ok": rc != 255})
                        except (OSError, ConnectionError, ValueError): pass
                        print(green(tr('✓ Права: {p0}', p0=self.rights_label(s))) if rc != 255 else red(tr("✗ Вход не удался")))
                    except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e:
                        print(red(f"✗ {e or tr('сервер не найден в списке телефона')}"))
                    finally: ch.close()
                    pause()
                elif a.isdigit() and 1 <= int(a) <= len(self.ACTIONS):
                    need = self.ACTIONS[int(a) - 1][1]
                    if lv and rank < need:
                        print(yellow(tr('Недостаточно прав. Нужно: {p0}.', p0=NEED[need])))
                        print(dim(tr("Права определяются при каждом входе; если их добавили — «Проверить права».")))
                    elif a == "1": self.history(s)
                    elif a == "2": self.audit(s); continue
                    elif a == "3": self.history(s, ATTACKS_SH, show_attacks, tr("попытки взлома"))
                    elif a == "4": self.diagnose(s); continue
                    elif a == "5": self.health(s); continue
                    elif a == "6": self.reboot(s); continue
                    elif a == "7" and self.d["recovery"] == "": print(yellow(tr("Участников добавляет админ команды.")))
                    elif a == "7": self.add_member(s); continue
                    elif a == "8": self.check_procs(s); continue
                    elif a == "9": self.tunnel(s); continue
                    elif a == "10": self.new_vps(s); continue
                    else:
                        print(yellow(tr("Этот пункт в разработке (этап 2).")))
                    pause()
                else: return

        def history(self, s, script=None, show=None, title=tr("история")):
            days = ask(tr("За сколько дней"), 7, validate=lambda v: v.isdigit() and 0 < int(v) <= 365)
            ch = self.session(tr('{p0} {p1} (только чтение)', p0=title, p1=s['name']))
            if not ch: return
            try:
                rc, out = self.phone_ssh(ch, s, "sh -c " + shlex.quote(history_cmd(days, script=script)))
                try: ch.call({"t": "result", "ok": rc != 255})
                except (OSError, ConnectionError, ValueError): pass
                if rc == 255 or "==END==" not in (out or ""): print(red(tr("✗ Не удалось получить историю"))); return
                header(tr('{p0} · {p1} · {p2} дн.', p0=title, p1=s['name'], p2=days))
                (show or show_history)(parse_history(out))
            except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e: print(red(f"✗ {e}"))
            finally: ch.close()

        def audit(self, s):
            while True:
                header(tr('запись команд · {p0}', p0=s['name']))
                print(dim(tr("  auditd записывает каждую запущенную команду с исходным пользователем входа —")))
                print(dim(tr("  видно, кто на самом деле работал, даже после sudo -i / su. Нужен root или sudo.\n")))
                a = menu([tr("Включить запись команд"), tr("История команд"), tr("Выключить (откат к прежним настройкам)"), tr("Назад")],
                         default=2)
                if a == "1":
                    print(yellow(tr("Будут записываться команды ВСЕХ пользователей сервера с аргументами (в т.ч. пароль, если его набрать\n"
                                 "прямо в команде: mysql -pПАРОЛЬ). Читать журнал может любой с sudo. Предупредите участников.")))
                    if not yes(tr("Включить?")): continue
                    self.danger(tr("включить запись команд (auditd)"), s,
                                lambda ch: (self.phone_ssh(ch, s, "sh -c " + shlex.quote(AUDIT_ON_CMD), tty=True)[0] == 0,
                                            tr("запись команд включена")))
                elif a == "3":
                    self.danger(tr("выключить запись команд (auditd), откат"), s,
                                lambda ch: (self.phone_ssh(ch, s, "sh -c " + shlex.quote(AUDIT_OFF_CMD), tty=True)[0] == 0,
                                            tr("запись команд выключена")))
                elif a == "2":
                    p = menu([tr("Сегодня"), tr("Неделя"), tr("Месяц")], default=2)
                    start = {"1": "today", "3": "this-month"}.get(p, "week-ago")
                    ch = self.session(tr('история команд {p0} (только чтение)', p0=s['name']))
                    if not ch: continue
                    try:
                        header(tr('история команд · {p0}', p0=s['name']))
                        print(dim(tr("время  исходный пользователь -> от чьего имени:  команда\n")))
                        rc, _ = self.phone_ssh(ch, s, "sh -c " + shlex.quote(audit_history_cmd(start)), tty=True)
                        try: ch.call({"t": "result", "ok": rc != 255})
                        except (OSError, ConnectionError, ValueError): pass
                    except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e: print(red(f"✗ {e}"))
                    finally: ch.close()
                    pause()
                else: return

        def health(self, s):
            full = menu([tr("Быстрая (диск, память, нагрузка, время)"),
                         tr("Полная (+ OOM, рост ошибок, SSL-сертификаты, обновления безопасности)")], default=1) == "2"
            ch = self.session(tr('проверка {p0} (только чтение)', p0=s['name']))
            if not ch: return
            try:
                rc, out = self.phone_ssh(ch, s, "sh -c " + shlex.quote(f"FULL={int(full)}\n" + HEALTH_SH +
                                                                       "\ncat ~/.ssh-storage-metrics 2>/dev/null; echo ==METRICS=="))
                try: ch.call({"t": "result", "ok": rc != 255})
                except (OSError, ConnectionError, ValueError): pass
                if rc == 255 or "==END==" not in (out or ""): print(red(tr("✗ Не удалось выполнить проверку"))); return
                header(tr('проверка · {p0} · {p1}', p0=s['name'], p1=tr('полная') if full else tr('быстрая')))
                out, hist = out.split("==END==", 1)
                show_health(out)
            except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e: print(red(f"✗ {e}")); return
            finally: ch.close()
            pts = [[float(x) for x in l.split()] for l in hist.splitlines() if re.fullmatch(r"\d+ \d+ \d+ \d+ [\d.]+", l)]
            m = re.search(tr(r"на (\d+) ядер"), out); cores = int(m[1]) if m else 1
            while True:
                print()
                a = menu([tr('График: {p0}', p0=x) for x in METRICS] +
                         [tr("Сборщик истории: ") + (tr("удалить (и всю историю)") if pts else tr("установить (графики за час / сутки / месяц)")), tr("Назад")],
                         default=6)
                if a in ("1", "2", "3", "4"):
                    if not pts: print(yellow(tr("История пуста: установите сборщик (пункт 5). Первые точки — через 5 минут."))); continue
                    p = menu([tr("Последний час"), tr("Сутки"), tr("Месяц")], default=2)
                    header(tr('история · {p0}', p0=s['name']))
                    show_metric(pts, int(a), {"1": 3600, "3": 31 * 86400}.get(p, 86400), cores); pause()
                elif a == "5":
                    on = not pts
                    if not on and not yes(red(tr("Удалить сборщик и всю накопленную историю?"))): continue
                    self.danger((tr("установить") if on else tr("удалить")) + tr(" сборщик истории нагрузки"), s,
                                lambda ch: ("SSH-STORAGE-OK" in (self.phone_ssh(ch, s, "sh -c " + shlex.quote(COLLECT_ON if on else COLLECT_OFF))[1] or ""),
                                            tr("сборщик установлен: точка раз в 5 мин, хранится 31 день") if on else tr("сборщик и история удалены")))
                    return
                else: return

        def diagnose(self, s):
            ch = self.session(tr('диагностика {p0} (только чтение)', p0=s['name']))
            if not ch: return
            try:
                rc, out = self.phone_ssh(ch, s, "sh -c " + shlex.quote(history_cmd(1, 30, script=DIAG_SH)))
                try: ch.call({"t": "result", "ok": rc != 255})
                except (OSError, ConnectionError, ValueError): pass
            except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e: print(red(f"✗ {e}")); pause(); return
            finally: ch.close()
            if rc == 255 or "==END==" not in (out or ""): print(red(tr("✗ Не удалось получить данные"))); pause(); return
            sec = parse_history(out)
            units = [u for u in sec.get("FAILED", []) if re.fullmatch(r"[\w@.:-]+", u) and not u.startswith(("sshd", "ssh."))]
            procs = [l.split() for l in sec.get("PROCS", [])]
            procs = [f for f in procs if len(f) == 5 and f[0].isdigit()]
            header(tr('диагностика · {p0}', p0=s['name']))
            print(bold(tr("Упавшие сервисы")))
            for n, u in enumerate(units, 1): print(f"  {n:>2}. {red(u)}")
            if not units: print(green(tr("  нет")))
            print("\n" + bold(tr("Ошибки журнала за сутки")) + dim(tr("  (последние 30, без IP)")))
            for l in sec.get("ERRORS", []) or [green(tr("нет"))]: print("  " + l[:160])
            print("\n" + bold(tr("Процессы с наибольшей нагрузкой")) + dim(tr("  (PID 1, sshd и свой сеанс не показаны)")))
            for n, f in enumerate(procs, len(units) + 1):
                print(f"  {n:>2}. {f[4]:<20} {dim('pid')} {f[0]:<7} {dim(tr('польз.'))} {f[1]:<10} cpu {f[2]}%  mem {f[3]}%")
            print()
            a = menu([tr("Перезапустить сервисы (номера)"), tr("Остановить процессы — SIGTERM (номера)"),
                      tr("Убить процессы принудительно — SIGKILL (номера)"), tr("Назад")], default=4)
            if a not in ("1", "2", "3"): return
            nums = {int(n) for n in re.split(r"[\s,]+", input(blue(tr("Номера через запятую или пробел: "))).strip()) if n.isdigit()}
            if a == "1": items = [units[n - 1] for n in sorted(nums) if 1 <= n <= len(units)]
            else: items = [(procs[n - 1 - len(units)][0], procs[n - 1 - len(units)][4]) for n in sorted(nums)
                           if len(units) < n <= len(units) + len(procs)]
            if not items: print(yellow(tr("Нет подходящих номеров."))); pause(); return
            kind = {"1": "restart", "2": "TERM", "3": "KILL"}[a]
            what = {"restart": tr("перезапустить"), "TERM": tr("остановить (SIGTERM)"), "KILL": tr("убить (SIGKILL)")}[kind]
            print(yellow(tr('\nБудет {p0}:', p0=what)))
            for x in items: print("  " + (x if kind == "restart" else f"{x[1]} (pid {x[0]})"))
            if kind == "KILL": print(red(tr("SIGKILL не даёт процессу сохранить данные — только если SIGTERM не помог.")))
            if not yes(red(tr("Выполнить?"))): return
            names = ", ".join(x if kind == "restart" else x[1] for x in items)
            self.danger(f"{what}: {names}"[:100], s,
                        lambda ch: (self.phone_ssh(ch, s, "sh -c " + shlex.quote(diag_action_cmd(kind, items)), tty=True)[0] == 0,
                                    f"{what}: {names}"[:150]))

        def section_special(self):
            while True:
                header(tr("специальные возможности"))
                items = [("recovery", tr("Восстановление по резервному паролю"))]
                if os.path.exists(LEGACY_VAULT): items.append(("migrate", tr("Перенести старые подключения (vault.json)")))
                items += [("journal", tr("Журнал одобрений (с телефона)")), ("wipe", tr("Стереть все данные")), ("back", tr("Назад"))]
                a = menu([text for _, text in items], default=len(items))
                act = items[int(a) - 1][0] if a.isdigit() and 1 <= int(a) <= len(items) else "back"
                if act == "recovery":
                    if self.d["recovery"] == "": print(yellow(tr("Вы участник команды: доступ восстанавливает админ (добавит ваш новый ключ)."))); pause()
                    else: self.recovery()
                elif act == "migrate": self.migrate()
                elif act == "journal": self.journal()
                elif act == "wipe":
                    if pc_wipe(): return "wiped"
                else: return

        def ask_member(self):
            print(dim(tr("  У каждого участника свой Unix-пользователь и свой ключ — в журналах видно, кто что делал.\n")))
            login = ask(tr("Логин на сервере (a-z, 0-9, _ -)"), validate=lambda v: bool(re.fullmatch(LOGIN_RE, v)))
            nick = ask(tr("Ник участника (для метки ключа)"), login, validate=lambda v: bool(re.fullmatch(NICK_RE, v)))
            key = " ".join(ask(tr("Публичный ключ участника (строка ssh-ed25519 …)"),
                               validate=lambda v: bool(re.fullmatch(PUBKEY_RE, " ".join(v.split()[:2])))).split()[:2])
            print(dim(tr("  Роль задаёт права. Администратору sudo нужен только если он ставит пакеты и правит системные файлы.")))
            a = menu(list(ROLES.values()), default=3)
            role = list(ROLES)[int(a) - 1] if a in ("1", "2", "3") else "viewer"
            return login, nick, key, role

        def add_member(self, s):
            header(tr('новый пользователь · {p0}', p0=s['name']))
            login, nick, key, role = self.ask_member()
            print(yellow(tr('\nБудет создан пользователь {p0} на {p1} с ключом участника {p2}.', p0=login, p1=s['name'], p2=nick)))
            if not yes(red(tr("Выполнить?"))): return
            def run(ch):
                ok = self.phone_ssh(ch, s, "sh -c " + shlex.quote(member_cmd(login, key, nick, role)), tty=True)[0] == 0
                if ok: self.sync_members(ch, add=nick)
                return ok, tr('создан пользователь {p0} ({p1})', p0=login, p1=nick)
            self.danger(tr('создать пользователя {p0} ({p1})', p0=login, p1=nick), s, run)

        def check_procs(self, s):
            ch = self.session(tr('проверка процессов {p0} (только чтение)', p0=s['name']))
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
            if "==END==" not in (out or ""): print(red(tr("✗ Не удалось выполнить проверку (нужен root или sudo)"))); pause(); return
            bases = self.d.setdefault("proc_base", {}); base = bases.get(self.skey(s))
            found, hidden, ports, shas = analyze_procs(out, base)
            header(tr('проверка процессов · {p0}', p0=s['name']))
            icon = {"crit": red("✗"), "warn": yellow("⚠"), "info": cyan("•")}
            for lv, e, why, pr in found:
                print(f"  {icon[lv]} {bold(e)}\n      {why}\n      {dim(', '.join(pr[:5]) + (tr(' и ещё {p0}', p0=len(pr) - 5) if len(pr) > 5 else '''))}")
            for pid, comm in hidden: print(tr('  {p0} {p1} (pid {p2}) скрыт от ps — признак руткита', p0=red('✗'), p1=bold(comm), p2=pid))
            if not found and not hidden: print(green(tr("  Подозрительного не найдено.")))
            print("\n" + bold(tr("Открытые порты")) + dim(tr("  (кто слушает входящие подключения)")))
            for proto, port, name in ports: print(f"  {proto:<4} {port:>6}  {name or dim('?')}")
            if base is None: print(yellow(tr("\nЭталона ещё нет: если сейчас всё ваше — нажмите «Доверять», и в следующий раз будут видны новые программы.")))
            print()
            a = menu([tr("Доверять: запомнить текущие программы как нормальные"), tr("Назад")], default=2)
            if a == "1": bases[self.skey(s)] = shas; self.save(); print(green(tr('✓ Запомнено программ: {p0}', p0=len(shas)))); pause()

        def reboot(self, s):
            if not yes(red(tr('Перезагрузить {p0}? Все подключения и работающие программы прервутся.', p0=s['name']))): return
            # ssh обрывается вместе с сервером (код 255) — это не ошибка
            cmd = 'S=""; [ "$(id -u)" = 0 ] || S=sudo; $S systemctl reboot || $S reboot'
            if not self.danger(tr("перезагрузить сервер"), s, lambda ch: (
                    self.phone_ssh(ch, s, "sh -c " + shlex.quote(cmd), tty=True)[0] in (0, 255), tr("команда перезагрузки отправлена")), wait=False):
                pause(); return
            print(dim(tr("Жду, пока сервер выключится и снова ответит по SSH… (Ctrl+C — перестать ждать)")))
            try:
                down = False; t = time.time()
                while time.time() - t < 600:
                    try: up = ssh_alive(s)
                    except subprocess.TimeoutExpired: up = False
                    if not up: down = True
                    elif down: print(green(tr('✓ Сервер снова в сети ({p0} с)', p0=int(time.time() - t)))); break
                    elif time.time() - t > 90:  # команда принята (ssh оборвался или 0), а падение не застали — быстрая перезагрузка
                        print(green(tr("✓ Сервер в сети")) + dim(tr(" (момент перезагрузки не застали — она была быстрой)"))); break
                    time.sleep(3)
                else: print(red(tr("✗ Сервер не вернулся за 10 минут. Проверьте его через панель хостинга.")))
            except KeyboardInterrupt: print(yellow(tr("\nОжидание прервано.")))
            pause()

        def danger(self, reason, s, run, wait=True):
            """Опасное действие: отдельный сеанс с причиной на телефоне, run(ch) -> (ok, отчёт), отчёт — в журнал телефона."""
            header(tr("опасное действие"))
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
            header(tr("журнал одобрений"))
            ch = self.session(tr("просмотр журнала одобрений"))
            if not ch: return
            try:
                header(tr("журнал одобрений")); show_journal(ch.call({"t": "journal"})["log"])
            except (OSError, ConnectionError, ValueError, KeyError) as e: print(red(f"✗ {e}"))
            finally: ch.close()
            pause()

        # --- добавление сервера ---
        def add_server(self, ch, s, identity=None, opts=None, extra=""):
            """Прописать ключ телефона и резервный ключ на сервер; при успехе сохранить на телефоне."""
            r = ch.call({"t": "add", "server": s})
            if not r.get("ok"): print(red(tr("✗ Отклонено на телефоне"))); return False
            cmd = extra + install_cmd(with_nick(r["line"], server_tag(s)), r["recovery"])
            if identity: opts = ["-o", "IdentitiesOnly=yes", "-i", identity]
            opts = opts or []
            print(dim(tr('Захожу на {p0}@{p1}…', p0=s['user'], p1=s['host'])))
            p = subprocess.run(ssh_cmd(s, *opts) + ["sh -c " + shlex.quote(cmd)], stdout=subprocess.PIPE, text=True)
            if "SSH-STORAGE-OK" not in (p.stdout or ""):
                print(red(tr("✗ Не удалось прописать ключи. Можно вручную — выполните на сервере:")))
                print(cyan(cmd))
                # сохранить с пометкой: по ID на сервере потом видно, установилась ли строка
                ch.call({"t": "added", "server": dict(s, pending=True)})
                self.cache([x for x in self.d["servers"] if (x["host"], x["user"]) != (s["host"], s["user"])]
                           + [dict(s, pending=True)])
                print(yellow(tr('«{p0}» сохранён с пометкой «ключи не установлены» (#{p1})', p0=s['name'], p1=s.get('id'))))
                return False
            s.pop("pending", None)
            ch.call({"t": "added", "server": s})
            self.cache([x for x in self.d["servers"] if (x["host"], x["user"]) != (s["host"], s["user"])] + [s])
            print(green(tr('✓ «{p0}»: ключ телефона и резервный ключ прописаны', p0=s['name'])))
            return True

        def tunnel(self, s):
            port = int(ask(tr("Порт панели на сервере"), 2053, validate=port_ok))
            ch = self.session(tr('туннель к панели {p0}:{p1}', p0=s['name'], p1=port))
            if not ch: return
            try:
                print(green(tr('Откройте в браузере http://127.0.0.1:{p0}/ (путь панели — как обычно). Ctrl+C — закрыть туннель.', p0=port)))
                print(yellow(tr("Пока туннель открыт, порт доступен и другим программам на этом компьютере — закройте сразу после работы.")))
                print(dim(tr("Подсказка: в 3x-ui можно оставить панель только на 127.0.0.1 — снаружи её не будет видно.")))
                try: rc, _ = self.phone_ssh(ch, s, opts=("-N", "-L", f"127.0.0.1:{port}:127.0.0.1:{port}"))
                except KeyboardInterrupt: rc = 0
                try: ch.call({"t": "result", "ok": rc != 255})
                except (OSError, ConnectionError, ValueError): pass
            except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e: print(red(f"✗ {e}"))
            finally: ch.close()
            pause()

        def phone_ssh(self, ch, s, *cmd, tty=False, opts=(), key_only=False):
            """ssh на сервер ключом телефона (подписи — на телефоне). Возвращает (код, stdout|None).
            Один вход: первое соединение становится мастером (ControlMaster) и заодно проверяет права;
            команда или интерактивный сеанс идут через него без новых подписей."""
            r = ch.call({"t": "list"})
            i = next(n for n, x in enumerate(r["servers"]) if x == s)
            if not ch.call({"t": "use", "i": i}).get("ok"):
                return 255, None
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
                if key_only:
                    # -i добавляет ключ к IdentityFile из конфига, а не заменяет их. Изолируем проверку,
                    # сохраняя разрешённые настройки маршрута и проверки ключа сервера, но не другие идентичности.
                    config = subprocess.run(ssh_cmd(s, "-G"), capture_output=True, text=True)
                    if config.returncode: return 255, None
                    transport = {"hostname", "proxyjump", "proxycommand", "hostkeyalias", "userknownhostsfile",
                                 "globalknownhostsfile", "stricthostkeychecking", "hostkeyalgorithms", "checkhostip",
                                 "addressfamily", "bindaddress", "bindinterface", "connecttimeout", "connectionattempts"}
                    # Не BatchMode: на новом порту нужно разрешить явное подтверждение host key.
                    isolated = ["-F", os.devnull, "-o", "PreferredAuthentications=publickey",
                                "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no"]
                    for line in config.stdout.splitlines():
                        key, _, value = line.partition(" ")
                        if key in transport and value and value != "none": isolated += ["-o", key + "=" + value]
                    base[1:1] = isolated
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
            return RIGHTS[lv][0] if lv else tr("права не проверены")

        def disable_old(self, ch, s):
            print(dim(tr("Проверяю вход ключом телефона и отключаю старые ключи…")))
            rc, out = self.phone_ssh(ch, s, "sh -c " + shlex.quote(DISABLE_OLD_CMD))
            ok = "SSH-STORAGE-OK" in (out or "")
            try: ch.call({"t": "result", "ok": rc != 255})
            except (OSError, ConnectionError, ValueError): pass
            if ok:
                print(green(tr("✓ Вход телефоном работает; старые ключи закомментированы (копия: authorized_keys.ssh-storage.bak)")))
            elif rc == 255:
                print(red(tr("✗ Вход ключом телефона не прошёл — старые ключи НЕ тронуты")))
            else:
                print(red(tr("✗ Не удалось отключить старые ключи — на сервере выполните вручную:"))); print(cyan(DISABLE_OLD_CMD))
            return ok

        def add_menu(self):
            a = menu([tr("Подключить существующий сервер"), tr("Настроить новый VPS"), tr("Назад")], default=1)
            if a == "1": self.add()
            elif a == "2": self.new_vps()

        def vps_plan(self, source):
            def choose(title, explanation):
                print("\n" + bold(title)); print(dim(explanation))
                a = menu([tr("Выполнить"), tr("Пропустить"), tr("Отмена настройки")], default=1)
                if a not in ("1", "2"): raise InterruptedError()
                return a == "1"
            p = {"user": source["user"], "port": source["port"]}
            try:
                p["update"] = choose(tr("Обновить список пакетов"), tr("apt update: только список доступных пакетов, без установки обновлений."))
                p["create"] = choose(tr("Создать нового пользователя"), tr("Отдельный логин для входа вместо root. При пропуске остаётся текущий пользователь."))
                if p["create"]:
                    p["user"] = ask(tr("Логин нового пользователя"), validate=lambda v: bool(re.fullmatch(LOGIN_RE, v)) and v != "root")
                p["admin"] = choose(tr("Выдать права администратора"), tr("Добавить пользователя в sudo: административные команды с паролем. Пароль программа не сохраняет."))
                p["term"] = choose(tr("Настроить цвета терминала"), tr("Добавить export TERM=xterm-256color в ~/.profile выбранного пользователя для следующих входов."))
                p["keys"] = choose(tr("Настроить вход ключами приложения"), tr("Добавить публичный ключ телефона и резервный ключ. Чужие ключи сохраняются; приватный ключ на VPS не создаётся."))
                change_port = choose(tr("Изменить порт SSH"), tr("Новый порт уменьшает шум от ботов, но не заменяет защиту ключами. Откройте его также в firewall хостера."))
                if change_port:
                    p["port"] = int(ask(tr("Новый порт SSH"), 4724, validate=lambda v: port_ok(v) and int(v) != source["port"]))
                p["root"] = choose(tr("Запретить вход root по SSH"), tr("Прямой SSH-вход под root перестанет работать. Права sudo у обычного пользователя сохраняются."))
                p["passwords"] = choose(tr("Отключить вход по паролю SSH"), tr("Вход только ключами, включая отключение интерактивного пароля. Пароль для sudo остаётся."))
            except InterruptedError:
                return None
            if p["root"] and p["user"] == "root":
                print(red(tr("Нельзя запретить root-вход, оставив root целевым пользователем. Запустите мастер заново и измените выбор.")))
                return None
            if p["create"] and not p["keys"] and (change_port or p["root"] or p["passwords"]):
                print(red(tr("Для нового пользователя без ключей нельзя проверить вход перед изменением SSH. Выберите установку ключей или пропустите изменения SSH.")))
                return None
            return p

        def vps_remove_old(self, ch, source, target):
            if self.skey(source) == self.skey(target): return
            sv = ch.call({"t": "list"})["servers"]
            if source not in sv or target not in sv: return
            print(dim(tr("Удаляется только запись на ПК и телефоне. Пользователь, файлы и ключи на VPS остаются.")))
            if yes(tr("Удалить старое подключение из списка?"), False):
                if not ch.call({"t": "delete", "i": sv.index(source), "old": source}).get("ok"):
                    print(yellow(tr("Старое подключение оставлено в списке.")))
                self.cache(ch.call({"t": "list"})["servers"])

        def new_vps(self, source=None):
            header(tr("Настроить VPS"))
            if not self.d.get("recovery"):
                print(yellow(tr("Настройка VPS доступна владельцу резервного доступа. Сначала выполните сопряжение."))); pause(); return
            saved = source is not None
            if source is None:
                source = edit_server(servers=self.d["servers"])
            if not check_reach(source): return
            p = self.vps_plan(source)
            if p is None: pause(); return
            if not any(p[k] for k in ("update", "create", "admin", "term", "keys", "root", "passwords")) and p["port"] == source["port"]:
                print(dim(tr("Все действия пропущены. Сервер не изменён."))); pause(); return
            target = dict(source, user=p["user"], port=p["port"])
            if self.skey(target) != self.skey(source):
                target = new_id({k: v for k, v in target.items() if k not in ("id", "added", "pending")})
            print(tr("\nЦелевое подключение: {p0}", p0=server_line(target)))
            for k, title in (("update", tr("Обновить список пакетов")), ("create", tr("Создать нового пользователя")),
                             ("admin", tr("Выдать права администратора")), ("term", tr("Настроить цвета терминала")),
                             ("keys", tr("Настроить вход ключами приложения")), ("root", tr("Запретить вход root по SSH")),
                             ("passwords", tr("Отключить вход по паролю SSH"))):
                print("  " + title + ": " + (tr("Выполнить") if p[k] else tr("Пропустить")))
            print(tr("  Порт SSH: {p0} → {p1}", p0=source["port"], p1=p["port"]))
            print(yellow(tr("Нужны Ubuntu/Debian и root или sudo у исходного пользователя. Сохраните доступ к консоли хостера.")))
            if not yes(tr("Выполнить выбранные действия?"), False): return
            opts, tmp = [], None
            use_phone = False
            if saved:
                a = menu([tr("Ключом телефона"), tr("Другим способом (пароль или SSH-ключ)"), tr("Назад")],
                         default=2 if source.get("pending") else 1)
                if a not in ("1", "2"): return
                use_phone = a == "1"
            if not use_phone:
                opts, tmp = first_login()
                if opts is None: return
            ch = None
            try:
                ch = self.session(tr("Настроить VPS"), danger=True)
                if ch: self.execute_vps(ch, source, target, p, opts, use_phone)
            except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e:
                print(red(f"✗ {e}"))
                print(yellow(tr("Настройка не завершена. Изменения могли выполниться частично; старое подключение не удалено. Если SSH уже менялся, дождитесь отката через 3 минуты.")))
            finally:
                if ch: ch.close()
                if tmp: shutil.rmtree(tmp, ignore_errors=True)
            pause()

        def execute_vps(self, ch, source, target, p, opts, use_phone):
            def source_run(command):
                if use_phone:
                    sv = ch.call({"t": "list"})["servers"]
                    current = next(x for x in sv if self.skey(x) == self.skey(source))
                    return self.phone_ssh(ch, current, command, tty=True)[0]
                return subprocess.call(ssh_cmd(source, "-t", *opts) + [command])

            def store(record):
                if not ch.call({"t": "added", "server": record}).get("ok"):
                    raise ValueError("Could not save connection on phone")
                sv = ch.call({"t": "list"})["servers"]
                if record not in sv: raise ValueError("Phone did not save connection")
                self.cache(sv)

            def failure():
                print(yellow(tr("Настройка не завершена. Изменения могли выполниться частично; старое подключение не удалено. Если SSH уже менялся, дождитесь отката через 3 минуты.")))

            # Не затираем метаданные существующего целевого подключения без подтверждения.
            sv = ch.call({"t": "list"})["servers"]
            existing = next((x for x in sv if self.skey(x) == self.skey(target)), None)
            if existing:
                if existing != source and not yes(tr("Целевое подключение уже есть. Использовать его запись?"), False): return False
                target = dict(existing)
            r = ch.call({"t": "add", "server": target})
            if not r.get("ok"): print(red(tr("✗ Отклонено на телефоне"))); return False
            token = secrets.token_hex(12)
            ssh_change = p["port"] != source["port"] or p["root"] or p["passwords"] or p["keys"]
            kwargs = {"user": target["user"], "root": p["root"], "passwords": p["passwords"], "keys": p["keys"]}
            if ssh_change and source_run(vps_ssh_cmd(token, "check", source["port"], target["port"], **kwargs)):
                failure(); return False
            inst = install_cmd(with_nick(r["line"], server_tag(target)), r["recovery"]) if p["keys"] else ""
            if source_run(vps_prepare_cmd(target["user"], create=p["create"], admin=p["admin"], term=p["term"], update=p["update"], install=inst)):
                failure(); return False
            pending = dict(source) if existing == source else dict(target, pending=True)
            store(pending)
            started = time.monotonic()
            if ssh_change:
                print(yellow(tr("SSH: включён независимый откат через 3 минуты до подтверждения нового входа.")))
                if source_run(vps_ssh_cmd(token, "stage", source["port"], target["port"], **kwargs)):
                    failure(); return False
            rc, _ = self.phone_ssh(ch, pending, "true", key_only=True)
            if rc != 0:
                failure(); return False
            if ssh_change:
                # Слишком медленное подтверждение не должно гоняться с серверным таймером отката.
                if time.monotonic() - started > 150:
                    failure(); return False
                if source_run(vps_ssh_cmd(token, "finish", source["port"], target["port"], **kwargs)):
                    failure(); return False
                rc, out = self.phone_ssh(ch, pending, vps_ssh_cmd(token, "commit", source["port"], target["port"], **kwargs), key_only=True)
                if rc != 0 or "SSH-STORAGE-VERIFIED" not in (out or "") or time.monotonic() - started > 170:
                    failure(); return False
            target.pop("pending", None)
            store(target)
            print(green(tr("Готово: выбранные действия выполнены, новый вход ключом телефона проверен.")))
            self.vps_remove_old(ch, source, target)
            return True

        def add(self, extra=""):
            header(tr("новый сервер"))
            s = edit_server(servers=self.d["servers"])
            if not check_reach(s): return
            opts, tmp = first_login()
            if opts is None: return
            print(tr("\nДругие ключи в ~/.ssh/authorized_keys на сервере — те, которыми вы входили раньше"))
            print(dim(tr("(ключи с компьютеров, другие ssh-ключи; ключи телефонов, резервный и участников команды не затрагиваются):")))
            old = menu([tr("Оставить — они продолжат работать, просто добавится ключ телефона"),
                        tr("Отключить — входить ими станет нельзя. Строки не удаляются: в начало ставится «#»,\n"
                        "      вернуть можно, убрав «#» или из копии authorized_keys.ssh-storage.bak.\n"
                        "      Делается только после того, как вход телефоном проверен.")])
            disable_old = old == "2"
            try:
                ch = self.session(tr('добавить сервер {p0}', p0=s['name']))
                if not ch: return
                try:
                    if self.add_server(ch, s, opts=opts, extra=extra) and disable_old: self.disable_old(ch, s)
                except (OSError, ConnectionError, ValueError, KeyError) as e: print(red(f"✗ {e}"))
                finally: ch.close()
                pause()
            finally:
                if tmp: shutil.rmtree(tmp, ignore_errors=True)

        def bulk_add(self):
            header(tr("массовое добавление"))
            a = menu([tr("Из файла (строки: имя хост [порт] [пользователь])"), tr("Из ~/.ssh/config"),
                      tr("Вставить списком"), tr("Назад")], default=1)
            if a == "1":
                path = os.path.expanduser(ask(tr("Путь к файлу")))
                if not os.path.isfile(path): print(red(tr("✗ Файл не найден"))); pause(); return
                sv, bad = parse_servers(open(path, errors="replace").read())
            elif a == "2": sv, bad = ssh_config_servers()
            elif a == "3":
                print(dim(tr("Строки «имя хост [порт] [пользователь]», пустая строка — конец:")))
                lines = []
                while (l := input()).strip(): lines.append(l)
                sv, bad = parse_servers("\n".join(lines))
            else: return
            header(tr("массовое добавление"))
            print(dim(tr("Проверяю доступность…")))
            down = {}
            with concurrent.futures.ThreadPoolExecutor(16) as ex:
                for x, why in zip(sv, ex.map(reachable, sv)):
                    if why: down[x["name"], x["host"]] = why
            for x in sv:
                why = down.get((x["name"], x["host"]))
                print("  " + server_line(x) + (red(f"  ✗ {why}") if why else green("  ✓")))
            for b in bad: print(red(tr("  ✗ пропущено, неверный формат — ") + b))
            if not sv: print(yellow(tr("Нечего добавлять."))); pause(); return
            print(); nick = pick_nick({}, self.d["servers"])
            sv = [new_id(dict(x, nick=nick)) for x in sv]
            print(tr("\nСпособ первого входа:"))
            per = menu([tr("Общий для всех серверов"), tr("Свой для каждого сервера")], default=1) == "2"
            if down and not yes(yellow(tr('Недоступно: {p0}. Добавить их всё равно (сохранятся с пометкой)?', p0=len(down)))):
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
                ch = self.session(tr('добавить серверы ({p0})', p0=len(sv)))
                if not ch: return
                done, fail = [], []
                try:
                    if not ch.call({"t": "add_many", "servers": sv}).get("ok"):
                        print(red(tr("✗ Отклонено на телефоне"))); pause(); return
                    for x in sv:
                        o = logins[x["name"], x["host"]]
                        if o is None: fail.append((x, tr("пропущен (отмена входа)"))); continue
                        print(bold(f"\n→ {x['name']}"))
                        try:
                            if self.add_server(ch, x, opts=o): done.append(x)
                            else: fail.append((x, tr("не удалось прописать ключи (вход или права)")))
                        except (OSError, ConnectionError, ValueError, KeyError) as e: fail.append((x, str(e)))
                finally: ch.close()
                header(tr("итог массового добавления"))
                print(green(tr('  Добавлено: {p0}', p0=len(done))))
                for x in done: print("    " + server_line(x))
                if fail or bad: print(red(tr('  Не добавлено: {p0}', p0=len(fail) + len(bad))))
                for x, why in fail: print(f"    {server_line(x)}  {red(why)}")
                for b in bad: print(f"    {red(b)}  {dim(tr('неверный формат'))}")
            finally:
                for t in tmps: shutil.rmtree(t, ignore_errors=True)
            pause()

        def add_member_many(self):
            header(tr("участник → серверы"))
            sv = [x for x in self.d["servers"] if server_ok(x)]
            if not sv: print(yellow(tr("Список серверов пуст."))); pause(); return
            login, nick, key, role = self.ask_member()
            for n, x in enumerate(sv, 1): print(f"  {n}. {server_line(x)}")
            nums = re.split(r"[\s,]+", input(blue(tr("\nНомера серверов через запятую или пробел (Enter — отмена): "))).strip())
            sel = [sv[n - 1] for n in sorted({int(n) for n in nums if n.isdigit() and 1 <= int(n) <= len(sv)})]
            if not sel: return
            print(yellow(tr('\nПользователь {p0} (участник {p1}) на серверах: {p2}', p0=login, p1=nick, p2=', '.join(x['name'] for x in sel))))
            if not yes(red(tr("Выполнить?"))): return
            ch = self.session(tr('добавить участника {p0} ({p1}) на серверы ({p2})', p0=nick, p1=login, p2=len(sel)), danger=True)
            if not ch: return
            done, fail = [], []
            try:
                for x in sel:
                    print(bold(f"\n→ {x['name']}"))
                    try: (done if self.phone_ssh(ch, x, "sh -c " + shlex.quote(member_cmd(login, key, nick, role)), tty=True)[0] == 0 else fail).append(x)
                    except (OSError, ConnectionError, ValueError, KeyError, StopIteration): fail.append(x)
                text = tr('участник {p0} ({p1}): добавлен на {p2}, не добавлен на {p3}', p0=nick, p1=login, p2=len(done), p3=len(fail))
                try: ch.call({"t": "report", "ok": not fail, "text": text})
                except (OSError, ConnectionError, ValueError): pass
                if done: self.sync_members(ch, add=nick)
            finally: ch.close()
            header(tr("итог"))
            print(green(tr('  Добавлен: {p0}', p0=len(done)))); [print("    " + server_line(x)) for x in done]
            if fail: print(red(tr('  Не добавлен: {p0} (недоступен, отказ sudo или логин занят)', p0=len(fail)))); [print("    " + server_line(x)) for x in fail]
            pause()

        def revoke_member(self):
            header(tr("отозвать участника"))
            sv = [x for x in self.d["servers"] if server_ok(x) and not x.get("pending")]
            if not sv: print(yellow(tr("Список серверов пуст."))); pause(); return
            known = self.d.get("members", [])
            if known: print(dim(tr("Добавленные через это меню (можно ввести номер):"))); [print(f"  {n}. {k}") for n, k in enumerate(known, 1)]
            nick = ask(tr("Ник участника"), validate=lambda v: bool(re.fullmatch(NICK_RE, v)) or v.isdigit() and 1 <= int(v) <= len(known))
            if nick.isdigit() and 1 <= int(nick) <= len(known): nick = known[int(nick) - 1]
            n_all = len(sv); sv = pick_many(sv, tr("Где"))
            if not sv: return
            full = menu([tr("Только снять ключи — пользователь и его файлы останутся"),
                         tr("Удалить полностью — пользователя, его папку и ключи (необратимо)"), tr("Назад")], default=1)
            if full not in ("1", "2"): return
            full = full == "2"
            if full:
                print(red(tr('\nНа {p0} будут удалены пользователи участника {p1} и все их файлы. Вернуть нельзя.', p0=', '.join(x['name'] for x in sv), p1=nick)))
                print(dim(tr("Удаляются только созданные через меню участников; ваш пользователь и root — никогда.")))
                if input(red(tr('Для подтверждения введите ник {p0}: ', p0=nick))).strip() != nick: return
            else:
                print(yellow(tr('\nУчастник {p0} на {p1}: ключи снять, вход заблокировать, открытые сеансы закрыть, sudo снять. Пользователь и файлы останутся; вернуть — «Добавить участника».', p0=nick, p1=', '.join(x['name'] for x in sv))))
                if not yes(red(tr("Отозвать?"))): return
            cmd = delete_member_cmd(nick) if full else revoke_cmd(nick)
            ch = self.session(tr('{p0} участника {p1} на серверах ({p2})', p0=tr('удалить') if full else tr('отозвать'), p1=nick, p2=len(sv)), danger=True)
            if not ch: return
            res = []
            try:
                for x in sv:
                    print(bold(f"\n→ {x['name']}"))
                    try:
                        rc = self.phone_ssh(ch, x, "sh -c " + shlex.quote(cmd), tty=True)[0]
                        res.append((x, {0: tr("удалено") if full else tr("снято"), 3: tr("участника не было")}.get(rc)))
                    except (OSError, ConnectionError, ValueError, KeyError, StopIteration): res.append((x, None))
                bad = [x for x, w in res if w is None]
                try: ch.call({"t": "report", "ok": not bad, "text": tr('отзыв {p0}: не выполнен на {p1} из {p2}', p0=nick, p1=len(bad), p2=len(res))})
                except (OSError, ConnectionError, ValueError): pass
                self.sync_members(ch, drop=nick if full and not bad and len(sv) == n_all else None)  # удалён не везде — ник остаётся
            finally: ch.close()
            header(tr('итог отзыва · {p0}', p0=nick))
            for x, w in res: print(f"  {server_line(x)}  " + (green(w) if w else red(tr("не выполнено (недоступен или отказ sudo) — повторите"))))
            pause()

        def bulk_delete(self):
            header(tr("массовое удаление"))
            sv = [x for x in self.d["servers"] if server_ok(x)]
            if not sv: print(yellow(tr("Список серверов пуст."))); pause(); return
            for n, x in enumerate(sv, 1): print(f"  {n}. {server_line(x)}")
            nums = re.split(r"[\s,]+", input(blue(tr("\nНомера через запятую или пробел (Enter — отмена): "))).strip())
            pick = sorted({int(n) for n in nums if n.isdigit() and 1 <= int(n) <= len(sv)})
            if not pick: return
            sel = [sv[n - 1] for n in pick]
            header(tr("массовое удаление"))
            for x in sel: print("  " + server_line(x))
            mode = menu([tr("Только из списка (ключи на серверах остаются)"),
                         tr("Из списка + снять ключ телефона и резервный с серверов"), tr("Отмена")], default=1)
            if mode not in ("1", "2"): return
            keys = mode == "2"
            if keys: print(yellow(tr("⚠ Ключ телефона и резервный будут сняты: войти на эти серверы через ssh-storage станет нельзя.")))
            if not yes(red(tr('Удалить серверов: {p0}?', p0=len(sel)))): return
            ch = self.session(tr('удалить серверы ({p0})', p0=len(sel)) + (tr(" и снять ключи") if keys else ""), danger=keys)
            if not ch: return
            done, fail = [], []
            try:
                r = ch.call({"t": "list"})
                sel = [x for x in sel if x in r["servers"]]  # список мог измениться на телефоне
                if not ch.call({"t": "delete_many", "servers": sel, "keys": keys}).get("ok"):
                    print(red(tr("✗ Отклонено на телефоне"))); pause(); return
                for x in sel:
                    if not keys: done.append(x); continue
                    print(bold(f"\n→ {x['name']}"))
                    try:
                        _, out = self.phone_ssh(ch, x, "sh -c " + shlex.quote(remove_keys_cmd(r["line"], r["recovery"])))
                        if "SSH-STORAGE-OK" in (out or ""): done.append(x)
                        else: fail.append((x, tr("ключи не сняты (сервер недоступен или вход не прошёл) — оставлен в списке")))
                    except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e: fail.append((x, str(e)))
                ch.call({"t": "delete_done", "servers": done})
                self.cache([x for x in r["servers"] if x not in done])
            except (OSError, ConnectionError, ValueError, KeyError) as e: print(red(f"✗ {e}"))
            finally: ch.close()
            header(tr("итог массового удаления"))
            print(green(tr('  Удалено: {p0}', p0=len(done))))
            for x in done: print("    " + server_line(x))
            if fail: print(red(tr('  Не удалено: {p0}', p0=len(fail))))
            for x, why in fail: print(f"    {server_line(x)}  {red(why)}")
            pause()

        def rekey(self):
            """Перевыпуск: 1) старым ключом дописать новые на все серверы; 2) телефон переключается на новые;
            3) новым ключом снять старые (это же проверка нового ключа)."""
            header(tr("перевыпуск ключей"))
            print(dim(tr("Один ключ на устройство: перевыпуск действует сразу на всех серверах из списка.\n")))
            what = menu([tr("Ключ телефона"), tr("Резервный ключ (новый резервный пароль)"), tr("Оба"), tr("Назад")], default=1)
            if what not in ("1", "2", "3"): return
            phone, rec = what in ("1", "3"), what in ("2", "3")
            if rec and self.d["recovery"] == "": print(yellow(tr("Резервного ключа у участника команды нет — он у админа."))); pause(); return
            mode = menu([tr("Добавить: остальные ключи на серверах не трогать"),
                         tr("Затереть: оставить на серверах только ключи ssh-storage этого телефона"), tr("Назад")], default=1)
            if mode not in ("1", "2"): return
            wipe = mode == "2"
            sv = [x for x in self.d["servers"] if server_ok(x)]
            if not sv: print(yellow(tr("Список серверов пуст."))); pause(); return
            header(tr("перевыпуск ключей — сводка"))
            print(tr('  Перевыпустить: {p0}', p0=bold(', '.join(w for w, on in ((tr('ключ телефона'), phone), (tr('резервный ключ'), rec)) if on))))
            print(tr('  Режим: {p0}', p0=red(tr('затереть остальные ключи')) if wipe else tr('добавить')))
            print(tr('  Серверы ({p0}):', p0=len(sv)))
            for x in sv: print("    " + server_line(x))
            if rec: print(yellow(tr("\n⚠ Старый резервный пароль перестанет работать — будет показан новый.")))
            if wipe: print(red(tr("⚠ Чужие ключи на серверах будут удалены (список — после проверки серверов).")))
            if input(red(tr("\nДля подтверждения введите ПЕРЕВЫПУСК: "))).strip().upper() not in (tr("ПЕРЕВЫПУСК").upper(), "ПЕРЕВЫПУСК"): return
            new_rec = self.new_recovery() if rec else None
            ch = self.session(tr("перевыпуск ключей на всех серверах"), danger=True)
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
                        warn.append(tr('{p0}: потеряют доступ ключей — {p1}', p0=x['name'], p1=len(other))
                                    + (tr(' (участники: {p0})', p0=', '.join(nicks)) if nicks else ""))
                    for w in warn: print(red("  ⚠ " + w))
                    if warn and not yes(red(tr("Участники выше потеряют доступ. Продолжить?"))): return
                resp = ch.call({"t": "rekey", "phone": phone, "recovery": new_rec, "wipe": wipe, "warn": warn})
                if not resp.get("ok"):
                    print(red(tr("✗ Отклонено на телефоне")) + (yellow(tr(" — новый резервный пароль не применён, действует старый")) if rec else ""))
                    pause(); return
                new_line = resp.get("line") or r["line"]
                new_b = ([new_line.split()[1]] if phone else []) + ([new_rec.split()[1]] if rec else [])
                ok1 = []
                for x in sv:  # 1) старым ключом: дописать новые
                    print(bold(tr('→ {p0}: новые ключи', p0=x['name'])))
                    add = ([with_nick(new_line, server_tag(x))] if phone else []) + ([new_rec] if rec else [])
                    try: res = run(x, keys_cmd(add=add, keep=[k for k in (ob, orb) if k != "-"] if wipe else None))
                    except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e: res = str(e)
                    (ok1.append(x) if "SSH-STORAGE-OK" in res else fail.append((x, tr("новые ключи не записаны (сервер недоступен?)"))))
                if fail:
                    for x, why in fail: print(red(f"  ✗ {x['name']}: {why}"))
                    print(yellow(tr("На них останутся только старые ключи") + (tr(": вход телефоном туда пропадёт, останется резервный пароль") if phone else "") + "."))
                    if not yes(red(tr("Всё равно перейти на новые ключи?"))):
                        for x in ok1:  # откат: убрать дописанные новые ключи
                            try: run(x, keys_cmd(drop=new_b))
                            except (OSError, ConnectionError, ValueError, KeyError, StopIteration): pass
                        print(dim(tr("Отменено, новые ключи убраны с серверов."))); pause(); return
                if not ch.call({"t": "rekey_commit"}).get("ok"): print(red(tr("✗ Телефон не применил новые ключи"))); pause(); return
                if rec: self.d["recovery"] = new_rec; self.save()
                r2 = ch.call({"t": "list"}); self.cache(r2["servers"])
                for x in ok1:  # 3) новым ключом: снять старые
                    print(bold(tr('→ {p0}: снять старые ключи', p0=x['name'])))
                    drop = ([ob] if phone else []) + ([orb] if rec else [])
                    try: res = run(x, keys_cmd(drop=drop, backup=False))  # копия — состояние до перевыпуска
                    except (OSError, ConnectionError, ValueError, KeyError, StopIteration) as e: res = str(e)
                    (done.append(x) if "SSH-STORAGE-OK" in res
                     else fail.append((x, tr("новый ключ записан, но вход им не прошёл — старый не снят"))))
                try: ch.call({"t": "report", "ok": not fail, "text": tr('перевыпуск: готово {p0}, ошибок {p1}', p0=len(done), p1=len(fail))})
                except (OSError, ConnectionError, ValueError): pass
            except (OSError, ConnectionError, ValueError, KeyError) as e: print(red(f"✗ {e}"))
            finally: ch.close()
            header(tr("итог перевыпуска"))
            print(green(tr('  Готово: {p0}', p0=len(done))))
            for x in done: print("    " + server_line(x))
            if fail: print(red(tr('  С ошибками: {p0}', p0=len(fail))))
            for x, why in fail: print(f"    {server_line(x)}  {red(why)}")
            pause()

        # --- восстановление ---
        def recovery(self):
            header(tr("восстановление"))
            print(tr("Вход резервным ключом из 20-символьного пароля.\n"))
            while True:
                pw = getpass.getpass(blue(tr("Резервный пароль (Enter — отмена): ")))
                if not pw: return
                print(dim(tr("Вычисляю ключ…")))
                seed = recovery_seed(pw)
                if self.d["recovery"] and recovery_line(seed) != self.d["recovery"]:
                    print(red(tr("✗ Не тот пароль\n"))); continue
                break
            if not self.d["recovery"]: self.d["recovery"] = recovery_line(seed); self.save()
            tmp = tempfile.mkdtemp(prefix="sshstore-", dir=RAM)
            key = os.path.join(tmp, "recovery")
            fd = os.open(key, os.O_WRONLY | os.O_CREAT, 0o600)
            with os.fdopen(fd, "w") as f: f.write(openssh_ed25519_private(seed, RECOVERY_TAG))
            try:
                while True:
                    header(tr("восстановление"))
                    sv = self.d["servers"]
                    ch = menu([server_line(s) for s in sv] + [tr("Другой сервер…"), dim(tr("Назад"))])
                    if ch == str(len(sv) + 2): return
                    if ch == str(len(sv) + 1): header(tr("сервер")); s = edit_server()
                    elif ch.isdigit() and 1 <= int(ch) <= len(sv): s = sv[int(ch) - 1]
                    else: continue
                    a = menu([tr("Подключиться резервным ключом"), tr("Привязать сопряжённый телефон к этому серверу"), tr("Назад")])
                    if a == "1":
                        clear(); subprocess.call(ssh_cmd(s, "-o", "IdentitiesOnly=yes", "-i", key)); pause()
                    elif a == "2":
                        c2 = self.session(tr('привязать к серверу {p0}', p0=s['name']))
                        if c2:
                            try: self.bind_recovery_phone(c2, s, key)
                            except (OSError, ConnectionError, ValueError, KeyError) as e: print(red(f"✗ {e}"))
                            finally: c2.close()
                            pause()
            finally:
                shutil.rmtree(tmp, ignore_errors=True)

        def bind_recovery_phone(self, ch, s, key):
            """Сначала проверить новый телефон, затем снять явно выбранный старый ключ."""
            new_blob = ch.call({"t": "list"})["line"].split()[1]
            opts = ["-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-i", key]
            result = subprocess.run(ssh_cmd(s, *opts) + ["cat ~/.ssh/authorized_keys"], capture_output=True, text=True)
            if result.returncode:
                print(red(tr("✗ Не удалось прочитать ключи резервным ключом — ничего не изменено"))); return False
            old = []
            for line in result.stdout.splitlines():
                fields = line.split()
                if (not line.lstrip().startswith("#") and len(fields) >= 3
                        and (fields[-1] == PHONE_TAG or fields[-1].startswith(PHONE_TAG + ":"))):
                    match = re.search(r"(?:^|\s)ecdsa-sha2-nistp256 ([A-Za-z0-9+/=]+)(?:\s|$)", line)
                    if match and match[1] != new_blob and match[1] not in [b for b, _ in old]:
                        old.append((match[1], fields[-1]))
            print(yellow(tr("Выберите ключ потерянного телефона для отзыва. Ключи других людей не выбирайте.")))
            pick = menu([tr('Отозвать: {p0} ({p1}…)', p0=tag, p1=blob[:16]) for blob, tag in old]
                        + [tr("Только добавить новый телефон (старые ключи останутся)"), tr("Отмена")], default=len(old) + 2)
            if not pick.isdigit() or not 1 <= int(pick) <= len(old) + 1: return False
            drop = [old[int(pick) - 1][0]] if int(pick) <= len(old) else []
            if not self.add_server(ch, s, opts=opts): return False
            rc, _ = self.phone_ssh(ch, s, "true")
            if rc != 0:
                print(red(tr("✗ Новый вход не прошёл проверку — старые ключи НЕ сняты"))); return False
            if drop:
                rc, out = self.phone_ssh(ch, s, "sh -c " + shlex.quote(keys_cmd(drop=drop)))
                ok = rc == 0 and "SSH-STORAGE-OK" in (out or "")
                print(green(tr("✓ Новый телефон проверен, выбранный старый ключ отозван")) if ok else red(tr("✗ Старый ключ НЕ отозван — повторите восстановление")))
                return ok
            print(yellow(tr("⚠ Новый телефон проверен, но старые ключи остались действующими")))
            return True

        # --- перенос из старого хранилища (vault.json) ---
        def migrate(self):
            header(tr("перенос старых подключений"))
            with open(LEGACY_VAULT) as f: v = json.load(f)
            pw = getpass.getpass(blue(tr("Пароль администратора старого хранилища: ")))
            print(dim(tr("Проверяю…")))
            try:
                k = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(v["salt"]), n=2**17, r=8, p=1, maxmem=2**28, dklen=64)
                M = open_sym(k, bytes.fromhex(v["admin"]))
                conns = []
                for b in v["conns"]:
                    b = bytes.fromhex(b); epub, rest = b[:32], b[32:]
                    conns.append(json.loads(open_sym(H(x25519(M, epub), epub, pubkey(M)), rest, epub)))
            except ValueError:
                print(red(tr("✗ Неверный пароль"))); pause(); return
            ch = self.session(tr("перенос старых подключений"))
            if not ch: return
            tmp = tempfile.mkdtemp(prefix="sshstore-", dir=RAM)
            try:
                for cn in conns:
                    s = {k2: cn[k2] for k2 in ("name", "host", "port", "user")}
                    print("\n" + server_line(s))
                    if not server_ok(s): print(red(tr("  пропущен: недопустимый адрес"))); continue
                    key = None
                    if cn.get("private_key"):
                        key = os.path.join(tmp, "old")
                        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                        with os.fdopen(fd, "w") as f: f.write(cn["private_key"])
                    self.add_server(ch, s, identity=key)
                print(yellow(tr('\nКогда всё проверите, старое хранилище можно удалить: {p0}', p0=LEGACY_VAULT)))
            except (OSError, ConnectionError, ValueError, KeyError) as e:
                print(red(f"✗ {e}"))
            finally:
                shutil.rmtree(tmp, ignore_errors=True); ch.close()
            pause()

    def pc_wipe():
        header(tr("стереть данные"))
        print(tr("Удалится ") + bold(PC_STATE) + tr(": сопряжение и список серверов."))
        print(dim(tr("Удалится закрытый ключ сопряжения; SSH-ключ остаётся на телефоне, резервный пароль — на бумаге.")))
        print(yellow(tr("Резервный пароль после этого здесь не будет известен: при новом сопряжении создастся новый.")))
        if not confirm_wipe(): return False
        if os.path.exists(PC_STATE): os.remove(PC_STATE)
        if os.path.exists(LEGACY_VAULT) and yes(yellow(tr("Удалить и старый vault.json?"))): os.remove(LEGACY_VAULT)
        print(green(tr("✓ Стёрто."))); return True

    def pc_main():
        if not shutil.which(SSH): print(red(tr("ssh не найден"))); sys.exit(1)
        cleanup_stale()
        pc = PC()
        while True:
            header(tr("главное меню"))
            phone = green(tr("Телефон: ") + pc.d["phone"]["fp"]) if pc.d["phone"] else yellow(tr("Телефон не сопряжён"))
            rec = green(tr("Резервный ключ есть")) if pc.d["recovery"] else yellow(tr("Резервного ключа нет"))
            print(f"  {phone}   {rec}\n")
            ch = menu([tr("Подключиться к серверу"), tr("Серверы"), tr("Сопряжение"), tr("Действия на сервере"),
                       tr("Специальные возможности"), tr("Language / Язык"), tr("Выход")], default=1 if pc.d["phone"] else 3)
            if ch == "1": pc.connect()
            elif ch == "2": pc.section_servers()
            elif ch == "3": pc.section_pairing()
            elif ch == "4": pc.section_actions()
            elif ch == "5":
                if pc.section_special() == "wiped": return
            elif ch == "6": language_settings(pc.d, pc.save)
            elif ch == "7": clear(); return

    if __name__ == "__main__":
        try: phone_main() if IS_PHONE else pc_main()
        except (KeyboardInterrupt, EOFError): print("\n" + dim(tr("пока!")))
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
