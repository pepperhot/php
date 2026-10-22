#!/usr/bin/env bash
# PHP2Shell — recherche d'indicateurs de compromission. Ne modifie rien. Root recommandé.
# Usage : sudo ./03_detection_lecture_seule.sh [DATE_DEBUT]   (défaut : 2026-10-20)
# Un indicateur seul ne prouve pas une exploitation ; l'absence d'indicateur ne prouve rien non plus.
set -uo pipefail
SINCE="${1:-2026-10-20}"
WEBROOT="${WEBROOT:-/var/www}"
WEBUSER="${WEBUSER:-www-data}"
section() { printf '\n== %s\n' "$*"; }
ACCESS=(/var/log/apache2/*access*.log* /var/log/nginx/*access*.log*)
ERRORS=(/var/log/apache2/*error*.log* /var/log/nginx/*error*.log* /var/log/php*-fpm.log*)

section "1. POST terminés en HTTP 500, par IP (format combined)"
zcat -f "${ACCESS[@]}" 2>/dev/null | awk '$6=="\"POST" && $9==500 {print $1}' | sort | uniq -c | sort -rn | head -20

section "2. Épuisement mémoire PHP (déclencheur CVE-2026-109618)"
zgrep -hE 'Allowed memory size of [0-9]+ bytes exhausted|Out of memory \(allocated' "${ERRORS[@]}" 2>/dev/null | tail -30

section "3. Workers tués par signal (SIGABRT/SIGBUS/SIGSEGV)"
zgrep -hE 'exited on signal (6|7|11)' /var/log/php*-fpm.log* 2>/dev/null | tail -30
zgrep -h 'AH00052' /var/log/apache2/error.log* 2>/dev/null | tail -30
journalctl -k --since "$SINCE" --no-pager 2>/dev/null | grep -E 'segfault|general protection' | tail -30
coredumpctl list --no-pager 2>/dev/null | grep -Ei 'php|apache'

section "4. Redémarrages des services"
journalctl -u 'php*-fpm*' -u apache2 -u nginx --since "$SINCE" -o short-iso --no-pager 2>/dev/null | grep -Ei 'start|stop|fail|kill' | tail -40

section "5. Diagnostics INI avant initialisation (consommateur CVE-2026-109619)"
zgrep -hE 'PHP (Warning|Deprecated|Notice):.* in Unknown on line 0' "${ERRORS[@]}" 2>/dev/null | sort | uniq -c | sort -rn | head

section "6. Processus du compte web qui ne sont pas des workers"
ps -u "$WEBUSER" -o pid,ppid,lstart,cmd --no-headers 2>/dev/null | grep -vE 'php-fpm|apache2|nginx'

section "7. Connexions établies par les workers"
ss -tnp state established 2>/dev/null | grep -E 'php-fpm|apache2'

section "8. Fichiers PHP créés ou modifiés depuis $SINCE"
find "$WEBROOT" -xdev -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '.htaccess' -o -name '.user.ini' \) \
  -newermt "$SINCE" -printf '%TY-%Tm-%Td %TT %u %m %p\n' 2>/dev/null | sort | tail -100

section "9. PHP dans les répertoires d'upload et temporaires"
find "$WEBROOT" -xdev -ipath '*upload*' -name '*.ph*' -ls 2>/dev/null
find /tmp /var/tmp /dev/shm -xdev -type f -newermt "$SINCE" -ls 2>/dev/null | head -50

section "10. Fichiers de session volumineux"
find /var/lib/php/sessions -type f -size +100k -ls 2>/dev/null

section "11. Injection auto_prepend_file / auto_append_file"
grep -RnE 'auto_(prepend|append)_file' /etc/php "$WEBROOT" --include='*.ini' --include='.htaccess' --include='.user.ini' 2>/dev/null

section "12. Intégrité des fichiers des paquets PHP/Apache"
# shellcheck disable=SC2046
dpkg --verify $(dpkg-query -W -f='${binary:Package} ' 'php*' 'libapache2-mod-php*' apache2 2>/dev/null)

section "13. Persistance"
crontab -l -u "$WEBUSER" 2>/dev/null
ls -la /var/spool/cron/crontabs /etc/cron.d 2>/dev/null
find /etc/systemd /lib/systemd/system /etc/init.d /etc/ld.so.preload -newermt "$SINCE" -ls 2>/dev/null
ls -la "$(getent passwd "$WEBUSER" | cut -d: -f6)/.ssh" 2>/dev/null
getent passwd | awk -F: '$3==0 || $3>=1000'
last -F 2>/dev/null | head -20
