#!/usr/bin/env bash
# PHP2Shell — inventaire Debian/Ubuntu. Ne modifie rien. Root recommandé.
# Répond à : quels PHP sont installés, d'où viennent-ils, lequel sert chaque site ?
set -uo pipefail
section() { printf '\n== %s\n' "$*"; }

section "Système"
grep -E '^(PRETTY_NAME|VERSION_CODENAME)=' /etc/os-release

section "Paquets PHP (paquet, version complète, paquet source)"
dpkg-query -W -f='${binary:Package}\t${Version}\t${source:Package}\t${db:Status-Abbrev}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null \
  | awk -F'\t' '$4 ~ /^ii/ {print $1 "\t" $2 "\t" $3}' | sort | column -t

section "Dépôt d'origine des paquets PHP du cœur"
for p in $(dpkg-query -W -f='${binary:Package} ${source:Package}\n' 'php*-common' 2>/dev/null | awk '$2 ~ /^php[0-9]/ {print $1}'); do
  echo "-- $p"; apt-cache policy "$p" | sed -n '2,6p'
done

section "Binaires PHP et CLI par défaut"
ls -1 /usr/bin/php[0-9]* /usr/sbin/php-fpm* 2>/dev/null
update-alternatives --display php 2>/dev/null | head -2

section "Binaires PHP HORS paquets (apt ne les met pas à jour)"
find / -xdev \( -name php -o -name 'php-fpm*' -o -name 'libphp*.so' -o -name frankenphp -o -name lsphp \) -type f 2>/dev/null \
  | while read -r f; do dpkg -S "$f" >/dev/null 2>&1 || echo "$f"; done

section "Services"
systemctl list-units --type=service --all --no-legend --plain 'php*-fpm*' 'apache2*' 'nginx*' 'lsws*' 2>/dev/null

section "Apache : mod_php actif ? MPM ?"
apache2ctl -M 2>/dev/null | grep -Ei 'php|mpm' || echo "apache2 absent ou sans mod_php"

section "Site → handler PHP (Apache)"
grep -RniE 'SetHandler|proxy:unix|ProxyPassMatch|AddHandler' /etc/apache2/sites-enabled/ /etc/apache2/conf-enabled/ 2>/dev/null

section "Site → socket FastCGI (Nginx)"
grep -RnE 'fastcgi_pass' /etc/nginx/sites-enabled/ /etc/nginx/conf.d/ 2>/dev/null

section "Socket → pool → branche PHP-FPM"
grep -RnE '^\s*(\[|listen\s*=|user\s*=)' /etc/php/*/fpm/pool.d/ 2>/dev/null

section "Masters PHP-FPM en cours"
ps -eo pid,user,lstart,cmd | grep -E '[p]hp-fpm: master'

section "Port FastCGI exposé ? (doit être vide hors 127.0.0.1)"
ss -ltnp 2>/dev/null | awk 'NR>1 && $4 ~ /:900[0-9]$/'
