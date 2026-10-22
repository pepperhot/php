#!/usr/bin/env bash
# PHP2Shell (CVE-2026-109618 / CVE-2026-109619) — preuve de correction sur Debian/Ubuntu.
# Ne modifie rien. À lancer en root pour lire /proc de tous les processus.
#
# Trois preuves, toutes obligatoires :
#   P1  version COMPLÈTE du paquet installé >= version de l'avis de la distribution
#   P2  aucun processus n'exécute encore un binaire/bibliothèque PHP supprimé
#   P3  services PHP/Apache démarrés après la dernière installation des paquets PHP
# Indice complémentaire (non suffisant) : CVE citées dans changelog.Debian.gz.
#
# Usage : sudo ./02_verifier_correctif.sh [--ref PAQUET_SOURCE=VERSION ...]
#   --ref php8.3=8.3.6-0ubuntu0.24.04.13   impose une référence (release absente de la table)
# Codes retour : 0 corrigé · 1 non corrigé · 2 indéterminé (référence absente, droits insuffisants)
# Références vérifiées le 2026-10-22 : DSA-6574-1, DLA-4848-1, USN-8948-1, USN-8948-2, php.net.
set -uo pipefail

declare -A REF=(
  [debian:13:php8.4]="8.4.27-1~deb13u1"
  [debian:12:php8.2]="8.2.35-1~deb12u1"
  [ubuntu:26.10:php8.5]="8.5.9-0ubuntu2.1"
  [ubuntu:26.04:php8.5]="8.5.4-0ubuntu1.5"
  [ubuntu:24.04:php8.3]="8.3.6-0ubuntu0.24.04.13"
  [ubuntu:22.04:php8.1]="8.1.2-1ubuntu2.28"
  [ubuntu:20.04:php7.4]="7.4.3-4ubuntu2.29+esm5"
  [ubuntu:18.04:php7.2]="7.2.24-0ubuntu0.18.04.17+esm14"
  [ubuntu:16.04:php7.0]="7.0.33-0ubuntu0.16.04.16+esm22"
  [ubuntu:14.04:php5]="5.5.9+dfsg-1ubuntu4.29+esm18"
)
declare -A UPSTREAM=([8.2]="8.2.35" [8.3]="8.3.36" [8.4]="8.4.27" [8.5]="8.5.12")
declare -A OVERRIDE=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ref) OVERRIDE["${2%%=*}"]="${2#*=}"; shift 2 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "Option inconnue : $1" >&2; exit 2 ;;
  esac
done

# shellcheck disable=SC1091
. /etc/os-release
OS_ID="${ID:-inconnu}"; OS_VER="${VERSION_ID:-}"
ko=0; indet=0
ok()    { printf '  OK      %s\n' "$*"; }
nok()   { printf '  KO      %s\n' "$*"; ko=1; }
undet() { printf '  ?       %s\n' "$*"; indet=1; }

echo "== Système : ${PRETTY_NAME:-$OS_ID $OS_VER}"
[[ $EUID -eq 0 ]] || undet "exécution non-root : P2 et P3 peuvent être incomplets"

echo "== P1 — version complète des paquets PHP installés"
mapfile -t PKGS < <(dpkg-query -W -f='${binary:Package} ${source:Package} ${Version} ${db:Status-Abbrev}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null \
  | awk '$2 ~ /^php[0-9]/ && $4 ~ /^ii/ {print $1, $2, $3}')
if [[ ${#PKGS[@]} -eq 0 ]]; then
  undet "aucun paquet PHP dpkg : PHP compilé, embarqué ou en conteneur — vérifier 'php -v' du binaire réellement servi"
fi
LATEST_INSTALL=0
for line in "${PKGS[@]}"; do
  read -r pkg src ver <<<"$line"
  want="${OVERRIDE[$src]:-${REF[$OS_ID:$OS_VER:$src]:-}}"
  basis="avis distribution"
  if [[ -z "$want" && "$ver" == *deb.sury.org* ]]; then
    branch="${src#php}"; want="${UPSTREAM[$branch]:-}"; basis="version upstream (dépôt Sury)"
  fi
  if [[ -z "$want" ]]; then
    undet "$pkg $ver : aucune référence pour $OS_ID $OS_VER / $src (branche EOL ou release absente) — utiliser --ref"
    continue
  fi
  if dpkg --compare-versions "$ver" ge "$want"; then ok "$pkg $ver >= $want ($basis)"; else nok "$pkg $ver < $want ($basis)"; fi
  f="/var/lib/dpkg/info/${pkg}.list"; [[ -f "$f" ]] || f="/var/lib/dpkg/info/${pkg}:$(dpkg --print-architecture).list"
  if [[ -f "$f" ]]; then t=$(stat -c %Y "$f"); (( t > LATEST_INSTALL )) && LATEST_INSTALL=$t; fi
done

echo "== P2 — processus exécutant un PHP supprimé (mise à jour sans redémarrage)"
mapfile -t STALE < <(grep -lE '(php|libphp|apache2|httpd|lsphp|frankenphp).*\(deleted\)$' /proc/[0-9]*/maps 2>/dev/null)
if [[ ${#STALE[@]} -eq 0 ]]; then
  ok "aucun processus avec code PHP supprimé en mémoire"
else
  for m in "${STALE[@]}"; do p="${m#/proc/}"; p="${p%/maps}"; nok "PID $p ($(cat "/proc/$p/comm" 2>/dev/null)) exécute l'ancien code"; done
fi

echo "== P3 — services démarrés après la dernière installation PHP"
mapfile -t UNITS < <(systemctl list-units --type=service --state=active --no-legend --plain 'php*-fpm*' 'apache2*' 'lsws*' 2>/dev/null | awk '{print $1}')
if [[ ${#UNITS[@]} -eq 0 ]]; then
  ok "aucun service PHP/Apache actif"
elif [[ $LATEST_INSTALL -eq 0 ]]; then
  undet "date d'installation des paquets inconnue"
else
  for u in "${UNITS[@]}"; do
    ts=$(systemctl show -p ActiveEnterTimestamp --value "$u")
    started=$(date -d "$ts" +%s 2>/dev/null || echo 0)
    if (( started >= LATEST_INSTALL )); then ok "$u démarré $ts"; else nok "$u démarré $ts, AVANT l'installation du $(date -d "@$LATEST_INSTALL" '+%F %T') → systemctl restart $u"; fi
  done
fi

echo "== Indice complémentaire — CVE citées dans le changelog (ne prouve rien seul)"
for src in $(printf '%s\n' "${PKGS[@]}" | awk '{print $2}' | sort -u); do
  pkg=$(printf '%s\n' "${PKGS[@]}" | awk -v s="$src" '$2==s {print $1; exit}')
  cl="/usr/share/doc/$pkg/changelog.Debian.gz"
  if [[ -r "$cl" ]]; then
    n=$(zgrep -cE 'CVE-2026-10961[89]' "$cl" || true)
    printf '  info    %s : %s mention(s) de CVE-2026-109618/109619\n' "$src" "$n"
  fi
done

echo
if (( ko )); then echo "RÉSULTAT : NON CORRIGÉ"; exit 1; fi
if (( indet )); then echo "RÉSULTAT : INDÉTERMINÉ (voir lignes '?')"; exit 2; fi
echo "RÉSULTAT : CORRIGÉ (P1, P2, P3 validées)"; exit 0
