# Rapport d'audit PHP — web-noble

- Généré : 2026-10-22T08:27:04+00:00 (outil 1.0.1, mode `audit`, environnement `production`)
- Système : Ubuntu 24.04.5 LTS
- Inventaire collecté : 2026-10-22T08:00:00+00:00
- Avis : PHP2SHELL-2026-10 (vérifié le 2026-10-22)

## Verdict : **VULNERABLE**

| Statut | Nombre |
|---|---|
| ℹ️ INFO | 6 |
| 🔴 VULNERABLE | 2 |
| 🟡 WARN | 2 |

## Constats prioritaires

| Statut | Sévérité | ID | Composant | Constat | Action |
|---|---|---|---|---|---|
| 🔴 VULNERABLE | critical | `PKG-php8.3` | php8.3 | php8.3 vulnérable | Installer 8.3.6-0ubuntu0.24.04.13 ou supérieur depuis le dépôt sécurité ubuntu, puis redémarrer les services PHP. |
| 🔴 VULNERABLE | critical | `RUN-STALE` | processus | 1 processus exécutent encore une bibliothèque/binaire PHP supprimé | Redémarrage complet (stop/start) des services PHP-FPM / Apache concernés ; 'reload' et 'graceful' ne suffisent pas pour mod_php. |
| 🟡 WARN | medium | `MIT-8.3-fpm:www-MIT-POST-MAX-SIZE` | fpm:www | PHP 8.3 fpm:www : post_max_size = 64M | Mitigation temporaire uniquement, ne remplace pas la mise à jour. Tester en préproduction. |
| 🟡 WARN | low | `MIT-8.3-fpm:www-MIT-MEMORY-LIMIT` | fpm:www | PHP 8.3 fpm:www : memory_limit = -1 | Valeur posée par php_value (modifiable par l'application) : utiliser php_admin_value/php_admin_flag. |

## Détail des constats

### 🔴 `PKG-php8.3` — php8.3 vulnérable
- Statut / sévérité : **VULNERABLE** / critical — contrôle `PKG`
- CVE : CVE-2026-109618, CVE-2026-109619
- Détail : 8.3.6-0ubuntu0.24.04.12 < 8.3.6-0ubuntu0.24.04.13 (USN-8948-1).
- Action : Installer 8.3.6-0ubuntu0.24.04.13 ou supérieur depuis le dépôt sécurité ubuntu, puis redémarrer les services PHP.
- Preuves :
```json
{
  "source_package": "php8.3",
  "version": "8.3.6-0ubuntu0.24.04.12",
  "origin": "ubuntu",
  "binaries": [
    "php8.3-cli",
    "php8.3-common",
    "php8.3-fpm"
  ],
  "changelog_cves": [],
  "os": "ubuntu 24.04 noble",
  "fixed_version": "8.3.6-0ubuntu0.24.04.13",
  "distro_advisory": "USN-8948-1",
  "basis": "table distribution"
}
```
- Réf. : https://lists.ubuntu.com/archives/ubuntu-security-announce/2026-October/011433.html

### 🔴 `RUN-STALE` — 1 processus exécutent encore une bibliothèque/binaire PHP supprimé
- Statut / sévérité : **VULNERABLE** / critical — contrôle `RUN`
- CVE : CVE-2026-109618, CVE-2026-109619
- Détail : Le paquet a été mis à jour mais l'ancien code reste chargé en mémoire.
- Action : Redémarrage complet (stop/start) des services PHP-FPM / Apache concernés ; 'reload' et 'graceful' ne suffisent pas pour mod_php.
- Preuves :
```json
{
  "matches": [
    {
      "pid": 4242,
      "comm": "php-fpm8.3",
      "paths": [
        "/usr/sbin/php-fpm8.3 (deleted)"
      ]
    }
  ]
}
```

### 🟡 `MIT-8.3-fpm:www-MIT-POST-MAX-SIZE` — PHP 8.3 fpm:www : post_max_size = 64M
- Statut / sévérité : **WARN** / medium — contrôle `MIT`
- CVE : CVE-2026-109618
- Détail : Mitigation absente sur une branche non confirmée corrigée. 8M sans upload, 32M avec upload ; upload_max_filesize < post_max_size. Insuffisant seul : les requêtes sans Content-Length exploitable contournent la vérification initiale.
- Action : Mitigation temporaire uniquement, ne remplace pas la mise à jour. Tester en préproduction.
- Preuves :
```json
{
  "branch": "8.3",
  "context": "fpm:www",
  "directive": "post_max_size",
  "value": "64M",
  "set_by": "php.ini",
  "package_status": "VULNERABLE"
}
```
- Réf. : https://www.php.net/archive/2026.php#2026-10-21-5
- Réf. : https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-014/

### 🟡 `MIT-8.3-fpm:www-MIT-MEMORY-LIMIT` — PHP 8.3 fpm:www : memory_limit = -1
- Statut / sévérité : **WARN** / low — contrôle `MIT`
- CVE : CVE-2026-109618
- Détail : Supprime le déclenchement OOM interne. Effet de bord : risque d'épuisement mémoire de l'hôte ; à combiner avec une limite cgroup qui tue uniquement le worker. Ne pas utiliser RLIMIT_AS / RLIMIT_DATA.
- Action : Valeur posée par php_value (modifiable par l'application) : utiliser php_admin_value/php_admin_flag.
- Preuves :
```json
{
  "branch": "8.3",
  "context": "fpm:www",
  "directive": "memory_limit",
  "value": "-1",
  "set_by": "php_value (surchargeable)",
  "package_status": "VULNERABLE"
}
```

### ℹ️ `BIN-/usr/bin/php8.3` — /usr/bin/php8.3 : PHP 8.3.6 (cli)
- Statut / sévérité : **INFO** / info — contrôle `BIN`
- Détail : Binaire fourni par le paquet php8.3-cli : statut évalué par le contrôle PKG (les backports conservent le numéro upstream).
- Preuves :
```json
{
  "path": "/usr/bin/php8.3",
  "realpath": "/usr/bin/php8.3",
  "version": "8.3.6",
  "sapi": "cli",
  "owner_package": "php8.3-cli",
  "exposure": "cli"
}
```

### ℹ️ `BIN-/usr/sbin/php-fpm8.3` — /usr/sbin/php-fpm8.3 : PHP 8.3.6 (fpm-fcgi)
- Statut / sévérité : **INFO** / info — contrôle `BIN`
- Détail : Binaire fourni par le paquet php8.3-fpm : statut évalué par le contrôle PKG (les backports conservent le numéro upstream).
- Preuves :
```json
{
  "path": "/usr/sbin/php-fpm8.3",
  "realpath": "/usr/sbin/php-fpm8.3",
  "version": "8.3.6",
  "sapi": "fpm-fcgi",
  "owner_package": "php8.3-fpm",
  "exposure": "web"
}
```

### ℹ️ `LOG-OFF` — Détection désactivée
- Statut / sévérité : **INFO** / info — contrôle `LOG`

### ℹ️ `MIT-8.3-fpm:www-MAXREQ` — PHP 8.3 fpm:www : pm.max_requests = 500
- Statut / sévérité : **INFO** / info — contrôle `MIT`
- Détail : pm.max_requests=1 supprime la réutilisation de worker (CVE-2026-109619) au prix des performances.
- Preuves :
```json
{
  "user": "www-data",
  "listen": "/run/php/php8.3-fpm.sock"
}
```

### ℹ️ `MIT-8.3-fpm:www-MIT-UPLOAD-PROGRESS` — PHP 8.3 fpm:www : session.upload_progress.enabled = 0
- Statut / sévérité : **INFO** / info — contrôle `MIT`
- CVE : CVE-2026-109619
- Détail : Bloque les chemins de session confirmés uniquement. Doit être posé dans php.ini, le pool FPM (php_admin_flag) ou la configuration serveur ; ini_set() et .user.ini sont inefficaces. Redémarrer tous les workers.
- Preuves :
```json
{
  "branch": "8.3",
  "context": "fpm:www",
  "directive": "session.upload_progress.enabled",
  "value": "0",
  "set_by": "php_admin",
  "package_status": "VULNERABLE"
}
```

### ℹ️ `RUN-SERVICES` — Services web/PHP actifs
- Statut / sévérité : **INFO** / info — contrôle `RUN`
- Preuves :
```json
{
  "services": [
    {
      "unit": "php8.3-fpm.service",
      "load": "loaded",
      "active": "active",
      "sub": "running"
    },
    {
      "unit": "nginx.service",
      "load": "loaded",
      "active": "active",
      "sub": "running"
    }
  ]
}
```

## Données manquantes / erreurs de collecte

- Aucune

## Sources

- [PHP Group — Security advisory: Critical remote code execution vulnerabilities, update now](https://www.php.net/archive/2026.php#2026-10-21-5) — vérifié le 2026-10-22
- [PHP Group (GitHub) — GHSA-w8hw-w9fx-j79w - RCE via OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) — vérifié le 2026-10-22
- [PHP Group (GitHub) — GHSA-6wmf-4rv5-p3rp - RCE via stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) — vérifié le 2026-10-22
- [CERT-FR — CERTFR-2026-ALE-014](https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-014/) — vérifié le 2026-10-22
- [CERT-FR — CERTFR-2026-AVI-1359](https://cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1359/) — vérifié le 2026-10-22
- [CERT-EU — Security Advisory 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018/) — vérifié le 2026-10-22
- [NCSC-NL — NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell) — vérifié le 2026-10-22
- [Debian — Security tracker CVE-2026-109618](https://security-tracker.debian.org/tracker/CVE-2026-109618) — vérifié le 2026-10-22
- [Debian — Security tracker CVE-2026-109619](https://security-tracker.debian.org/tracker/CVE-2026-109619) — vérifié le 2026-10-22
- [Canonical — USN-8948-1](https://lists.ubuntu.com/archives/ubuntu-security-announce/2026-October/011433.html) — vérifié le 2026-10-22
- [Canonical — USN-8948-2](https://ubuntu.com/security/notices/USN-8948-2) — vérifié le 2026-10-22
- [AWS — AWS Security Bulletin 2026-143-AWS](https://aws.amazon.com/security/security-bulletins/2026-143-aws/) — vérifié le 2026-10-22
- [AWS — Amazon Linux Security Center CVE-2026-109618](https://explore.alas.aws.amazon.com/CVE-2026-109618.html) — vérifié le 2026-10-22
- [Debian LTS — DLA-4848-1 php8.2 security update (CVE-2026-109618, CVE-2026-109619)](https://security-tracker.debian.org/tracker/DLA-4848-1) — vérifié le 2026-10-22

> Collecte sans modification de la configuration système (seuls les rapports et l'inventaire sont écrits). Une mitigation ne remplace pas le correctif. Une version corrigée ne nettoie pas un serveur déjà compromis.
