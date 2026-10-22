# Plan de remédiation PHP2Shell — Debian / Ubuntu

Version 1.1 — 22/10/2026. Versions de référence : `FICHE_REFLEXE.md` §1 ou note, matrice C.2.

**Règles**

- Préproduction d'abord, puis production serveur par serveur, retiré du load balancer.
- Étapes 0, 1, 2, 6, 7 : aucune modification du système (l'outil d'audit écrit seulement ses rapports).
- Étapes 3, 4, 5 : modifient le système → validation explicite (go/no-go) du responsable.
- `python3 phpaudit.py plan` génère les étapes 3 à 6 sous forme de script : refus de démarrer sans `--i-have-reviewed`, confirmation à chaque étape, arrêt si une preuve échoue.
- Ne jamais lancer d'exploit ou de PoC sur un système réel pour « vérifier ».

| Étape | Action | Modifie le système | Durée indicative |
|---|---|---|---|
| 0 | Audit initial | non (écrit les rapports) | 2 min |
| 1 | Inventaire | non | 5 min |
| 2 | PHP servi par chaque site | non | 10 min |
| 3 | Sauvegarde | **oui** (fichiers de sauvegarde) | 5 min |
| 4 | Mise à jour | **oui** | 5 min |
| 5 | Redémarrage | **oui** (coupure courte) | 2 min |
| 6 | Preuve de correction + tests | non | 15 min |
| 7 | Surveillance, retour arrière | non / oui | J+1, J+3 |

## Étape 0 — Audit initial

```bash
cd /opt/php-vuln-audit
sudo python3 phpaudit.py audit    # n'écrit que dans reports/ et data/inventory/
sudo python3 phpaudit.py plan     # reports/plan_<hôte>_<env>.md et .sh, à relire
```

Verdict et code retour : `OK` 0 · `VULNERABLE` 1 · `ALERT` 2 · `INCOMPLETE` 3. Lire d'abord le tableau « Constats prioritaires ».

## Étape 1 — Inventaire

`sudo annexes/01_inventaire.sh` affiche, sans rien modifier :

- les paquets PHP avec **version complète** et paquet source ;
- le dépôt d'origine (sécurité de la distribution, Sury/PPA ondrej) ;
- les binaires PHP **hors paquets** (compilés, `/opt/bitnami`, FrankenPHP) : `apt` ne les corrige pas ;
- les services, la présence de mod_php et du MPM ;
- un port FastCGI (9000–9009) exposé hors de `127.0.0.1`, à fermer.

## Étape 2 — PHP réellement servi par chaque site

Même script, sections « Site → handler », « Socket → pool », « Masters PHP-FPM ». Construire le tableau vhost → handler → socket → pool → branche. `php -v` ne renseigne que le CLI ; `X-Powered-By` n'est pas fiable.

## Étape 3 — Sauvegarde *(go/no-go)*

```bash
BK=/root/php-remediation-$(date -u +%Y%m%dT%H%M%SZ); mkdir -p "$BK"
tar czf "$BK/etc.tgz" /etc/php /etc/apache2 /etc/nginx 2>/dev/null
dpkg-query -W -f='${binary:Package}\t${Version}\n' 'php*' 'libapache2-mod-php*' > "$BK/packages-before.tsv"
cp -a /var/cache/apt/archives/php*.deb "$BK/" 2>/dev/null || true
```

- Snapshot de la machine si possible : c'est le retour arrière le plus sûr.
- Rester dans la même branche (ex. `…24.04.12` → `…24.04.13`, `8.4.26` → `8.4.27`) : risque applicatif faible. Pas de changement de branche (8.1 → 8.4) dans l'urgence.

## Étape 4 — Mise à jour depuis une source confirmée *(go/no-go)*

**4.1 Vérifier la version proposée par le dépôt avant d'installer** (exemple Ubuntu 24.04 — adapter paquet et version) :

```bash
sudo apt-get update
dpkg --compare-versions "$(apt-cache policy php8.3-common | awk '/Candidate:/{print $2}')" ge 8.3.6-0ubuntu0.24.04.13 \
  && echo "CANDIDATE CORRIGÉE" || echo "STOP : correctif non disponible dans ce dépôt"
```

Si **STOP** : ne rien installer d'autre (dépôt inconnu, `.deb` téléchargé à la main). Isoler le serveur ou appliquer les mitigations (`annexes/mitigation-*`), puis suivre l'avis de la distribution.

**4.2 Mettre à jour uniquement les paquets PHP du cœur déjà installés** :

```bash
sudo apt-get install --only-upgrade 'php8.3-*' libapache2-mod-php8.3
```

Pas d'`apt upgrade` global pendant la fenêtre : il élargit le changement sans améliorer la correction.

## Étape 5 — Redémarrage *(go/no-go)*

```bash
sudo php-fpm8.3 -t && sudo systemctl restart php8.3-fpm
sudo apache2ctl configtest && sudo systemctl restart apache2
```

- mod_php : `restart` obligatoire ; `reload` et `apachectl graceful` ne rechargent pas `libphp` de façon fiable.
- Redémarrer aussi les workers PHP longue durée (supervisord, files de messages, `php artisan queue:restart`) et, pour LiteSpeed, les processus `lsphp`.

## Étape 6 — Preuve de correction

```bash
sudo annexes/02_verifier_correctif.sh ; echo "code=$?"     # 0 corrigé · 1 non corrigé · 2 indéterminé
sudo python3 phpaudit.py audit
```

| Preuve | Critère d'acceptation |
|---|---|
| P1 | Chaque paquet PHP installé a une **version complète** ≥ celle de l'avis distribution |
| P2 | Aucun processus n'a de binaire ou de bibliothèque PHP marqué `(deleted)` |
| P3 | PHP-FPM / Apache démarrés **après** l'installation des paquets |
| Indice | Les CVE figurent dans `changelog.Debian.gz` (complément seulement) |

Ensuite, tests fonctionnels : pages clés en 200, connexion et session, formulaire POST, upload nominal et proche de la limite, tâches cron, taux de 5xx comparé à la veille.

## Étape 7 — Surveillance et retour arrière

- J+1 et J+3 : relancer l'audit et `annexes/03_detection_lecture_seule.sh` ; vérifier l'absence de nouveaux `.php` dans les webroots.
- Retirer les mitigations devenues inutiles (`memory_limit=-1`, blocage multipart au WAF) ; garder `session.upload_progress.enabled=0` si la fonction n'est pas utilisée.

**Retour arrière** — il réintroduit la vulnérabilité : uniquement sur un serveur **isolé**.

1. Configuration : `tar xzf "$BK/etc.tgz" -C /` puis redémarrage des services.
2. Paquets : `dpkg -i "$BK"/php*.deb` si les anciens paquets étaient en cache ; sinon `apt-get install paquet=version` si la version est encore publiée.
3. Le plus fiable : restaurer le snapshot de l'étape 3.

## Cas particuliers

| Cas | Conduite à tenir |
|---|---|
| Branche ≤ 8.1 | Ubuntu 22.04 (php8.1) et 20.04/18.04 avec Ubuntu Pro ont un correctif. Ailleurs : correctif fournisseur vérifié ou migration ; isoler en attendant |
| Dépôt Sury, branche ≤ 8.1 | Version de référence non publiée : `02_verifier_correctif.sh` renvoie « indéterminé ». Considérer vulnérable tant que l'avis Sury n'est pas confirmé |
| PHP compilé (`/usr/local`) | Recompiler depuis 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, ou depuis les branches de correctif 7.4/8.0/8.1 publiées par l'équipe PHP ; redémarrer |
| Bitnami (`/opt/bitnami/php`) | Non mis à jour par `apt` : mettre à jour la pile Bitnami ou migrer vers des paquets (procédure AWS Lightsail) |
| Conteneurs | `FROM php:8.x.y-fpm` corrigé ou digest épinglé, `docker compose build --pull --no-cache`, `docker compose up -d --force-recreate`, puis `php -v` dans le conteneur |
| Panneaux (cPanel, Plesk) | PHP fourni hors distribution : suivre l'avis de l'éditeur du panneau — **À confirmer** par éditeur |
