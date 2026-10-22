# php-vuln-audit

Audit des vulnérabilités du moteur PHP sur Debian/Ubuntu, **sans modification de la configuration système**, piloté par des fichiers de données. Version **1.0.1** (22/10/2026). Premier avis embarqué : PHP2Shell (CVE-2026-109618, CVE-2026-109619).

Documents liés : [`FICHE_REFLEXE.md`](FICHE_REFLEXE.md) · [`NOTE_CORRECTIF_PHP2SHELL.md`](NOTE_CORRECTIF_PHP2SHELL.md) · [`PLAN_REMEDIATION.md`](PLAN_REMEDIATION.md) · [`AWS_SECURITY.md`](AWS_SECURITY.md) · [`CHANGELOG.md`](CHANGELOG.md)

## Principes

- **Mode audit uniquement** : le schéma de configuration n'accepte que `"mode": "audit"`. L'outil exécute des commandes de consultation (`dpkg-query`, `dpkg -S`, `<binaire> -v`, `systemctl list-units`, lecture de fichiers et de `/proc`). Il **écrit** uniquement ses rapports (`reports/` ou `--output-dir`) et ses inventaires (`data/inventory/`). Options désactivées par défaut : `docker exec php -r` dans les conteneurs, requêtes `HEAD` vers des URL configurées.
- **Détection ≠ recommandation ≠ application** : `checks/` constate, `core/report.py` recommande, `remediation/` génère un script **à relire**, exécuté manuellement, protégé par `--i-have-reviewed` et une confirmation par étape.
- **Données, pas code** : versions corrigées, correctifs de distribution, mitigations, règles de détection et sources (datées) vivent dans `data/` et `config/`, validés par schéma.
- **Bibliothèque standard Python 3** uniquement (testé avec Python 3.13) ; `jsonschema` utilisé s'il est présent, sinon validateur intégré.

## Installation

```bash
sudo git clone <dépôt> /opt/php-vuln-audit     # ou copie de l'archive
cd /opt/php-vuln-audit
python3 phpaudit.py validate                    # configuration, avis et règles valides
python3 -m unittest discover -s tests           # 55 tests (22/10/2026, Python 3.13)
```

## Utilisation

```bash
sudo python3 phpaudit.py audit                         # collecte + évaluation + rapports MD/JSON
sudo python3 phpaudit.py audit --skip-logs             # sans analyse des journaux
sudo python3 phpaudit.py audit --checks PKG RUN        # sous-ensemble de contrôles
sudo python3 phpaudit.py collect -o inv.json           # inventaire seul (à transférer)
python3 phpaudit.py audit --inventory inv.json         # analyse hors ligne d'un inventaire
python3 phpaudit.py plan --inventory inv.json          # plan de remédiation (.md + .sh à relire)
python3 phpaudit.py --env preproduction audit          # profil d'environnement
python3 phpaudit.py list-checks
```

`root` est recommandé (lecture de `/proc/*/maps` et des journaux) ; en non-root, le rapport signale les données manquantes.

**Codes retour** : `0` OK · `1` VULNERABLE · `2` ALERT (indicateurs dans les journaux) · `3` INCOMPLETE (statuts indéterminés) · `4` erreur de configuration. Utilisables en CI ou via SSM Run Command.

**Statuts** : `VULNERABLE`, `ALERT`, `UNKNOWN` (à confirmer), `WARN` (mitigation/exposition), `LIKELY_FIXED` (backport prouvé par le changelog mais absent de la table), `FIXED`, `INFO`.

## Annexes et exemple

| Fichier | Rôle | Validation |
|---|---|---|
| `annexes/01_inventaire.sh` | Inventaire PHP, sans modification | shellcheck |
| `annexes/02_verifier_correctif.sh` | Preuves P1 (version complète ≥ avis), P2 (aucun processus sur l'ancien PHP), P3 (services redémarrés) ; code 0/1/2 | shellcheck + test réel Ubuntu 24.04 |
| `annexes/03_detection_lecture_seule.sh` | Recherche d'indicateurs de compromission, sans modification | shellcheck |
| `annexes/mitigation-php.ini`, `mitigation-php-fpm-pool.conf`, `mitigation-apache-modphp.conf` | Mitigations temporaires | `php`, `php-fpm8.3 -t`, `apache2ctl -t` |
| `annexes/aws-waf-*-phase-test.json` | Règles WAF en mode Count (phase de test) | modèle d'API WAFv2 (botocore) |
| `annexes/ssm-audit-flotte.sh` | Audit de la flotte via SSM, code retour préservé | shellcheck + modèle d'API SSM |
| `exemples/rapport_exemple_web-noble.md` / `.json` | Rapport généré à partir d'un inventaire **fictif** de test | — |

## Contrôles

| ID | Module | Vérifie |
|---|---|---|
| PKG | `checks/packages.py` | Paquets source `phpX.Y` : table de correctifs distribution (comparaison de versions Debian), sinon version upstream, sinon preuve de backport dans `changelog.Debian.gz` ; branches EOL |
| BIN | `checks/binaries.py` | Binaires PHP hors dpkg (compilés, `/opt/*`, embarqués) : `apt` ne les corrige pas |
| RUN | `checks/runtime.py` | Processus exécutant un PHP supprimé (mise à jour sans redémarrage), services actifs, mod_php |
| MIT | `checks/mitigations.py` | Valeur effective des directives de mitigation par branche/SAPI/pool FPM (php_admin > php_value > php.ini > défaut), surcharges `.htaccess` |
| EXT | `checks/external.py` | Conteneurs (option) et en-têtes `X-Powered-By` (sondes HTTP optionnelles) |
| LOG | `checks/logs.py` | Règles regex de `config/detection_rules.json` sur les journaux configurés (gz pris en charge, secrets masqués) |

## Architecture

```
config/       settings.json (+ schéma) · detection_rules.json (+ schéma) — seuils, chemins, environnements
data/         advisories/<id>.json (+ schéma) — CVE, versions corrigées, correctifs distro, mitigations, sources datées
              inventory/ — inventaires collectés
checks/       contrôles modulaires (registre dans checks/__init__.py)
remediation/  planner.py + platforms/<plateforme>.json — étapes, commandes, retour arrière
core/         collecte, versions Debian, validation de schéma, moteur, rapports
reports/      rapports générés (Markdown + JSON), plans
tests/        tests unitaires et fixtures (inventaires, journaux)
annexes/      scripts et configurations copiables (voir tableau ci-dessus)
exemples/     exemple de rapport
```

## Configuration

`config/settings.json` (validé par `config/settings.schema.json`, clés inconnues refusées) :

- `collect.php_binary_globs` — où chercher des binaires PHP (ajouter vos chemins d'installation).
- `collect.web_roots` — racines scannées pour les `.htaccess` contenant `php_value`/`php_flag`.
- `collect.containers.enabled` / `exec_version_probe` — inventaire Docker (désactivé par défaut ; la sonde exécute `php -r` dans le conteneur).
- `collect.http_probes` — URL interrogées en `HEAD` pour `X-Powered-By`.
- `detection.log_sources` — journaux par type (`access`, `error`, `fpm`, `system`, `waf`) ; `min_hits_to_flag` — seuils par sévérité ; `max_file_age_days`, `max_lines_per_file`, `max_samples_per_rule`.
- `environments` — profils (production, préproduction, lab) ; `allow_remediation_script` contrôle la génération du `.sh`.

## Maintenance

### Ajouter une nouvelle vulnérabilité PHP

1. Copier `data/advisories/php2shell-2026-10.json` vers `data/advisories/<id>.json`.
2. Renseigner : CVE, `upstream.branches.<X.Y>.fixed`, `min_supported_branch`, `distro_fixes` (une entrée par distribution/release/paquet source, **avec URL et date de vérification**), `mitigations`, `sources`.
3. Ajouter le chemin dans `settings.json > advisories`.
4. `python3 phpaudit.py validate` puis `python3 -m unittest discover -s tests`.
5. Ajouter des fixtures si la logique de versions diffère ; consigner dans `CHANGELOG.md`.

### Mettre à jour un avis existant

- Nouvelle release distribution corrigée → ajouter une entrée `distro_fixes` (ex. Debian sid, ELTS) et mettre à jour `verified_on`.
- Écart signalé « À confirmer » (ex. tracker Debian bookworm/619) → vérifier la source, mettre à jour la `note`.
- Ne jamais saisir une version corrigée sans source primaire.

### Ajouter une règle de détection
Ajouter un objet dans `config/detection_rules.json` (`id` `DR-NNN`, `applies_to`, `pattern`, `severity`, `rationale`, `false_positives`) ; le chargement refuse regex invalides et doublons. Ajouter un cas positif dans `tests/test_detection.py` (le test échoue si une règle n'en a pas).

### Ajouter une plateforme de remédiation
Créer `remediation/platforms/<nom>.json` (`applies_to_os`, `steps`, `rollback`). Les commandes acceptent les variables `{binary_packages}`, `{backup_dirs}`, `{timestamp}` ; `commands_per_service` reçoit `{service}`.

### Cadence recommandée

- Hebdomadaire et après chaque avis PHP : `audit` sur la flotte (cron/SSM), archivage des JSON.
- Revue mensuelle des `verified_on` > 30 jours dans `data/advisories`.

## Limites connues

- Debian/Ubuntu (dpkg) uniquement pour PKG et le plan ; RPM/Alpine/Windows non couverts.
- Les pools FPM inclus hors `/etc/php/*/fpm/pool.d/` et les directives `php_admin_*` dans les vhosts Apache ne sont pas résolus individuellement (compte global des surcharges uniquement).
- La version servie par un vhost donné est déduite par l'administrateur (`PLAN_REMEDIATION.md` étape 2), pas par l'outil.
- La détection par journaux dépend des formats ; les formats par défaut ne contiennent ni `Content-Type` ni corps. Absence d'alerte ≠ absence de compromission.
- Le contrôle EXT de conteneurs nécessite l'accès au socket Docker.
- L'outil ne prouve pas l'absence de compromission et ne nettoie rien.
