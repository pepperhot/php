# Fiche réflexe PHP2Shell

**CVE-2026-109618 · CVE-2026-109619** — exécution de code à distance sans authentification dans le moteur PHP. CVSS v4 9,2. Exposition maximale : Apache avec mod_php. Données vérifiées le 22/10/2026.

## 1. Mon système → la version qui corrige

Comparer la **version complète du paquet installé**, jamais `php -v` : les distributions corrigent sans changer le numéro PHP.

| Système | Paquet source | Version minimale corrigée | Avis |
|---|---|---|---|
| Debian 13 trixie | php8.4 | `8.4.27-1~deb13u1` | DSA-6574-1 |
| Debian 12 bookworm | php8.2 | `8.2.35-1~deb12u1` | DLA-4848-1 |
| Ubuntu 26.04 LTS / 26.10 | php8.5 | `8.5.4-0ubuntu1.5` / `8.5.9-0ubuntu2.1` | USN-8948-1 |
| Ubuntu 24.04 LTS | php8.3 | `8.3.6-0ubuntu0.24.04.13` | USN-8948-1 |
| Ubuntu 22.04 LTS | php8.1 | `8.1.2-1ubuntu2.28` | USN-8948-1 |
| Ubuntu 20.04 / 18.04 (Ubuntu Pro) | php7.4 / php7.2 | `7.4.3-4ubuntu2.29+esm5` / `7.2.24-0ubuntu0.18.04.17+esm14` | USN-8948-2 |
| Dépôt Sury, compilation, conteneur | phpX.Y | 8.2.35 · 8.3.36 · 8.4.27 · 8.5.12 | php.net |
| Amazon Linux 2023 | php8.2 à 8.5 | ALAS2023-2026-3301 à 3304 | ALAS |
| Toute autre branche ≤ 8.1 | — | **aucun correctif** | migrer ou isoler |

## 2. Corriger

1. Vérifier que le dépôt propose la bonne version **avant** d'installer : `apt-cache policy php8.3-common` (ligne *Candidate*).
2. Mettre à jour uniquement les paquets PHP : `apt-get install --only-upgrade 'php8.3-*' libapache2-mod-php8.3` (adapter la branche).
3. **Redémarrer** (pas `reload`) : `systemctl restart php8.3-fpm` et/ou `systemctl restart apache2`.

## 3. Prouver la correction — les trois preuves sont obligatoires

| Preuve | Commande | Attendu |
|---|---|---|
| P1 — version du paquet ≥ avis | `dpkg --compare-versions "$(dpkg-query -W -f='${Version}' php8.3-common)" ge 8.3.6-0ubuntu0.24.04.13 && echo OK` | `OK` |
| P2 — aucun processus sur l'ancien PHP | `grep -lE '(php\|libphp\|apache2).*\(deleted\)$' /proc/[0-9]*/maps` | aucune ligne |
| P3 — services redémarrés après l'installation | `systemctl show -p ActiveEnterTimestamp php8.3-fpm apache2` | date postérieure à la mise à jour |

Tout-en-un : `sudo annexes/02_verifier_correctif.sh` → code retour `0` = corrigé, `1` = non corrigé, `2` = indéterminé.
La présence des CVE dans `changelog.Debian.gz` est un indice, pas une preuve.

## 4. Si la correction est impossible aujourd'hui, puis après

- **Impossible aujourd'hui** : isoler le serveur des réseaux publics (CERT-FR, CERT-EU) ; à défaut `annexes/mitigation-*`, qui ne couvrent qu'une partie des chemins d'attaque.
- **Après correction** : rechercher une compromission avec `sudo annexes/03_detection_lecture_seule.sh 2026-10-20`. Exécution de code confirmée → préserver les preuves, isoler, changer les secrets, **reconstruire** : une mise à jour ne nettoie pas un serveur compromis.
