# Note de correctif de sécurité — PHP2Shell (CVE-2026-109618, CVE-2026-109619)

| Champ | Valeur |
|---|---|
| Référence | PHP2SHELL-2026-10 |
| Version de la note | 1.1 — 22/10/2026 (corrections de relecture : WAF, Debian 12, preuve de correction, SSM) |
| Informations vérifiées le | 22/10/2026 (sources datées en fin de document) |
| Logiciel | Moteur PHP (php-src), tous SAPI servant des requêtes web |
| Gravité éditeur | Critique — CVSS v4.0 9,2 pour chaque CVE [S2][S3] |
| Correctifs upstream | 8.5.12, 8.4.27, 8.3.36, 8.2.35 (21/10/2026) [S1] |
| Statut d'exploitation | Exploitation observée par watchTowr sur ses honeypots dès le 21/10 [S14] ; non confirmée par CERT-EU, absente du catalogue CISA KEV à la date de vérification [S6][S15] |

Légende : **[Fait]** = confirmé par une source primaire citée ; **[Hypothèse]** = affirmation non confirmée par une source primaire ; **[Reco]** = recommandation de l'auteur de la note ; **À confirmer** = information non vérifiable à la date de rédaction.

---

## A. Synthèse exécutive

**Ce qu'est PHP2Shell.** Nom d'usage (non officiel) de deux vulnérabilités mémoire du moteur PHP lui-même, publiées le 21/10/2026 [S1] :

- **CVE-2026-109618** — corruption mémoire lors de la gestion d'un *out-of-memory* (OOM) : PHP interrompt la requête par `longjmp()` alors que des données de requête sont partiellement initialisées ; le nettoyage de fin de requête les traite ensuite comme valides [S2]. **[Fait]**
- **CVE-2026-109619** — état global périmé : un état appartenant à une requête survit à la libération de sa mémoire ; une requête ultérieure traitée **par le même worker** peut l'utiliser avant réinitialisation (use-after-free) [S3]. **[Fait]**

Les deux peuvent permettre une **exécution de code à distance sans authentification**, avec les privilèges du compte du worker web (`www-data` sous Debian/Ubuntu) [S1][S2][S3]. **[Fait]**

**Conséquences métier.** Prise de contrôle du serveur web au niveau du compte applicatif : lecture des fichiers de configuration (identifiants de base de données, clés API), accès aux données traitées par l'application, dépôt de portes dérobées, rebond vers le réseau interne et, sur AWS, utilisation des identifiants du rôle d'instance. Le défaut est dans l'interpréteur : **mettre à jour WordPress, Drupal, Joomla ou tout autre CMS ne corrige rien** [S16].

**Conditions d'exploitation connues [Fait, S2][S3].**

- Aucune authentification, aucune interaction utilisateur. Complexité d'attaque élevée (AC:H) et prérequis d'attaque présents (AT:P) dans le vecteur CVSS.
- **Apache mod_php** : exposition la plus forte ; RCE validée par HTTP avec limites mémoire et d'entrée par défaut, déclenchement **avant tout code applicatif** [S1][S2].
- **PHP-FPM** : CVE-2026-109619 validée via le chemin *session upload progress* ; CVE-2026-109618 « susceptible » d'après l'analyse du code, exploit complet non démontré [S2][S3].
- FrankenPHP, LiteSpeed, php-cgi : concernés selon l'éditeur ; niveau de démonstration variable [S1].
- La fiabilité dépend du build, des extensions, du frontal et de l'agencement de l'allocateur [S2]. Selon VulnCheck (cité par Tanium, source secondaire), aucune exploitation publique ne contourne l'ASLR sur x86-64 à ce jour [S17] — **À confirmer** ; un dépôt public prétend le contraire en laboratoire (voir §B.8).

**Versions concernées [Fait, S1][S4][S5].** PHP 8.2 < 8.2.35, 8.3 < 8.3.36, 8.4 < 8.4.27, 8.5 < 8.5.12, ainsi que **toutes** les versions 5.x, 7.x, 8.0.x et 8.1.x (non maintenues, sans correctif upstream).

**Priorité : P1 — traitement immédiat** pour tout serveur exposé à Internet exécutant PHP en mod_php ou FPM.

**Mesures immédiates [Reco].**

1. Inventorier les versions réellement exécutées (paquets **et** binaires hors paquets) — `python3 phpaudit.py audit`.
2. Installer le paquet corrigé de la distribution (ou la version upstream corrigée) puis **redémarrer complètement** PHP-FPM / Apache.
3. Si la correction est impossible sous quelques heures : isoler le serveur des réseaux publics (recommandation CERT-EU et CERT-FR [S4][S6]) ; à défaut, appliquer les mitigations du §E en sachant qu'elles **ne rendent pas l'installation sûre** [S1].
4. Rechercher des signes de compromission (§F), en particulier sur les serveurs restés exposés depuis le 20/10/2026.

---

## B. Analyse technique

### B.1 Fonctionnement normal d'une requête PHP

1. **Démarrage de requête** : le SAPI (mod_php, FPM…) reçoit la requête, applique la configuration (php.ini, pool FPM, directives Apache, `.htaccess` sous mod_php), puis PHP analyse le corps (`application/x-www-form-urlencoded`, `multipart/form-data` selon RFC 1867) pour remplir `$_POST` et `$_FILES`. Cette phase s'exécute **avant** le script.
2. **Exécution** du script ; toutes les allocations « par requête » passent par le gestionnaire mémoire de Zend, borné par `memory_limit`.
3. **Fin de requête** : destruction des objets, fermeture de session, libération en bloc de la mémoire de requête.
4. **Réutilisation du worker** : un worker FPM ou un enfant Apache prefork traite des centaines de requêtes successives. Certains états globaux persistent volontairement entre requêtes ; ils doivent être réinitialisés **avant** que la mémoire qu'ils référencent soit libérée.

### B.2 CVE-2026-109618 — corruption lors d'un OOM [Fait, S2]

- PHP gère l'épuisement mémoire par `longjmp()` pour abandonner la requête. Si l'allocation échoue alors que des structures de requête sont partiellement initialisées, la sortie anticipée n'est pas prise en compte : le nettoyage de fin de requête lit ou exploite un état invalide. L'allocation qui échoue n'a pas besoin d'être liée à la mémoire invalide.
- Stratégies OOM décrites par l'éditeur dans le parsing multipart : requêtes **sans `Content-Length` exploitable** (contournant la vérification initiale de `post_max_size`), parties multipart avec un nombre illimité d'en-têtes (forte amplification mémoire interne), contrôles de fichier vides et noms de champs imbriqués gonflant les tableaux ; d'autres chemins applicatifs peuvent déclencher l'OOM.
- **Sessions : non mentionnées** dans l'avis de cette CVE.
- Correctif : remplacement du chemin OOM par `longjmp()` par un OOM « doux » différé au prochain point sûr de la VM, plus un OOM « dur » immédiat au-delà d'un seuil supérieur.

### B.3 CVE-2026-109619 — état global périmé [Fait, S3]

- Un **producteur** (requête qui publie un état appartenant à la requête dans une globale) et un **consommateur** (requête ultérieure sur le même worker qui lit cet état avant réinitialisation) sont nécessaires.
- Deux façons de laisser l'état : erreurs fatales (OOM, erreurs de parsing/compilation, `require` en échec, *Maximum execution time exceeded*…) qui interrompent avant la remise à zéro ; diagnostics non fatals émis pendant l'arrêt qui réécrivent un état d'erreur déjà nettoyé.
- Chemins identifiés :
  - **session.upload_progress** — activé par défaut, ne nécessite pas `session_start()`, atteint la gestion de session avant l'initialisation normale ; validé contre mod_php et FPM.
  - **fatal_error_backtraces (PHP 8.5)** — cas le plus solide, base de la RCE sur mod_php.
  - **Diagnostics INI avant initialisation** — avertissements émis lors de l'application de directives par requête (obsolètes ou invalides), indépendamment de `error_reporting`, `@`, `display_errors`, `log_errors`. Sous mod_php, `.htaccess` et `php_value` s'appliquent tôt ; FPM est exposé de façon conditionnelle.
  - Autres états (erreurs, exceptions, objets, extensions) : conditionnels, dépendent de l'application.
- **FPM** : producteur et consommateur doivent atteindre le même worker ; plusieurs workers et le recyclage réduisent la probabilité sans supprimer la condition. FPM tue un enfant dont le démarrage échoue.

### B.4 Différences entre les deux CVE

| Critère | CVE-2026-109618 | CVE-2026-109619 |
|---|---|---|
| Nature | Corruption pendant le nettoyage après OOM | Use-after-free d'état global entre deux requêtes |
| Déclencheur | Échec d'allocation (OOM) en cours de requête | Fatal/diagnostic laissant un état, puis consommation par une requête suivante |
| Requêtes nécessaires | Une requête peut suffire (mod_php) | Producteur + consommateur sur le même worker |
| Rôle de `session.upload_progress` | Aucun selon l'avis | Chemin confirmé (mod_php et FPM) |
| Mitigation partielle principale | `memory_limit=-1` + limites de taille/structure en amont | `session.upload_progress.enabled=0` ; `fatal_error_backtraces=0` (8.5) |
| SAPI démontré | mod_php (RCE validée) | mod_php (RCE), FPM (chemin session validé) |

### B.5 Rôle des composants cités

| Composant | Rôle confirmé | Source |
|---|---|---|
| Uploads HTTP (multipart) | Vecteur principal de l'OOM (618) et du chemin session (619) | [S2][S3] |
| Sessions | Chemin *upload progress* de 619 ; absent de 618 | [S3] |
| Erreurs mémoire | Déclencheur de 618 ; producteur possible de 619 | [S2][S3] |
| OPcache | **Non mentionné** dans les avis GHSA. L'affirmation du document initial liant 619 à OPcache n'est pas étayée : **[Hypothèse non confirmée]** | [S2][S3] |
| PHP-FPM | Concerné ; réutilisation de worker = condition de 619 ; `pm.max_requests=1` supprime cette réutilisation | [S3] |
| PHP CLI | Non mentionné comme surface d'attaque (pas de parsing de requête HTTP). Le binaire CLI partage le code du paquet : à mettre à jour, priorité moindre | [S1] |

### B.6 Scénarios d'impact

- **RCE** : exécution de code natif dans le worker. Conséquence importante : `disable_functions`, `open_basedir` et les autres restrictions de niveau PHP **ne protègent pas** contre du code natif injecté. [Reco, déduit de la nature de la faille]
- **Fuite de données** : divulgation mémoire explicitement citée pour 619 [S3] (fragments d'autres requêtes : cookies, en-têtes, données de formulaires) ; ensuite tout ce que le compte du worker peut lire.
- **Compromission applicative** : modification de fichiers PHP inscriptibles, comptes administrateurs, contenus.
- **Rebond** : base de données et services joignables depuis le serveur, métadonnées cloud (IMDS) et identifiants de rôle, élévation de privilèges locale si le noyau ou la configuration le permettent.

### B.7 Prérequis et limites de l'exploitation

- Complexité élevée ; résultats variables selon architecture, build et allocateur [S2]. Red Hat juge la RCE difficile en pratique sur FPM par défaut (rapporté par Tanium, source secondaire) [S17] — **À confirmer** sur la source Red Hat.
- Un worker exploité peut planter : crashs et 500 sont des symptômes possibles, pas une preuve.
- Les mitigations par configuration ne couvrent que des chemins **confirmés** ; d'autres variantes existent [S1][S3].

### B.8 Analyse des dépôts GitHub fournis

| Dépôt | Nature | Points concordants | Écarts / alertes |
|---|---|---|---|
| [NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell) | Référentiel opérationnel d'un CSIRT national (TLP:CLEAR, en cours d'enrichissement) | Descriptions, versions corrigées, SAPI, mitigations alignés sur php.net | Pas d'IOC ni de signature à la date de lecture ; répertoire `detection_mitigation` non consultable (robots) — **À confirmer** |
| [ikow/php2shell-poc](https://github.com/ikow/php2shell-poc) | Laboratoire Docker + analyse (FPM/nginx 8.2.34, build ASAN) | Versions corrigées identiques | Attribue les **deux** CVE à `session.upload_progress` (faux pour 618) ; chaînes nécessitant LFI ou `unserialize()` applicatifs, contrairement à la RCE pré-applicative décrite pour mod_php ; recommande `session.use_only_cookies` (absent des avis) ; résultats auto-déclarés |
| [9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp) | Write-up de recherche, mod_php prefork, PHP 8.4.26 compilé sans patch, Debian 12 | Cohérent avec l'exposition mod_php | Aucun identifiant CVE ; `memory_limit=8M` de laboratoire ; contournement ASLR revendiqué sur un seul build, petits échantillons ; attribué à un modèle d'IA ; non reproductible en l'état |
| [syrex1013/php2shell](https://github.com/syrex1013/php2shell) | **Outil offensif** (dépôt de webshell, empoisonnement de logs) ; 2 commits, 0 étoile | Versions corrigées identiques | Décrit les deux CVE comme un UAF de `session.upload_progress` (contredit 618) ; prérequis LFI/port FastCGI exposé/pearcmd ; **ne jamais l'exécuter hors laboratoire isolé** ; des faux PoC distribuent des malwares [S17] |

Usage défensif retenu : les indicateurs de chaînage (LFI vers `pearcmd`, PHP dans les répertoires d'upload, port FastCGI exposé) alimentent les règles DR-011/DR-012 et le §E réseau. Aucun payload n'est repris.

### B.9 Corrections apportées au document initial

| Affirmation initiale | Statut |
|---|---|
| Correctifs pour 8.2 et supérieures le 21/10/2026 | **Confirmé** [S1] |
| CVSS 4.0 9,2 | **Confirmé** [S2][S3] |
| 618 implique « uploads, sessions » | **Partiellement faux** : uploads oui, sessions non (les sessions relèvent de 619) [S2] |
| 619 implique OPcache | **Non étayé** par les avis [S3] |
| `session.upload_progress.enabled=Off` = mesure recommandée | **Incomplet** : ne couvre que les chemins session de 619, rien pour 618 [S1][S4] |
| « Wiz a démontré sur WordPress, Drupal et Joomla » | **Non confirmé**. Un chercheur Wiz figure parmi les rapporteurs [S2] ; la publication Wiz « wp2shell » concerne d'autres CVE (CVE-2026-63030/60137) [S18] |
| ENISA confirme | **À confirmer** (référence ENISA CNW-2026-04 citée par NCSC-NL, non consultée directement) |
| `sudo apt upgrade` | **Insuffisant comme garantie** : voir §D (vérification de la version candidate et des backports) |
| Surveiller les PHPSESSID volumineux | **Hypothèse** issue d'un dépôt de recherche, absente des avis officiels |

---

## C. Matrice de compatibilité et de risque

### C.1 Branches upstream (état au 22/10/2026)

| Branche | Maintenance [S12] | Vulnérable | Version corrigée | Source | Action |
|---|---|---|---|---|---|
| 8.5 | Active, sécurité jusqu'au 31/12/2029 | < 8.5.12 | **8.5.12** | [S1] | Mettre à jour ; en attente : `fatal_error_backtraces=0` |
| 8.4 | Active, sécurité jusqu'au 31/12/2028 | < 8.4.27 | **8.4.27** | [S1] | Mettre à jour |
| 8.3 | Sécurité seule, jusqu'au 31/12/2027 | < 8.3.36 | **8.3.36** | [S1] | Mettre à jour |
| 8.2 | Sécurité seule, **fin le 31/12/2026** | < 8.2.35 | **8.2.35** | [S1] | Mettre à jour + planifier migration 8.4/8.5 |
| 8.1, 8.0, 7.4 | Fin de vie | Toutes | Aucune upstream ; backports source minimaux publiés par l'équipe PHP | [S1] | Backport fournisseur vérifié ou migration ; isoler en attendant |
| ≤ 7.3, 5.x | Fin de vie | Toutes [S4][S5] | Aucune upstream | [S4] | Migration ; backport commercial uniquement si vérifié |

### C.2 Paquets de distribution (rétroportages : le numéro upstream ne change pas)

| Distribution | Paquet source | Version corrigée | Avis | Source |
|---|---|---|---|---|
| Debian 13 trixie | php8.4 | 8.4.27-1~deb13u1 | DSA-6574-1 | [S7] |
| Debian 12 bookworm | php8.2 | 8.2.35-1~deb12u1 | DLA-4848-1 | [S7b] — corrige **les deux** CVE |
| Debian 11 bullseye | php7.4 | Hors Debian LTS (fin 31/08/2026) ; ELTS Freexian payant | — | Source secondaire [S19] — **À confirmer** |
| Debian forky/sid | php8.4 | Non corrigé au 22/10 (8.4.26-1) | — | [S7] |
| Ubuntu 26.10 | php8.5 | 8.5.9-0ubuntu2.1 | USN-8948-1 | [S8] |
| Ubuntu 26.04 LTS | php8.5 | 8.5.4-0ubuntu1.5 | USN-8948-1 | [S8] |
| Ubuntu 24.04 LTS | php8.3 | 8.3.6-0ubuntu0.24.04.13 | USN-8948-1 | [S8] |
| Ubuntu 22.04 LTS | php8.1 | 8.1.2-1ubuntu2.28 | USN-8948-1 | [S8] |
| Ubuntu 20.04 / 18.04 | php7.4 / php7.2 | 7.4.3-4ubuntu2.29+esm5 / 7.2.24-0ubuntu0.18.04.17+esm14 | USN-8948-2 (Ubuntu Pro) | [S9] |
| Ubuntu 16.04 / 14.04 | php7.0 / php5 | 7.0.33-0ubuntu0.16.04.16+esm22 / 5.5.9+dfsg-1ubuntu4.29+esm18 | USN-8948-2 (Legacy) | [S9] |
| Dépôt Sury (deb.sury.org, PPA ondrej) | php8.2–8.5 | Versions upstream 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 | — | [S20] (secondaire) ; builds Launchpad 8.4.27 visibles [S21] |
| Dépôt Sury | php5.6–8.1 | Backports annoncés, chaînes exactes non publiées | — | **À confirmer** via changelog du paquet |
| Remi (RPM) | — | Pas de mise à jour le 21/10 ; l'équipe PHP recommande paquets distribution ou compilation | — | [S1] |

### C.3 Par mode d'exécution

| Mode | Exposition | Spécificités de correction | Vérification |
|---|---|---|---|
| **PHP CLI** | Non mentionné comme vecteur | Même paquet source ; redémarrer les workers CLI longue durée (queues, supervisord, Laravel `queue:restart`) | `dpkg-query` + contrôle `/proc/*/maps` |
| **PHP-FPM** | 619 validée (session) ; 618 susceptible | Paquet `phpX.Y-fpm` + `systemctl restart phpX.Y-fpm` | Versions, absence de mappings `(deleted)`, pools actifs |
| **Apache mod_php** | **Maximale** (618 et 619 confirmées, avant code applicatif) | Paquet `libapache2-mod-phpX.Y` + **restart** Apache (pas `reload`/`graceful`) [S19] | `apache2ctl -M`, mappings `libphp*.so (deleted)` |
| **Conteneurs** | Celle du SAPI embarqué | Reconstruire depuis une image corrigée (`--pull`), redéployer ; une image corrigée dans le registre ne protège pas un conteneur en cours [S22] | `php -v` dans le conteneur, SBOM, digest |
| **Compilé / embarqué** (`/usr/local`, `/opt/bitnami`, FrankenPHP, appliances) | Celle du SAPI | `apt` ne met rien à jour : recompiler depuis 8.x corrigée, mettre à jour la pile fournisseur ; branches 7.4–8.1 : backports source [S1][S11] | Contrôle `BIN` de l'outil (binaire non possédé par dpkg) |

---

## D. Procédure de remédiation et preuve de correction

Procédure commande par commande, go/no-go et retour arrière : **`PLAN_REMEDIATION.md`**. Résumé :

1. **Inventorier** paquets, binaires hors paquets, services et pools (`annexes/01_inventaire.sh`).
2. **Identifier le PHP qui sert chaque site** (vhost → handler → pool → branche). `php -v` ne renseigne que le CLI.
3. **Sauvegarder** `/etc/php`, `/etc/apache2`, `/etc/nginx`, la liste des paquets ; snapshot si possible.
4. **Vérifier la version candidate** (`apt-cache policy`) **avant** d'installer, puis mettre à jour uniquement les paquets PHP.
5. **Redémarrer** PHP-FPM / Apache (`restart`, pas `reload`).
6. **Prouver la correction** (ci-dessous), puis tests fonctionnels.
7. **Surveiller** ; retour arrière uniquement sur serveur isolé, car il réintroduit la faille.

**Preuve de correction — trois conditions, toutes obligatoires [Reco]**

| Preuve | Pourquoi | Contrôle |
|---|---|---|
| **P1** Version **complète** du paquet installé ≥ version de l'avis (USN/DSA/DLA) | Seule comparaison fiable : Ubuntu 24.04 corrigé affiche toujours `PHP 8.3.6` | `dpkg --compare-versions "$(dpkg-query -W -f='${Version}' php8.3-common)" ge 8.3.6-0ubuntu0.24.04.13 && echo OK` |
| **P2** Aucun processus n'exécute l'ancien PHP | Un paquet à jour ne protège pas tant que les processus chargés avant la mise à jour tournent | `grep -lE '(php\|libphp\|apache2).*\(deleted\)$' /proc/[0-9]*/maps` → aucune ligne |
| **P3** Services démarrés après l'installation | Confirme le redémarrage effectif | `systemctl show -p ActiveEnterTimestamp php8.3-fpm apache2` |

Les CVE citées dans `changelog.Debian.gz` sont un **indice complémentaire**, jamais une preuve suffisante.

Le script `annexes/02_verifier_correctif.sh` contrôle P1, P2 et P3 et renvoie `0` (corrigé), `1` (non corrigé) ou `2` (indéterminé). Testé le 22/10/2026 sur Ubuntu 24.04 avec le vrai paquet `8.3.6-0ubuntu0.24.04.13` : code `0` ; avec un processus resté sur un binaire supprimé : code `1`. Le plan généré par `phpaudit.py plan` applique les mêmes contrôles et s'arrête en erreur si P1 ou P2 échoue.

## E. Mesures compensatoires (temporaires, non équivalentes au correctif)

> L'équipe PHP : « There are no complete mitigations, updating is the only safe choice » [S1]. Fichiers prêts à copier, syntaxe validée sur PHP 8.3 / Apache 2.4 : `annexes/mitigation-php.ini`, `annexes/mitigation-php-fpm-pool.conf`, `annexes/mitigation-apache-modphp.conf`. Toute directive ci-dessous doit être posée là où elle s'applique **avant** le parsing de la requête (php.ini, pool FPM, configuration Apache), puis **tous les workers redémarrés**. `ini_set()` et `.user.ini` sont inopérants [S1][S3].

### E.1 `session.upload_progress.enabled = Off` (CVE-2026-109619)

| | |
|---|---|
| Syntaxe vérifiée | php.ini : `session.upload_progress.enabled = Off` ; pool FPM : `php_admin_flag[session.upload_progress.enabled] = off` [S5] ; Apache/mod_php (conf serveur ou vhost) : `php_admin_flag session.upload_progress.enabled off` |
| Périmètre | Bloque les chemins de session confirmés de 619 uniquement ; **aucun effet sur 618** [S1][S17] |
| Effets de bord | Désactive la progression d'upload côté serveur (`$_SESSION[...]` de progression) ; les barres de progression JavaScript basées sur XHR ne sont pas concernées |
| Tests | `php-fpmX.Y -t` ; valeur effective par pool via `phpaudit.py audit --checks MIT` ; test d'upload fonctionnel |
| Risque résiduel | Autres producteurs/consommateurs d'état (fatals, diagnostics INI) |
| Point d'attention | Sous mod_php, un `.htaccess` (`php_value`/`php_flag`) peut réactiver la directive : n'utiliser que `php_admin_flag`. L'avis recommande de la laisser désactivée **même après correctif** si inutilisée [S3] |

### E.2 `fatal_error_backtraces = 0` (PHP 8.5 uniquement, CVE-2026-109619)

Bloque le seul chemin *fatal backtrace* confirmé (base de la RCE mod_php) [S3]. Effet de bord : traces de pile absentes des erreurs fatales (diagnostic plus difficile). Pool FPM : `php_admin_value[fatal_error_backtraces] = 0`.

### E.3 `memory_limit = -1` + limite cgroup (CVE-2026-109618)

| | |
|---|---|
| Syntaxe | Pool FPM : `php_admin_value[memory_limit] = -1` ; Apache : `php_admin_value memory_limit -1` ; vérifier qu'aucun pool, répertoire ou application ne réapplique une limite finie [S1] |
| Périmètre | Supprime le déclenchement de l'OOM interne PHP (cœur de 618) |
| Effets de bord | **Risque de déni de service** : une requête peut consommer toute la mémoire de l'hôte ; certaines applications ajustent `memory_limit` par `ini_set()` |
| Compensation | Limite mémoire cgroup/conteneur, « de préférence avec une politique qui tue seulement le worker concerné » [S1]. Exemple systemd **[Reco — à valider en préproduction]** : drop-in `MemoryMax=` + `OOMPolicy=continue` sur `phpX.Y-fpm.service` (le master FPM relance l'enfant tué). **Ne pas utiliser `RLIMIT_AS`/`RLIMIT_DATA`** : elles peuvent provoquer l'échec d'allocation vulnérable [S1][S2] |
| Tests | Charge réaliste en préproduction ; surveiller `MemoryCurrent` (`systemctl show phpX.Y-fpm -p MemoryCurrent`) |
| Risque résiduel | OOM déclenchables par d'autres voies (allocations système, extensions) |

### E.4 Limites de taille et de structure des requêtes (CVE-2026-109618)

| Mesure | Syntaxe | Remarque |
|---|---|---|
| `post_max_size` | `8M` sans upload, `32M` avec upload ; `upload_max_filesize` < `post_max_size` [S1] | Insuffisant seul : requêtes sans `Content-Length` exploitable |
| Nombre de parties / variables / imbrication / fichiers | `max_multipart_body_parts`, `max_input_vars`, `max_input_nesting_level`, `max_file_uploads` | Réduire aux besoins réels de l'application [S2] |
| Nginx | `client_max_body_size 32m;` | Comportement exact vis-à-vis des corps *chunked* et de `CONTENT_LENGTH` transmis à FastCGI : **À confirmer** en préproduction |
| Apache | `LimitRequestBody 33554432`, `LimitRequestFields 50`, `LimitRequestFieldSize 8190` | Application aux corps *chunked* : **à vérifier** en préproduction |
| Nombre d'en-têtes par partie multipart | Aucun réglage PHP connu | Uniquement WAF/proxy capable d'inspecter le multipart |

### E.5 WAF

- CERT-FR : bloquer les requêtes `Content-Type: multipart/*` ou, à défaut, les superviser [S5]. **Effet de bord : casse tous les formulaires d'upload.** Variante ciblée [Reco] : bloquer le multipart sur les chemins qui n'acceptent jamais d'upload.
- AWS WAF : la configuration de référence est la règle **bloquante** publiée par AWS (bulletin 2026-143-AWS) [S10]. Les fichiers `annexes/aws-waf-*-phase-test.json` sont en mode **Count** : ils observent sans bloquer, pour mesurer les faux positifs avant de passer en Block. Détails : `AWS_SECURITY.md` §4.
- Limites : sur ALB, seuls les 8 premiers Ko du corps sont inspectés ; le PoC public place ses marqueurs vers 56 Ko [S13][S23]. Une règle par signature (`PHP_SESSION_UPLOAD_PROGRESS`, `PHPSESSID`) ne couvre pas CVE-2026-109618 et se contourne si `session.name` ou `session.upload_progress.name` sont personnalisés.

### E.6 Réseau, moindre privilège, isolation [Reco]

- **Isolement** des serveurs non corrigeables (CERT-EU, CERT-FR) [S4][S6].
- Ne jamais exposer FastCGI : `ss -ltnp | grep -E ':900[0-9]'` doit être vide côté interfaces publiques (prérequis de certains PoC [B.8]).
- Filtrage sortant des serveurs web (limite le téléchargement d'outils et les shells inversés).
- Un pool FPM par site avec utilisateur dédié ; webroot **non inscriptible** par l'utilisateur du pool hors répertoires d'upload ; interdire l'exécution PHP dans les répertoires d'upload.
- Durcissement systemd de `phpX.Y-fpm` (`NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=strict` + `ReadWritePaths=`, `ProtectHome=yes`) : à tester en préproduction.
- `pm.max_requests = 1` supprime la réutilisation de worker exigée par 619, au prix d'un coût CPU important [S3].
- Préférer PHP-FPM à mod_php (isolation par pool, exposition moindre).

---

## F. Détection et réponse à incident

Les commandes de recherche ne modifient rien. Elles sont regroupées dans **`annexes/03_detection_lecture_seule.sh`** (13 sections, date de début en argument). L'outil (`phpaudit.py audit`, contrôle `LOG`) applique en plus les 12 règles de `config/detection_rules.json` aux journaux.

| Indicateur | Où regarder | Section de l'annexe 03 |
|---|---|---|
| POST terminés en 500, par IP | journaux d'accès Apache/Nginx | 1 |
| Épuisement mémoire PHP | journaux d'erreurs, log PHP-FPM | 2 |
| Workers tués par signal, segfaults, core dumps | log FPM, `AH00052` Apache, `journalctl -k` | 3 |
| Redémarrages de services | `journalctl -u php*-fpm* -u apache2` | 4 |
| Avertissements INI « in Unknown on line 0 » | journaux d'erreurs | 5 |
| Processus inattendus du compte web, connexions sortantes | `ps -u www-data`, `ss -tnp` | 6–7 |
| PHP créés/modifiés, PHP dans les uploads, `/tmp`, sessions volumineuses | webroot, `/tmp`, `/var/lib/php/sessions` | 8–10 |
| `auto_prepend_file`, intégrité des paquets, persistance (cron, systemd, SSH, comptes) | `/etc`, `dpkg --verify` | 11–13 |

**Les formats de log par défaut n'enregistrent ni `Content-Type`, ni taille de requête, ni corps.** Pour la suite (à activer après validation) :

- Apache (mod_logio pour `%I`) : `LogFormat "%h %l %u %t \"%r\" %>s %b %I \"%{Content-Type}i\" %D" php2shell`
- Nginx : `log_format php2shell '$remote_addr [$time_local] "$request" $status $body_bytes_sent $request_length "$content_type" $request_time';`

### F.4 Comptes, sessions, application

Lister les comptes administrateurs applicatifs créés ou modifiés depuis le 20/10 (ex. WordPress : `wp user list --role=administrator --fields=ID,user_login,user_registered`, sans modification), les tâches planifiées applicatives, les extensions installées récemment.

### F.5 Limites

- Une exploitation réussie peut tenir en une requête sans erreur visible ; l'absence d'alerte ne prouve rien.
- Les logs locaux peuvent être modifiés par un attaquant disposant des droits du serveur web ou plus : privilégier une copie centralisée (syslog distant, CloudWatch).
- Les crashs et 500 ont de nombreuses causes bénignes : un indicateur isolé ne prouve pas une exploitation ; corréler horodatage, IP source et PID.

### F.6 Si une compromission est plausible

1. **Préserver** avant toute modification : snapshot disque (ou image forensique), capture mémoire avec l'outil validé par votre CSIRT, copie des journaux avec empreintes (`sha256sum`), liste des processus et connexions (sections 6–7 de l'annexe 03).
2. **Isoler** : retirer du load balancer, filtrer entrée/sortie sauf accès d'investigation ; ne pas éteindre avant la capture mémoire si elle est requise.
3. **Faire tourner les secrets** accessibles au compte web : identifiants base de données, clés API, sels/clefs de session applicatifs (invalide les sessions), clés SSH, identifiants cloud (rôle d'instance : révoquer les sessions actives).
4. **Rechercher la persistance** (sections 8–13 de l'annexe 03) sur l'hôte et sur les systèmes joignables avec les secrets exposés.
5. **Reconstruire** le serveur depuis une image saine, PHP corrigé, données restaurées et auditées, si l'un des cas suivants est vrai : exécution de commandes confirmée ; fichiers système ou appartenant à root modifiés ; persistance trouvée ; chronologie impossible à établir ; indice d'élévation de privilèges. **Mettre à jour PHP ne nettoie pas un serveur compromis.**
6. **Obligations** : violation de données personnelles → notification CNIL sous 72 h (RGPD art. 33) si un risque pour les personnes existe ; déclaration possible au CERT-FR.

---

## G. Recommandations AWS (synthèse)

Détail, prérequis, configurations et limites : **`AWS_SECURITY.md`**.

- AWS indique que ses services ne sont pas affectés ; le PHP exécuté par le client (EC2, conteneurs, Lightsail, plateformes Elastic Beanstalk non mises à jour) relève du client [S10].
- Amazon Linux 2023 : php8.2/8.3/8.4/8.5 corrigés (ALAS2023-2026-3301 à 3304) ; **php8.1 AL2023 et php du cœur AL2 : « No Fix Planned »** [S11].
- Elastic Beanstalk : plateformes PHP v4.13.12 (mitigations) le 21/10, correctif upstream annoncé pour le 22/10 ; Lightsail : nouvelles instances depuis les blueprints mis à jour ; Bitnami non mis à jour par `apt` [S10][S24].
- WAF : règles AWS = contrôles compensatoires ; limite d'inspection du corps (8 Ko ALB) [S13][S23].
- Aucun service AWS n'est documenté comme détectant spécifiquement ces CVE ; GuardDuty Runtime Monitoring et CloudTrail aident à détecter la post-exploitation et l'abus d'identifiants.

---

## H. Plan de validation (checklist)

**Avant correctif**

- [ ] Inventaire complet produit (`phpaudit.py audit`) et archivé (JSON + Markdown).
- [ ] Pour chaque paquet source PHP : version corrigée de référence identifiée dans la matrice C.2, **source officielle** notée.
- [ ] Version candidate APT ≥ version corrigée (étape S2 du plan généré).
- [ ] Sauvegarde configurations + liste des paquets + snapshot.
- [ ] Plan validé en préproduction (même OS, même branche, mêmes extensions).
- [ ] Fenêtre et retrait du load balancer planifiés ; parties prenantes informées.

**Après correctif**

- [ ] **P1** — chaque paquet PHP installé a une version complète ≥ celle de l'avis distribution (`annexes/02_verifier_correctif.sh`, code 0).
- [ ] **P2** — aucun processus avec binaire/bibliothèque PHP `(deleted)` ; `needrestart -b -r l` ne signale rien.
- [ ] **P3** — PHP-FPM / Apache démarrés après l'installation des paquets.
- [ ] Audit : `PKG` en `FIXED` pour chaque paquet source (un `LIKELY_FIXED` n'est accepté qu'avec l'avis distribution correspondant) ; `BIN` sans binaire hors paquet vulnérable ou indéterminé.
- [ ] Configurations valides : `php-fpmX.Y -t`, `apache2ctl configtest`, `nginx -t`.
- [ ] Tests fonctionnels : pages clés en 200, connexion/déconnexion, formulaire POST, **upload** de taille nominale et proche de la limite, tâches planifiées.
- [ ] Pas de régression : taux de 5xx et latence comparés à la veille.
- [ ] Conteneurs : images reconstruites, digest déployé = digest corrigé, `php -v` vérifié dans les conteneurs en cours.
- [ ] Mitigations réévaluées : garder `session.upload_progress.enabled=0` si inutilisé ; retirer `memory_limit=-1` et les blocages WAF gênants une fois corrigé.
- [ ] Recherche de compromission (annexe 03) exécutée et résultat consigné.

**Surveillance post-déploiement** : relancer `phpaudit.py audit` à J+1 et J+3 (le contrôle `LOG` compare les indicateurs), alarmes sur DR-005/DR-006/DR-007.

**Critères de clôture** : verdict `OK` de l'audit sur tous les hôtes du périmètre ; aucun constat `ALERT` non expliqué ; preuves (rapports, versions, sources) archivées ; serveurs EOL soit migrés, soit isolés avec date de migration validée.

---

## I. Stratégie de maintenance

L'outil `php-vuln-audit` (voir `README.md`) sépare données, contrôles, remédiation et rapports. Une nouvelle faille PHP se traite en ajoutant un fichier `data/advisories/<id>.json` (validé par schéma, sources datées), sans modifier le code. L'audit collecte sans modifier la configuration système (il écrit uniquement ses rapports et son inventaire) ; la remédiation est un script généré, à relire et lancer manuellement.

---

## Sources (consultées le 22/10/2026)

Primaires :

- [S1] PHP Group — [Security advisory: Critical remote code execution vulnerabilities, update now](https://www.php.net/archive/2026.php#2026-10-21-5), 21/10/2026
- [S2] PHP Group — [GHSA-w8hw-w9fx-j79w (CVE-2026-109618)](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [S3] PHP Group — [GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [S4] CERT-FR — [CERTFR-2026-AVI-1359](https://cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1359/)
- [S5] CERT-FR — [CERTFR-2026-ALE-014](https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-014/)
- [S6] CERT-EU — [Security Advisory 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018/)
- [S7b] Debian LTS — [DLA-4848-1 php8.2 (CVE-2026-109618, CVE-2026-109619)](https://security-tracker.debian.org/tracker/DLA-4848-1) · [annonce debian-lts-announce](https://lists.debian.org/debian-lts-announce/2026/10/msg00042.html)
- [S7] Debian — security tracker [CVE-2026-109618](https://security-tracker.debian.org/tracker/CVE-2026-109618), [CVE-2026-109619](https://security-tracker.debian.org/tracker/CVE-2026-109619)
- [S8] Canonical — [USN-8948-1](https://lists.ubuntu.com/archives/ubuntu-security-announce/2026-October/011433.html)
- [S9] Canonical — [USN-8948-2](https://ubuntu.com/security/notices/USN-8948-2)
- [S10] AWS — [Security Bulletin 2026-143-AWS](https://aws.amazon.com/security/security-bulletins/2026-143-aws/)
- [S11] AWS — [Amazon Linux Security Center CVE-2026-109618](https://explore.alas.aws.amazon.com/CVE-2026-109618.html)
- [S12] PHP Group — [Supported Versions](https://www.php.net/supported-versions.php)
- [S13] AWS — [AWS WAF : inspection du corps des requêtes](https://docs.aws.amazon.com/waf/latest/developerguide/web-request-body-inspection.html)
- [NCSC] NCSC-NL — [php2shell](https://github.com/NCSC-NL/php2shell)

Secondaires (utilisées uniquement là où elles sont citées) :

- [S14] watchTowr — [PHP RCE FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/) (page partiellement incohérente)
- [S15] Check Point — [php2shell: What We Know](https://blog.checkpoint.com/security/php2shell-what-we-know-about-the-leaked-critical-php-vulnerabilities-cve-2026-109618-cve-2026-109619/)
- [S16] idem S15 (CMS non correctifs)
- [S17] Tanium — [PHP2Shell: Responding to CVE-2026-109618 and CVE-2026-109619](https://www.tanium.com/blog/php2shell-responding-to-cve-2026-109618-and-cve-2026-109619)
- [S18] Wiz — [Exploitation in the Wild of wp2shell](https://wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137)
- [S19] ma.ttias.be — [How to apply the patches](https://ma.ttias.be/php-cve-2026-109618-patch/) (rédigé avant publication des correctifs)
- [S20] LinuxCompatible — [Sury.org ships updates](https://www.linuxcompatible.org/story/php2shell-patch-suryorg-ships-debian-ubuntu-updates-for-every-php-version-from-56-to-85/)
- [S21] Launchpad — [build php8.4 8.4.27 (PPA ondrej)](https://launchpad.net/~ondrej/+archive/ubuntu/php/+build/33861469)
- [S22] Docker (DEV Community) — [How to Fix PHP2Shell](https://dev.to/docker/how-to-fix-php2shell-cve-2026-109618-and-cve-2026-109619-3df3)
- [S23] Classmethod — [Test des règles AWS WAF PHP2Shell](https://dev.classmethod.jp/en/articles/aws-security-bulletin-php2shell-waf-rules/)
- [S24] AWS — [Update PHP on Lightsail instances](https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-update-php-security-vulnerabilities.html)
