# Changelog

## 1.0.1 — 2026-10-22 (relecture avant diffusion)
### Corrigé
- WAF : les JSON fournis sont explicitement une **phase de test en mode Count** ; la configuration finale renvoie à la règle bloquante officielle du bulletin AWS 2026-143-AWS. JSON déplacé dans `annexes/` et validé contre le modèle d'API WAFv2.
- Debian 12 : `8.2.35-1~deb12u1` corrige les deux CVE (DLA-4848-1) ; mention « À confirmer » retirée.
- Preuve de correction : trois preuves obligatoires (P1 version complète ≥ avis, P2 aucun processus sur l'ancien PHP, P3 services redémarrés après installation) ; le changelog n'est plus qu'un indice. Étape S5 du plan généré réordonnée et bloquante si P1 ou P2 échoue.
- SSM : suppression du `echo` final qui masquait le code retour de l'audit ; table de correspondance code → statut SSM.
- Formulation « lecture seule » remplacée par « sans modification de la configuration système » ; les écritures de l'outil (rapports, inventaires) sont explicitées.

### Ajouté
- `FICHE_REFLEXE.md` : système concerné → correctif → vérification, sur une page.
- `annexes/` : inventaire, vérification du correctif, détection, mitigations php.ini / PHP-FPM / Apache, règles WAF de test, audit SSM — tous validés (shellcheck, php, php-fpm -t, apache2ctl -t, modèles d'API AWS).
- `exemples/` : rapport généré à partir d'un inventaire fictif.
- Tests : 55 (annexes, ordre des preuves dans le plan).

## 1.0.0 — 2026-10-22
### Ajouté
- Avis `PHP2SHELL-2026-10` (CVE-2026-109618, CVE-2026-109619) : versions upstream 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, correctifs Debian (DSA-6574-1, DLA-4848-1) et Ubuntu (USN-8948-1, USN-8948-2), mitigations officielles, 13 sources primaires datées.
- Contrôles PKG, BIN, RUN, MIT, EXT, LOG ; 12 règles de détection (DR-001 à DR-012).
- Rapports Markdown et JSON ; codes retour 0–4.
- Générateur de plan de remédiation Debian/Ubuntu (script gardé par `--i-have-reviewed`, confirmation par étape, vérification de la version candidate avant installation).
- Schémas JSON pour paramètres, règles et avis ; validateur intégré si `jsonschema` absent.
- 49 tests unitaires.

### À confirmer (suivi)
- Versions exactes des backports Sury pour les branches 5.6–8.1.
- Versions de paquets Amazon Linux corrigés (ALAS2023-2026-3301 à 3304).
