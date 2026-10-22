# PHP2Shell — CVE-2026-109618 / CVE-2026-109619

Bulletin de sécurité complet et outil d'audit en lecture seule pour **PHP2Shell**, deux vulnérabilités critiques (CVSS v4 9,2) du moteur PHP lui-même permettant une exécution de code à distance **sans authentification** (RCE pré-auth).

> ⚠️ Le défaut est dans l'interpréteur PHP : mettre à jour WordPress, Drupal, Joomla ou tout autre CMS ne corrige rien. Seule une mise à jour du moteur PHP (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 ou supérieur) corrige la faille.

## Contenu du dépôt

| Élément | Description |
|---|---|
| [`Rapport_PHP2Shell.pdf`](Rapport_PHP2Shell.pdf) | Bulletin complet (28 pages) : synthèse exécutive, analyse technique des deux CVE, matrice de compatibilité, plan de remédiation Debian/Ubuntu pas à pas, mesures compensatoires, détection & réponse à incident, recommandations AWS, checklist de validation. |
| [`php-vuln-audit-1.0.1/`](php-vuln-audit-1.0.1/) | Outil d'audit **en lecture seule** (Python 3, bibliothèque standard uniquement) qui inventorie les versions PHP exposées (paquets, binaires hors paquets, services, mitigations) et génère un rapport de statut par hôte. Voir son propre [README](php-vuln-audit-1.0.1/README.md). |

## Résumé des deux CVE

- **CVE-2026-109618** — corruption mémoire lors de la gestion d'un *out-of-memory* (OOM) pendant le parsing d'une requête (uploads multipart). RCE validée sur Apache mod_php, déclenchée avant tout code applicatif.
- **CVE-2026-109619** — état global périmé (*use-after-free*) : un état appartenant à une requête survit à la libération de sa mémoire et peut être réutilisé par une requête suivante traitée par le même worker. Chemin confirmé via `session.upload_progress`, sur mod_php et PHP-FPM.

Aucune authentification ni interaction utilisateur n'est nécessaire. Les mitigations de configuration ne sont que temporaires : **seule la mise à jour du moteur PHP corrige la faille**.

## Démarrage rapide

```bash
# Audit en lecture seule d'un serveur Debian/Ubuntu
cd php-vuln-audit-1.0.1
sudo python3 phpaudit.py audit

# Générer un plan de remédiation (script à relire avant exécution)
sudo python3 phpaudit.py plan
```

Codes retour : `0` OK · `1` VULNERABLE · `2` ALERT · `3` INCOMPLETE · `4` erreur de configuration — utilisables en CI ou via AWS SSM Run Command.

## Sources

Avis primaires : PHP Group (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp), CERT-FR, CERT-EU, Debian Security Tracker, Canonical (USN-8948-1/2), AWS Security Bulletin. Liste complète et datée dans le rapport PDF.

---

*Bulletin TLP:CLEAR — librement partageable. Les mitigations ne remplacent pas le correctif ; une mise à jour ne nettoie pas un serveur déjà compromis.*
