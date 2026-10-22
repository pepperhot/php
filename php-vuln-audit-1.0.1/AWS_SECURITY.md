# PHP2Shell sur AWS — recommandations

Version 1.1 — 22/10/2026. Complète `NOTE_CORRECTIF_PHP2SHELL.md`. Les commandes AWS CLI ne modifient rien, sauf mention « modifie ». Fichiers copiables dans `annexes/`.

## 1. Partage des responsabilités

| Périmètre | Responsable | État au 22/10/2026 |
|---|---|---|
| Services AWS eux-mêmes | AWS | « AWS services are not impacted by these issues » [A1] |
| Amazon WorkMail | AWS | Contrôles de configuration appliqués ; montée en 8.3.36 visée le 22/10 ; aucune action client [A1] |
| Elastic Beanstalk (plateforme PHP) | AWS publie, **le client applique** | v4.13.12 (21/10) avec mesures provisoires ; version avec correctif upstream annoncée pour le 22/10 ; mise à jour auto seulement si *Managed Platform Updates* activé [A1] |
| Amazon Linux (paquets) | AWS publie, **le client installe** | Voir §2 [A2] |
| Lightsail | **Client** | Blueprints mis à jour ; instances existantes non modifiées : recréer ou mettre à jour [A1][A3] |
| EC2 Debian/Ubuntu, conteneurs ECS/EKS, PHP compilé, Lambda custom | **Client** | Procédure `PLAN_REMEDIATION.md` / §6 |

## 2. EC2 — mise à jour du système et du moteur PHP

**Amazon Linux** [A2]

| Version | Paquet | Statut | Avis |
|---|---|---|---|
| AL2023 | php8.2 / php8.3 / php8.4 / php8.5 | Fixed | ALAS2023-2026-3301 / 3302 / 3303 / 3304 |
| AL2023 | php8.1 | **No Fix Planned** | — |
| AL2 Extras | php8.2 | Fixed | ALAS2PHP8.2-2026-015 |
| AL2 Core | php | **No Fix Planned** | — |

Versions de paquet corrigées : non affichées par l'ALAS Explorer — **À confirmer** dans chaque avis ALAS.

```bash
# AL2023 (lecture)
dnf updateinfo list --security 2>/dev/null | grep -i php
rpm -qa 'php*' | sort
# AL2023 (modifie) — après go/no-go
sudo dnf upgrade --advisory=ALAS2023-2026-3302    # adapter à la branche installée
```
**Risque traité** : 618 et 619 sur l'hôte. **Limites** : php8.1 AL2023 et php AL2 cœur ne seront pas corrigés → migration vers php8.2+ (AL2023) ou isolement.

**Debian/Ubuntu sur EC2** : `PLAN_REMEDIATION.md` à l'identique. Redémarrer PHP-FPM/Apache après mise à jour.

## 3. AWS Systems Manager — inventaire et correctifs

| Fonction | Usage ici | Prérequis | Limites |
|---|---|---|---|
| **Inventory** | Lister les paquets PHP de toute la flotte | Agent SSM, rôle d'instance avec `AmazonSSMManagedInstanceCore`, association Inventory | Ne voit pas les binaires compilés ni le PHP des conteneurs |
| **Patch Manager — Scan** | État de conformité des correctifs | Patch baseline adaptée | Les baselines Ubuntu/Debian approuvent par priorité/section ; la documentation consultée ne décrit pas de sélection par CVE pour ces OS [A4] → compléter par l'audit ci-dessous |
| **Patch Manager — Install** | Installation (modifie) | Fenêtre de maintenance | `RebootIfNeeded` par défaut : redémarrage machine (élimine les processus obsolètes, mais impact prod) ; `NoReboot` laisse l'ancien PHP en mémoire → redémarrer FPM/Apache séparément |
| **Run Command** | Exécuter `phpaudit.py audit` sur la flotte (aucune modification système ; rapports dans `/var/tmp/phpaudit`) | Outil déployé sur l'instance, bucket S3 de sortie | Aucune action corrective |

```bash
# Paquets PHP installés sur une instance (lecture)
aws ssm list-inventory-entries --instance-id i-0123456789abcdef0 --type-name AWS:Application \
  --filters Key=Name,Values=php,Type=BeginWith --query 'Entries[].[Name,Version]' --output table
# Scan de conformité (n'installe rien)
aws ssm send-command --document-name AWS-RunPatchBaseline --parameters Operation=Scan \
  --targets Key=tag:Role,Values=web
```

**Audit de la flotte** : `annexes/ssm-audit-flotte.sh` (paramètres validés contre le modèle d'API SSM). La commande exécutée est uniquement :

```bash
cd /opt/php-vuln-audit && python3 phpaudit.py audit --output-dir /var/tmp/phpaudit
```

Aucune commande ne suit l'audit : son code retour devient celui de SSM, exploitable pour le suivi automatique.

| Code audit | Verdict | Statut SSM | `ResponseCode` |
|---|---|---|---|
| 0 | OK | Success | 0 |
| 1 | VULNERABLE | Failed | 1 |
| 2 | ALERT (indicateurs dans les journaux) | Failed | 2 |
| 3 | INCOMPLETE | Failed | 3 |
| 4 | Erreur de configuration | Failed | 4 |

```bash
aws ssm list-command-invocations --command-id <CommandId> --details \
  --query 'CommandInvocations[].[InstanceId,Status,CommandPlugins[0].ResponseCode]' --output table
```

## 4. AWS WAF (ALB, CloudFront, API Gateway, App Runner…)

**Configuration de référence = règles publiées par AWS** [A1], en mode **Block** :

- CVE-2026-109618 : règle `SizeRestrictions_BODY` du groupe géré **Core rule set** (corps > 8 Ko).
- CVE-2026-109619 : **groupe géré PHP version 2.3** (version par défaut) et règle personnalisée `PHP2Shell` (priorité 0, **Block**) : méthode POST **et** `PHPSESSID` (clé de cookie ou corps) **et** `PHP_SESSION_UPLOAD_PROGRESS` dans le corps ; *OversizeHandling* `CONTINUE`.
- AWS les qualifie de **contrôles compensatoires**, pas de mitigations complètes.

**Déploiement en deux phases [Reco]**

| Phase | Action WAF | Effet | Fichier |
|---|---|---|---|
| 1. Test (24–48 h) | `Count` | Compte et journalise les requêtes ciblées, **ne bloque rien** | `annexes/aws-waf-php2shell-phase-test.json`, `annexes/aws-waf-taille-corps-phase-test.json` |
| 2. Production | `Block` | Bloque | Règle officielle du bulletin AWS 2026-143-AWS [A1] |

- Les deux fichiers de phase 1 sont des objets `Rule` WAFv2, **validés contre le modèle d'API WAFv2** (botocore) le 22/10/2026, à coller dans l'éditeur JSON de règles de la console.
- `PHP2Shell-test` reproduit la logique décrite dans le bulletin ; la détection du cookie y passe par l'en-tête `cookie`. Pour la phase 2, reprendre **le JSON officiel du bulletin**, pas une modification manuelle de ce fichier.
- Passage en phase 2 si les requêtes comptées sont attribuables à des attaques ou à des usages que l'on accepte de bloquer (métriques CloudWatch `PHP2Shell-test`, `Body-over-8KB-test`, échantillons de requêtes).

**Limites vérifiées**

- Inspection du corps : **8 Ko fixes** pour ALB et AppSync ; 16 Ko par défaut, jusqu'à 64 Ko, pour CloudFront, API Gateway, Cognito, App Runner, Verified Access [A5].
- Avec `CONTINUE`, seuls les premiers octets inspectables sont évalués : le PoC public place les marqueurs vers 56 Ko et passe la règle `PHP2Shell` sur ALB ; seule la règle de taille l'a bloqué lors du test [A6].
- La règle de taille bloque aussi tout upload, JSON ou PUT/PATCH > 8 Ko : faux positifs massifs sur les applications avec upload → **mode Count d'abord**, puis Block ciblé par chemin.
- Contournements : `session.name` ≠ `PHPSESSID` ou `session.upload_progress.name` personnalisé ; CVE-2026-109618 n'a pas besoin de ces chaînes.
- Le WAF ne protège que le trafic passant par la ressource associée : restreindre le Security Group des instances au seul ALB, ou à la *prefix list* gérée CloudFront `com.amazonaws.global.cloudfront.origin-facing` pour une origine CloudFront.

## 5. Journalisation et investigation

| Service | Ce qu'il voit réellement | Ce qu'il ne voit pas |
|---|---|---|
| **ALB access logs** (S3) | Ligne de requête, statut ELB/cible, tailles reçue/envoyée, IP client | Corps, `Content-Type` |
| **AWS WAF logs** (CloudWatch Logs / S3 / Firehose) | En-têtes, règle déclenchée, action | Corps de la requête |
| **CloudWatch Logs** (agent) | Ce que vous y envoyez : logs Apache/Nginx/FPM/kern | Rien de plus que les fichiers source |
| **CloudTrail** | Appels d'API AWS (y compris avec les identifiants du rôle d'instance) | Aucune requête HTTP applicative ; pas l'exploitation elle-même |
| **VPC Flow Logs** | Flux réseau (connexions sortantes inhabituelles) | Contenu |

```bash
# Filtre de métrique sur les workers tués (modifie : crée un filtre)
aws logs put-metric-filter --log-group-name /web/php-fpm --filter-name php-worker-signal \
  --filter-pattern '"exited on signal"' \
  --metric-transformations metricName=PhpWorkerSignal,metricNamespace=Web/PHP,metricValue=1
```
CloudWatch Logs Insights (lecture) :
```
fields @timestamp, @logStream, @message
| filter @message like /exited on signal (6|7|11)|AH00052|Allowed memory size of/
| stats count() by bin(10m), @logStream
```
CloudTrail — usage des identifiants d'une instance web depuis le 20/10 (la session du rôle d'instance porte l'ID d'instance) :
```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=i-0123456789abcdef0 \
  --start-time 2026-10-20T00:00:00Z --query 'Events[].[EventTime,EventName,EventSource]' --output table
```

## 6. Détection gérée : GuardDuty, Inspector, Security Hub

- **Aucune source AWS consultée n'affirme une détection spécifique de CVE-2026-109618/109619.** Ne pas présumer de couverture.
- **GuardDuty** : `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` signale l'usage des identifiants d'une instance hors AWS (vol après RCE). **Runtime Monitoring** (agent ; EC2, ECS sur Fargate, EKS hors Fargate) observe exécutions de processus, accès fichiers et connexions réseau [A7] : pertinent pour la post-exploitation (shell lancé par le worker web). Noms exacts des findings runtime : à vérifier dans la référence GuardDuty.
- **Amazon Inspector** : scanne les paquets EC2 (via SSM) et images ECR ; détection de ces CVE dépendante de la mise à jour de sa base — vérifier en filtrant par `vulnerabilityId`. Le PHP compilé hors paquet n'est pas couvert.
- **Security Hub** : agrège GuardDuty/Inspector ; utile pour le suivi de clôture, pas comme détecteur.

## 7. Conteneurs (ECS, EKS, ECR)

1. Mettre à jour la base : `FROM php:8.4.27-fpm` (ou digest épinglé) ; ne pas compter sur `php:8.2-fpm` flottant (pointait encore 8.2.34 le 21/10 selon une source secondaire [A8]).
2. Reconstruire avec `--pull --no-cache`, pousser dans ECR, laisser Inspector scanner l'image.
3. Redéployer (modifie) :
   ```bash
   aws ecs update-service --cluster <c> --service <s> --force-new-deployment
   kubectl rollout restart deployment/<d> -n <ns>
   ```
4. Vérifier les **tâches/pods en cours** (lecture) :
   ```bash
   aws ecs describe-tasks --cluster <c> --tasks $(aws ecs list-tasks --cluster <c> --service-name <s> --query 'taskArns[]' --output text) \
     --query 'tasks[].containers[].[name,imageDigest]' --output table
   kubectl get pods -n <ns> -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{..imageID}{"\n"}{end}'
   kubectl exec -n <ns> <pod> -- php -v
   ```
Une image corrigée dans ECR ne protège aucun conteneur déjà lancé.

## 8. Lambda et environnements PHP personnalisés

Lambda n'a pas de runtime PHP géré ; PHP n'y existe que via runtime personnalisé (`provided.al2023`) ou image conteneur (ex. couches communautaires). Si c'est votre cas : reconstruire la couche/l'image avec PHP corrigé et publier une nouvelle version de fonction. Exposition exacte (réutilisation d'environnement d'exécution, FPM embarqué ou non) : **À confirmer** auprès du fournisseur de la couche.

## 9. IAM, secrets, réseau — réduction du rayon d'impact

| Mesure | Risque traité | Configuration à vérifier | Limite |
|---|---|---|---|
| IMDSv2 obligatoire | SSRF vers les métadonnées | `aws ec2 modify-instance-metadata-options --instance-id <i> --http-tokens required --http-put-response-hop-limit 1` (modifie) | Une RCE locale peut toujours appeler IMDSv2 |
| Rôle d'instance minimal | Abus post-RCE | Pas de `*:*`, pas d'accès S3 global ; Access Analyzer | — |
| Secrets Manager / Parameter Store | Secrets en clair dans `.env`/`wp-config.php` | Rotation prête à déclencher | Le processus PHP lit le secret : rotation obligatoire après compromission |
| Security Groups | Exposition directe | Entrée 80/443 uniquement depuis ALB/CloudFront ; **aucun port 9000 (FastCGI)** | — |
| Filtrage sortant (SG/NACL/Network Firewall) | Téléchargement d'outils, shell inversé | Sortie limitée (dépôts, API nécessaires) | Mise en place progressive |
| Comptes séparés (prod/préprod) | Propagation | AWS Organizations, SCP | — |

**En cas de suspicion de compromission** (modifie) : basculer l'instance en *standby* de l'Auto Scaling group, lui appliquer un Security Group d'isolement, créer un snapshot EBS (`aws ec2 create-snapshot --volume-id <vol> --description "IR php2shell"`), révoquer les sessions actives du rôle d'instance (console IAM « Revoke active sessions »), faire tourner les secrets, puis reconstruire depuis une AMI saine (cf. note §F.6).

## Sources (consultées le 22/10/2026)

- [A1] AWS — [Security Bulletin 2026-143-AWS](https://aws.amazon.com/security/security-bulletins/2026-143-aws/)
- [A2] AWS — [Amazon Linux Security Center CVE-2026-109618](https://explore.alas.aws.amazon.com/CVE-2026-109618.html)
- [A3] AWS — [Update PHP on Lightsail instances](https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-update-php-security-vulnerabilities.html)
- [A4] AWS — [Patch Manager : baselines prédéfinies et personnalisées](https://docs.aws.amazon.com/systems-manager/latest/userguide/patch-manager-predefined-and-custom-patch-baselines.html)
- [A5] AWS — [AWS WAF : inspection du corps](https://docs.aws.amazon.com/waf/latest/developerguide/web-request-body-inspection.html)
- [A6] Classmethod (secondaire) — [Test des règles AWS WAF PHP2Shell](https://dev.classmethod.jp/en/articles/aws-security-bulletin-php2shell-waf-rules/)
- [A7] AWS — [GuardDuty Runtime Monitoring](https://docs.aws.amazon.com/guardduty/latest/ug/runtime-monitoring.html)
- [A8] Docker / DEV Community (secondaire) — [How to Fix PHP2Shell](https://dev.to/docker/how-to-fix-php2shell-cve-2026-109618-and-cve-2026-109619-3df3)
