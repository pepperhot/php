#!/usr/bin/env bash
# PHP2Shell — lancer l'audit sur une flotte EC2 via SSM Run Command et relever les verdicts.
# Prérequis : agent SSM, outil déployé dans /opt/php-vuln-audit, bucket S3 de sortie.
# L'audit ne modifie pas la configuration système ; il écrit ses rapports dans /var/tmp/phpaudit.
#
# Le code retour de l'audit est conservé (pas de commande après lui) :
#   0 OK → SSM « Success »
#   1 VULNERABLE · 2 ALERT · 3 INCOMPLETE · 4 erreur config → SSM « Failed », ResponseCode = code
set -euo pipefail
TAG_KEY="${TAG_KEY:-Role}"
TAG_VALUE="${TAG_VALUE:-web}"
BUCKET="${BUCKET:?définir BUCKET=<bucket-de-sortie>}"

CMD_ID=$(aws ssm send-command \
  --document-name AWS-RunShellScript \
  --targets "Key=tag:${TAG_KEY},Values=${TAG_VALUE}" \
  --parameters '{"commands":["cd /opt/php-vuln-audit && python3 phpaudit.py audit --output-dir /var/tmp/phpaudit"]}' \
  --output-s3-bucket-name "$BUCKET" --output-s3-key-prefix php2shell/ \
  --comment "PHP2Shell audit" \
  --query 'Command.CommandId' --output text)
echo "CommandId : $CMD_ID"
echo "Verdicts (relancer la commande ci-dessous jusqu'à ce qu'aucune instance ne soit InProgress) :"
echo "aws ssm list-command-invocations --command-id $CMD_ID --details --query 'CommandInvocations[].[InstanceId,Status,CommandPlugins[0].ResponseCode]' --output table"
