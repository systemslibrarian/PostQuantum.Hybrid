#!/usr/bin/env bash
# One-shot bootstrap: build the WebApiDemo image in ACR and deploy it to
# Azure Container Apps with scale-to-zero. Run from the REPOSITORY ROOT
# (the Dockerfile references ../../src, so the build context must be the root).
#
#   bash samples/WebApiDemo/deploy.sh
#
# Idempotent enough to re-run; resource creation is skipped if it already exists.
# To God be the glory - 1 Corinthians 10:31.
set -euo pipefail

# ---- variables (edit these) ------------------------------------------------
RESOURCE_GROUP="pqhybrid-demos"
LOCATION="eastus"
ENVIRONMENT="pqhybrid-env"
ACR_NAME="pqhybriddemoacr"          # must be globally unique - change if taken
APP_NAME="pqhybrid-webapidemo"
IMAGE="pqhybrid-webapidemo:latest"
DOCKERFILE="samples/WebApiDemo/Dockerfile"
# ---------------------------------------------------------------------------

echo ">> Ensuring resource group, environment, and registry exist..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" -o none
az containerapp env create --name "$ENVIRONMENT" --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" -o none 2>/dev/null || true
az acr create --resource-group "$RESOURCE_GROUP" --name "$ACR_NAME" \
  --sku Basic --location "$LOCATION" --admin-enabled true -o none 2>/dev/null || true

echo ">> Building image in ACR (cloud build, repo root as context)..."
az acr build --registry "$ACR_NAME" --image "$IMAGE" --file "$DOCKERFILE" .

echo ">> Deploying / updating the container app..."
az containerapp up \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --environment "$ENVIRONMENT" \
  --image "${ACR_NAME}.azurecr.io/${IMAGE}" \
  --registry-server "${ACR_NAME}.azurecr.io" \
  --ingress external \
  --target-port 8080

# COST CONTROL: scale to zero when idle, cap at 1 replica so a traffic spike or
# bot scrape can't fan out to the default max of 10 and run up a bill.
az containerapp update --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" \
  --min-replicas 0 --max-replicas 1 -o none

URL=$(az containerapp show -n "$APP_NAME" -g "$RESOURCE_GROUP" \
  --query "properties.configuration.ingress.fqdn" -o tsv)
echo ">> Live at: https://${URL}  (Swagger UI is at the site root)"
echo ">> Try it from the shell:"
echo ">>   curl https://${URL}/pub/kem-public-key"
echo ">>   curl -X POST https://${URL}/seal -H 'Content-Type: application/json' -d '{\"plaintext\":\"hello\"}'"
echo ">>   curl -X POST https://${URL}/sign -H 'Content-Type: application/json' -d '{\"data\":\"sign me\"}'"
echo ">> Verify OpenSSL 3.5 inside the container:"
echo ">>   az containerapp exec -n $APP_NAME -g $RESOURCE_GROUP --command 'openssl version'"
