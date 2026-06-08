# Deploying WebApiDemo live (Azure Container Apps)

The WebApiDemo is an ASP.NET Core Minimal API whose crypto runs server-side
and needs **OpenSSL 3.5+** for the native .NET 10 ML-KEM / ML-DSA path. (On a
base image with older OpenSSL the library falls back to BouncyCastle per
[ADR 0012](../../docs/adr/0012-runtime-backend-fallback.md) and the demo still
works — but we want the live URL to exercise the real native path.) Azure
Container Apps (ACA) is the cheapest, simplest fit: it builds the existing
`Dockerfile` (which brings OpenSSL 3.5 via conda-forge — the Azure Linux base
is only on 3.3.5) and gives you a public HTTPS URL with scale-to-zero so an
idle demo costs almost nothing.

> **Build context is the repo root.** This Dockerfile references `../../src`,
> so every command below runs from the **repository root** and points at the
> Dockerfile with `-f`. Don't `cd` into the sample folder.

> **You do not need Docker installed locally.** `az acr build` runs the
> build in the cloud. You only need the Azure CLI (`az`).

## One-time setup

```bash
# Install / update the CLI extension and register providers (once per subscription)
az login
az extension add --name containerapp --upgrade
az provider register --namespace Microsoft.ContainerRegistry --wait
az provider register --namespace Microsoft.App --wait
az provider register --namespace Microsoft.OperationalInsights --wait
```

> On a brand-new subscription these providers aren't registered yet, so ACR /
> Container App creation fails with `MissingSubscriptionRegistration` until the
> `register` commands above complete (`--wait` blocks until they do).

## Fastest path — the bundled script

From the **repository root**:

```bash
bash samples/WebApiDemo/deploy.sh
```

It creates the resource group, ACR, and container-apps environment if
missing, runs a cloud build, deploys with `--ingress external` on
`--target-port 8080`, pins `min-replicas 0 / max-replicas 1` (cost control),
and prints the live URL plus sample `curl` commands.

## Manual path (most reliable when you want to inspect each step)

From the **repository root**:

```bash
# 1) Create the resource group + a registry (once)
az group create --name pqhybrid-demos --location eastus
az acr create --resource-group pqhybrid-demos --name pqhybriddemoacr --sku Basic --admin-enabled true

# 2) Build the image in the cloud, using our Dockerfile and the repo root as context
az acr build \
  --registry pqhybriddemoacr \
  --image pqhybrid-webapidemo:latest \
  --file samples/WebApiDemo/Dockerfile \
  .

# 3) Deploy the image to Container Apps (scale-to-zero keeps idle cost ~$0)
az containerapp up \
  --name pqhybrid-webapidemo \
  --resource-group pqhybrid-demos \
  --environment pqhybrid-env \
  --image pqhybriddemoacr.azurecr.io/pqhybrid-webapidemo:latest \
  --registry-server pqhybriddemoacr.azurecr.io \
  --ingress external \
  --target-port 8080

# 4) COST CONTROL — do not skip. `containerapp up` defaults to max 10 replicas
#    and no explicit minimum; pin min 0 (scale to zero, ~$0 idle) and max 1 so a
#    traffic spike or bot can't fan out to 10 replicas and run up a bill.
az containerapp update \
  --name pqhybrid-webapidemo \
  --resource-group pqhybrid-demos \
  --min-replicas 0 --max-replicas 1
```

The deploy prints the public URL (e.g.
`https://pqhybrid-webapidemo.<region>.azurecontainerapps.io`).

> **Scale-to-zero trade-off:** with `min-replicas 0`, an idle app has no
> running replica, so the first request after idle cold-starts and can take
> up to a minute (this image bundles OpenSSL 3.5, so it's a chunky cold
> start). Tell users the demo may take a moment to wake.

## Try the live demo

The deployed URL serves **Swagger UI at the root**, so anyone can open the
page in a browser and click through `/seal`, `/sign`, and the public-key
endpoints without writing any code.

```bash
URL="https://pqhybrid-webapidemo.<region>.azurecontainerapps.io"

# Or hit it from the shell:

# The hybrid KEM public key the server uses for /seal
curl "$URL/pub/kem-public-key"

# Server seals a plaintext under its own KEM public key
curl -X POST "$URL/seal" \
     -H "Content-Type: application/json" \
     -d '{"plaintext":"hello hybrid PQC"}'

# Server hybrid-signs a payload (Ed25519 + ML-DSA-65)
curl -X POST "$URL/sign" \
     -H "Content-Type: application/json" \
     -d '{"data":"sign me"}'
```

## Verify OpenSSL inside the running container

If the native PQ paths ever fail closed in the cloud, the base image's
OpenSSL is the first suspect:

```bash
az containerapp exec \
  --name pqhybrid-webapidemo --resource-group pqhybrid-demos \
  --command "openssl version"
# expect: OpenSSL 3.5.x or newer
```

## Continuous deploy from GitHub (optional)

A ready workflow lives at
[`.github/workflows/deploy-webapidemo.yml`](../../.github/workflows/deploy-webapidemo.yml).
It builds with ACR and updates the container app on every push to `main`
that touches the demo or the library source. Set these repository secrets:

- `AZURE_CREDENTIALS` — output of
  `az ad sp create-for-rbac --sdk-auth --role contributor --scopes /subscriptions/<SUB>/resourceGroups/pqhybrid-demos`
- `ACR_NAME` — e.g. `pqhybriddemoacr`

## Recommended: managed identity for ACR pull (no admin credentials)

The quickstart above lets Container Apps pull with registry admin
credentials. For anything you keep around, prefer a system-assigned managed
identity with the `AcrPull` role — no stored secrets:

```bash
# 1) Give the app a system-assigned identity
PRINCIPAL_ID=$(az containerapp identity assign \
  --name pqhybrid-webapidemo --resource-group pqhybrid-demos \
  --system-assigned --query principalId -o tsv)

# 2) Grant it pull rights on the registry
ACR_ID=$(az acr show --name pqhybriddemoacr --query id -o tsv)
az role assignment create \
  --assignee "$PRINCIPAL_ID" --role AcrPull --scope "$ACR_ID"

# 3) Point the app at the registry via that identity (no --registry-password)
az containerapp registry set \
  --name pqhybrid-webapidemo --resource-group pqhybrid-demos \
  --server pqhybriddemoacr.azurecr.io --identity system
```

## Tear down

```bash
az group delete --name pqhybrid-demos --yes --no-wait
```

## Cost note

With `--min-replicas 0`, ACA scales the demo to zero when no one is using
it, so you pay only for actual request time plus the small ACR storage. A
low-traffic public demo typically costs a few dollars a month or less.

## Custom domain

To serve the demo at `demo.pqhybrid.systemslibrarian.dev` with a free
managed certificate (Cloudflare DNS), see
**[CUSTOM-DOMAIN.md](CUSTOM-DOMAIN.md)**.

---

*To God be the glory — 1 Corinthians 10:31.*
