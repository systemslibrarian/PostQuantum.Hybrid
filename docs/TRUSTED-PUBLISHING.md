# Trusted Publishing on nuget.org

The release workflow publishes packages to nuget.org using **Trusted
Publishing** — short-lived API keys minted on demand from a GitHub OIDC
token. There is **no long-lived `NUGET_API_KEY` secret** in this repo.
The benefits, in concrete terms:

- A leaked CI secret can't be used to publish: the key is issued for one
  push and expires in an hour.
- A fork cannot publish to our package IDs: nuget.org checks the OIDC
  token against an owner+repo+workflow+environment policy.
- There is nothing to rotate. The OIDC trust is the credential.

Microsoft docs: <https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing>.

## One-time setup

Two sides — nuget.org and GitHub. Do them in this order.

### 1. nuget.org — create the trusted-publishing policy

1. Sign in to <https://www.nuget.org>.
2. Click your username (top right) → **Trusted Publishing**.
   (If the menu item is missing, the feature has not rolled out to your
   account yet. Microsoft is gating rollout.)
3. **Add a new GitHub Actions policy** with these values:

   | Field             | Value                                            |
   | ----------------- | ------------------------------------------------ |
   | Owner             | `systemslibrarian`                               |
   | Repository        | `PostQuantum.Hybrid`                             |
   | Workflow File     | `release.yml`  *(file name only — no `.github/workflows/`)* |
   | Environment       | `nuget`                                          |

4. Choose the owner (you, or an org you belong to). Whichever owner you
   pick is the one nuget.org will look up for the published packages, so
   it must match the existing package owner.
5. Save. If this is a private repo or the package has not been used yet,
   the policy starts in a 7-day temporary state until the first successful
   publish; for our public repo it's permanently active immediately.

### 2. GitHub — `NUGET_USER` secret + `nuget` environment

The workflow refers to two things you set up here.

#### `NUGET_USER` repo secret

The `NuGet/login@v1` action requires your nuget.org **profile name** (not
your email). Stored as a secret so the workflow source can stay public
without leaking the account name to scrapers.

1. <https://github.com/systemslibrarian/PostQuantum.Hybrid/settings/secrets/actions>
2. **New repository secret**
3. Name: `NUGET_USER`
4. Value: your nuget.org profile name (e.g. `systemslibrarian`)

#### `nuget` environment

The workflow's `environment: nuget` line. Creating the environment also
gives you a place to add protection rules later (required reviewers,
allowed branches) without touching workflow code.

1. <https://github.com/systemslibrarian/PostQuantum.Hybrid/settings/environments>
2. **New environment** → name it `nuget`
3. (Optional but recommended) under **Deployment branches and tags**,
   restrict to selected tags matching `v*.*.*` so a stray push to main
   can never run the release job.

### 3. Verify

Cut a small patch release (e.g. v1.0.1 with a docs-only change). On
push, the workflow should:

1. Pack + attach artifacts to the GitHub release.
2. Hit **NuGet login (OIDC -> short-lived API key)** — successful.
3. Hit **Publish to NuGet** — `dotnet nuget push` reports the upload.

If step 2 fails with `401 Unauthorized`, the most common causes (in
descending order of likelihood):

- The nuget.org policy's `Workflow File` field doesn't exactly match
  `release.yml` (people put `.github/workflows/release.yml` — don't).
- The policy's `Environment` field doesn't match the workflow's
  `environment: nuget` line.
- `NUGET_USER` is set to your email instead of your profile name.
- The policy was created against a different owner than the package
  owner on nuget.org.

## Retiring the old long-lived key

Once a trusted-publishing release has succeeded:

1. Delete the `NUGET_API_KEY` repo secret on
   <https://github.com/systemslibrarian/PostQuantum.Hybrid/settings/secrets/actions>.
2. Revoke the corresponding API key on
   <https://www.nuget.org/account/apikeys>.
3. Delete the local `Nuget.key.txt` at the repo root (it's already
   `.gitignored` and `.dockerignored`, but there's no reason to keep
   the file once trusted publishing is the canonical path).

## Why the workflow looks the way it does

- **`environment: nuget` is at job scope**, not above the `jobs:` key —
  that's the GitHub-supported location and makes the policy match work.
- **`id-token: write` is on the job**, not the workflow. Job-scoped
  permissions are a least-privilege default and the only scope the
  `NuGet/login` action requires.
- **`contents: write`** is still needed at job scope for
  `softprops/action-gh-release` to attach the `.nupkg` files to the
  GitHub release. Trusted publishing only handles the NuGet leg.
- **`--skip-duplicate`** stays on the `dotnet nuget push` call so a
  partial re-run of a tagged release doesn't fail on packages that
  already uploaded.

---

*To God be the glory — 1 Corinthians 10:31.*
