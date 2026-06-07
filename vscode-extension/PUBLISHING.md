# Publishing the PostQuantum.Hybrid VS Code extension

This extension is a pure snippets package — no TypeScript, no build
step. Packaging produces a single `.vsix` file from the manifest +
snippets + readme.

## Prerequisites

1. **Node.js + vsce.** Install the publisher CLI globally:

   ```bash
   npm install -g @vscode/vsce
   ```

2. **A Marketplace publisher account.** Sign in to
   [marketplace.visualstudio.com/manage](https://marketplace.visualstudio.com/manage),
   confirm a publisher exists with the name `systemslibrarian` (matching
   the `publisher` field in `package.json`). If you want a different
   name, change `package.json` first.

3. **An Azure DevOps Personal Access Token.** Create one at
   [dev.azure.com](https://dev.azure.com), going to *User Settings →
   Personal access tokens → New Token*. The token needs:
   - **Organization:** All accessible organizations
   - **Scope:** *Marketplace → Manage* (custom scope)
   Save the token — it is shown only once.

## Pack and publish

From this directory (`vscode-extension/`):

```bash
# Build the .vsix locally so you can inspect / smoke-test it.
vsce package

# Sign in with the PAT once per shell session.
vsce login systemslibrarian
# (paste the PAT when prompted)

# Publish to the Marketplace.
vsce publish
```

Increment the `version` field in `package.json` and add a row to
`CHANGELOG.md` before each publish.

## Local install (for testing before publish)

```bash
vsce package
code --install-extension postquantum-hybrid-snippets-1.1.0.vsix
```

Then open any `.cs` file and try the prefixes `pqh-kem`,
`pqh-kem-encrypt`, `pqh-signed-encrypted` etc.

## Icon

The manifest currently points to `vsc-icon.png`. Keep the icon file in
sync with the `icon` field in `package.json`, and keep it at a
Marketplace-friendly square size (128×128 or larger).
