# Production Hardening Checklist

This is a release gate for production systems that use PostQuantum.Hybrid.
Treat every unchecked box as a ship blocker unless it is explicitly marked as
recommended.

An item is not complete until you can point to all three:

- the code or configuration that implements the control,
- the test or CI job that exercises it,
- the runbook, owner, or operational process that keeps it true over time.

If you cannot name the evidence, leave the box unchecked.

*Tip: If you are a developer writing code, focus on the **[DEV]** tags. If you manage infrastructure or pipelines, focus on **[OPS]** and **[CI]**.*

## 1. Safe surface selection

- [ ] **[DEV]** **If the application only needs sealed/opened envelopes, it uses
      `PostQuantum.Hybrid.Envelopes` instead of custom KEM + HKDF + AEAD
      glue.** Prefer `HybridEnvelope` / `SignedHybridEnvelope` unless you
      have a documented protocol reason not to.
- [ ] **[DEV]** **If the application is ASP.NET Core and loads long-lived keys at
      startup, key loading is centralized through
      `AddPostQuantumHybrid(...)` or an equivalent single abstraction.** Do
      not scatter PEM loading and private-key import across controllers,
      middleware, and background jobs.
- [ ] **[DEV]** **`PostQuantum.Hybrid.Analyzers` is installed in every project that
      touches hybrid keys, ciphertexts, signatures, or shared secrets.**
      *(Run `dotnet add package PostQuantum.Hybrid.Analyzers` in your app project).*
- [ ] **[CI]** **`PQH001` through `PQH005` are treated as build-breaking in CI.**
      *(Add `<WarningsAsErrors>PQH001;PQH002;PQH003;PQH004;PQH005</WarningsAsErrors>` to your `.csproj` or `Directory.Build.props`).*
- [ ] **[DEV]** **Every suppression of `PQH001` through `PQH005` has a written
      justification, an owner, and review history.**

## 2. Key lifecycle and secret handling

- [ ] **[DEV]** **Private keys never appear in logs, traces, telemetry, metrics labels,
      crash dumps, support bundles, or error responses.** This includes any
      `.Export()` / `.ExportPem()` output.
- [ ] **[CI]** **Private keys are never committed to source control or baked into
      container images, deployment manifests, IaC templates, or CI
      artifacts.**
- [ ] **[OPS]** **Private keys are stored encrypted at rest** (KMS, HSM, OS keystore,
      secret-managed file, or equivalent), with access controls and audit
      logging.
- [ ] **[OPS]** **The identities allowed to read decapsulation keys or signing keys are
      least-privilege and auditable.**
- [ ] **[DEV]** **The public-key distribution path is authenticated.** Callers do not
      blindly trust the first PEM or byte blob they receive.
- [ ] **[DEV]** **Every code path that allocates `HybridKemKeyPair`,
      `HybridKemPrivateKey`, `HybridSignatureKeyPair`,
      `HybridSignaturePrivateKey`, or `HybridKemEncapsulationResult`
      disposes it deterministically.** Use `using` or an equivalent explicit
      lifecycle.
- [ ] **[OPS]** **Backups of long-lived private-key material exist, are encrypted, and
      have been test-restored.** "We have backups" is not enough.
- [ ] **[OPS]** **A documented rotation cadence exists for long-lived keys, plus an
      emergency rotation playbook.**
- [ ] **[DEV/OPS]** **Rotation includes a safe rollout plan for public-key consumers,
      overlapping trust windows where needed, and a way to revoke old
      keys.**

## 3. Protocol construction

- [ ] **[DEV]** **The KEM shared secret is treated only as keying material.** It is
      never used directly as plaintext, an AEAD key, or a MAC key.
- [ ] **[DEV]** **HKDF is used before any symmetric primitive, with an
      application-specific `info` string that includes protocol/app identity
      and purpose.**
- [ ] **[DEV]** **An AEAD (AES-GCM, ChaCha20-Poly1305, or equivalent) protects the
      payload.** The KEM is for key agreement, not bulk encryption.
- [ ] **[DEV]** **The hybrid KEM ciphertext is bound into AEAD `associatedData`.**
- [ ] **[DEV]** **A fresh KEM ciphertext and fresh derived AEAD key are used per
      message, unless a documented session protocol replaces this with a
      ratchet or KDF chain.**
- [ ] **[DEV]** **In signed-and-encrypted flows, verification happens before
      decapsulation or decryption.** Prefer `SignedHybridEnvelope.Open(...)`
      when it fits.
- [ ] **[DEV]** **Replay and freshness protection exists at the protocol layer.** The
      library does not provide it.
- [ ] **[DEV]** **The system treats AEAD authentication failure as the signal that a
      malformed or tampered KEM ciphertext did not authenticate.** It does
      not assume that "decapsulation returned bytes" means success.
- [ ] **[DEV]** **The algorithm-id byte is preserved end-to-end and validated on every
      import.** It is never stripped for compactness or re-packed into an ad
      hoc format.
- [ ] **[DEV]** **Any custom wire format or envelope format is versioned and
      documented.** Future algorithm-id changes must be introducible without
      ambiguity.

## 4. Input validation and negative testing

- [ ] **[DEV]** **Untrusted hybrid blobs are size-bounded before buffering or
      parsing.** Reject obviously oversized payloads before handing them to
      `Import(...)`, `FromBytes(...)`, or PEM parsing.
- [ ] **[DEV]** **Code paths that ingest raw bytes or PEM accept only the exact
      artifact types they expect.**
- [ ] **[DEV/CI]** **Integration tests prove that tampered ciphertexts fail
      authentication.**
- [ ] **[DEV/CI]** **Integration tests prove that tampered signatures fail
      verification.**
- [ ] **[DEV/CI]** **Integration tests prove that wrong-key opens or decapsulations do not
      silently succeed.**
- [ ] **[DEV/CI]** **Integration tests prove that wrong algorithm-id and wrong length
      inputs are rejected.**
- [ ] **[DEV/CI]** **If artifacts cross process, service, or language boundaries,
      interoperability tests cover the exact raw and PEM formats you ship.**
- [ ] **[DEV]** **Failure-path tests assert coarse logging only.** No payload bytes,
      no ciphertext bodies, no signatures, no private-key material.

## 5. Runtime and platform

- [ ] **[OPS]** **Operators know which backend each environment uses.** On .NET 10 the
      library prefers native `MLKem` / `MLDsa` when supported and otherwise
      falls back to BouncyCastle; on .NET 8 it uses BouncyCastle.
- [ ] **[DEV/OPS]** **If policy, certification, or performance requires the native .NET 10
      PQ backend, startup explicitly probes
      `System.Security.Cryptography.MLKem.IsSupported` and
      `System.Security.Cryptography.MLDsa.IsSupported` and fails closed when
      they are false.**
- [ ] **[OPS]** **Readiness checks exercise the real crypto path with canary keys or a
      startup smoke test:** key load or import, sign and verify, and
      encapsulate and open/decapsulate.
- [ ] **[OPS]** **Crash-dump, swap, paging, and telemetry policies reduce secret
      exposure on the host.**
- [ ] **[OPS]** **The host OS and runtime receive security updates on an enforced
      cadence.** "We will patch later" is not a control.
- [ ] **[OPS]** **Platform hardening follows the normal host baseline:** least
      privilege, ASLR/DEP, restricted debug access, locked-down secret files,
      and audited administrator access.

## 6. Build, CI, and supply chain

- [ ] **[CI]** **`BouncyCastle.Cryptography` is pinned to a reviewed version
      `>= 2.6.2`, and dependency automation watches for updates and
      advisories.**
- [ ] **[CI]** **CI builds and tests every target framework and deployment shape the
      application actually ships.**
- [ ] **[CI]** **CI runs software composition analysis such as
      `dotnet list package --vulnerable` or an equivalent scanner.**
- [ ] **[CI]** **CI or release automation scans for accidentally committed secrets and
      private-key material.**
- [ ] **[CI]** **Release artifacts have a dependency inventory / SBOM or an equivalent
      auditable package manifest.**
- [ ] **[CI]** **Build output fails if `PQH001` through `PQH005` fire, unless a
      reviewed suppression exists.**

## 7. Operations, monitoring, and incident response

- [ ] **[OPS]** **Monitoring includes coarse counters for sign, verify, encapsulate,
      decapsulate, envelope seal, and envelope open success and failure,**
      labeled by algorithm and environment rather than by sensitive data.
- [ ] **[OPS]** **Alerts exist for spikes in authentication failures, key load/import
      failures, readiness failures, and overdue key rotation.**
- [ ] **[SEC/OPS]** **There is a documented procedure for private-key compromise,**
      including revocation, replacement, and downstream re-issuance of public
      keys.
- [ ] **[SEC/OPS]** **There is a documented procedure for a break in one primitive,**
      including algorithm-id migration, compatibility handling, and rollout
      sequencing.
- [ ] **[OPS]** **Disaster-recovery drills include restoring keys, reloading them into
      the app, and proving that old data still verifies or decrypts where
      policy says it should.**
- [ ] **[SEC]** **Security documentation states the exact deployed algorithms**
      (`X25519MlKem768`, `Ed25519MlDsa65`), the target frameworks, backend
      expectations, and the replay and rotation assumptions the application
      adds on top of the library.
- [ ] **[SEC]** **The application's security documentation references or restates the
      library threat model in `docs/THREAT-MODEL.md`, the secure usage
      guidance in `src/SECURE-USAGE.md`, and this checklist.**

## Copy-Paste PR Template for Developers
*(To use in your `.github/pull_request_template.md`)*
```markdown
### PostQuantum.Hybrid Security (If modifying crypto paths)
- [ ] Analyzers are active (`PQH001`-`PQH005` yield zero warnings or are suppressed with justification)
- [ ] `using` blocks wrap all private keys & encapsulation results
- [ ] Raw KEM shared secrets are fed through HKDF, not used as direct AES-GCM keys
- [ ] KEM ciphertexts are passed into AES-GCM `associatedData`
- [ ] Verifications run BEFORE decapsulations in sign-and-encrypt workflows
- [ ] Negative test cases added (tampered ciphertext -> auth tag failure, etc)
```

## Minimum evidence pack

Before declaring this checklist complete, collect all of the following:

- a CI run proving the negative tests above,
- the analyzer configuration that makes `PQH001` to `PQH005`
      build-breaking. You can use a reviewed, versioned local copy of the
      `audit-pqh.ps1` preflight script as supporting evidence for the
      analyzer, warnings-as-errors, dependency-audit, and export-review
      portions of this checklist. Review the script before use and keep a
      stable local copy in source control or your build environment; do not
      pipe a remote PowerShell script straight into `Invoke-Expression`.
- the secret-storage and key-rotation runbook,
- the incident-response runbook for key compromise and primitive break,
- the document that states which algorithms, formats, and deployment
  backends the system uses.
