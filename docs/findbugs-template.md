# Whole-repo bug audit prompt

> **What this file is.** The prompt the maintainer hands to an external
> reviewer (a person, an AI assistant, or both) when requesting a
> structured bug audit of the entire PostQuantum.Hybrid repository. It
> exists so every round of external review produces output the maintainer
> can act on the same day without translating between formats.
>
> **What this file is not.** A general security checklist or a list of
> things the maintainer already knows are gaps — those live in
> [`KNOWN-GAPS.md`](../KNOWN-GAPS.md) and the audit-matrix template at
> the bottom of [`HARDENING-CHECKLIST.md`](../HARDENING-CHECKLIST.md).
> Use **this** file when commissioning an exhaustive read of every
> source line in the repo.
>
> **How to use it.** Copy the entire body below into the new chat /
> ticket / engagement. Do not summarise. The audit's quality depends on
> the reviewer following the structure verbatim — every dropped section
> visibly lowers the signal of the resulting report.

---

## Task

Perform an **exhaustive, file-by-file bug audit** of the
`PostQuantum.Hybrid` repository at
<https://github.com/systemslibrarian/PostQuantum.Hybrid>.

Read every source file in the two areas listed below. Do not sample.
Do not skip files. Samples are first-class production-influencing code —
people copy them verbatim — so a bug in a sample is a shipped bug.

Audit against the commit SHA pinned in the message that delivered this
prompt; absent one, the tip of `main` at the time you start. Record the
full SHA in your report header so the maintainer can diff your findings
against the exact tree you read. If you have no way to determine a real
SHA (no git access, no commit pinned in the message), write
`unavailable — no git access` in the Commit field. A fabricated
40-character hex string is grounds to discard the report.

The deliverable is a single Markdown file conforming to the **Output
contract** at the bottom of this prompt.

## Begin by listing the files you will read

Before you write any findings or analysis prose, populate the two
inventory tables (one per scope area) from the **Output contract**
below — file column filled, "Bugs" column blank at the start, counts
updated in place as findings land. This commits the reviewer to full
coverage and makes selective reading visible to the maintainer. The
Output contract governs the *bytes* of the final file (header block
first, then `## File inventory`); this section governs the *order of
work* — inventory populated before any finding is written, never
after.

If you do not have filesystem search or directory-listing tools
(chat-UI paste, no workspace access), write `No filesystem access —
inventory unavailable.` in place of all tables. Do not invent file
paths from the repo URL, README fragments, or training data to
populate the manifest — that is the most structurally-rewarded
hallucination in this prompt, and the maintainer treats a fabricated
inventory as grounds to discard the entire report.

Declaring no filesystem access at inventory commits you to a Findings
section that is either empty or contains only findings cited from code
the maintainer pasted directly into your message. Any later finding
with a `file:line` cite to a file you could not list contradicts your
own declaration and is treated as fabrication. The Coverage statement
must reflect this: "No production code was read; no findings reported."

## Scope (read these globs in full, in this order)

1. **Core libraries** — `src/**/*.cs`
   - `src/PostQuantum.Hybrid/**/*.cs` — primitives library (`HybridKem`, `HybridSignature`, key types, internal backends)
   - `src/PostQuantum.Hybrid.Envelopes/**/*.cs` — `HybridEnvelope` / `SignedHybridEnvelope` opinionated wrappers
   - `src/PostQuantum.Hybrid.AspNetCore/**/*.cs` — DI + rotating-key providers
   - `src/PostQuantum.Hybrid.Analyzers/**/*.cs` — Roslyn analyzers and code-fix providers
   - `src/PostQuantum.Hybrid.TestingSupport/**/*.cs` — consumer test helpers
2. **Samples** — `samples/**/*.cs`
   (every sample under `samples/`: BasicDemo, KemEncryption, SignedDocument,
   KeyPersistence, SecureMessenger, WebApiDemo, LargeFileEncryption)

**Out of scope** — do not produce findings against:

- `tests/**` — has its own conventions; flag missing coverage as part of
  the relevant production finding instead
- `fuzz/**` — property-style fuzz tests; same handling as `tests/`
- `**/bin/**`, `**/obj/**` — build output
- `benchmarks/**` — measurement scaffolding, not production code
- `templates/**/content/**` — `dotnet new` template scaffolding;
  template defects are tracked separately
- Markdown documentation under `docs/`, plus `README.md`, `CHANGELOG.md`,
  `SECURITY.md`, `KNOWN-GAPS.md`, `HARDENING-CHECKLIST.md`, `CLAUDE.md`,
  `LLM-USAGE.md`, `SECURE-USAGE.md` — out of scope for findings *as
  targets*, but in scope as evidence: a doc artifact (e.g. `docs/SPEC.md`,
  `docs/adr/*.md`) may be cited in PROOF as the *broken contract* whose
  target is a `src/` or `samples/` finding (for example, a wire-format
  byte count drifting from `docs/SPEC.md` is reported as a `src/` bug
  with `docs/SPEC.md` cited as the contract, not as a `docs/` finding).

## Evidence requirements (mandatory)

Every reported finding must be **proven**. A claim without proof is
rejected outright. Each finding carries this inline block placed directly
above the offending line of the most relevant file:

```text
// BUG: <one-sentence description of the wrong behaviour>
// PROOF: <a specific input → expected vs. actual trace with values at
//         each step; OR the broken contract cited by file:line in this
//         repo or by RFC / FIPS / draft section number; OR a
//         counterexample demonstrating an invariant violation>
// TRIGGER: <precise conditions: input, state, interleaving, edge case>
// SEVERITY: <Critical | High | Medium | Low | Info> — <one-clause
//          threat model: who controls what, what they gain>
```

Discipline rules for evidence:

- **No hallucinated paths or line numbers.** Every cited `file:line`
  must be one you actually read. Quote the code you're citing.
- **Show the caller.** When a bug depends on a caller, cite the calling
  code by `file:line` too.
- **Self-verify the PROOF before reporting.** Walk the cited input
  through the code yourself. If the intermediate values you wrote do
  not actually reach the cited line under the stated TRIGGER, the
  finding is hallucinated — discard it. Triple-check before reporting
  Critical / High; one wrong trace burns the credibility of every
  other finding in the report.
- **Threat model for crypto.** State what the attacker controls, what
  they do not, what the bug lets them achieve. "Severity: High" with no
  threat model is not a finding — it is opinion.
- **Sample findings name the root cause.** If the finding is in
  `samples/`, state explicitly in the PROOF whether the cause is (a) a
  defect in the library's public API that makes the safe pattern hard
  to write — the maintainer fixes the library — or (b) a misuse of the
  API specific to the sample — the maintainer fixes the sample. Both
  matter, but the fix lands in different places.
- **Quote, don't paraphrase.** Findings must include the source lines
  verbatim so the maintainer can grep them.

## Pre-stated NOT bugs (do not re-report)

These are documented, deliberate design decisions. Re-flagging any of
them as bugs lowers the signal of the audit. Skip them unless you can
show the implementation deviates from the documented design.

1. **One algorithm combination per family in v1.** `HybridKemAlgorithm`
   exposes only `X25519MlKem768`; `HybridSignatureAlgorithm` only
   `Ed25519MlDsa65`. Adding combinations requires a new algorithm-id
   byte. See [ADR 0001](adr/0001-x25519-mlkem768-default.md) and
   [ADR 0002](adr/0002-ed25519-mldsa65-default.md). Flag a *parser* bug
   that accepts unknown ids; do not flag the single-combination design.
2. **BouncyCastle is required.** X25519 and Ed25519 always go through
   BC because the BCL doesn't expose them publicly on net8 or net10.
   ML-KEM and ML-DSA go through BC only on net8 (the BCL doesn't have
   them there) and through native types on net10 (`#if NET10_0_OR_GREATER`
   in `Internal/MlKemBackend.cs` and `Internal/MlDsaBackend.cs`). See
   [ADR 0005](adr/0005-multi-target-net8-net10.md) and
   [ADR 0006](adr/0006-backend-abstraction.md). Flag a *correctness*
   divergence between the two backends; do not flag the dual-backend
   design.
3. **HKDF-SHA256 combiner, not X-Wing.** The KEM combiner is
   HKDF-SHA256 over `ss_X25519 || ss_MLKEM` with both ciphertexts bound
   into `info` for transcript binding. This is *not* X-Wing
   (`draft-connolly-cfrg-xwing-kem`); a future algorithm-id `0x02`
   would opt into X-Wing precisely. See
   [ADR 0003](adr/0003-kem-combiner.md). Flag a transcript-binding
   *omission* (e.g. a path that fails to include a ciphertext in
   `info`); do not flag the choice of HKDF.
4. **Hybrid signatures are concatenated, both-must-verify.**
   `algId || sig_Ed25519 || sig_MLDSA65`. Both signatures are computed
   over the user-supplied message bytes directly; each scheme does its
   own internal hashing. Verification requires **both** to pass. See
   [ADR 0004](adr/0004-signature-concat.md). Flag a path where verify
   passes when one half is invalid; do not flag the concatenation
   construction.
5. **Wire format includes a 1-byte algorithm identifier on every blob.**
   This is the only thing keeping future combinations parseable. See
   [ADR 0007](adr/0007-versioned-wire-format.md). Flag a path that
   skips the id check, or strips the id on serialization; do not flag
   the byte's presence.
6. **ML-KEM implicit rejection is intentional.** Per FIPS 203, a
   malformed `MLKEM.Decapsulate` does not throw — it returns a
   pseudorandom secret. Combined with our HKDF-transcript combiner,
   this means a tampered hybrid KEM ciphertext yields a *different*
   shared secret, not an exception. Downstream AEAD authentically
   rejects. Flag a path that *throws* on a malformed ciphertext (which
   would leak structural information); do not flag the non-throwing
   behaviour.
7. **ML-DSA randomized signing.** `HybridSignature.Sign` calls
   `MLDsa.SignData(..., context: default)` — pure FIPS-204 ML-DSA with
   empty context, randomized variant. Two signatures over the same
   bytes under the same key will differ. Flag a path that assumes
   signature determinism; do not flag the randomization.
8. **`HybridSignature.Verify` returns `bool`; throwing is not the
   contract.** The library returns `false` for malformed signatures,
   wrong-length blobs, mismatched algorithm-ids, and signature
   mismatches. It throws `ArgumentNullException` only for null
   `publicKey`. Catching `CryptographicException` from `Verify` is
   reasonable defensive programming on the caller side, but the library
   itself does not throw on verify failure. Flag a `Verify` path that
   *throws* on bad input; do not flag the bool-returning contract.
9. **Private key types are `IDisposable` and zero on dispose.**
   `HybridKemPrivateKey`, `HybridSignaturePrivateKey`,
   `HybridKemKeyPair`, `HybridSignatureKeyPair`, and
   `HybridKemEncapsulationResult` zero their buffers on `Dispose`.
   `using` is the intended call pattern. Flag a path that does not
   dispose; do not flag the disposable design.
10. **No PKCS#8 / SPKI encoding.** Per `KNOWN-GAPS.md`, hybrid blobs
    use a library-specific concatenated format. PKCS#8 / SPKI support
    will arrive when IETF composite-key OIDs stabilize. Flag a parser
    bug; do not flag the absence of SPKI support.
11. **No streaming sign/verify or streaming encapsulation.** All public
    APIs take complete byte spans. The `LargeFileEncryption` sample
    shows how to compose a chunked-AEAD pattern on top of a single
    hybrid KEM exchange. Flag a defect in *that* composition; do not
    flag the absence of `SignStream`.
12. **AspNetCore key rotation triggers on FileSystemWatcher events,
    with a 50 ms debounce.** A brief window where two readers see
    different keys is acceptable — the prior private key remains valid
    until the caller releases its handle. Flag a path where the prior
    key is disposed while an in-flight verify can still touch it; do
    not flag the debounce design.

## Pre-stated existing assurance layers (don't duplicate)

Before flagging "this isn't tested", check that none of these already
cover it:

| Layer | Location |
|---|---|
| Unit + edge-case tests | `tests/PostQuantum.Hybrid.Tests/` (87 tests on net8.0, 89 on net10.0) |
| Envelopes round-trip + tamper tests | `tests/PostQuantum.Hybrid.Envelopes.Tests/` (20 tests × both TFMs) |
| AspNetCore DI + rotation tests | `tests/PostQuantum.Hybrid.AspNetCore.Tests/` (10 tests × both TFMs) |
| TestingSupport unit tests | `tests/PostQuantum.Hybrid.TestingSupport.Tests/` (15 tests × both TFMs) |
| Roslyn analyzer tests | `tests/PostQuantum.Hybrid.Analyzers.Tests/` (28 tests covering PQH001–PQH005) |
| Roslyn analyzers themselves | `src/PostQuantum.Hybrid.Analyzers/` — PQH001 dispose, PQH002 SharedSecret-without-HKDF, PQH003 Decapsulate-before-Verify, PQH004 ignored Verify, PQH005 AEAD without `associatedData` |
| Roslyn code-fix providers | `src/PostQuantum.Hybrid.Analyzers/AddUsingDeclarationCodeFix.cs`, `WrapVerifyCodeFix.cs` |
| Property-style fuzz tests | `fuzz/PostQuantum.Hybrid.Fuzz/` — 9 tests, ~7,200 random/mutated inputs per run, both TFMs |
| KAT-style regression tests | `tests/PostQuantum.Hybrid.Tests/DeterministicKeyGenerationTests.cs` — pins SHA-256 of public keys derived from fixed seeds; on net10 cross-validates BC vs. native byte-for-byte |
| BenchmarkDotNet suite | `benchmarks/PostQuantum.Hybrid.Benchmarks/` — KEM, signatures, serialization on both TFMs; measured numbers in `docs/PERFORMANCE.md` |
| Mutation testing config | `stryker-config.json` (weekly run via `.github/workflows/mutation.yml`) |
| Public-API baseline | `src/PostQuantum.Hybrid/PublicAPI.Shipped.txt` enforced by `Microsoft.CodeAnalysis.PublicApiAnalyzers` |
| CycloneDX SBOM | `.github/workflows/sbom.yml` runs on release; attaches per-package SBOMs |
| OpenSSF Scorecard | `.github/workflows/scorecard.yml` runs weekly + on push to `main` |
| CodeQL | `.github/workflows/codeql.yml` runs weekly + per PR |
| Reviewer-facing docs | `docs/TESTING.md`, `docs/SPEC.md`, `docs/SUPPLY-CHAIN.md`, `docs/THREAT-MODEL.md`, `docs/PERFORMANCE.md`, `docs/COMPARISON.md`, `docs/adr/0001..0008` |

A genuine gap in these layers IS a finding. "This isn't tested" without
checking the above is not. When a finding claims an assurance gap, cite
specifically which layer you inspected and what you found absent — a
test name, an analyzer rule id, a file path under `tests/` or `fuzz/`,
a doc section. "Not covered by fuzz" as a bare assertion is the same
failure mode as an uncited `file:line`, and reviewers who rely on it
are bluffing.

## What to check explicitly

### General

Logic errors, null / none dereferences, boundary conditions (empty /
zero / max / overflow / off-by-one), resource leaks, concurrency (races,
non-atomic check-then-act, shared mutable state, disposal during
in-flight verify or decapsulate), error handling (swallowed exceptions,
missing rollback), type / coercion mistakes, dead / unreachable code,
code that contradicts its own docstring / comment / signature.

### Hybrid KEM correctness

- **Wire-format byte counts.** Every `Import` / `FromBytes` must
  length-check against the exact value in `Internal/AlgorithmSizes.cs`.
  Off-by-one, accepting variable-length blobs, or skipping the check
  are findings. Cross-reference against `docs/SPEC.md`.
- **Algorithm-id byte.** Every `Import` / `FromBytes` must inspect
  byte 0 and reject unknown ids. Stripping the id on `Export`,
  prepending the wrong id, or accepting `0x00` are findings.
- **Combiner construction.** `Internal/KemCombiner.cs` must:
  (a) feed `ss_X25519 || ss_MLKEM` as IKM,
  (b) include the ASCII label `"PostQuantum.Hybrid v1 KEM X25519-MLKEM768"`
  in `info`,
  (c) bind BOTH ciphertexts into `info`,
  (d) output exactly 32 bytes via HKDF-SHA256.
  Any deviation is a finding. Cross-reference against
  [ADR 0003](adr/0003-kem-combiner.md).
- **Ephemeral keys.** `HybridKem.Encapsulate` must generate a fresh
  X25519 ephemeral key pair per call. Reusing an ephemeral, seeding
  with a constant, or sourcing randomness from anything other than
  `RandomNumberGenerator` / BouncyCastle's `SecureRandom` is a finding.
- **Implicit rejection plumbing.** A tampered hybrid KEM ciphertext
  must result in `HybridKem.Decapsulate` returning a *different* secret,
  not throwing. The deterministic-implicit-rejection test in
  `tests/PostQuantum.Hybrid.Tests/KemEdgeCaseTests.cs` proves this for
  the PQ half; verify the X25519 path doesn't short-circuit with an
  exception.

### Hybrid signature correctness

- **Concatenation order and lengths.** `algId(1) || ed25519_sig(64) ||
  mldsa65_sig(3309) = 3374 bytes`. Off-by-one, wrong order, or wrong
  slice indices are findings.
- **Both halves required.** `Verify` must return `false` if either
  component fails. A short-circuit that returns `true` on the first
  successful verify is a critical finding.
- **Empty context for ML-DSA.** `HybridSignature.Sign` calls
  `MLDsa.SignData(data, sig, context: default)`. A path that reads
  context from token headers, environment, or any
  attacker-influenceable source is a critical finding.
- **No early-exit signature comparison.** The library does not compare
  signature bytes for equality (the primitives do that internally);
  flag any caller-side `==` on signature bytes (e.g. in samples).
- **Signature length validation precedes parsing.** `Verify` must
  length-check before slicing.

### Envelope correctness (`HybridEnvelope`, `SignedHybridEnvelope`)

- **HKDF info parameter must include the KEM ciphertext** for transcript
  binding. Cross-reference against `src/PostQuantum.Hybrid.Envelopes/HybridEnvelope.cs`.
- **AEAD `associatedData` must include the KEM ciphertext.** Per
  PQH005, this prevents an attacker from swapping KEM ciphertexts to
  re-key the AEAD against a different exchange.
- **Nonce generation per call.** `Seal` must call
  `RandomNumberGenerator.Fill` for a fresh 12-byte nonce on every
  invocation. Reusing a nonce under the same derived AES key is
  catastrophic; this is a critical-severity finding.
- **`SignedHybridEnvelope.Open` MUST verify before decapsulating.**
  Per PQH003. Reordering is a critical-severity finding.
- **AES-GCM tag length pinned to 16.** Reading the tag length from the
  envelope is a critical-severity finding.

### Backend abstraction (`Internal/MlKemBackend.cs`, `Internal/MlDsaBackend.cs`)

- **`#if NET10_0_OR_GREATER` correctness.** The native branch must use
  `System.Security.Cryptography.MLKem` / `MLDsa`; the `#else` branch
  must use BouncyCastle. Any path that calls BouncyCastle under
  `NET10_0_OR_GREATER`, or that hard-codes the native types on `net8.0`,
  is a finding.
- **Encoded format compatibility.** BC's
  `MLKemPrivateKeyParameters.WithPreferredFormat(SeedAndEncoding)` is
  required for byte-compatibility with the native FIPS-203 2400-byte
  encoding. A path that uses `SeedOnly` or `EncodingOnly` would produce
  a 1312-byte blob that doesn't round-trip with native — finding.

### Wire format & deserialization

- **Length check FIRST, then algorithm-id check, then component slicing.**
  Out-of-order checks can leak partial information via timing or via
  the *type* of exception thrown.
- **`PostQuantumHybridException` is preferred over bare
  `CryptographicException`** for parse failures so callers can branch
  on `HybridFailureReason`. Flag a `throw new CryptographicException(...)`
  in parser code where the typed equivalent would convey more.
- **Algorithm-id mismatch between artifacts** (e.g. decapsulating
  with a private key of one algorithm and a ciphertext of another) is
  caught explicitly in `HybridKem.Decapsulate`. Verify the same check
  exists in any future cross-artifact API.

### Memory hygiene

- **`CryptographicOperations.ZeroMemory` on every secret buffer**
  before it goes out of scope: KEM shared secret, AES key, X25519
  shared secret. Flag any path that allocates a secret and lets the GC
  reclaim it un-zeroed.
- **Dispose ordering.** In `HybridKemKeyPair.Dispose`, the private key
  is disposed (which zeros it). In `HybridKemEncapsulationResult.Dispose`,
  the shared secret is zeroed. A path that overwrites these buffers
  after zero-out (e.g. a reuse-after-dispose) is a finding.
- **Stack-allocated secret material** via `stackalloc Span<byte>` is
  fine — the JIT zeros stack on return. Flag *heap-allocated* secrets
  that lack explicit `ZeroMemory`.

### Concurrency

- **`HybridKem` and `HybridSignature` are static facades and must be
  thread-safe.** Each call constructs its own ephemeral state. Flag
  any shared static mutable state.
- **Private-key types are NOT documented thread-safe.** Sharing a
  `HybridKemPrivateKey` across threads simultaneously is undefined.
  Flag a `samples/` or AspNetCore path that shares one instance
  unprotected.
- **`RotatingHybridKemKeyProvider` / `RotatingHybridSignatureKeyProvider`**
  use a lock for the swap. Verify:
  (a) the lock covers both the public-key and private-key field
      assignments,
  (b) the previously-active private key is disposed *after* the swap
      releases the lock (so an in-flight caller's handle stays valid),
  (c) disposal of the provider does not deadlock with a rotation in
      flight.

### Analyzer correctness

- **False positives are findings.** A PQH001–PQH005 rule that fires on
  code that is in fact safe is a usability bug. Cite the safe pattern
  it incorrectly flags.
- **False negatives are findings.** A documented misuse the rule
  should catch but doesn't is a usability bug. Cite a clear example.
- **Code-fix correctness.** `AddUsingDeclarationCodeFix` and
  `WrapVerifyCodeFix` must produce code that compiles AND has the same
  semantic effect as the manual fix. A fix that drops trivia, changes
  evaluation order, or breaks subsequent statements is a finding.

### Sample correctness

- **Samples are reference architecture.** A misuse in `samples/` will
  be copied into production. Apply every rule above with the same
  rigor as for `src/`.
- **The `samples/WebApiDemo` generates ephemeral keys on startup**
  for demo purposes. This is documented in the sample's own comments;
  not a finding. A production app that does the same IS a misuse, but
  the sample says so.

### AspNetCore wiring

- **`HybridCryptoOptions`.** Inline PEM wins over file path. Both
  empty for a family means the provider throws on first use, not at
  registration. Verify this matches `src/PostQuantum.Hybrid.AspNetCore/KeyProviderFactory.cs`.
- **File permissions.** The `KeyPersistence` sample tightens private-
  key file perms on Unix. Verify the AspNetCore loader does not
  silently relax them on writes (it shouldn't write at all — it only
  reads).

## Severity rubric (must be threat-modelled)

| Severity | Definition |
|---|---|
| **Critical** | A remote attacker with no prior access can forge a hybrid signature the library accepts, recover a hybrid KEM private key, decrypt an envelope they should not, cause the library to derive a predictable or attacker-influenced shared secret, or recover key material from memory. |
| **High** | A remote attacker can cause unauthenticated denial of service (parser crash, infinite loop, unbounded allocation), can be silently accepted under attacker-influenced conditions, can race a `RotatingHybrid*KeyProvider` into an inconsistent state under realistic load, or can produce a silent downgrade from hybrid to single-primitive security. |
| **Medium** | An interop / reliability bug an attacker cannot trigger directly but that breaks the documented wire format, causes round-trip failures under non-adversarial load, or that an analyzer false negative actively encourages misuse of. |
| **Low** | A correctness or code-quality bug with no security impact — a wrong default a careful operator overrides, a wasteful pattern, a misleading comment. |
| **Info** | A note worth recording but not a bug — dead code, possible future refactor, design observation. |

If you cannot articulate the threat model, the finding is not Critical
or High. Default to Low / Info unless the model is concrete. A threat
model that names only attacker-controlled inputs as preconditions —
"the attacker sends the ciphertext," "the attacker controls the public
key," "the attacker chooses the message" — articulates nothing the
rubric did not already assume for a remote attacker, and earns at most
Medium. Critical and High require at least one non-trivial precondition
the attacker does NOT control by default: a misconfiguration, a
specific server state, prior compromise of a different system, or a
race the attacker must win.

## Output contract

Produce **one Markdown file**, with this exact top-level structure (the
maintainer parses it; deviations slow the response loop):

````markdown
# <reviewer-name>: PostQuantum.Hybrid — Whole-Repo Bug Audit

**Auditor:** <name-or-model-id>
**Date:** YYYY-MM-DD
**Commit:** <40-char SHA of the tree you audited, OR
`unavailable — no git access` if you cannot determine one>
**Scope:** Every source file under `src/**/*.cs` and `samples/**/*.cs`
(the two globs in the audit prompt).
**Method:** File-by-file read. No sampling. All findings proven from
code actually present.

---

## File inventory

Two tables — one per scope area, carrying the **final** finding
counts. These are the same tables you produced at the very start with
blank "Bugs" columns; update the counts in place as findings land. Do
not emit a duplicate inventory. Files with zero findings stay in the
table so the maintainer can see they were covered.

### Core libraries (`src/`)

| File | Bugs |
|---|---:|
| `src/PostQuantum.Hybrid/HybridKem.cs` | 0 |
| `…` | `…` |

### Samples (`samples/`)

| File | Bugs |
|---|---:|
| `…` | `…` |

---

## Summary

| # | File | Severity | Category | One-line description |
|---|---|---|---|---|
| 1 | `samples/…/X.cs` | High | Key handling | … |
| 2 | `src/…/Y.cs` | Medium | Wire format | … |

---

## Findings

One `### BUG-N · Severity · Category` heading per finding, in Summary
order. Each finding contains the **Evidence block** quoted from the
file, followed by a **Fix** paragraph proposing the smallest correct
change in prose. Do NOT apply the fix to the code.

### BUG-1 · High · Key handling

**File:** `samples/.../X.cs`
**Lines:** L–L  (the exact range read)

```csharp
// BUG: …
// PROOF: …
// TRIGGER: …
// SEVERITY: …
<verbatim source lines from the file>
```

**Fix:** <smallest correct change, in prose; no patch>. Prose only — a
Fix containing a code block (C# patch, diff, before/after snippet, or
otherwise) is malformed. The maintainer wants the *idea* of the fix
so they can implement it; your draft of the code goes in the bin.

---

## Previously-found bugs

If you do not have filesystem search or directory-listing tools (e.g.
you are running in a chat UI on a pasted prompt, not as an agent with
workspace access), write "No filesystem access — section skipped." and
move on. Do not invent prior reviewer files to satisfy the structural
demand of this section.

Otherwise, list the files at the repo root whose names match
`*audit*.md`, `*bugs*.md`, `*review*.md`, or `findings*.md`
(case-insensitive). If none exist on this audit, write "None on file."
and move on. Otherwise, for each finding in each prior file, verify
whether it is still present in current source:

- **FIXED** items cite the Resolution commit by SHA.
- **REMAINS** items cite the current `file:line` where the bug still
  exists, with the same evidence discipline as a new finding.

Do NOT include speculative or unproven re-flags.

---

## Coverage statement

One paragraph stating which files were fully read and which were
skipped (must match the "Out of scope" list in the prompt). End with
the exact sentence:

> Entire requested repository scope has been covered. <N> proven
> bug(s) reported.

---

## Suspected, unproven (optional, max 3 items)

Up to three items where you saw something that *might* be a bug but
could not prove from current code. Each item must rest on **partial
evidence from a file you actually read** — cite the `file:line` you
were looking at when the suspicion formed. State exactly what
additional evidence would be needed to convert it into a finding — a
test run, a specific input, a clarification from the maintainer. Pure
speculation with no code in hand belongs in neither Findings nor here.
Pad this section and the whole audit loses value. Items from the
**Pre-stated NOT bugs** list do not belong here; if you believe a
documented design decision is wrong, that is a discussion to open
separately, not an audit finding.
````

## Rules

1. **No fixes.** Audit only. Propose the smallest correct change in
   prose; do not patch the code.
2. **No padding.** Empty sections beat fabricated findings.
3. **No speculation in findings.** Move uncertain items to "Suspected,
   unproven" or omit them. When in doubt between a Finding and a
   Suspected entry, default to Suspected — a wrongly-cited
   high-confidence finding damages the audit more than a missing one,
   because the maintainer stops trusting the rest of the report.
4. **No re-flagging the Pre-stated NOT bugs** unless you demonstrate
   the implementation deviates from the documented design.
5. **Cite file:line for every claim.** Hallucinated paths or line
   numbers poison the entire audit; the maintainer discards the report
   after the first wrong cite. If you couldn't open the file, say so.
6. **Severity must be threat-modelled.** Critical / High require an
   articulated attacker model.
7. **One file, one delivery.** Don't deliver findings piecemeal.

---

*To God be the glory — 1 Corinthians 10:31.*
