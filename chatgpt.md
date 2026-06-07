# PostQuantum.Hybrid - Ideas For Becoming The Standard

This file is a strategy memo, not a promise list. The goal is to think clearly
about what would make PostQuantum.Hybrid the default, trusted .NET foundation
for hybrid post-quantum cryptography.

The short version: this repo does not win by shipping the most algorithms. It
wins by being the most trustworthy, best-documented, hardest-to-misuse option,
with a small stable core and excellent companion tooling.

## The thesis

PostQuantum.Hybrid should aim to become the boring default primitive layer for
.NET developers who need hybrid post-quantum KEM and signatures.

"The standard" here means:

- It is the first NuGet package people recommend for hybrid PQ primitives in
  .NET.
- Other packages build on it instead of re-implementing crypto locally.
- Security reviewers trust the docs because they match the code and the known
  gaps.
- Operators understand the runtime requirements, failure modes, and migration
  story before they deploy it.
- The repo is conservative in the right places: stable wire formats, no silent
  downgrade, no speculative algorithm buffet.

The repo already has strong bones for this:

- small public facades (`HybridKem`, `HybridSignature`)
- fixed-size versioned wire formats
- `net8.0` and `net10.0` support
- analyzers already started
- fuzz and benchmark projects already present
- samples already present
- clear security and threat-model docs

That is enough to justify aiming higher. The next step is not more surface
area. The next step is trust, coherence, misuse resistance, and ecosystem pull.

## The winning shape

If this repo becomes the standard, it probably looks like this:

- The core package stays narrow and disciplined.
- The documentation reads like a serious security product, not a code dump.
- The analyzer package catches the most common mistakes before runtime.
- The templates and samples make correct usage feel normal.
- Companion packages solve app-level integration problems without bloating the
  primitive layer.
- The project publishes enough assurance material that reviewers do not have to
  reverse-engineer intent from source.

That is the same playbook that makes a repo feel "real" instead of merely
interesting.

## Steal The Right Lessons From PostQuantum.Jwt

The other project's strongest qualities are worth copying directly:

- A README that positions the package honestly at the top, before any code.
- Explicit statements about what the package is, and is not.
- Operational tradeoff documentation, not just API examples.
- Reviewer-facing docs such as testing methodology, supply-chain notes, and a
  roadmap to a stable release.
- Samples that feel like realistic deployments rather than toy snippets.
- Tooling around the package, not just the package itself.

For this repo, the equivalent should be:

- a top-tier README/NuGet landing page
- reviewer docs for assurance and release verification
- excellent secure-usage guidance for primitives users
- stronger analyzer coverage
- production-shape samples and templates

## Principle: keep the core narrow

If the repo starts chasing every interesting idea inside the main package, it
will stop being standard and start being noisy.

Double down in core on:

- one default hybrid KEM combination
- one default hybrid signature combination
- stable wire formats
- import/export correctness
- fail-closed behavior
- disposal and zeroization discipline
- backend parity across TFMs

Push out of core into companion packages or samples:

- protocol negotiation
- remote key discovery
- ASP.NET Core conveniences
- session protocols
- message containers and file formats
- certificate and SPKI/PKCS#8 integration until standards settle

The standard primitive library should be small enough that a reviewer can hold
the whole public surface in their head.

## Immediate priority: eliminate trust-eroding drift

The fastest way to lose credibility is documentation that is no longer true.
This repo already has some of that drift:

- `KNOWN-GAPS.md` says there are no analyzers yet, but the analyzer package is
  already in-tree.
- `KNOWN-GAPS.md` says there is no template yet, but `templates/` exists.
- `KNOWN-GAPS.md` says there are no fuzz tests, but the fuzz project exists.
- `docs/design.md` still speaks about analyzers and templates as follow-up work.

That should be fixed before almost anything else. A security-oriented package is
only as believable as the alignment between README, gaps, roadmap, and code.

Concrete idea:

- Make "documentation coherence" a release gate.
- Treat stale roadmap claims as real bugs.
- Add one pass before every release that reconciles README, CHANGELOG,
  KNOWN-GAPS, SECURITY, and design docs.

## Make the README good enough to carry the package

Right now the README explains the core well, but "becoming the standard" means
the README has to do more than explain syntax.

It should eventually include the same caliber of sections that made
PostQuantum.Jwt feel complete:

- Read this first.
- What this package is, and is not.
- When to use it, and when not to use it.
- Public API at a glance.
- Security posture.
- Operational tradeoffs.
- Compatibility and runtime requirements.
- Analyzer and template tooling.
- Samples.
- Building and testing from source.

Important repo-specific framing for the top of the README:

- This is a primitives library, not a full protocol.
- It does not give replay protection, key distribution, negotiation, or
  freshness on its own.
- The KEM shared secret is KDF input, not an application payload.
- Hybrid signatures here are both-must-verify constructions, not a standard
  certificate/interoperability story.
- Interop with external ecosystems should not be implied where standards do not
  exist yet.

If the first page is excellent, the rest of the project gets easier.

## Assurance is the moat

If the ambition is to become the standard, assurance is the highest-leverage
technical investment after documentation coherence.

### 1. Add reviewer-facing assurance docs

Borrow the structure that worked well elsewhere:

- `docs/TESTING.md` explaining the test pyramid, exact commands, and what each
  suite proves.
- `docs/SUPPLY-CHAIN.md` explaining SourceLink, symbols, deterministic build
  posture, SBOM, provenance, and how to verify a release.
- `docs/ROADMAP-TO-1.0.md` explaining what blocks the repo from claiming a
  stronger maturity level.

These docs turn "trust us" into "here is the evidence surface."

### 2. Deepen the test corpus

High-value additions:

- known-answer tests for both backends where feasible
- cross-backend golden vectors for import/export and round-trip behavior
- a negative corpus of malformed blobs pinned in files, not only inline tests
- explicit tests for all parser and import failure classes
- end-to-end corpus files that future versions must continue to parse

The standard package is the one that future maintainers are afraid to break.

### 3. Upgrade fuzzing

The property-style fuzz project is already a good start. To raise the bar:

- run the current fuzz suite in CI
- add coverage-guided fuzzing via SharpFuzz or an equivalent harness
- keep public parser entry points under fuzz continuously
- treat any unexpected exception type as a release blocker

Parser robustness is part of the product, not just test garnish.

### 4. Add mutation testing where it matters

Focus mutation testing on:

- wire-format parsing
- length and algorithm-id checks
- fail-closed branching
- disposal guards
- verification and tamper-detection paths

This is especially useful for a library whose surface is small but security
critical.

### 5. Make performance regressions visible

Benchmarks already exist. To make them matter:

- publish benchmark baselines per platform/backend
- add a CI comparison job
- document expected net8 vs net10 deltas
- expose measured sizes and throughput numbers in docs instead of leaving them
  hidden in BenchmarkDotNet output

People deciding whether to adopt the library need cost data, not vibes.

## Build a misuse-resistance story, not just an API

The analyzer package is one of the most important assets in this repo. It is how
the library becomes harder to misuse than raw BCL plus BouncyCastle code.

The next analyzer ideas should be very selective: high-signal, low-false-
positive rules that encode the repo's hard security guidance.

Strong candidates:

- `PQH002`: using `SharedSecret` directly as a crypto key or as plaintext
  instead of deriving a context-specific key with HKDF
- `PQH003`: verify-after-decrypt or verify-after-decapsulate ordering in
  sign-then-encrypt flows
- `PQH004`: ignored result of `HybridSignature.Verify(...)`
- `PQH005`: KEM-derived AEAD encryption without binding the KEM ciphertext as
  `associatedData`
- `PQH006`: long-lived disposable hybrid key material created without an
  ownership pattern the analyzer can recognize

Also worth doing:

- code fixes where feasible
- docs pages for each rule with good/bad examples
- sample projects that intentionally trigger each rule

If the analyzer package gets good enough, it becomes a major reason to adopt the
ecosystem instead of using the primitives directly.

## Companion packages should create pull without polluting the core

The repo can become standard partly by being the substrate under several very
useful, focused sibling packages.

### Best companion package candidate: PostQuantum.Hybrid.AspNetCore

Not as a crypto kitchen sink. As a thin, boring integration layer.

Good scope:

- DI registrations
- key-loading helpers
- health checks that verify crypto backend availability
- background key rotation / reload helpers
- options objects that keep secure defaults obvious

Bad scope:

- inventing a new secure messaging protocol in middleware
- hiding all cryptographic decisions behind magic abstractions
- broad multi-algorithm negotiation

The standard path is usually: small primitive package, then thin ecosystem
packages that make correct wiring easy.

### Other high-value companion ideas

- `PostQuantum.Hybrid.Envelopes`: explicit, opinionated message envelopes for
  common sign-then-encrypt workflows, if kept tightly scoped and spec'd
- `PostQuantum.Hybrid.Testing`: fixtures, corpus helpers, and deterministic
  reference materials for consumer test suites
- `PostQuantum.Hybrid.KeyManagement`: only if there is a real need and a clear
  interface, not as speculative architecture

The rule should be: companion packages solve recurring integration pain, not
invent new categories of software.

## Samples need to feel production-shaped

Samples are part of the product story. The current repo already has a good set
of starting points, but to become the standard they should read like reference
implementations.

Highest-value sample upgrades:

- `SecureMessenger` should be the canonical sign-then-encrypt sample with
  verify-before-decapsulate, HKDF context binding, AEAD AAD binding, and clear
  failure behavior.
- A file-encryption sample should show envelope encryption, key persistence,
  tamper detection, and safe metadata handling.
- A signed-document sample should show detached signatures, storage format, and
  verification failures that are easy to reason about.
- A key-rotation sample should show import/export, versioned key IDs, and
  migration behavior.

Good samples reduce both misuse and support burden.

## Templates should be first-class, not hidden

The template work is already underway. To turn it into adoption leverage:

- publish the template package and link it from the root README
- make the scaffold include analyzers by default
- include a secure-usage note in the generated project
- consider a second template once the ecosystem grows, such as a minimal web
  API or secure-messaging starter

Templates are how a package starts shaping norms instead of merely offering
features.

## Standardization strategy: do not confuse being useful with being universal

Becoming the standard does not require pretending the ecosystem is further
along than it is.

The right standards posture is:

- keep the current wire format stable and well specified
- publish exact byte layouts and parsing rules
- publish interop vectors, even if only within .NET at first
- track LAMPS and related hybrid/composite key work closely
- add PKCS#8/SPKI only when the standards picture is stable enough to avoid
  locking in the wrong shape
- if moving to a different combiner or algorithm suite, use a new algorithm-id
  and keep old material parseable

That last point matters. "The standard" package is not the one that changes its
mind casually on wire contracts.

## Release quality should feel enterprise-grade

This repo should eventually have the release discipline people expect from a
standard security library:

- package signing
- SBOM generation
- deterministic-build posture
- SourceLink and symbol packages
- release notes that call out security-relevant changes clearly
- a documented verification path for consumers
- package validation against prior versions to catch accidental API breaks

This matters more than it sounds. Many teams choose dependencies based as much
on operational confidence as on code quality.

## An external review is eventually mandatory

If the stated ambition is "become the standard," then at some point the project
needs a concrete independent-review plan.

That does not mean pretending an audit exists today. It means preparing for one
well:

- spec complete and reconciled with code
- threat model current
- known gaps honest
- tests documented
- vectors published
- release process documented
- misuse guidance explicit

An audit lands much better when the repo is already easy to review.

## Good comparisons to add

A future README or docs section should compare PostQuantum.Hybrid against the
closest alternatives or fallback choices:

- direct use of raw BouncyCastle
- direct use of .NET 10 PQ primitives plus hand-written X25519/Ed25519 wiring
- classical-only libraries for teams that are not actually ready for PQ

The comparison should explain why this package exists:

- fewer misuse opportunities
- one coherent wire format
- backend abstraction already solved
- stronger docs and analyzers
- stable versioning and migration posture

If people can immediately see why the repo exists, adoption gets easier.

## Things not to do

These are attractive traps that would probably hurt the repo:

- Do not add lots of algorithm combinations just because they are available.
- Do not let protocol helpers bloat the primitive package.
- Do not imply generic interop where standards are not ready.
- Do not make the docs sound more mature than the evidence supports.
- Do not add analyzer rules with high false-positive rates just to increase the
  count.
- Do not chase browser/WASM support unless there is a clear threat model,
  runtime story, and user need.
- Do not turn roadmap docs into stale marketing.

The package should feel disciplined, not restless.

## The best order of operations

If I had to prioritize the work in the order most likely to make this repo feel
like the standard, I would do it in this sequence:

1. Reconcile all docs with the current repo reality.
2. Rewrite the README and NuGet package page to the same quality bar as
   PostQuantum.Jwt.
3. Publish reviewer-facing docs: testing, supply chain, and roadmap-to-1.0.
4. Promote analyzers, templates, and samples to first-class documented features.
5. Expand analyzers with only the highest-signal misuse rules.
6. Add coverage-guided fuzzing, mutation testing, and benchmark baselines.
7. Harden release transparency: SBOM, provenance, package signing, API
   baseline checks.
8. Improve the production-shape samples until they feel reference-quality.
9. Ship a thin ASP.NET Core companion package if real usage justifies it.
10. Prepare and pursue an external review.

That order compounds trust. It does not just add features.

## Final thought

The standard library in a security-sensitive space is rarely the flashiest one.
It is the one that is hardest to misuse, easiest to review, honest about its
limits, stable under pressure, and backed by an ecosystem that makes the right
thing the easy thing.

PostQuantum.Hybrid can plausibly become that package if it keeps the core small
and spends the next round of effort on coherence, assurance, analyzers,
templates, and production-grade documentation.