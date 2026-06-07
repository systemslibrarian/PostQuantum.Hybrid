# ADR 0010: AspNetCore key rotation via FileSystemWatcher

**Status:** Accepted

## Context

`PostQuantum.Hybrid.AspNetCore`'s v1 release shipped
`IHybridKemKeyProvider` and `IHybridSignatureKeyProvider` as
singletons that load keys once at app startup. Key rotation required a
host restart.

Production deployments need a way to roll keys without restarting:

- Long-lived signing keys reach end-of-life on a rotation schedule.
- An incident response may require an emergency key swap.
- Multiple-instance deployments don't want all instances bouncing
  simultaneously.

## Options considered

### A. `IOptionsMonitor<HybridCryptoOptions>` reload

ASP.NET Core's built-in mechanism for live-reloadable config. Works for
inline-PEM keys via `appsettings.json` reload, but doesn't help for the
common path where keys are mounted as files (e.g. K8s `Secret` volumes
that update via symlink swap).

### B. `FileSystemWatcher` on the key files (our choice)

Watches the two PEM file paths (public + private). On either changing,
re-load both, atomically swap the active key pair, dispose the old
private key, raise a `Rotated` event.

### C. Cron-style polling

Reload every N seconds regardless of file changes. Simple but burns
CPU and disk IO for nothing in the common case where keys don't
change.

## Decision

Option B with a 50 ms debounce.

- New interfaces: `IRotatingHybridKemKeyProvider`,
  `IRotatingHybridSignatureKeyProvider` (extend the non-rotating
  interfaces; add `Version` and `Rotated` event).
- New DI helpers: `services.AddRotatingHybridKemKeys(pubPath, privPath)`
  and `services.AddRotatingHybridSignatureKeys(pubPath, privPath)`.
- The rotating provider also satisfies the non-rotating
  `IHybridKem(/Sig)KeyProvider` interface, so existing consumer code
  works unchanged.

## Implementation notes

- The swap holds a lock that covers BOTH public-key and private-key
  field assignment. A reader sees either old or new pair, never mixed.
- The PRIOR private key is disposed *after* the lock releases. In-
  flight callers that obtained the prior `PrivateKey` reference before
  the swap retain a valid handle until they release it.
- The 50 ms debounce handles the "atomic rename + truncate" pattern
  most editors and `kubectl create secret` use, where the file
  briefly exists in a half-written state.
- Reload failures (corrupt PEM, partial write) are logged and the
  current key pair is kept. The provider does NOT crash on a bad
  reload.

## Consequences

- Operators can rotate keys live: write new PEMs over the old paths,
  the next AspNetCore request uses the new keys.
- An `IDataProtector`-style adapter (the next obvious addition) can
  rotate transparently via the same mechanism.
- We do NOT support per-key versioned routing in v1: a blob protected
  with version N can only be unprotected with version N. Adopters
  needing read-old-write-new rotation will need a custom
  `IHybridKemKeyProvider` that holds multiple decapsulation keys
  selected by an inline version byte.
