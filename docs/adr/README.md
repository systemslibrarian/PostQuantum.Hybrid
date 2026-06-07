# Architecture Decision Records

Each ADR captures one significant architectural decision: the context, the
options considered, what we picked, and why.

| # | Decision |
|---|---|
| [0001](0001-x25519-mlkem768-default.md) | X25519 + ML-KEM-768 as the default hybrid KEM |
| [0002](0002-ed25519-mldsa65-default.md) | Ed25519 + ML-DSA-65 as the default hybrid signature |
| [0003](0003-kem-combiner.md) | HKDF-SHA256 KEM combiner with transcript binding |
| [0004](0004-signature-concat.md) | Concatenated, both-must-verify signature combiner |
| [0005](0005-multi-target-net8-net10.md) | Multi-target net8.0 and net10.0 |
| [0006](0006-backend-abstraction.md) | Backend abstraction for ML-KEM and ML-DSA |
| [0007](0007-versioned-wire-format.md) | Versioned wire format with algorithm-id byte |
| [0008](0008-bouncycastle-only-dependency.md) | Single optional dependency: BouncyCastle |

Status legend: **Accepted** • **Superseded** • **Deprecated**
