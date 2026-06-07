# ADR 0011: Typed exception taxonomy

**Status:** Accepted

## Context

v1's early implementation threw `CryptographicException` for every
structural failure (wrong length, unknown algorithm-id, mismatched
algorithm-ids between artifacts, missing primitive support). Callers
who wanted to react differently to "the blob is malformed" vs. "the
algorithm-id is wrong" had to string-match the exception message,
which is brittle and version-unstable.

## Options considered

### A. Keep throwing `CryptographicException`

Status quo. Simple. Doesn't give callers a way to branch.

### B. New, unrelated `PostQuantumHybridException` type

Breaks every existing `catch (CryptographicException)` handler in
calling code.

### C. `PostQuantumHybridException : CryptographicException` with a
typed reason (our choice)

Existing `catch (CryptographicException)` handlers still fire. Callers
that want to branch can `catch (PostQuantumHybridException ex) when
(ex.Reason == HybridFailureReason.UnsupportedAlgorithmId)`.

## Decision

Option C.

```csharp
public enum HybridFailureReason
{
    Unknown = 0,
    InvalidLength = 1,
    UnsupportedAlgorithmId = 2,
    AlgorithmMismatch = 3,
    PrimitiveNotSupported = 4,
}

public class PostQuantumHybridException : CryptographicException
{
    public HybridFailureReason Reason { get; }
    // ...
}
```

The library replaces every `throw new CryptographicException(...)` for
structural failures with the typed equivalent. Test sites that used
`Assert.Throws<CryptographicException>` were updated to
`Assert.ThrowsAny<CryptographicException>` (since `Throws<T>` is
exact-type) to preserve their original intent.

## Consequences

- **Back-compat preserved.** Inheriting from `CryptographicException`
  means the existing exception hierarchy continues to work.
- **Reasoning at catch sites.** Callers can branch on `Reason` without
  parsing exception messages.
- **Stable values.** `HybridFailureReason` is a public enum; values
  are stable in minor releases. New reasons can be added; existing
  values cannot be renumbered.
- **`AesGcm`-derived `AuthenticationTagMismatchException` is NOT
  rewrapped.** When `HybridEnvelope.Open` calls `aes.Decrypt` and the
  tag fails, the BCL's native exception type surfaces. This is
  intentional — callers that catch
  `AuthenticationTagMismatchException` specifically are usually doing
  AEAD-aware handling and we don't want to obscure that.
