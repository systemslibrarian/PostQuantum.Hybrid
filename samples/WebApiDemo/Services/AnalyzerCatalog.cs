// =============================================================================
// Catalog of PQH001-PQH005 — the Roslyn analyzers that ship in
// PostQuantum.Hybrid.Analyzers.
//
// Each entry's Title and DiagnosticMessage are the exact strings from the
// analyzer's DiagnosticDescriptor (see the linked source). The bad-code
// snippet would fire the rule under a normal `dotnet build`; the good-code
// snippet is the analyzer-clean replacement (and matches the canonical
// patterns the codebase enforces — `TreatWarningsAsErrors=true` + the
// analyzer reference together turn PQH001-PQH005 into build errors across
// the library, tests, samples, and benchmarks).
//
// Updating the catalog: when the analyzer rule text changes upstream
// (rare), refresh the corresponding Title / DiagnosticMessage by grepping
// for `MessageFormat` in the analyzer .cs file.
// =============================================================================

namespace PostQuantum.Hybrid.Samples.WebApiDemo.Services;

public static class AnalyzerCatalog
{
    public sealed record AnalyzerRule(
        string Id,
        string Title,
        string Severity,
        string ShortExplanation,
        string DiagnosticMessage,
        string BadCode,
        string GoodCode,
        string SourceUrl);

    public static readonly IReadOnlyList<AnalyzerRule> All = new[]
    {
        new AnalyzerRule(
            Id: "PQH001",
            Title: "PostQuantum.Hybrid disposable not declared with `using`",
            Severity: "Warning",
            ShortExplanation:
                "Hybrid private-key and encapsulation-result types zero their buffers on Dispose. " +
                "A local of one of those types declared without `using` leaks the buffers until GC " +
                "(potentially forever for shared statics).",
            DiagnosticMessage:
                "'enc' holds sensitive key material; declare with `using` so its buffers are zeroed on dispose",
            BadCode: """
                var pair = HybridKem.GenerateKeyPair();
                var enc  = HybridKem.Encapsulate(pair.PublicKey);
                // ... enc.SharedSecret used ...
                // Buffers stay in memory until GC fires.
                """,
            GoodCode: """
                using var pair = HybridKem.GenerateKeyPair();
                using var enc  = HybridKem.Encapsulate(pair.PublicKey);
                // Buffers are zeroed on scope exit, even if we throw.
                """,
            SourceUrl: "https://github.com/systemslibrarian/PostQuantum.Hybrid/blob/main/src/PostQuantum.Hybrid.Analyzers/HybridDisposeAnalyzer.cs"),

        new AnalyzerRule(
            Id: "PQH002",
            Title: "Hybrid KEM SharedSecret used as a key without HKDF",
            Severity: "Warning",
            ShortExplanation:
                "A hybrid KEM shared secret is uniform 32 bytes — coincidentally what AES-256 needs — " +
                "but using it directly loses domain separation across uses of the same exchange. " +
                "Feed it through HKDF.Expand with a purpose-specific `info` parameter.",
            DiagnosticMessage:
                "'enc.SharedSecret' is being passed directly to a symmetric primitive constructor; feed it through HKDF.Expand with a purpose-specific 'info' first",
            BadCode: """
                using var aes = new AesGcm(enc.SharedSecret, tagSizeInBytes: 16);
                // Direct use of the shared secret as the AES key — no domain
                // separation. Two uses of the same exchange share state.
                """,
            GoodCode: """
                var aesKey = new byte[32];
                try
                {
                    HKDF.Expand(
                        HashAlgorithmName.SHA256,
                        enc.Secret,             // typed wrapper (not raw byte[])
                        aesKey,
                        info: AeadLabel);       // purpose-specific
                    using var aes = new AesGcm(aesKey, tagSizeInBytes: 16);
                    // ... use aes ...
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(aesKey);
                }
                """,
            SourceUrl: "https://github.com/systemslibrarian/PostQuantum.Hybrid/blob/main/src/PostQuantum.Hybrid.Analyzers/SharedSecretWithoutHkdfAnalyzer.cs"),

        new AnalyzerRule(
            Id: "PQH003",
            Title: "HybridKem.Decapsulate called before HybridSignature.Verify",
            Severity: "Warning",
            ShortExplanation:
                "In sign-then-encrypt flows, the signature must be verified before any cryptographic " +
                "operation runs on the carried material. Decapsulating first derives a shared secret " +
                "from unauthenticated input and widens the attack surface (and can leak key-related " +
                "side channels).",
            DiagnosticMessage:
                "Decapsulating before verifying derives a shared secret from unauthenticated input; call HybridSignature.Verify first and abort on failure",
            BadCode: """
                // Decap runs on attacker-controlled bytes before authenticity is checked.
                var secret = HybridKem.Decapsulate(kemPriv, kemCt);
                if (!HybridSignature.Verify(sigPub, signedBody, sig))
                    throw new CryptographicException("bad signature");
                """,
            GoodCode: """
                // Verify FIRST. Only authenticated input reaches Decapsulate.
                if (!HybridSignature.Verify(sigPub, signedBody, sig))
                    throw new CryptographicException("bad signature");
                var secret = HybridKem.Decapsulate(kemPriv, kemCt);
                """,
            SourceUrl: "https://github.com/systemslibrarian/PostQuantum.Hybrid/blob/main/src/PostQuantum.Hybrid.Analyzers/DecapsulateBeforeVerifyAnalyzer.cs"),

        new AnalyzerRule(
            Id: "PQH004",
            Title: "HybridSignature.Verify result discarded",
            Severity: "Warning",
            ShortExplanation:
                "HybridSignature.Verify returns a bool. Discarding it lets the caller treat " +
                "unauthenticated input as authenticated — exactly the failure mode signatures exist " +
                "to prevent.",
            DiagnosticMessage:
                "The return value of HybridSignature.Verify must be checked; ignoring it is equivalent to skipping signature verification",
            BadCode: """
                // Result thrown away. Forgery is now indistinguishable from valid input.
                HybridSignature.Verify(sigPub, data, sig);
                ProcessAuthenticatedMessage(data);
                """,
            GoodCode: """
                if (!HybridSignature.Verify(sigPub, data, sig))
                    throw new CryptographicException("bad signature");
                ProcessAuthenticatedMessage(data);
                """,
            SourceUrl: "https://github.com/systemslibrarian/PostQuantum.Hybrid/blob/main/src/PostQuantum.Hybrid.Analyzers/IgnoredVerifyResultAnalyzer.cs"),

        new AnalyzerRule(
            Id: "PQH005",
            Title: "AES-GCM call inside a hybrid KEM flow without associatedData binding",
            Severity: "Warning",
            ShortExplanation:
                "When AES-GCM is keyed from a hybrid KEM exchange, binding the KEM ciphertext into " +
                "associatedData prevents an attacker from swapping ciphertexts to re-key the AEAD " +
                "against a different exchange.",
            DiagnosticMessage:
                "AesGcm.Encrypt is called without 'associatedData' but the same method uses hybrid KEM; bind the KEM ciphertext as associatedData",
            BadCode: """
                using var aes = new AesGcm(aesKey, tagSizeInBytes: 16);
                aes.Encrypt(nonce, plaintext, ciphertext, tag);
                // No associatedData. Swapping kemCt for a different exchange's
                // ciphertext can re-key the AEAD without detection.
                """,
            GoodCode: """
                using var aes = new AesGcm(aesKey, tagSizeInBytes: 16);
                aes.Encrypt(
                    nonce, plaintext, ciphertext, tag,
                    associatedData: kemCt);     // binds the KEM exchange in
                """,
            SourceUrl: "https://github.com/systemslibrarian/PostQuantum.Hybrid/blob/main/src/PostQuantum.Hybrid.Analyzers/AeadWithoutKemBindingAnalyzer.cs"),
    };
}
