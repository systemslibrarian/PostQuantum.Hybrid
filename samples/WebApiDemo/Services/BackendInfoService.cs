// =============================================================================
// Backend transparency.
//
// The library's MlKemBackend / MlDsaBackend pick between the native
// System.Security.Cryptography.MLKem / MLDsa primitives and BouncyCastle at
// runtime, depending on whether the BCL on this platform supports them (see
// ADR 0012). For a playground that calls itself a "gold-standard reference
// implementation" we want the live page to TELL the visitor which backend is
// running — otherwise the OpenSSL-3.5 detail in the Dockerfile becomes a
// black-box claim. This service captures the same signal at startup so the
// Razor header badge can display it.
// =============================================================================

using System.Runtime.InteropServices;
#if NET10_0_OR_GREATER
using System.Security.Cryptography;
#endif

namespace PostQuantum.Hybrid.Samples.WebApiDemo.Services;

/// <summary>
/// Snapshots which ML-KEM / ML-DSA backend resolved at app startup so the
/// playground can show the visitor whether the live container is exercising
/// the native .NET 10 BCL or the BouncyCastle fallback.
/// </summary>
public sealed class BackendInfoService
{
    public BackendInfoService()
    {
#if NET10_0_OR_GREATER
        NativeKemSupported = MLKem.IsSupported;
        NativeDsaSupported = MLDsa.IsSupported;
#else
        NativeKemSupported = false;
        NativeDsaSupported = false;
#endif

        KemBackendName       = NativeKemSupported ? "native .NET 10 (System.Security.Cryptography.MLKem)" : "BouncyCastle";
        SignatureBackendName = NativeDsaSupported ? "native .NET 10 (System.Security.Cryptography.MLDsa)" : "BouncyCastle";
        RuntimeFramework     = RuntimeInformation.FrameworkDescription;
        OSDescription        = RuntimeInformation.OSDescription;
        NativePqAvailable    = NativeKemSupported && NativeDsaSupported;
    }

    /// <summary>True when the runtime BCL exposes both <c>MLKem</c> and <c>MLDsa</c>.</summary>
    public bool NativePqAvailable { get; }

    /// <summary>True when the runtime BCL exposes <c>MLKem</c>.</summary>
    public bool NativeKemSupported { get; }

    /// <summary>True when the runtime BCL exposes <c>MLDsa</c>.</summary>
    public bool NativeDsaSupported { get; }

    /// <summary>Human-readable name of the resolved ML-KEM backend.</summary>
    public string KemBackendName { get; }

    /// <summary>Human-readable name of the resolved ML-DSA backend.</summary>
    public string SignatureBackendName { get; }

    /// <summary>.NET runtime description (e.g. <c>.NET 10.0.0</c>).</summary>
    public string RuntimeFramework { get; }

    /// <summary>Operating-system description.</summary>
    public string OSDescription { get; }

    /// <summary>Short label for the header badge.</summary>
    public string ShortLabel =>
        NativePqAvailable ? "native .NET 10" : "BouncyCastle fallback";

    /// <summary>Tooltip / aria-label text for the header badge.</summary>
    public string DetailedLabel =>
        $"ML-KEM backend: {KemBackendName}. " +
        $"ML-DSA backend: {SignatureBackendName}. " +
        $"Runtime: {RuntimeFramework}. " +
        $"OS: {OSDescription}.";
}
