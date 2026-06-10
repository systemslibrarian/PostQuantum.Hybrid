namespace PostQuantum.Hybrid.Internal;

internal static class AlgorithmSizes
{
    // X25519 (RFC 7748)
    public const int X25519PublicKeyBytes = 32;
    public const int X25519PrivateKeyBytes = 32;
    public const int X25519SharedSecretBytes = 32;

    // Ed25519 (RFC 8032)
    public const int Ed25519PublicKeyBytes = 32;
    public const int Ed25519PrivateKeyBytes = 32;
    public const int Ed25519SignatureBytes = 64;

    // ML-KEM-768 (FIPS 203)
    public const int MlKem768PublicKeyBytes = 1184;
    public const int MlKem768PrivateKeyBytes = 2400;
    public const int MlKem768CiphertextBytes = 1088;
    public const int MlKem768SharedSecretBytes = 32;

    // ML-DSA-65 (FIPS 204)
    public const int MlDsa65PublicKeyBytes = 1952;
    public const int MlDsa65PrivateKeyBytes = 4032;
    public const int MlDsa65SignatureBytes = 3309;

    // Hybrid wire-format sizes (algorithm-id byte + classical + post-quantum)
    public const int HybridKemPublicKeyBytes  = 1 + X25519PublicKeyBytes  + MlKem768PublicKeyBytes;   // 1217
    public const int HybridKemPrivateKeyBytes = 1 + X25519PrivateKeyBytes + MlKem768PrivateKeyBytes;  // 2433
    public const int HybridKemCiphertextBytes = 1 + X25519PublicKeyBytes  + MlKem768CiphertextBytes;  // 1121
    public const int HybridSharedSecretBytes  = 32;

    // IETF X-Wing (draft-connolly-cfrg-xwing-kem), algorithm-id 0x03.
    // Public key and ciphertext sizes coincide with the v1 hybrid sizes
    // (1217 / 1121 with the algorithm-id byte) but the component order is
    // post-quantum-first and the private key is a bare 32-byte seed.
    public const int XWingSeedBytes            = 32;
    public const int XWingExpandedBytes        = 96;  // SHAKE-256(seed, 96)
    public const int MlKem768KeyGenSeedBytes   = 64;  // FIPS 203 d || z
    public const int XWingPublicKeyBytes       = MlKem768PublicKeyBytes + X25519PublicKeyBytes;   // 1216
    public const int XWingCiphertextBytes      = MlKem768CiphertextBytes + X25519PublicKeyBytes;  // 1120
    public const int XWingHybridPrivateKeyBytes = 1 + XWingSeedBytes;                             // 33

    public const int HybridSigPublicKeyBytes  = 1 + Ed25519PublicKeyBytes  + MlDsa65PublicKeyBytes;   // 1985
    public const int HybridSigPrivateKeyBytes = 1 + Ed25519PrivateKeyBytes + MlDsa65PrivateKeyBytes;  // 4065
    public const int HybridSignatureBytes     = 1 + Ed25519SignatureBytes  + MlDsa65SignatureBytes;   // 3374
}
