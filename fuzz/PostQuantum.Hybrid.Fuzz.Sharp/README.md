# PostQuantum.Hybrid.Fuzz.Sharp — coverage-guided fuzzing

Companion to the in-tree property-style fuzz project
(`fuzz/PostQuantum.Hybrid.Fuzz`). This harness wires the library's
public parsers to [SharpFuzz](https://github.com/Metalnem/sharpfuzz)
so a Linux AFL or libFuzzer driver can discover inputs that exercise
new code paths.

The harness is not run in normal CI — coverage-guided fuzzing wants
long, continuous runs on a dedicated machine. The property-style fuzz
project covers the day-to-day "did this commit introduce a parser
crash" need.

## Setup (Linux)

```bash
# 1. Install AFL.
sudo apt install afl++ -y

# 2. Install SharpFuzz CLI.
dotnet tool install -g SharpFuzz.CommandLine

# 3. Build the harness Release.
dotnet build fuzz/PostQuantum.Hybrid.Fuzz.Sharp -c Release

# 4. Instrument the target DLL (one-time per build).
sharpfuzz fuzz/PostQuantum.Hybrid.Fuzz.Sharp/bin/Release/net10.0/PostQuantum.Hybrid.dll
```

## Running

```bash
mkdir -p fuzz/PostQuantum.Hybrid.Fuzz.Sharp/Findings

afl-fuzz \
    -i fuzz/PostQuantum.Hybrid.Fuzz.Sharp/Corpus \
    -o fuzz/PostQuantum.Hybrid.Fuzz.Sharp/Findings \
    -- dotnet fuzz/PostQuantum.Hybrid.Fuzz.Sharp/bin/Release/net10.0/PostQuantum.Hybrid.Fuzz.Sharp.dll kem-public-key
```

## Targets

| Target name | Drives |
|---|---|
| `kem-public-key`     | `HybridKemPublicKey.Import` |
| `kem-private-key`    | `HybridKemPrivateKey.Import` |
| `kem-ciphertext`     | `HybridKemCiphertext.FromBytes` |
| `sig-public-key`     | `HybridSignaturePublicKey.Import` |
| `sig-private-key`    | `HybridSignaturePrivateKey.Import` |
| `sig-verify`         | `HybridSignature.Verify` with a fresh keypair |
| `pem-kem-public-key` | `HybridKemPublicKey.ImportPem` (drives the base64 + label parser) |

## Pass / fail criteria

Any thrown exception type **other** than `CryptographicException`
(including `PostQuantumHybridException`), `FormatException`, or
`ArgumentException` is a fuzz finding. The harness's
`TryOrSwallow` deliberately lets unexpected exceptions propagate so
the fuzzer's `SIGSEGV`-detection trips on them.

## Seed corpus

The `Corpus/` directory is seeded with one minimal-valid blob per
target (generated during corpus build). Add interesting inputs there
to bias the fuzzer toward your area of interest.
