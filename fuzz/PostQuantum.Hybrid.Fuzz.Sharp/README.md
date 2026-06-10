# PostQuantum.Hybrid.Fuzz.Sharp — coverage-guided fuzzing

Companion to the in-tree property-style fuzz project
(`fuzz/PostQuantum.Hybrid.Fuzz`). This harness wires the library's
public parsers to [SharpFuzz](https://github.com/Metalnem/sharpfuzz)
so a Linux AFL or libFuzzer driver can discover inputs that exercise
new code paths.

The harness runs weekly in CI: `.github/workflows/fuzz.yml` drives
every target under AFL++ for a time-boxed run (one matrix job per
target) and fails on any crash. The property-style fuzz project
covers the day-to-day "did this commit introduce a parser crash"
need; truly long-running fuzzing on a dedicated machine is still a
worthwhile upgrade (see `KNOWN-GAPS.md`).

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
# Generate one minimal-valid seed per target into corpus/<target>/.
dotnet fuzz/PostQuantum.Hybrid.Fuzz.Sharp/bin/Release/net10.0/PostQuantum.Hybrid.Fuzz.Sharp.dll \
    make-corpus corpus

AFL_SKIP_BIN_CHECK=1 afl-fuzz \
    -i corpus/kem-public-key \
    -o findings \
    -t 10000 -m 10240 \
    -- dotnet fuzz/PostQuantum.Hybrid.Fuzz.Sharp/bin/Release/net10.0/PostQuantum.Hybrid.Fuzz.Sharp.dll kem-public-key
```

`AFL_SKIP_BIN_CHECK=1` is required: afl-fuzz checks that the target
binary is instrumented, but here the *managed DLL* carries the
instrumentation, not `dotnet` itself.

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

The checked-in `Corpus/` directory is intentionally empty: seeds are
generated fresh by the harness's `make-corpus` mode (one
minimal-valid blob per target), both locally and in CI. Add
interesting inputs to your generated corpus directory to bias the
fuzzer toward your area of interest.
