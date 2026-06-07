# LargeFileEncryption — chunked file encryption with PostQuantum.Hybrid

PostQuantum.Hybrid and its Envelopes package operate on complete byte
spans. For multi-gigabyte files you don't want the entire payload in
memory at once. This sample shows the canonical streaming pattern:

- **One** hybrid KEM exchange against the recipient's public key.
- **One** HKDF-derived AES-256-GCM master key, bound to the KEM
  ciphertext.
- **Chunked AES-GCM**, with the chunk index and a final-flag in
  associated data so reordered or truncated chunks fail decryption.

## Usage

```bash
# 1. Recipient generates a hybrid KEM key pair.
dotnet run --project samples/LargeFileEncryption -- gen alice

# 2. Sender seals an input file.
dotnet run --project samples/LargeFileEncryption -- seal alice.pub.pem input.bin output.pqhl

# 3. Recipient opens.
dotnet run --project samples/LargeFileEncryption -- open alice.priv.pem output.pqhl recovered.bin
diff input.bin recovered.bin && echo OK
```

## Wire format

```
[ 4B  magic = "PQHL" ]
[ 1B  format version = 0x01 ]
[ 4B  chunk-size little-endian ]
[ 1121B hybrid KEM ciphertext ]
[ N times: [ encrypted chunk ] [ 16B tag ] ]
```

The associated-data for each AEAD chunk is:

```
"PQH-LFE v1 chunk" || chunkIndex(8B BE) || final-flag(1B)
```

The final chunk has `final-flag = 0x01`; all others `0x00`. If an
attacker truncates the file, the would-be-last chunk's AAD changes
(`0x00` → `0x01`), so its tag check fails. If an attacker reorders
chunks, their indices change, so their tags fail.

## What this sample does NOT show

- **Random access:** chunks must be opened in order because the AES-GCM
  tag is computed over the chunk's ciphertext + AAD; you can't decrypt
  chunk 47 without decrypting 0..46 first under this layout. If you
  need random access, use a deterministic per-chunk nonce + a separate
  manifest signed by the sender.
- **Streaming sign-then-encrypt:** add a hybrid signature over the
  entire file header + ciphertext if you need sender authentication.
- **Authenticated metadata:** filename, mode, mtime, etc. — these
  belong in the AAD of chunk 0 or in a separate signed manifest.
