# MeshCore Radio Wire Protocol Compliance

## Pinned upstream commit

| Reference | Value |
|-----------|-------|
| MeshCore commit | [`07a3ca9`](https://github.com/meshcore-dev/MeshCore/commit/07a3ca9) |
| Merged | 2026-06-06 ("Merge branch 'dev'") |

All compliance claims below refer to this exact upstream revision.

---

## Compliance matrix

| Feature | Decode | Encode | Strict validation | Go test vectors | JS/WASM parity |
|---------|:------:|:------:|:-----------------:|:---------------:|:--------------:|
| Generic frame | ✅ | ✅ | ✅ | ✅ | ☐ |
| Transport routes | ✅ | ✅ | ✅ | ✅ | ☐ |
| 1-byte path hashes | ✅ | ✅ | ✅ | ✅ | ☐ |
| 2-byte path hashes | ✅ | ✅ | ✅ | ✅ | ☐ |
| 3-byte path hashes | ✅ | ✅ | ✅ | ✅ | ☐ |
| Reserved path mode 0b11 | ❌ rejected | ❌ rejected | ✅ | ✅ | ☐ |
| Path ≤ 64 bytes | ✅ | ✅ | ✅ | ✅ | ☐ |
| Payload ≤ 184 bytes | ✅ | ✅ | ✅ | ✅ | ☐ |
| Hop count ≤ 63 | ✅ | ✅ | ✅ | ✅ | ☐ |
| Version = 0 only | ✅ | ✅ | ✅ | ✅ | ☐ |
| `0x00` REQ | ✅ | ✅ | ✅ | ✅ | ☐ |
| `0x01` RESPONSE | ✅ | ✅ | ✅ | ✅ | ☐ |
| `0x02` TXT_MSG | ✅ | ✅ | ✅ | ✅ | ☐ |
| `0x03` ACK | ✅ | ✅ | ✅ | ✅ | ☐ |
| `0x04` ADVERT | ✅ | ✅ | ✅ | ✅ | ☐ |
| `0x05` GRP_TXT | ✅ | ✅ | ✅ | ✅ | ☐ |
| `0x06` GRP_DATA | ✅ | ✅ | ✅ | ✅ | ☐ |
| `0x07` ANON_REQ | ✅ | ✅ | ☐ | ✅ | ☐ |
| `0x08` PATH | ✅ | ☐ | ☐ | ✅ | ☐ |
| `0x09` TRACE | ✅ | ✅ | ✅ | ✅ | ☐ |
| `0x0A` MULTIPART | ✅ | ✅ | ✅ | ✅ | ☐ |
| `0x0B` CONTROL | ✅ | ✅ | ☐ | ✅ | ☐ |
| `0x0C–0x0E` reserved | raw pass-through | ❌ rejected | ✅ | ✅ | ☐ |
| `0x0F` RAW_CUSTOM | ✅ raw pass-through | ✅ raw pass-through | ✅ | ✅ | ☐ |
| Ed25519 identity | ✅ | ✅ | ✅ | ✅ (Go–Go) | ☐ |
| Ed25519 → X25519 ECDH | ✅ | ✅ | ✅ | ✅ (Go–Go) | ☐ |
| ADVERT signature (create) | ✅ | ✅ | ✅ | ✅ | ☐ |
| ADVERT signature (verify) | ✅ | — | ✅ | ✅ | ☐ |
| Wire vs firmware semantics split | ✅ | ✅ | ✅ | ✅ | ☐ |
| Extensible decoder registry | ✅ | — | — | ✅ | ☐ |
| Firmware C++ oracle vectors | ☐ | ☐ | — | ☐ | ☐ |
| Fuzz all decoders | ☐ | — | — | ☐ | ☐ |

**Legend:**
- ✅ implemented and tested
- ☐ planned (see roadmap in README)
- ❌ explicitly rejected (by design)


## Known gaps

| Gap | Milestone |
|-----|-----------|
| PATH encoder (encode a ReturnedPath back to bytes) | M3 |
| ANON_REQ strict field validation | M3 |
| CONTROL strict sub-type validation | M3 |
| Firmware C++ oracle harness and cross-compiled vectors | M7 |
| Ed25519 ECDH firmware interop test (C++ ↔ Go) | M7 |
| Fuzz corpus for all public decoders | M8 |
| Go/WASM shared JSON fixture suite | M9 |
| Upstream drift detection CI job | M10 |
