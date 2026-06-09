# meshpkt

[![Go Reference](https://pkg.go.dev/badge/github.com/meshcore-cz/meshpkt.svg)](https://pkg.go.dev/github.com/meshcore-cz/meshpkt)
[![npm](https://img.shields.io/npm/v/@meshcore-cz/meshpkt)](https://www.npmjs.com/package/@meshcore-cz/meshpkt)

> **Early development.** This library is a work in progress. APIs may change before v1.0 — pin to a specific version in production.

Compliance is tracked against a pinned upstream MeshCore commit. See [`COMPLIANCE.md`](COMPLIANCE.md) for the full feature matrix.

Pure Go codec for the MeshCore radio packet wire format. WASM-safe with a single small dependency ([`filippo.io/edwards25519`](https://pkg.go.dev/filippo.io/edwards25519)) for firmware-compatible Ed25519 identity exchange.

- **Go package:** [pkg.go.dev/github.com/meshcore-cz/meshpkt](https://pkg.go.dev/github.com/meshcore-cz/meshpkt)
- **npm package:** [@meshcore-cz/meshpkt](https://www.npmjs.com/package/@meshcore-cz/meshpkt) — TypeScript/WASM build for browsers
- **Full SDK:** [meshcore-go](https://github.com/meshcore-cz/meshcore-go) — client SDK, device transports, CLI

Key source: [MeshCore packet format](https://github.com/meshcore-dev/MeshCore/blob/main/docs/packet_format.md).

## Wire format

```
[header:1][transport_codes:0|4][path_len:1][path:N][payload]

header    = 0bVVPPPPRR
              RR   — route type (2 bits)
              PPPP — payload type (4 bits)
              VV   — version (2 bits)

path_len  = 0bSSHHHHHH
              HHHHHH — hop count (6 bits)
              SS     — (hashSize − 1) (2 bits) → hashSize = (byte >> 6) + 1

transport_codes — two uint16 LE values (4 bytes total), present only for
                  route types TRANSPORT_FLOOD (0x00) and TRANSPORT_DIRECT (0x03)
```

## Packet types

| Constant | Code | Description |
|---|---|---|
| `PayloadReq` | `0x00` | Request |
| `PayloadResponse` | `0x01` | Response |
| `PayloadTxtMsg` | `0x02` | Direct text message (TXT_MSG) |
| `PayloadAck` | `0x03` | Acknowledgement |
| `PayloadAdvert` | `0x04` | Node advertisement |
| `PayloadGrpTxt` | `0x05` | Channel text message (GRP_TXT) |
| `PayloadGrpData` | `0x06` | Channel data |
| `PayloadAnonReq` | `0x07` | Anonymous request |
| `PayloadPath` | `0x08` | Path |
| `PayloadTrace` | `0x09` | Trace |
| `PayloadMultipart` | `0x0A` | Multipart |
| `PayloadControl` | `0x0B` | Control |
| `PayloadRawCustom` | `0x0F` | Raw / custom |

## Payload formats

**GRP_TXT** (channel message)
```
[channel_hash:1][mac:2][AES-128-ECB ciphertext]
plaintext = [timestamp:4 LE][flags:1]["Sender: text"]
```

**TXT_MSG** (direct message)
```
[dest_hash:1][src_hash:1][mac:2][AES-128-ECB ciphertext]
plaintext = [timestamp:4 LE][flags:1]["text"]
```

**ADVERT** (node advertisement, unencrypted)
```
[pubkey:32][timestamp:4 LE][signature:64][appdata]
appdata = [flags:1][lat?:4 int32 LE ×1e-6°][lon?:4 int32 LE ×1e-6°][feat1?:2][feat2?:2][name string]

signed  = pubkey || timestamp || appdata   (Ed25519 over these bytes)
```

All-zero signatures are accepted as unsigned (e.g. from the codec tool). `DecodeAdvertPayload` returns an error for any non-zero signature that fails verification. All declared optional fields (GPS, feature flags) must be present in the payload and GPS coordinates must be within valid ranges.

## Identity and ECDH

```go
// Firmware-compatible Ed25519 identity (matches Identity::calcSharedSecret)
id, err := meshpkt.GenerateIdentity()
// or restore: id, err := meshpkt.IdentityFromSeed(seed)

// Sign with Ed25519
sig := id.Sign(message)
ok  := meshpkt.Verify(id.PublicKey, message, sig)

// Derive shared secret (Ed25519 → X25519 conversion, same as firmware)
shared, err := id.SharedSecret(peerIdentity.PublicKey)
aesKey := shared[:16]

// Sign an ADVERT in one step
signed, err := meshpkt.SignAdvert(id, adv)
err         = meshpkt.VerifyAdvert(signed)
```

Derivation: `scalar = SHA-512(seed)[0:32]` with RFC 7748 bit clamping, peer public key converted Edwards→Montgomery via `BytesMontgomery()`.

## Packet validation layers

```go
// Wire validity — mirrors firmware's byte-level checks
err := meshpkt.ValidateWire(pkt)

// Firmware semantics — payload-type-specific rules (TRACE must be DIRECT, etc.)
err  = meshpkt.ValidateFirmwareSemantics(pkt)
```

## Payload dispatcher

```go
ctx := meshpkt.DecodeContext{Shared16: shared[:16], ChannelSecret: secret}
result, err := meshpkt.DecodePayload(pkt, ctx)
// result is a typed value (Advert, GroupText, TracePayload, …)
// or RawPayload for opaque / reserved types
```

Register application-defined body decoders without forking:

```go
reg := meshpkt.NewRegistry()
reg.RequestDecoders[0x05] = func(body []byte) (any, error) { /* … */ }
ctx.Registry = reg
```

## Crypto

```
key32    = secret16 ‖ zero16
mac      = HMAC-SHA256(key32, ciphertext)[:2]
cipher   = AES-128-ECB, zero-padded to block boundary

channel secret  = SHA256(channelName)[:16]
channel hash    = SHA256(secret[:16])[0]    — 1-byte routing hint
identity secret = X25519(SHA-512(seed)[:32]_clamped, peer_montgomery)[:16]
direct secret   = X25519(myPriv, peerPub)[:16]  ← legacy X25519 helpers

ADVERT sig      = Ed25519(identityPrivKey, pubkey ‖ timestamp ‖ appdata)
```

## Files

| File | Contents |
|---|---|
| `doc.go` | Package overview and wire-format reference |
| `packet.go` | Envelope encode/decode, `RouteType`, `PayloadType`, `Packet`, constants |
| `validate.go` | `ValidateWire`, `ValidateFirmwareSemantics` — two-layer validation |
| `registry.go` | `DecodePayload` dispatcher, `DecodeContext`, extensible `Registry` |
| `crypto.go` | AES-128-ECB, HMAC-SHA256, `sealMAC`/`openMAC` (unexported) |
| `keys.go` | `Identity` (Ed25519 + ECDH), `GenerateIdentity`, `IdentityFromSeed`, legacy X25519 helpers |
| `channel.go` | `DeriveChannelSecret`, `ChannelHash` |
| `grptxt.go` | GRP_TXT (channel text) encode/decode |
| `grpdata.go` | GRP_DATA (group datagram) encode/decode |
| `txtmsg.go` | TXT_MSG (direct text) encode/decode |
| `req.go` | REQ / RESPONSE / PATH decode + shared encrypted envelope |
| `anonreq.go` | ANON_REQ encode/decode |
| `advert.go` | ADVERT encode/decode, `SignAdvert`/`VerifyAdvert` |
| `ack.go` | ACK encode/decode |
| `trace.go` | TRACE encode/decode, SNR accumulator |
| `multipart.go` | MULTIPART encode/decode |
| `control.go` | CONTROL / DISCOVER encode/decode |
| `ops.go` | `Op` registry — declarative definitions consumed by binding layers |
| `call.go` | `CallJSON` / `Call` — JSON dispatch for TinyGo and HTTP bindings |
| `examples.go` | Hardware-captured packet test vectors |
| `COMPLIANCE.md` | Pinned upstream commit + per-feature compliance matrix |
| `testdata/upstream/` | Firmware-verified test vectors (identity ECDH, packets) |
| `bindings/` | Copy-paste templates (TinyGo WASM, TypeScript codegen) — see [`bindings/README.md`](bindings/README.md) |

## Usage

```go
import "github.com/meshcore-cz/meshpkt"

// Channel message — encode
secret := meshpkt.DeriveChannelSecret("#general")
pkt, err := meshpkt.GroupTextPacket(secret, "Alice", "hello", time.Now())

// Channel message — convenience (derive secret internally)
pkt, err := meshpkt.GroupTextPacketFromName("#general", "Alice", "hello", time.Now())

// Channel message — decode
envelope, err := meshpkt.DecodePacket(raw)
msg, err := meshpkt.DecodeGroupTextPayload(secret, envelope.Payload)
fmt.Println(msg.Sender, msg.Text)

// Direct message — encode (from hex key strings)
pkt, err := meshpkt.DirectTextPacketFromKeys(myPrivHex, peerPubHex, "hello", time.Now())

// Direct message — decode
msg, err := meshpkt.DecodeDirectTextPayloadFromKeys(envelope.Payload, myPrivHex, peerPubHex)

// ADVERT — decode (signature verified automatically; error on bad sig)
adv, err := meshpkt.DecodeAdvertPayload(envelope.Payload)
fmt.Println(adv.Name, adv.NodeType)

// ADVERT — encode and sign (one step via SignAdvert)
id, err  := meshpkt.GenerateIdentity()
adv      := meshpkt.Advert{PublicKey: id.PublicKey[:], NodeType: meshpkt.AdvertNodeChat, Name: "Alice"}
signed, err := meshpkt.SignAdvert(id, adv)
payload, err := meshpkt.EncodeAdvertPayload(signed)
pkt, err      := meshpkt.EncodePacket(meshpkt.Packet{
    Route: meshpkt.RouteFlood, Type: meshpkt.PayloadAdvert,
    PathHashSize: 2, Payload: payload,
})

// X25519 keypair (for direct messages)
kp, err := meshpkt.Generate()
shared, err := meshpkt.SharedSecret(myPrivHex, peerPubHex)
```

## Op registry

`meshpkt.Ops` is a slice of `Op` descriptors that binding layers (WASM, HTTP, CLI) can iterate to wire up their dispatch tables without duplicating argument parsing logic:

```go
type Op struct {
    Name   string
    Params []Param   // each has Name and Kind (ParamString | ParamHex | ParamInt)
    Run    func(args []any) (map[string]any, error)
}
```

Copy [`bindings/wasm-lite.main.go.tmpl`](bindings/wasm-lite.main.go.tmpl) for TinyGo (~400 KB WASM) or [`bindings/wasm.main.go.tmpl`](bindings/wasm.main.go.tmpl) for full Go `syscall/js`. Optional TypeScript types: [`bindings/gen-ts.main.go.tmpl`](bindings/gen-ts.main.go.tmpl). JSON dispatch: `meshpkt.CallJSON(name, argsJSON)`.

## Notes

- `Identity.SharedSecret` uses the same Ed25519 → X25519 conversion as firmware (`Identity::calcSharedSecret`). The legacy `SharedSecret(privHex, pubHex)` function uses native X25519 and is **not** firmware-compatible for on-air hardware.
- Channel (GRP_TXT / GRP_DATA) crypto matches firmware and round-trips correctly.
- `EncodePacket` and `DecodePacket` enforce all firmware validation rules and reject reserved/invalid fields.

---

## Roadmap

The following milestones are planned but not yet implemented. See [`COMPLIANCE.md`](COMPLIANCE.md) for current status.

### M7 — Firmware oracle and capture corpus

Build a small C++ test harness compiled against upstream MeshCore source that encodes and decodes packets, then compare both directions:

```
firmware encode → Go decode
Go encode       → firmware decode
```

Store results in `testdata/upstream/<sha>/packets.json` and `identity_vectors.json`. Currently the identity vectors in `testdata/upstream/07a3ca9/identity_vectors.json` are verified Go-to-Go only; firmware cross-check requires the C++ oracle.

Cover all four route modes, path hashes 1–3 bytes, zero-to-max hops, all payload types, and malformed/truncated inputs.

### M8 — Fuzz all public decoders

Add `FuzzDecodePacket`, `FuzzDecodeAdvertPayload`, `FuzzDecodeEncryptedEnvelope`, `FuzzDecodePathPayload`, `FuzzDecodeTracePayload`, `FuzzDecodeMultipartPayload`, `FuzzDecodeControlPayload`, and `FuzzDecodeGroupDataPayload`.

Required properties: decoder never panics, never allocates unbounded memory, encode→decode round-trips preserve all fields.

### M9 — Go/WASM fixture parity

Add a shared JSON fixture suite consumed by both `go test ./...` and `npm test`. Every vector must decode identically in Go and JavaScript.

Track WASM binary size (raw / gzip / brotli) in CI with a deliberate threshold so cryptographic correctness is never traded for binary size.

### M10 — Upstream drift detection

Scheduled CI job that checks the latest upstream MeshCore commit, compares payload-type constants, route-type constants, and size limits, runs the C++ oracle, and opens an issue when behaviour changes.

Store in releases:
```
Compatible with MeshCore upstream: <commit SHA>
Verified firmware versions: v1.12.x, v1.16.x, …
```
