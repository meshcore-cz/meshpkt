# @meshcore-cz/meshpkt

[![npm](https://img.shields.io/npm/v/@meshcore-cz/meshpkt)](https://www.npmjs.com/package/@meshcore-cz/meshpkt)
[![Go Reference](https://pkg.go.dev/badge/github.com/meshcore-cz/meshpkt.svg)](https://pkg.go.dev/github.com/meshcore-cz/meshpkt)

MeshCore radio packet codec for JavaScript and TypeScript, powered by WebAssembly.

> **Early development.** This package is a work in progress. APIs may change before v1.0 — pin to a specific version in production.

- **npm:** [npmjs.com/package/@meshcore-cz/meshpkt](https://www.npmjs.com/package/@meshcore-cz/meshpkt)
- **Go source & docs:** [pkg.go.dev/github.com/meshcore-cz/meshpkt](https://pkg.go.dev/github.com/meshcore-cz/meshpkt)

## Install

```sh
npm install @meshcore-cz/meshpkt
```

## Quick start

```ts
import { load } from "@meshcore-cz/meshpkt";

const meshpkt = await load();
```

`load()` fetches and initialises the bundled TinyGo WASM module. Call it once; subsequent calls return the same promise. All methods are synchronous after that.

The same loader works in browsers and Node.js. In Node.js it imports the bundled TinyGo runtime and reads the bundled `.wasm` file directly from the package.

## Error handling

Every method returns either the typed result or `{ error: string }`. The `"error"` key is the reliable way to distinguish them:

```ts
const result = meshpkt.decodeEnvelope(hex);
if ("error" in result) {
  console.error("decode failed:", result.error);
} else {
  console.log(result.type, result.hopCount);
}
```

---

## Examples

### Decode a packet from the air

```ts
const env = meshpkt.decodeEnvelope(
  "15453287568f06bf2d5ad94765d9aaa4aef45a465a5a84142b5abb55eafe11980bc7b891"
);

if ("error" in env) throw new Error(env.error);

console.log(env.route);       // "FLOOD"
console.log(env.type);        // "ADVERT"
console.log(env.hopCount);    // 5
console.log(env.hops);        // ["3287", "568f", "06bf", "2d5a", "d947"]
console.log(env.payloadHex);  // raw payload, pass to a decode* call below
```

---

### Channel (GRP_TXT) messages

```ts
// Encode — by channel name
const pkt = meshpkt.encodeGroupText("#general", "Alice", "Hello mesh!");
if ("error" in pkt) throw new Error(pkt.error);
console.log(pkt.hex); // ready to send over the radio link

// Encode — by pre-shared secret (16 bytes hex)
const secret = meshpkt.deriveChannelSecret("#general");
if ("error" in secret) throw new Error(secret.error);
const pkt2 = meshpkt.encodeGroupTextSecret(secret.hex, "Alice", "Hello mesh!");

// Decode — extract payload first, then decrypt
const env = meshpkt.decodeEnvelope(rawHex);
if ("error" in env || env.type !== "GRP_TXT") return;

const msg = meshpkt.decodeGroupText(env.payloadHex, "#general");
if ("error" in msg) throw new Error(msg.error);

console.log(msg.sender);    // "Alice"
console.log(msg.text);      // "Hello mesh!"
console.log(new Date(msg.timestamp * 1000));
```

---

### Direct (TXT_MSG) messages

```ts
// Generate a keypair (or load an existing one)
const kp = meshpkt.generateKeypair();
if ("error" in kp) throw new Error(kp.error);
// kp.privateKey / kp.publicKey — 64-char hex strings

// Encode
const pkt = meshpkt.encodeDirectText(myPrivKey, peerPubKey, "Hey, direct!");
if ("error" in pkt) throw new Error(pkt.error);

// Decode
const env = meshpkt.decodeEnvelope(rawHex);
if ("error" in env || env.type !== "TXT_MSG") return;

const msg = meshpkt.decodeDirectText(env.payloadHex, myPrivKey, peerPubKey);
if ("error" in msg) throw new Error(msg.error);

console.log(msg.text);     // "Hey, direct!"
console.log(msg.destHash); // first-byte hash of recipient's public key
```

For real MeshCore node identities, prefer the identity-compatible APIs:

- `encodeDirectTextIdentity(seed, peerPubKey, ...)` takes the original 32-byte seed (`64` hex chars).
- `encodeDirectTextExpanded(expandedPrivKey, myPubKey, peerPubKey, ...)` takes a MeshCore Companion exported expanded private key (`128` hex chars) plus your public key.
- The `*Path` variants send via a returned path instead of flooding.
- `encodePathTextAckIdentity` and `encodePathTextAckExpanded` build the PATH+ACK reply for a FLOOD-routed TXT_MSG.

Do not pass a `128`-hex Companion expanded key to an `*Identity*` encoder, and do not slice it to `64` hex chars. It is `SHA-512(seed)` material, not the seed, and packets encrypted that way will look valid but will not be decrypted or ACKed by the peer.

---

### Node advertisements (ADVERT)

The signature is verified automatically. `decodeAdvert` returns `{ error }` if
the packet carries a non-zero signature that does not verify — tampered data is
rejected before you ever see the fields.

```ts
const env = meshpkt.decodeEnvelope(rawHex);
if ("error" in env || env.type !== "ADVERT") return;

const adv = meshpkt.decodeAdvert(env.payloadHex);
if ("error" in adv) throw new Error(adv.error); // also catches bad signatures

console.log(adv.name);        // "CZ.NIC Repeater"
console.log(adv.publicKey);   // 64-char hex — treat this as the stable identity
console.log(adv.nodeType);    // 2 = repeater
console.log(adv.sigVerified); // true = Ed25519 signature verified
                              // false = all-zero signature (unsigned packet)
if (adv.hasGPS) {
  console.log(adv.lat, adv.lon);
}
```

> **Note:** `sigVerified: true` proves the holder of `publicKey` signed exactly
> this name and these coordinates. It does not prove the name is unique — use
> `publicKey` as the stable identity, and treat the name as a signed label.

---

### Key utilities

```ts
// Generate a fresh X25519 keypair
const kp = meshpkt.generateKeypair();
if ("error" in kp) throw new Error(kp.error);
console.log(kp.publicKey);  // 64-char hex
console.log(kp.privateKey); // 64-char hex

// Derive a channel PSK from its name
const secret = meshpkt.deriveChannelSecret("#ops");
if ("error" in secret) throw new Error(secret.error);
console.log(secret.hex);    // 32-char hex (16 bytes)

// Compute X25519 shared secret for direct-message crypto
const shared = meshpkt.sharedSecret(myPrivKey, peerPubKey);
if ("error" in shared) throw new Error(shared.error);
console.log(shared.hex);    // 64-char hex (32 bytes; use first 16 as AES key)
```

---

### Loader options

By default `load()` resolves the `.wasm` and `wasm_exec.js` files relative to the package using `import.meta.url`. Override either URL when your bundler places assets elsewhere:

```ts
const meshpkt = await load({
  wasmURL:     new URL("/assets/meshpkt.wasm",    import.meta.url),
  wasmExecURL: new URL("/assets/wasm_exec.js",    import.meta.url),
});
```

---

## TypeScript types

All result interfaces are re-exported from the package root:

```ts
import type {
  Envelope,
  GroupTextPayload,
  DirectTextPayload,
  AdvertPayload,
  GrpDataPayload,
  AckPayload,
  ReqPayload,
  ResponsePayload,
  PathPayload,
  AnonReqPayload,
  ControlPayload,
  KeypairResult,
  ErrResult,
} from "@meshcore-cz/meshpkt";
```

The `RouteTypes` and `PayloadTypes` constant arrays (code + label) are also exported for building UI dropdowns or switch statements.
