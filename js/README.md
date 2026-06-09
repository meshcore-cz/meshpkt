# @meshcore-cz/meshpkt

MeshCore radio packet codec for JavaScript and TypeScript, powered by WebAssembly.

## Install

```sh
npm install @meshcore-cz/meshpkt
````

## Usage

```ts
import { load } from "@meshcore-cz/meshpkt";

const meshpkt = await load();

const envelope = meshpkt.decodeEnvelope(
  "your-hex-encoded-meshcore-packet"
);

console.log(envelope);
```

The package includes the TinyGo WebAssembly module and generated TypeScript types.
