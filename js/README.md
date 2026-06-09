# @meshcore-cz/meshpkt

[![npm](https://img.shields.io/npm/v/@meshcore-cz/meshpkt)](https://www.npmjs.com/package/@meshcore-cz/meshpkt)
[![Go Reference](https://pkg.go.dev/badge/github.com/meshcore-cz/meshpkt.svg)](https://pkg.go.dev/github.com/meshcore-cz/meshpkt)

MeshCore radio packet codec for JavaScript and TypeScript, powered by WebAssembly.

- **npm:** [npmjs.com/package/@meshcore-cz/meshpkt](https://www.npmjs.com/package/@meshcore-cz/meshpkt)
- **Go source & docs:** [pkg.go.dev/github.com/meshcore-cz/meshpkt](https://pkg.go.dev/github.com/meshcore-cz/meshpkt)

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
