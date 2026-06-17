export * from "./wasm.gen.js";

import type { MeshcoreWasm } from "./wasm.gen.js";
import { meshcoreOpNames } from "./wasm.gen.js";

type MeshpktCall = (opName: string, argsJSON: string) => object;

interface TinyGoRuntime {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}

type TinyGoConstructor = new () => TinyGoRuntime;

type Globals = typeof globalThis & {
  Go?: TinyGoConstructor;
  meshpktCall?: MeshpktCall;
};

const globals = globalThis as Globals;

export interface LoadOptions {
  wasmURL?: string | URL;
  wasmExecURL?: string | URL;
}

let runtimeReady: Promise<void> | undefined;
let apiReady: Promise<MeshcoreWasm> | undefined;

function urlString(url: string | URL): string {
  return typeof url === "string" ? url : url.href;
}

async function loadTinyGoRuntime(url: string | URL): Promise<void> {
  if (globals.Go) return;

  runtimeReady ??= new Promise<void>((resolve, reject) => {
    if (typeof document !== "undefined") {
      const script = document.createElement("script");
      script.src = urlString(url);
      script.async = true;

      script.onload = () => {
        if (!globals.Go) {
          reject(new Error("TinyGo runtime loaded but globalThis.Go was not registered"));
          return;
        }

        resolve();
      };

      script.onerror = () => {
        reject(new Error(`Failed to load TinyGo runtime: ${script.src}`));
      };

      document.head.appendChild(script);
    } else {
      import(/* @vite-ignore */ urlString(url))
        .then(() => {
          if (!globals.Go) {
            reject(new Error("TinyGo runtime loaded but globalThis.Go was not registered"));
            return;
          }

          resolve();
        })
        .catch((error: unknown) => {
          reject(error);
        });
    }
  });

  return runtimeReady;
}

async function instantiate(
  url: string | URL,
  imports: WebAssembly.Imports
): Promise<WebAssembly.Instance> {
  if (isFileUrl(url) || typeof fetch === "undefined") {
    const { readFile } = await import("node:fs/promises");
    const bytes = await readFile(filePath(url));
    const result = await WebAssembly.instantiate(bytes, imports);
    return result.instance;
  }

  const response = await fetch(urlString(url));

  if (!response.ok) {
    throw new Error(`Failed to fetch WASM module: ${response.status} ${response.statusText}`);
  }

  try {
    const result = await WebAssembly.instantiateStreaming(response.clone(), imports);
    return result.instance;
  } catch {
    const bytes = await response.arrayBuffer();
    const result = await WebAssembly.instantiate(bytes, imports);
    return result.instance;
  }
}

function isFileUrl(url: string | URL): boolean {
  return url instanceof URL ? url.protocol === "file:" : url.startsWith("file:");
}

function filePath(url: string | URL): string | URL {
  return typeof url === "string" && url.startsWith("file:") ? new URL(url) : url;
}

async function waitForCall(): Promise<MeshpktCall> {
  const deadline = Date.now() + 10_000;

  while (Date.now() < deadline) {
    if (globals.meshpktCall) return globals.meshpktCall;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }

  throw new Error("meshpktCall was not registered by the WASM module");
}

function buildAPI(call: MeshpktCall): MeshcoreWasm {
  const api = {} as MeshcoreWasm;

  for (const name of meshcoreOpNames) {
    (api as unknown as Record<string, (...args: unknown[]) => object>)[name] = (
      ...args: unknown[]
    ) => call(name, JSON.stringify(args));
  }

  return api;
}

export function load(options: LoadOptions = {}): Promise<MeshcoreWasm> {
  if (apiReady) return apiReady;

  apiReady = (async () => {
    const wasmURL =
      options.wasmURL ?? new URL("./meshpkt.wasm", import.meta.url);

    const wasmExecURL =
      options.wasmExecURL ?? new URL("./wasm_exec.js", import.meta.url);

    await loadTinyGoRuntime(wasmExecURL);

    const Go = globals.Go;

    if (!Go) {
      throw new Error("TinyGo runtime is unavailable");
    }

    const go = new Go();
    const instance = await instantiate(wasmURL, go.importObject);

    void go.run(instance);

    const call = await waitForCall();
    return buildAPI(call);
  })();

  return apiReady;
}
