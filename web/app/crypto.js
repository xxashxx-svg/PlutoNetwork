// thin wrapper over the wasm core + byte helpers. all crypto lives in rust.

import init, { VeilClient } from "../../crates/veil-wasm/pkg/veil_wasm.js";

export async function makeClient(name) {
  await init();
  return new VeilClient(name);
}

export const toB64 = (bytes) => btoa(String.fromCharCode(...bytes));
export const fromB64 = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
export const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
export const encodeText = (s) => new TextEncoder().encode(s);
export const decodeText = (b) => new TextDecoder().decode(b);
