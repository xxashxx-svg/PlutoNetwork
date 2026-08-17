// thin wrapper over the wasm core + byte helpers. all crypto lives in rust.

import init, { PlutoNetworkClient } from "./pkg/plutonetwork_wasm.js";

let ready;
const ensure = () => (ready ??= init());

export async function makeClient(name) {
  await ensure();
  return new PlutoNetworkClient(name);
}

export async function restoreClient(snapshot) {
  await ensure();
  return PlutoNetworkClient.restore(snapshot);
}

export const toB64 = (bytes) => {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
};
export const fromB64 = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
export const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
export const fromHex = (hex) => new Uint8Array(hex.match(/../g)?.map((h) => parseInt(h, 16)) ?? []);
export const encodeText = (s) => new TextEncoder().encode(s);
export const decodeText = (b) => new TextDecoder().decode(b);
