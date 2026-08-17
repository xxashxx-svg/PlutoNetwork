// encrypted attachments, the Signal way: file is encrypted here with a
// one-off AES-256-GCM key, ciphertext goes to the relay's blob store, and
// only the tiny {id, key, iv} descriptor rides inside the MLS message.

import { uploadBlob, fetchBlob } from "./net.js?v=6";
import { toB64, fromB64 } from "./crypto.js?v=6";

export async function encryptAndUpload(bytes) {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes));
  const { id } = await uploadBlob(ct);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  return { id, key: toB64(raw), iv: toB64(iv) };
}

export async function downloadAndDecrypt({ id, key, iv }) {
  const ct = await fetchBlob(id);
  const k = await crypto.subtle.importKey("raw", fromB64(key), { name: "AES-GCM" }, false, ["decrypt"]);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(iv) }, k, ct));
}

// decrypted media as object URLs, one fetch per blob per session
const urls = new Map(); // blob id -> Promise<string>

export function mediaUrl(meta) {
  if (!urls.has(meta.id)) {
    urls.set(
      meta.id,
      downloadAndDecrypt(meta).then((bytes) => URL.createObjectURL(new Blob([bytes], { type: meta.mime })))
    );
  }
  return urls.get(meta.id);
}

export function rememberLocalUrl(id, blob) {
  urls.set(id, Promise.resolve(URL.createObjectURL(blob)));
}
