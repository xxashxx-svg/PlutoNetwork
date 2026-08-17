// password → two keys via one PBKDF2 pass:
//   authKey:  hex, sent to the relay as the "password" (server re-hashes it again)
//   vaultKey: AES-256-GCM, never leaves this device, encrypts MLS state + history
// so the server never sees the real password and can never read the vault.

const enc = new TextEncoder();

export async function deriveKeys(username, password) {
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt: enc.encode(`plutonetwork:v1:${username}`),
        iterations: 310_000,
      },
      base,
      512
    )
  );
  const authKey = [...bits.slice(0, 32)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return { authKey, vaultKeyRaw: bits.slice(32) };
}

export const importVaultKey = (raw) =>
  crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);

// sealed layout: 12-byte iv || AES-GCM ciphertext
export async function seal(vaultKey, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, vaultKey, bytes));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv);
  out.set(ct, iv.length);
  return out;
}

export async function unseal(vaultKey, sealed) {
  const iv = sealed.slice(0, 12);
  const ct = sealed.slice(12);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, vaultKey, ct));
}
