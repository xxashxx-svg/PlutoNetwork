// relay plumbing. the relay only ever sees base64 ciphertext.

// in production the relay serves this page, so everything is same-origin.
// local dev (client on :8080, relay on :4000) is the one special case.
const DEV = location.port === "8080";
const HTTP = DEV ? "http://localhost:4000" : "";
const WS = DEV
  ? "ws://localhost:4000"
  : (location.protocol === "https:" ? "wss://" : "ws://") + location.host;

let TOKEN = null;
export const setToken = (t) => (TOKEN = t);

const json = (body) => ({ "content-type": "application/json", ...(TOKEN && { authorization: `Bearer ${TOKEN}` }) });

async function post(path, body) {
  const r = await fetch(`${HTTP}${path}`, { method: "POST", headers: json(), body: JSON.stringify(body) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `${path} failed`);
  return d;
}

export const register = (user, pass) => post("/register", { user, pass });
export const login = (user, pass) => post("/login", { user, pass });

export async function whoami(token) {
  const r = await fetch(`${HTTP}/me`, { headers: { authorization: `Bearer ${token}` } });
  if (!r.ok) return null;
  return (await r.json()).user;
}

export const publishKeyPackage = (kp, reset = false) => post("/keypackages", { key_package: kp, reset });

// old/new are derived auth keys; the real password never leaves the device
export const changePassword = (oldKey, newKey) => post("/password", { old: oldKey, new: newKey });

export async function userExists(user) {
  const r = await fetch(`${HTTP}/users/${encodeURIComponent(user)}`, { headers: authHeader() });
  return r.ok;
}

export async function grabKeyPackage(user) {
  const r = await fetch(`${HTTP}/keypackages/${encodeURIComponent(user)}`, {
    headers: { authorization: `Bearer ${TOKEN}` },
  });
  if (!r.ok) return null;
  return (await r.json()).key_package;
}

// ---- encrypted blobs + history vault (relay stores ciphertext only) ----

const authHeader = () => ({ authorization: `Bearer ${TOKEN}` });

export async function uploadBlob(bytes) {
  const r = await fetch(`${HTTP}/blobs`, {
    method: "POST",
    headers: { ...authHeader(), "content-type": "application/octet-stream" },
    body: bytes,
  });
  if (!r.ok) throw new Error("upload failed");
  return r.json();
}

export async function fetchBlob(id) {
  const r = await fetch(`${HTTP}/blobs/${encodeURIComponent(id)}`, { headers: authHeader() });
  if (!r.ok) throw new Error("blob fetch failed");
  return new Uint8Array(await r.arrayBuffer());
}

export async function putVault(sealed) {
  const r = await fetch(`${HTTP}/vault`, { method: "PUT", headers: authHeader(), body: sealed });
  if (!r.ok) throw new Error("vault upload failed");
}

export async function getVault() {
  const r = await fetch(`${HTTP}/vault`, { headers: authHeader() });
  if (!r.ok) return null;
  return new Uint8Array(await r.arrayBuffer());
}

export function connect(onFrame, onDrop) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`${WS}/ws?token=${encodeURIComponent(TOKEN)}`);
    ws._seen = Date.now();
    let beats = 0;
    ws.onmessage = (e) => {
      ws._seen = Date.now();
      const data = JSON.parse(e.data);
      if (data.pong) return; // heartbeat answer, not a frame
      onFrame(data);
    };
    ws.onopen = () => {
      ws._beat = setInterval(() => {
        if (ws.readyState !== WebSocket.OPEN) return;
        // half-open detection: the relay answers every ping, so prolonged
        // silence means the link is dead even though it looks open
        if (Date.now() - ws._seen > 75_000) return ws.close();
        ws.send(JSON.stringify({ ping: 1 }));
        // an HTTP touch every ~4 min keeps free hosts from idling us out
        if (++beats % 10 === 0) fetch(`${HTTP}/health`).catch(() => {});
      }, 25_000);
      resolve(ws);
    };
    ws.onerror = () => reject(new Error("Can't reach the server. Is it running?"));
    ws.onclose = () => {
      clearInterval(ws._beat);
      onDrop && onDrop();
    };
  });
}

export const sendFrame = (ws, to, blob, kind) => ws.send(JSON.stringify({ to, blob, kind }));
