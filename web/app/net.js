// relay plumbing. the relay only ever sees base64 ciphertext.

const HTTP = "http://localhost:4000";
const WS = "ws://localhost:4000";

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

export const publishKeyPackage = (kp) => post("/keypackages", { key_package: kp });

export async function grabKeyPackage(user) {
  const r = await fetch(`${HTTP}/keypackages/${encodeURIComponent(user)}`, {
    headers: { authorization: `Bearer ${TOKEN}` },
  });
  if (!r.ok) return null;
  return (await r.json()).key_package;
}

export function connect(onFrame, onDrop) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`${WS}/ws?token=${encodeURIComponent(TOKEN)}`);
    ws.onmessage = (e) => onFrame(JSON.parse(e.data));
    ws.onopen = () => {
      // keepalive so the relay's idle timer never reaps us
      ws._beat = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ ping: 1 }));
      }, 25_000);
      resolve(ws);
    };
    ws.onerror = () => reject(new Error("Can't reach the server — is it running?"));
    ws.onclose = () => {
      clearInterval(ws._beat);
      onDrop && onDrop();
    };
  });
}

export const sendFrame = (ws, to, blob, kind) => ws.send(JSON.stringify({ to, blob, kind }));
