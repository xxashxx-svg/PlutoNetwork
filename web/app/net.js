// relay plumbing. the relay only ever sees base64 ciphertext.

const HTTP = "http://localhost:4000";
const WS = "ws://localhost:4000";

export function connect(user, onFrame, onDrop) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`${WS}/ws?user=${encodeURIComponent(user)}`);
    ws.onmessage = (e) => onFrame(JSON.parse(e.data));
    ws.onopen = () => {
      // keepalive so the relay's idle timer never reaps us
      ws._beat = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ ping: 1 }));
      }, 25_000);
      resolve(ws);
    };
    ws.onerror = () => reject(new Error("relay unreachable — is the server up?"));
    ws.onclose = () => {
      clearInterval(ws._beat);
      onDrop && onDrop();
    };
  });
}

export const sendFrame = (ws, to, blob, kind) =>
  ws.send(JSON.stringify({ to, blob, kind }));

export async function publishKeyPackage(user, kp) {
  await fetch(`${HTTP}/keypackages`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ user, key_package: kp }),
  });
}

export async function grabKeyPackage(user) {
  const r = await fetch(`${HTTP}/keypackages/${encodeURIComponent(user)}`);
  if (!r.ok) return null;
  return (await r.json()).key_package;
}
