// quick smoke test for the relay — run with: node smoke.mjs
// needs node 22+ (native WebSocket). covers accounts + ws routing.

const HTTP = process.env.RELAY || "http://localhost:4000";
const RELAY = HTTP.replace("http", "ws") + "/ws";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const results = [];
const check = (name, ok) => {
  results.push([name, ok]);
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
};

const post = async (path, body, token) => {
  const r = await fetch(`${HTTP}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(token && { authorization: `Bearer ${token}` }) },
    body: JSON.stringify(body),
  });
  return { status: r.status, body: await r.json().catch(() => ({})) };
};

// register-or-login (dets persists across runs)
async function auth(user, pass) {
  let r = await post("/register", { user, pass });
  if (r.status === 400) r = await post("/login", { user, pass });
  if (!r.body.token) throw new Error(`auth failed for ${user}: ${JSON.stringify(r.body)}`);
  return r.body.token;
}

const tokA = await auth("smoke_alice", "hunter22");
const tokB = await auth("smoke_bob", "hunter22");
const tokC = await auth("smoke_carol", "hunter22");
check("register/login issues tokens", !!tokA && !!tokB && !!tokC);

// wrong password rejected
const bad = await post("/login", { user: "smoke_alice", pass: "wrong-pass" });
check("wrong password rejected", bad.status === 401);

// keypackage publish requires auth
const noAuth = await post("/keypackages", { key_package: "AAAA" });
check("unauthenticated publish rejected", noAuth.status === 401);

const connect = (token) =>
  new Promise((resolve, reject) => {
    const ws = new WebSocket(`${RELAY}?token=${encodeURIComponent(token)}`);
    ws.inbox = [];
    ws.onmessage = (e) => ws.inbox.push(JSON.parse(e.data));
    ws.onopen = () => resolve(ws);
    ws.onerror = reject;
  });

// bad token can't connect
const rejected = await new Promise((resolve) => {
  const ws = new WebSocket(`${RELAY}?token=garbage`);
  ws.onopen = () => resolve(false);
  ws.onerror = () => resolve(true);
});
check("bad ws token rejected", rejected);

// live delivery
const alice = await connect(tokA);
const bob = await connect(tokB);

// heartbeat: a ping gets a pong (dead-link detection depends on this)
alice.send(JSON.stringify({ ping: 1 }));
await sleep(300);
check("ping gets pong", alice.inbox.some((m) => m.pong));
alice.send(JSON.stringify({ to: ["smoke_bob"], blob: "Y2lwaGVydGV4dA==", kind: "msg" }));
await sleep(300);
const live = bob.inbox.at(-1);
check("live delivery", live?.from === "smoke_alice" && live?.blob === "Y2lwaGVydGV4dA==" && live?.kind === "msg");

// offline queue: carol is offline right now
alice.send(JSON.stringify({ to: ["smoke_carol"], blob: "cXVldWVk", kind: "msg" }));
await sleep(300);
const carol = await connect(tokC);
await sleep(300);
check("offline mailbox flush", carol.inbox.some((m) => m.blob === "cXVldWVk"));

// fan-out
alice.send(JSON.stringify({ to: ["smoke_bob", "smoke_carol"], blob: "ZmFub3V0", kind: "welcome" }));
await sleep(300);
check("fan-out + kind", bob.inbox.at(-1)?.kind === "welcome" && carol.inbox.at(-1)?.blob === "ZmFub3V0");

// encrypted media blobs: upload → fetch round-trip, auth enforced
const blobBytes = new Uint8Array([1, 2, 3, 250, 251, 252]);
const up = await fetch(`${HTTP}/blobs`, {
  method: "POST",
  headers: { authorization: `Bearer ${tokA}`, "content-type": "application/octet-stream" },
  body: blobBytes,
});
const blobId = (await up.json()).id;
check("blob upload", up.status === 201 && !!blobId);
const down = await fetch(`${HTTP}/blobs/${blobId}`, { headers: { authorization: `Bearer ${tokB}` } });
const gotBlob = new Uint8Array(await down.arrayBuffer());
check("blob round-trip", down.status === 200 && gotBlob.length === blobBytes.length && gotBlob.every((b, i) => b === blobBytes[i]));
const noBlob = await fetch(`${HTTP}/blobs/${blobId}`);
check("unauthed blob fetch rejected", noBlob.status === 401);

// history vault: per-user encrypted backup
const vaultBody = new TextEncoder().encode("ciphertext-vault-v1");
const vput = await fetch(`${HTTP}/vault`, { method: "PUT", headers: { authorization: `Bearer ${tokA}` }, body: vaultBody });
check("vault upload", vput.status === 200);
const vget = await fetch(`${HTTP}/vault`, { headers: { authorization: `Bearer ${tokA}` } });
check("vault round-trip", vget.status === 200 && new TextDecoder().decode(await vget.arrayBuffer()) === "ciphertext-vault-v1");
const vno = await fetch(`${HTTP}/vault`, { method: "PUT", body: vaultBody });
check("unauthed vault rejected", vno.status === 401);

// exact-match user lookup for the search bar (no enumeration, no listing)
const uYes = await fetch(`${HTTP}/users/smoke_bob`, { headers: { authorization: `Bearer ${tokA}` } });
const uNo = await fetch(`${HTTP}/users/nobody_here_xyz`, { headers: { authorization: `Bearer ${tokA}` } });
const uAnon = await fetch(`${HTTP}/users/smoke_bob`);
check("user lookup finds exact name", uYes.status === 200);
check("user lookup 404s unknown name", uNo.status === 404);
check("unauthed user lookup rejected", uAnon.status === 401);

// password change: verified against the old key; old stops working, new works
const pcUser = `smoke_pc${Date.now() % 1000000}`;
const pcTok = (await post("/register", { user: pcUser, pass: "first-pass" })).body.token;
const pcNoAuth = await post("/password", { old: "first-pass", new: "second-pass" });
check("unauthed password change rejected", pcNoAuth.status === 401);
const pcWrong = await post("/password", { old: "not-it", new: "second-pass" }, pcTok);
check("wrong current password rejected", pcWrong.status === 401);
const pcOk = await post("/password", { old: "first-pass", new: "second-pass" }, pcTok);
check("password change accepted", pcOk.status === 200);
const pcOldLogin = await post("/login", { user: pcUser, pass: "first-pass" });
const pcNewLogin = await post("/login", { user: pcUser, pass: "second-pass" });
check("old password stops working", pcOldLogin.status === 401);
check("new password works", pcNewLogin.status === 200);

[alice, bob, carol].forEach((ws) => ws.close());
const failed = results.filter(([, ok]) => !ok).length;
console.log(failed === 0 ? "\nall smoke tests passed" : `\n${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);
