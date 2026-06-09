// quick smoke test for the relay — run with: node smoke.mjs
// needs node 22+ (native WebSocket). covers accounts + ws routing.

const HTTP = "http://localhost:4000";
const RELAY = "ws://localhost:4000/ws";
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

[alice, bob, carol].forEach((ws) => ws.close());
const failed = results.filter(([, ok]) => !ok).length;
console.log(failed === 0 ? "\nall smoke tests passed" : `\n${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);
