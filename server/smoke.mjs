// quick websocket smoke test for the relay — run with: node smoke.mjs
// needs node 22+ (native WebSocket)

const RELAY = "ws://localhost:4000/ws";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const results = [];
const check = (name, ok) => {
  results.push([name, ok]);
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
};

const connect = (user) =>
  new Promise((resolve, reject) => {
    const ws = new WebSocket(`${RELAY}?user=${user}`);
    ws.inbox = [];
    ws.onmessage = (e) => ws.inbox.push(JSON.parse(e.data));
    ws.onopen = () => resolve(ws);
    ws.onerror = reject;
  });

// 1. live delivery
const alice = await connect("alice");
const bob = await connect("bob");
alice.send(JSON.stringify({ to: ["bob"], blob: "Y2lwaGVydGV4dA==", kind: "msg" }));
await sleep(300);
check("live delivery", bob.inbox.length === 1 && bob.inbox[0].from === "alice" && bob.inbox[0].blob === "Y2lwaGVydGV4dA==");
check("kind passthrough", bob.inbox[0]?.kind === "msg");

// 2. welcome kind survives the trip
alice.send(JSON.stringify({ to: ["bob"], blob: "d2VsY29tZQ==", kind: "welcome" }));
await sleep(300);
check("welcome kind", bob.inbox[1]?.kind === "welcome");

// 3. offline queue: send to carol before she connects
alice.send(JSON.stringify({ to: ["carol"], blob: "cXVldWVk", kind: "msg" }));
await sleep(300);
const carol = await connect("carol");
await sleep(300);
check("offline mailbox flush", carol.inbox.length === 1 && carol.inbox[0].blob === "cXVldWVk");

// 4. fan-out to multiple recipients
alice.send(JSON.stringify({ to: ["bob", "carol"], blob: "ZmFub3V0", kind: "msg" }));
await sleep(300);
check("fan-out", bob.inbox.at(-1)?.blob === "ZmFub3V0" && carol.inbox.at(-1)?.blob === "ZmFub3V0");

[alice, bob, carol].forEach((ws) => ws.close());
const failed = results.filter(([, ok]) => !ok).length;
console.log(failed === 0 ? "\nall smoke tests passed" : `\n${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);
