import { makeClient, toB64, fromB64, toHex, encodeText, decodeText } from "./crypto.js";
import { connect, sendFrame, publishKeyPackage, grabKeyPackage } from "./net.js";

// ---------- state ----------
let me = null;
let client = null;
let ws = null;
const chats = new Map(); // hexId -> {id, title, members:Set, msgs:[], unread}
let activeChat = null;
const wireLog = []; // last frames, for the encryption details panel

const $ = (s) => document.querySelector(s);

// ---------- boot ----------
$("#gate-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = $("#gate-name").value.trim().toLowerCase();
  if (!name) return;
  const hint = $("#gate-hint");
  hint.classList.remove("err");
  hint.textContent = "Creating your encryption keys…";
  try {
    client = await makeClient(name);
    me = name;
    // publish a stack of key packages so several people can invite us
    for (let i = 0; i < 5; i++) await publishKeyPackage(me, toB64(client.key_package()));
    await linkUp();
    $("#me-name").textContent = me;
    $("#gate").classList.add("lifted");
    $("#shell").hidden = false;
  } catch (err) {
    hint.classList.add("err");
    hint.textContent = err.message || String(err);
  }
});

// reconnect forever — the relay queues our mail while we're gone
async function linkUp() {
  try {
    ws = await connect(me, onFrame, () => {
      $("#conn-dot").classList.remove("live");
      setTimeout(linkUp, 1500);
    });
    $("#conn-dot").classList.add("live");
  } catch {
    $("#conn-dot").classList.remove("live");
    setTimeout(linkUp, 1500);
  }
}

// ---------- incoming ----------
function onFrame(frame) {
  const bytes = fromB64(frame.blob);
  logWire("←", frame.kind, bytes.length);
  try {
    if (frame.kind === "welcome") {
      const id = client.join(bytes);
      const hex = toHex(id);
      ensureChat(hex, id, frame.from);
      chats.get(hex).members.add(frame.from);
      sysMsg(hex, `${frame.from} added you to the chat`);
    } else {
      const inc = client.recv(bytes);
      const hex = toHex(inc.chatId);
      const chat = ensureChat(hex, inc.chatId, inc.sender);
      chat.members.add(inc.sender);
      if (inc.plaintext === undefined) {
        sysMsg(hex, `Encryption keys were updated`);
      } else {
        handlePayload(hex, inc.sender, decodeText(inc.plaintext));
      }
    }
  } catch (err) {
    console.warn("frame dropped:", err);
  }
  renderChatList();
  if (activeChat) renderConvo();
}

// app-level payloads ride encrypted inside MLS messages
function handlePayload(hex, sender, raw) {
  let p;
  try { p = JSON.parse(raw); } catch { p = { t: "text", body: raw }; }
  const chat = chats.get(hex);
  if (p.t === "roster") {
    p.members.filter((m) => m !== me).forEach((m) => chat.members.add(m));
    chat.title = [...chat.members].join(", ");
    return;
  }
  chat.msgs.push({ who: sender, text: p.body, ts: Date.now(), mine: false });
  if (activeChat !== hex) chat.unread++;
  flashSeal();
}

// ---------- chats ----------
function ensureChat(hex, idBytes, title) {
  if (!chats.has(hex)) {
    chats.set(hex, { id: idBytes, title, members: new Set(), msgs: [], unread: 0 });
    chats.get(hex).msgs.push({ sys: true, text: "Messages in this chat are end-to-end encrypted", ts: Date.now() });
  }
  return chats.get(hex);
}

function sysMsg(hex, text) {
  chats.get(hex).msgs.push({ sys: true, text, ts: Date.now() });
}

$("#new-chat").addEventListener("submit", async (e) => {
  e.preventDefault();
  const who = $("#new-chat-name").value.trim().toLowerCase();
  $("#new-chat-name").value = "";
  if (!who || who === me) return;
  const kp = await grabKeyPackage(who);
  if (!kp) return alert(`"${who}" isn't registered on this server yet.`);
  const id = client.create_chat();
  const hex = toHex(id);
  const chat = ensureChat(hex, id, who);
  chat.members.add(who);
  const inv = client.invite(id, fromB64(kp));
  sendFrame(ws, [who], toB64(inv.welcome), "welcome");
  logWire("→", "welcome", inv.welcome.length);
  openChat(hex);
  renderChatList();
});

$("#add-person").addEventListener("click", async () => {
  if (!activeChat) return;
  const who = prompt("Add who?")?.trim().toLowerCase();
  if (!who || who === me) return;
  const chat = chats.get(activeChat);
  const kp = await grabKeyPackage(who);
  if (!kp) return alert(`"${who}" isn't registered on this server yet.`);
  const inv = client.invite(chat.id, fromB64(kp));
  const others = [...chat.members];
  // commit to the old roster, welcome to the newcomer, then share the roster (encrypted)
  if (others.length) sendFrame(ws, others, toB64(inv.commit), "msg");
  sendFrame(ws, [who], toB64(inv.welcome), "welcome");
  chat.members.add(who);
  chat.title = [...chat.members].join(", ");
  const roster = client.send(chat.id, encodeText(JSON.stringify({ t: "roster", members: [...chat.members, me] })));
  sendFrame(ws, [...chat.members], toB64(roster), "msg");
  logWire("→", "commit+welcome", inv.commit.length + inv.welcome.length);
  sysMsg(activeChat, `You added ${who} — encryption keys were updated`);
  renderChatList();
  renderConvo();
});

// ---------- sending ----------
$("#composer").addEventListener("submit", (e) => {
  e.preventDefault();
  const text = $("#composer-input").value.trim();
  if (!text || !activeChat) return;
  $("#composer-input").value = "";
  const chat = chats.get(activeChat);
  const wire = client.send(chat.id, encodeText(JSON.stringify({ t: "text", body: text })));
  sendFrame(ws, [...chat.members], toB64(wire), "msg");
  logWire("→", "msg", wire.length);
  chat.msgs.push({ who: me, text, ts: Date.now(), mine: true });
  flashSeal();
  renderChatList();
  renderConvo();
});

// ---------- render ----------
function avatarColor(name) {
  let h = 0;
  for (const c of name) h = (h * 31 + c.charCodeAt(0)) % 360;
  return `hsl(${h}, 48%, 47%)`;
}
const initial = (name) => (name?.[0] || "?").toUpperCase();

function renderChatList() {
  const nav = $("#chat-list");
  nav.innerHTML = "";
  for (const [hex, chat] of chats) {
    const btn = document.createElement("button");
    btn.className = "chat-item" + (hex === activeChat ? " active" : "");
    const last = chat.msgs.filter((m) => !m.sys).at(-1);
    btn.innerHTML = `
      <span class="avatar" style="background:${avatarColor(chat.title)}">${esc(initial(chat.title))}</span>
      <span class="ci-main">
        <span class="who">${esc(chat.title)}</span>
        <span class="last">${last ? esc((last.mine ? "You: " : "") + last.text) : "Say hello — it's encrypted"}</span>
      </span>
      <span class="ci-side">
        <span class="time">${last ? time(last.ts) : ""}</span>
        ${chat.unread ? `<span class="badge">${chat.unread}</span>` : ""}
      </span>`;
    btn.onclick = () => openChat(hex);
    nav.appendChild(btn);
  }
}

function openChat(hex) {
  activeChat = hex;
  chats.get(hex).unread = 0;
  $("#convo-empty").hidden = true;
  $("#convo-live").hidden = false;
  renderChatList();
  renderConvo();
  $("#composer-input").focus();
}

function renderConvo() {
  const chat = chats.get(activeChat);
  if (!chat) return;
  $("#convo-title").textContent = chat.title;
  $("#convo-avatar").textContent = initial(chat.title);
  $("#convo-avatar").style.background = avatarColor(chat.title);
  $("#convo-members").textContent =
    chat.members.size > 1
      ? `${chat.members.size + 1} members · end-to-end encrypted`
      : "end-to-end encrypted";
  const group = chat.members.size > 1;
  const box = $("#messages");
  box.innerHTML = "";
  for (const m of chat.msgs) {
    const el = document.createElement("div");
    if (m.sys) {
      el.className = "msg sys";
      el.innerHTML = `<div class="note">${esc(m.text)}</div>`;
    } else {
      el.className = "msg " + (m.mine ? "out" : "in");
      const name =
        !m.mine && group
          ? `<span class="sender" style="color:${avatarColor(m.who)}">${esc(m.who)}</span>`
          : "";
      el.innerHTML = `${name}<div class="bubble">${esc(m.text)}<span class="t">${time(m.ts)}</span></div>`;
    }
    box.appendChild(el);
  }
  box.scrollTop = box.scrollHeight;
  $("#wire-frames").textContent = wireLog
    .map((w) => `${w.dir} ${w.kind.padEnd(15)} ${String(w.bytes).padStart(5)} B`)
    .join("\n");
}

// ---------- encryption visibility ----------
function logWire(dir, kind, bytes) {
  wireLog.unshift({ dir, kind, bytes });
  if (wireLog.length > 8) wireLog.pop();
}

$("#peek-wire").addEventListener("click", () => {
  $("#wire-peek").hidden = !$("#wire-peek").hidden;
});

function flashSeal() {
  const b = $("#peek-wire");
  b.classList.remove("flash");
  void b.offsetWidth;
  b.classList.add("flash");
}

// ---------- utils ----------
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const time = (ts) => new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
