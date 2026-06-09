import { makeClient, toB64, fromB64, toHex, encodeText, decodeText } from "./crypto.js";
import { connect, sendFrame, publishKeyPackage, grabKeyPackage } from "./net.js";

// ---------- state ----------
let me = null;
let client = null;
let ws = null;
const chats = new Map(); // hexId -> {id, title, members:Set, msgs:[], unread, lastBytes}
let activeChat = null;
const wireLog = []; // last frames, for the "what the server sees" peek

const $ = (s) => document.querySelector(s);

// ---------- boot ----------
$("#gate-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = $("#gate-name").value.trim().toLowerCase();
  if (!name) return;
  const hint = $("#gate-hint");
  hint.classList.remove("err");
  hint.textContent = "forging keys on this device…";
  try {
    client = await makeClient(name);
    me = name;
    // publish a stack of key packages so several people can invite us
    for (let i = 0; i < 5; i++) await publishKeyPackage(me, toB64(client.key_package()));
    await linkUp();
    $("#me-name").textContent = me;
    $("#gate").classList.add("lifted");
    $("#shell").hidden = false;
    $("#ticker").hidden = false;
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
      sysMsg(hex, `${frame.from} sealed you into this chat`);
    } else {
      const inc = client.recv(bytes);
      const hex = toHex(inc.chatId);
      const chat = ensureChat(hex, inc.chatId, inc.sender);
      chat.members.add(inc.sender);
      chat.lastBytes = bytes.length;
      if (inc.plaintext === undefined) {
        sysMsg(hex, `group keys rotated (${inc.sender} changed the roster)`);
      } else {
        handlePayload(hex, inc.sender, decodeText(inc.plaintext), bytes.length);
      }
    }
  } catch (err) {
    console.warn("frame dropped:", err);
  }
  renderChatList();
  if (activeChat) renderConvo();
}

// app-level payloads ride encrypted inside MLS messages
function handlePayload(hex, sender, raw, wireBytes) {
  let p;
  try { p = JSON.parse(raw); } catch { p = { t: "text", body: raw }; }
  const chat = chats.get(hex);
  if (p.t === "roster") {
    p.members.filter((m) => m !== me).forEach((m) => chat.members.add(m));
    chat.title = [...chat.members].join(", ");
    return;
  }
  chat.msgs.push({ who: sender, text: p.body, bytes: wireBytes, ts: Date.now(), mine: false, fresh: true });
  if (activeChat !== hex) chat.unread++;
  flashSeal();
}

// ---------- chats ----------
function ensureChat(hex, idBytes, title) {
  if (!chats.has(hex)) {
    chats.set(hex, { id: idBytes, title, members: new Set(), msgs: [], unread: 0, lastBytes: 0 });
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
  if (!kp) return alert(`"${who}" hasn't published keys on this relay yet`);
  const id = client.create_chat();
  const hex = toHex(id);
  const chat = ensureChat(hex, id, who);
  chat.members.add(who);
  const inv = client.invite(id, fromB64(kp));
  sendFrame(ws, [who], toB64(inv.welcome), "welcome");
  logWire("→", "welcome", inv.welcome.length);
  sysMsg(hex, `you sealed ${who} into this chat`);
  openChat(hex);
  renderChatList();
});

$("#add-person").addEventListener("click", async () => {
  if (!activeChat) return;
  const who = prompt("add who?")?.trim().toLowerCase();
  if (!who || who === me) return;
  const chat = chats.get(activeChat);
  const kp = await grabKeyPackage(who);
  if (!kp) return alert(`"${who}" hasn't published keys on this relay yet`);
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
  sysMsg(activeChat, `you sealed ${who} into this chat — keys rotated`);
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
  chat.msgs.push({ who: me, text, bytes: wire.length, ts: Date.now(), mine: true });
  chat.lastBytes = wire.length;
  flashSeal();
  renderChatList();
  renderConvo();
});

// ---------- render ----------
function renderChatList() {
  const nav = $("#chat-list");
  nav.innerHTML = "";
  for (const [hex, chat] of chats) {
    const btn = document.createElement("button");
    btn.className = "chat-item" + (hex === activeChat ? " active" : "");
    const last = chat.msgs.at(-1);
    btn.innerHTML = `<span class="who">${esc(chat.title)}${chat.unread ? ` <span class="unread">●${chat.unread}</span>` : ""}</span>
      <span class="last">${last ? esc(last.sys ? last.text : (last.mine ? "you: " : "") + last.text) : "sealed channel open"}</span>`;
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
  $("#convo-members").textContent = `you + ${[...chat.members].join(", ")} · end-to-end encrypted`;
  $("#seal-count").textContent = `${chat.lastBytes} B`;
  const box = $("#messages");
  box.innerHTML = "";
  for (const m of chat.msgs) {
    const el = document.createElement("div");
    if (m.sys) {
      el.className = "msg sys";
      el.innerHTML = `<div class="bubble">${esc(m.text)}</div>`;
    } else {
      el.className = "msg" + (m.mine ? " mine" : "");
      el.innerHTML = `<span class="meta"><span class="who">${esc(m.who)}</span> · ${time(m.ts)}</span>
        <div class="bubble"></div>
        <span class="bytes">${m.bytes} B on the wire</span>`;
      const bubble = el.querySelector(".bubble");
      if (m.fresh) {
        descramble(bubble, m.text);
        m.fresh = false;
      } else {
        bubble.textContent = m.text;
      }
    }
    box.appendChild(el);
  }
  box.scrollTop = box.scrollHeight;
  $("#wire-frames").textContent = wireLog
    .map((w) => `${w.dir} ${w.kind.padEnd(8)} ${String(w.bytes).padStart(5)} B  ${w.peek}`)
    .join("\n");
}

// incoming text resolves out of ciphertext glyphs — encryption you can see
function descramble(el, text) {
  const glyphs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  const steps = Math.max(8, Math.min(22, text.length));
  let frame = 0;
  const tick = () => {
    frame++;
    const solved = Math.floor((frame / steps) * text.length);
    el.textContent =
      text.slice(0, solved) +
      [...text.slice(solved)].map((c) => (c === " " ? " " : glyphs[(Math.random() * glyphs.length) | 0])).join("");
    if (solved < text.length) requestAnimationFrame(tick);
    else el.textContent = text;
  };
  tick();
}

// ---------- wire visibility ----------
function logWire(dir, kind, bytes) {
  wireLog.unshift({ dir, kind, bytes, peek: "" });
  if (wireLog.length > 6) wireLog.pop();
  const t = $("#ticker");
  t.textContent = dir === "→" ? `→ sealed ${bytes} B → relay` : `← ${bytes} B opened locally`;
  t.classList.add("show");
  clearTimeout(t._fade);
  t._fade = setTimeout(() => t.classList.remove("show"), 1800);
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
const esc = (s) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const time = (ts) => new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
