import { makeClient, restoreClient, toB64, fromB64, toHex, fromHex, encodeText, decodeText } from "./crypto.js?v=4";
import {
  connect, sendFrame, publishKeyPackage, grabKeyPackage, register, login, whoami, setToken,
  putVault, getVault, changePassword, userExists,
} from "./net.js?v=4";
import { deriveKeys, importVaultKey, seal, unseal } from "./keys.js?v=4";
import { idbGet, idbPut } from "./storage.js?v=4";
import { encryptAndUpload, mediaUrl, rememberLocalUrl } from "./media.js?v=4";

// ---------- state ----------
let me = null;
let client = null;
let ws = null;
let vaultKey = null;
let vaultRev = 0;
const chats = new Map(); // hexId -> {id, title, members:Set, msgs:[], unread, dead}
const profiles = new Map(); // user -> encrypted avatar descriptor {id, key, iv, mime}
let activeChat = null;
const wireLog = []; // last frames, for the encryption details panel

const $ = (s) => document.querySelector(s);

// ---------- theme ----------
let themeFade;
function applyTheme(t, animate = false) {
  const root = document.documentElement;
  if (animate) {
    root.classList.add("theming");
    clearTimeout(themeFade);
    themeFade = setTimeout(() => root.classList.remove("theming"), 400);
  }
  root.dataset.theme = t;
  localStorage.setItem("pluto.theme", t);
}
applyTheme(
  localStorage.getItem("pluto.theme") ||
    (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")
);
$("#theme-toggle").addEventListener("click", () =>
  applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark", true)
);

// ---------- auth + boot ----------
const hint = (msg, err = false) => {
  const el = $("#gate-hint");
  el.classList.toggle("err", err);
  el.textContent = msg;
};

async function enter(name, token, vaultKeyRaw) {
  setToken(token);
  localStorage.setItem("pluto.session", JSON.stringify({ name, token }));
  await idbPut(`vk:${name}`, vaultKeyRaw);
  vaultKey = await importVaultKey(vaultKeyRaw);
  me = name;
  await boot();
}

const readVault = async (sealed, which) => {
  if (!sealed) return null;
  try {
    return JSON.parse(decodeText(await unseal(vaultKey, new Uint8Array(sealed))));
  } catch (err) {
    console.warn(`${which} vault unreadable:`, err);
    return null;
  }
};

function hydrateVault(vault, liveIds, { fillOnly = false } = {}) {
  for (const [u, d] of Object.entries(vault?.profiles ?? {})) {
    if (!fillOnly || !profiles.has(u)) profiles.set(u, d);
  }
  for (const c of vault?.chats ?? []) {
    if (fillOnly && chats.has(c.hex)) continue; // never clobber live state
    chats.set(c.hex, {
      id: fromHex(c.hex),
      title: c.title,
      members: new Set(c.members),
      msgs: c.msgs ?? [],
      unread: c.unread ?? 0,
      dead: !liveIds.has(c.hex),
    });
  }
}

async function boot() {
  hint("Unlocking your encryption keys…");

  // everything local first: MLS snapshot + vault copy unlock in milliseconds
  let liveIds = new Set();
  const sealedState = await idbGet(`mls:${me}`);
  if (sealedState) {
    try {
      client = await restoreClient(await unseal(vaultKey, sealedState));
      liveIds = new Set(JSON.parse(client.chat_ids_hex()));
    } catch (err) {
      console.warn("state restore failed, starting fresh:", err);
      client = null;
    }
  }
  const freshIdentity = !client;
  if (!client) client = await makeClient(me);

  const local = await readVault(await idbGet(`vault:${me}`), "local");
  vaultRev = local?.rev ?? 0;
  hydrateVault(local, liveIds);

  // show the app now; the network catches up behind it
  $("#gate").classList.add("lifted");
  $("#gate").classList.remove("resuming");
  $("#shell").hidden = false;
  renderChatList();

  linkUp(); // fire and forget, the reconnect loop owns failures

  (async () => {
    // the server backup is newer only if another device wrote; fill the gaps
    const remote = await readVault(await getVault().catch(() => null), "server");
    if ((remote?.rev ?? -1) > vaultRev) {
      vaultRev = remote.rev;
      hydrateVault(remote, liveIds, { fillOnly: true });
      renderChatList();
      if (activeChat) renderConvo();
    }
    // publish a stack of key packages so several people can invite us, then
    // persist since their private halves live in the MLS state. a fresh
    // identity clears the server's stale packages from a lost device
    await Promise.all(
      Array.from({ length: 5 }, (_, i) => publishKeyPackage(toB64(client.key_package()), i === 0 && freshIdentity))
    );
    await persist();
  })().catch((err) => console.warn("background boot failed:", err));
}

$("#gate-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = $("#gate-name").value.trim().toLowerCase();
  const pass = $("#gate-pass").value;
  if (!name || !pass) return;
  try {
    hint("Deriving your keys…");
    const { authKey, vaultKeyRaw } = await deriveKeys(name, pass);
    hint("Signing in…");
    const d = await login(name, authKey);
    await enter(d.user, d.token, vaultKeyRaw);
  } catch (err) {
    hint(err.message || String(err), true);
  }
});

$("#register-btn").addEventListener("click", async () => {
  const name = $("#gate-name").value.trim().toLowerCase();
  const pass = $("#gate-pass").value;
  if (!name || !pass) return hint("Pick a username and a password first.", true);
  try {
    hint("Deriving your keys…");
    const { authKey, vaultKeyRaw } = await deriveKeys(name, pass);
    hint("Creating your account…");
    const d = await register(name, authKey);
    await enter(d.user, d.token, vaultKeyRaw);
  } catch (err) {
    hint(err.message || String(err), true);
  }
});

$("#signout").addEventListener("click", () => {
  localStorage.removeItem("pluto.session");
  location.reload();
});

// resume a saved session if the token is still good and we have the vault key.
// the "resuming" class goes on synchronously so the sign-in form never flashes
(async () => {
  let saved = null;
  try {
    saved = JSON.parse(localStorage.getItem("pluto.session") || "null");
  } catch {}
  if (!saved?.token) return;
  $("#gate").classList.add("resuming");
  hint("Unlocking your encryption keys…");
  try {
    const vk = await idbGet(`vk:${saved.name}`);
    if (vk && (await whoami(saved.token)) === saved.name) {
      setToken(saved.token);
      vaultKey = await importVaultKey(vk);
      me = saved.name;
      await boot();
      return;
    }
  } catch {
    /* token expired or relay restarted, sign in normally */
  }
  $("#gate").classList.remove("resuming");
  document.documentElement.classList.remove("has-session"); // bring the form back
  hint("Session expired. Sign in to unlock your encrypted chats.");
})();

// ---------- persistence (sealed with the vault key) ----------
let persistTimer;
const markDirty = () => {
  clearTimeout(persistTimer);
  persistTimer = setTimeout(() => persist().catch((e) => console.warn("persist failed:", e)), 1200);
};

async function persist() {
  const snap = client.export_state();
  await idbPut(`mls:${me}`, await seal(vaultKey, snap));
  vaultRev++;
  const vault = {
    rev: vaultRev,
    profiles: Object.fromEntries(profiles),
    chats: [...chats.entries()].map(([hex, c]) => ({
      hex,
      title: c.title,
      members: [...c.members],
      msgs: c.msgs.slice(-500),
      unread: c.unread,
    })),
  };
  const sealed = await seal(vaultKey, encodeText(JSON.stringify(vault)));
  await idbPut(`vault:${me}`, sealed);
  try {
    await putVault(sealed); // best effort: offline is fine, idb copy has it
  } catch {}
}

// reconnect forever; the relay queues our mail while we're gone
let connecting = false;
let retries = 0;
const retryDelay = () => Math.min(30_000, 1500 * 2 ** Math.min(retries, 4));

async function linkUp() {
  if (connecting || (ws && ws.readyState === WebSocket.OPEN)) return;
  connecting = true;
  try {
    ws = await connect(onFrame, () => {
      $("#conn-dot").classList.remove("live");
      setTimeout(linkUp, retryDelay());
    });
    retries = 0;
    $("#conn-dot").classList.add("live");
  } catch {
    retries++;
    $("#conn-dot").classList.remove("live");
    setTimeout(linkUp, retryDelay());
  } finally {
    connecting = false;
  }
}

// waking the tab or regaining network is the moment to check the link
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && me) linkUp();
});
addEventListener("online", () => me && linkUp());

// ---------- incoming ----------
function onFrame(frame) {
  const bytes = fromB64(frame.blob);
  logWire("←", frame.kind, bytes.length);
  try {
    if (frame.kind === "welcome") {
      const id = client.join(bytes);
      const hex = toHex(id);
      const chat = ensureChat(hex, id, frame.from);
      chat.dead = false; // re-added after a device change, or brand new
      chat.members.add(frame.from);
      sysMsg(hex, `${frame.from} added you to the chat`);
      // introduce ourselves: the new chat should have our (encrypted) photo
      if (profiles.has(me)) try { sendPayload(chat, { t: "avatar", media: profiles.get(me) }); } catch {}
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
    return;
  }
  markDirty();
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
  if (p.t === "avatar") {
    if (p.media) profiles.set(sender, p.media);
    else profiles.delete(sender);
    return;
  }
  const msg = { who: sender, ts: Date.now(), mine: false, t: p.t || "text" };
  if (msg.t === "text") msg.text = p.body;
  else msg.media = p.media;
  chat.msgs.push(msg);
  if (activeChat !== hex) chat.unread++;
  flashSeal();
}

// ---------- chats ----------
function ensureChat(hex, idBytes, title) {
  if (!chats.has(hex)) {
    chats.set(hex, { id: idBytes, title, members: new Set(), msgs: [], unread: 0, dead: false });
    chats.get(hex).msgs.push({ sys: true, text: "Messages in this chat are end-to-end encrypted", ts: Date.now() });
  }
  return chats.get(hex);
}

function sysMsg(hex, text) {
  chats.get(hex).msgs.push({ sys: true, text, ts: Date.now() });
}

$("#fab").addEventListener("click", () => {
  const form = $("#new-chat");
  form.hidden = !form.hidden;
  $("#fab").classList.toggle("open", !form.hidden);
  if (!form.hidden) $("#new-chat-name").focus();
});

const chatWith = (who) =>
  [...chats.entries()].find(([, c]) => c.members.size === 1 && c.members.has(who))?.[0];

async function startChat(who) {
  if (!who || who === me) return;
  const existing = chatWith(who);
  if (existing) return openChat(existing);
  const kp = await grabKeyPackage(who);
  if (!kp) return alert(`"${who}" isn't registered on this server yet.`);
  const id = client.create_chat();
  const hex = toHex(id);
  const chat = ensureChat(hex, id, who);
  chat.members.add(who);
  const inv = client.invite(id, fromB64(kp));
  sendFrame(ws, [who], toB64(inv.welcome), "welcome");
  logWire("→", "welcome", inv.welcome.length);
  if (profiles.has(me)) try { sendPayload(chat, { t: "avatar", media: profiles.get(me) }); } catch {}
  markDirty();
  openChat(hex);
  renderChatList();
}

$("#new-chat").addEventListener("submit", async (e) => {
  e.preventDefault();
  const who = $("#new-chat-name").value.trim().toLowerCase();
  $("#new-chat-name").value = "";
  $("#new-chat").hidden = true;
  $("#fab").classList.remove("open");
  await startChat(who);
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
  if (profiles.has(me)) try { sendPayload(chat, { t: "avatar", media: profiles.get(me) }); } catch {}
  logWire("→", "commit+welcome", inv.commit.length + inv.welcome.length);
  sysMsg(activeChat, `You added ${who}. Encryption keys were updated`);
  markDirty();
  renderChatList();
  renderConvo();
});

// ---------- sending ----------
function sendPayload(chat, payload) {
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    alert("Not connected to the server. Try again in a moment.");
    throw new Error("offline");
  }
  const wire = client.send(chat.id, encodeText(JSON.stringify(payload)));
  sendFrame(ws, [...chat.members], toB64(wire), "msg");
  logWire("→", payload.t, wire.length);
  markDirty();
}

$("#composer").addEventListener("submit", (e) => {
  e.preventDefault();
  const text = $("#composer-input").value.trim();
  if (!text || !activeChat) return;
  const chat = chats.get(activeChat);
  try {
    sendPayload(chat, { t: "text", body: text });
  } catch {
    return; // stay in the input so nothing is lost
  }
  $("#composer-input").value = "";
  syncSendButton();
  chat.msgs.push({ who: me, text, ts: Date.now(), mine: true, t: "text" });
  flashSeal();
  renderChatList();
  renderConvo();
});

function syncSendButton() {
  const hasText = $("#composer-input").value.trim().length > 0;
  $("#send-btn").hidden = !hasText;
  $("#mic-btn").hidden = hasText;
}
$("#composer-input").addEventListener("input", syncSendButton);

// ---------- media sending ----------
$("#attach-btn").addEventListener("click", () => $("#file-input").click());

$("#file-input").addEventListener("change", async (e) => {
  const files = [...e.target.files];
  e.target.value = "";
  for (const f of files) await sendFile(f).catch((err) => alert(`Couldn't send ${f.name}: ${err.message}`));
});

async function sendFile(file) {
  if (!activeChat) return;
  const chat = chats.get(activeChat);
  if (chat.dead) return;
  const kind = file.type.startsWith("image/") ? "image" : file.type.startsWith("video/") ? "video" : "file";
  const bytes = new Uint8Array(await file.arrayBuffer());
  const enc = await encryptAndUpload(bytes);
  const media = { ...enc, mime: file.type || "application/octet-stream", size: file.size, name: file.name };
  if (kind === "image") {
    try {
      const bmp = await createImageBitmap(file);
      media.w = bmp.width;
      media.h = bmp.height;
      bmp.close();
    } catch {}
  }
  rememberLocalUrl(media.id, file);
  sendPayload(chat, { t: kind, media });
  chat.msgs.push({ who: me, mine: true, ts: Date.now(), t: kind, media });
  flashSeal();
  renderChatList();
  renderConvo();
}

// ---------- voice notes ----------
let rec = null;
let recChunks = [];
let recStart = 0;
let recTimer = null;
let recWanted = false; // false = cancelled

$("#mic-btn").addEventListener("click", async () => {
  if (!activeChat || chats.get(activeChat)?.dead) return;
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const mime = MediaRecorder.isTypeSupported("audio/webm;codecs=opus") ? "audio/webm;codecs=opus" : "";
    rec = new MediaRecorder(stream, mime ? { mimeType: mime } : undefined);
    recChunks = [];
    recWanted = false;
    rec.ondataavailable = (e) => e.data.size && recChunks.push(e.data);
    rec.onstop = async () => {
      stream.getTracks().forEach((t) => t.stop());
      stopRecUi();
      if (!recWanted || !recChunks.length) return;
      const blob = new Blob(recChunks, { type: rec.mimeType || "audio/webm" });
      const dur = Math.max(1, Math.round((Date.now() - recStart) / 1000));
      const chat = chats.get(activeChat);
      const enc = await encryptAndUpload(new Uint8Array(await blob.arrayBuffer()));
      const media = { ...enc, mime: blob.type, size: blob.size, dur };
      rememberLocalUrl(media.id, blob);
      sendPayload(chat, { t: "voice", media });
      chat.msgs.push({ who: me, mine: true, ts: Date.now(), t: "voice", media });
      flashSeal();
      renderChatList();
      renderConvo();
    };
    rec.start();
    recStart = Date.now();
    $("#composer").hidden = true;
    $("#rec-bar").hidden = false;
    recTimer = setInterval(() => ($("#rec-time").textContent = fmtDur((Date.now() - recStart) / 1000)), 250);
  } catch (err) {
    console.warn("mic unavailable:", err);
    alert("Microphone access is needed for voice messages.");
  }
});

function stopRecUi() {
  clearInterval(recTimer);
  $("#rec-time").textContent = "0:00";
  $("#rec-bar").hidden = true;
  $("#composer").hidden = false;
}
$("#rec-send").addEventListener("click", () => { recWanted = true; rec?.stop(); });
$("#rec-cancel").addEventListener("click", () => { recWanted = false; rec?.stop(); });

// ---------- render: sidebar ----------
function avatarColor(name) {
  let h = 0;
  for (const c of String(name)) h = (h * 31 + c.charCodeAt(0)) % 360;
  return `linear-gradient(135deg, hsl(${h}, 55%, 58%), hsl(${h}, 55%, 44%))`;
}
const initial = (name) => (name?.[0] || "?").toUpperCase();

// swap in decrypted profile photos wherever an avatar names its user
function hydrateAvatars(root) {
  root.querySelectorAll(".avatar[data-user]").forEach((el) => {
    const desc = profiles.get(el.dataset.user);
    if (!desc) return;
    mediaUrl(desc)
      .then((url) => {
        const img = document.createElement("img");
        img.src = url;
        img.alt = "";
        el.appendChild(img);
      })
      .catch(() => {});
  });
}

const previewText = (m) => {
  if (!m) return "Say hello, it's encrypted";
  const pre = m.mine ? "You: " : "";
  if (m.t === "image") return pre + "📷 Photo";
  if (m.t === "video") return pre + "🎬 Video";
  if (m.t === "voice") return pre + "🎤 Voice message";
  if (m.t === "file") return pre + "📎 " + (m.media?.name || "File");
  return pre + m.text;
};

// the search bar also finds people: exact usernames only, so there's
// still no way to browse or enumerate who's on the server
let searchHit = null;
let searchTimer;
$("#search").addEventListener("input", () => {
  const q = $("#search").value.trim().toLowerCase();
  searchHit = null;
  renderChatList();
  clearTimeout(searchTimer);
  if (!/^[a-z0-9_]{2,24}$/.test(q) || q === me || chatWith(q)) return;
  searchTimer = setTimeout(async () => {
    if ((await userExists(q).catch(() => false)) && $("#search").value.trim().toLowerCase() === q) {
      searchHit = q;
      renderChatList();
    }
  }, 250);
});

function renderChatList() {
  const nav = $("#chat-list");
  const q = $("#search").value.trim().toLowerCase();
  nav.innerHTML = "";
  const sorted = [...chats.entries()].sort(
    (a, b) => (b[1].msgs.at(-1)?.ts ?? 0) - (a[1].msgs.at(-1)?.ts ?? 0)
  );
  for (const [hex, chat] of sorted) {
    if (q && !chat.title.toLowerCase().includes(q)) continue;
    const btn = document.createElement("button");
    btn.className = "chat-item" + (hex === activeChat ? " active" : "");
    const last = chat.msgs.filter((m) => !m.sys).at(-1);
    const peer = chat.members.size === 1 ? [...chat.members][0] : null;
    btn.innerHTML = `
      <span class="avatar"${peer ? ` data-user="${esc(peer)}"` : ""} style="background:${avatarColor(chat.title)}">${esc(initial(chat.title))}</span>
      <span class="ci-main">
        <span class="who">${esc(chat.title)}</span>
        <span class="last">${esc(previewText(last))}</span>
      </span>
      <span class="ci-side">
        <span class="time">${last ? time(last.ts) : ""}</span>
        ${chat.unread ? `<span class="badge">${chat.unread}</span>` : ""}
      </span>`;
    btn.onclick = () => openChat(hex);
    nav.appendChild(btn);
  }
  if (searchHit && searchHit === q) {
    const btn = document.createElement("button");
    btn.className = "chat-item start-row";
    btn.innerHTML = `
      <span class="avatar" data-user="${esc(searchHit)}" style="background:${avatarColor(searchHit)}">${esc(initial(searchHit))}</span>
      <span class="ci-main">
        <span class="who">${esc(searchHit)}</span>
        <span class="last">Start an encrypted chat</span>
      </span>`;
    btn.onclick = () => {
      const who = searchHit;
      $("#search").value = "";
      searchHit = null;
      startChat(who);
    };
    nav.appendChild(btn);
  }
  hydrateAvatars(nav);
}

function openChat(hex) {
  activeChat = hex;
  chats.get(hex).unread = 0;
  document.body.classList.add("in-convo"); // phones: conversation takes the screen
  $("#convo").classList.remove("empty");
  $("#convo-empty").hidden = true;
  $("#convo-live").hidden = false;
  renderChatList();
  renderConvo();
  markDirty();
  $("#composer-input").focus();
}

$("#back-btn").addEventListener("click", () => {
  document.body.classList.remove("in-convo");
  activeChat = null;
  renderChatList();
});

// ---------- render: conversation ----------
function renderConvo() {
  const chat = chats.get(activeChat);
  if (!chat) return;
  $("#convo-title").textContent = chat.title;
  const cav = $("#convo-avatar");
  cav.textContent = initial(chat.title);
  cav.style.background = avatarColor(chat.title);
  if (chat.members.size === 1) cav.dataset.user = [...chat.members][0];
  else delete cav.dataset.user;
  hydrateAvatars($("#convo-head"));
  $("#convo-members").textContent =
    chat.members.size > 1
      ? `${chat.members.size + 1} members · end-to-end encrypted`
      : "end-to-end encrypted";
  $("#dead-banner").hidden = !chat.dead;
  $("#composer").hidden = chat.dead;
  $("#rec-bar").hidden = true;

  const group = chat.members.size > 1;
  const box = $("#messages");
  box.innerHTML = "";
  let lastDay = "";
  chat.msgs.forEach((m, i) => {
    const day = new Date(m.ts).toDateString();
    if (day !== lastDay) {
      lastDay = day;
      const pill = document.createElement("div");
      pill.className = "date-pill";
      pill.textContent = fmtDay(m.ts);
      box.appendChild(pill);
    }
    box.appendChild(msgEl(m, chat.msgs[i + 1], group));
  });
  box.scrollTop = box.scrollHeight;
  $("#wire-frames").textContent = wireLog
    .map((w) => `${w.dir} ${w.kind.padEnd(15)} ${String(w.bytes).padStart(5)} B`)
    .join("\n");
}

function msgEl(m, next, group) {
  const el = document.createElement("div");
  if (m.sys) {
    el.className = "msg sys";
    el.innerHTML = `<div class="note">${esc(m.text)}</div>`;
    return el;
  }
  const sameNext = next && !next.sys && next.who === m.who && next.mine === m.mine;
  el.className = `msg ${m.mine ? "out" : "in"}${sameNext ? "" : " tail"}`;
  const name =
    !m.mine && group
      ? `<span class="sender" style="color:hsl(${[...m.who].reduce((h, c) => (h * 31 + c.charCodeAt(0)) % 360, 0)}, 55%, 45%)">${esc(m.who)}</span>`
      : "";
  const stamp = `<span class="t">${time(m.ts)}</span>`;

  if (m.t === "image" || m.t === "video") {
    el.innerHTML = `<div class="bubble media">${name}<div class="media-pending">Decrypting…</div>${stamp}</div>`;
    const holder = el.querySelector(".media-pending");
    mediaUrl(m.media)
      .then((url) => {
        if (m.t === "image") {
          const img = document.createElement("img");
          img.src = url;
          if (m.media.w && m.media.h) img.style.aspectRatio = `${m.media.w}/${m.media.h}`;
          img.onclick = () => showLightbox(url);
          holder.replaceWith(img);
        } else {
          const vid = document.createElement("video");
          vid.src = url;
          vid.controls = true;
          holder.replaceWith(vid);
        }
      })
      .catch(() => (holder.textContent = "Couldn't decrypt media"));
  } else if (m.t === "voice") {
    el.innerHTML = `<div class="bubble">${name}<div class="voice">
        <button class="play-btn" title="Play voice message">${playSvg()}</button>
        <span class="voice-meta"><span class="voice-track"><span class="fill"></span></span>
        <span class="voice-dur">${fmtDur(m.media.dur || 0)}</span></span>
      </div>${stamp}</div>`;
    wireVoice(el, m);
  } else if (m.t === "file") {
    el.innerHTML = `<div class="bubble"><div class="filebox">
        <a href="#" download="${esc(m.media.name || "file")}">
          <span class="play-btn">📄</span>
          <span><span class="fname">${esc(m.media.name || "file")}</span><br/>
          <span class="fsize">${fmtSize(m.media.size)}</span></span>
        </a>
      </div>${stamp}</div>`;
    el.querySelector("a").addEventListener("click", async (e) => {
      e.preventDefault();
      const url = await mediaUrl(m.media);
      const a = document.createElement("a");
      a.href = url;
      a.download = m.media.name || "file";
      a.click();
    });
  } else {
    el.innerHTML = `${name ? `<div class="bubble">${name}${esc(m.text)}${stamp}</div>` : `<div class="bubble">${esc(m.text)}${stamp}</div>`}`;
  }
  return el;
}

const playSvg = (paused = false) =>
  paused
    ? `<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M6 4h4v16H6zM14 4h4v16h-4z"/></svg>`
    : `<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M7 4.5v15l13-7.5z"/></svg>`;

function wireVoice(el, m) {
  const btn = el.querySelector(".play-btn");
  const fill = el.querySelector(".fill");
  const durEl = el.querySelector(".voice-dur");
  let audio = null;
  btn.addEventListener("click", async () => {
    if (!audio) {
      btn.disabled = true;
      const url = await mediaUrl(m.media).catch(() => null);
      btn.disabled = false;
      if (!url) return (durEl.textContent = "error");
      audio = new Audio(url);
      audio.addEventListener("timeupdate", () => {
        const total = audio.duration && isFinite(audio.duration) ? audio.duration : m.media.dur || 1;
        fill.style.inset = `0 ${100 - Math.min(100, (audio.currentTime / total) * 100)}% 0 0`;
        durEl.textContent = fmtDur(audio.currentTime);
      });
      audio.addEventListener("ended", () => {
        btn.innerHTML = playSvg();
        fill.style.inset = "0 100% 0 0";
        durEl.textContent = fmtDur(m.media.dur || 0);
      });
    }
    if (audio.paused) {
      audio.play();
      btn.innerHTML = playSvg(true);
    } else {
      audio.pause();
      btn.innerHTML = playSvg();
    }
  });
}

// ---------- settings ----------
$("#settings-btn").addEventListener("click", () => {
  $("#s-name").textContent = me;
  refreshSettingsAvatar();
  $("#pass-form").reset();
  passStatus("");
  $("#settings-overlay").hidden = false;
});

function refreshSettingsAvatar() {
  const el = $("#s-avatar");
  el.textContent = initial(me);
  el.style.background = avatarColor(me);
  el.dataset.user = me;
  hydrateAvatars($("#settings"));
  $("#avatar-remove").hidden = !profiles.has(me);
}

// canvas re-encode: only pixels survive, so EXIF, GPS and every other
// metadata block is destroyed before the image is ever encrypted
async function scrubAvatar(file) {
  const bmp = await createImageBitmap(file);
  const side = Math.min(bmp.width, bmp.height);
  const size = Math.min(512, side);
  const c = document.createElement("canvas");
  c.width = c.height = size;
  c.getContext("2d").drawImage(bmp, (bmp.width - side) / 2, (bmp.height - side) / 2, side, side, 0, 0, size, size);
  bmp.close();
  return new Promise((res, rej) =>
    c.toBlob((b) => (b ? res(b) : rej(new Error("couldn't process that image"))), "image/jpeg", 0.85)
  );
}

// the photo travels only inside MLS messages, so only chat members get the key
function broadcastAvatar(desc) {
  for (const chat of chats.values()) {
    if (chat.dead) continue;
    try {
      sendPayload(chat, { t: "avatar", media: desc });
    } catch {}
  }
}

$("#avatar-btn").addEventListener("click", () => $("#avatar-input").click());

$("#avatar-input").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  e.target.value = "";
  if (!file) return;
  try {
    const clean = await scrubAvatar(file);
    const enc = await encryptAndUpload(new Uint8Array(await clean.arrayBuffer()));
    const desc = { ...enc, mime: "image/jpeg" };
    rememberLocalUrl(desc.id, clean);
    profiles.set(me, desc);
    broadcastAvatar(desc);
    markDirty();
    refreshSettingsAvatar();
    renderChatList();
    if (activeChat) renderConvo();
  } catch (err) {
    alert("Couldn't set photo: " + (err.message || err));
  }
});

$("#avatar-remove").addEventListener("click", () => {
  profiles.delete(me);
  broadcastAvatar(null);
  markDirty();
  refreshSettingsAvatar();
  renderChatList();
  if (activeChat) renderConvo();
});
$("#settings-close").addEventListener("click", () => ($("#settings-overlay").hidden = true));
$("#settings-overlay").addEventListener("click", (e) => {
  if (e.target === $("#settings-overlay")) $("#settings-overlay").hidden = true;
});

function passStatus(text, err = false) {
  const el = $("#pass-status");
  el.hidden = !text;
  el.textContent = text;
  el.classList.toggle("err", err);
}

$("#pass-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const oldPass = $("#pass-old").value;
  const newPass = $("#pass-new").value;
  if (newPass !== $("#pass-new2").value) return passStatus("New passwords don't match.", true);
  if (newPass === oldPass) return passStatus("That's already your password.", true);
  $("#pass-submit").disabled = true;
  try {
    passStatus("Re-deriving your keys…");
    const oldKeys = await deriveKeys(me, oldPass);
    const newKeys = await deriveKeys(me, newPass);
    // relay verifies the old auth key before accepting the new one
    await changePassword(oldKeys.authKey, newKeys.authKey);
    passStatus("Re-encrypting your data…");
    vaultKey = await importVaultKey(newKeys.vaultKeyRaw);
    await idbPut(`vk:${me}`, newKeys.vaultKeyRaw);
    await persist(); // reseals MLS state + vault with the new key, locally and on the relay
    passStatus("Password updated.");
    $("#pass-form").reset();
  } catch (err) {
    passStatus(err.message || String(err), true);
  } finally {
    $("#pass-submit").disabled = false;
  }
});

// ---------- lightbox ----------
function showLightbox(url) {
  const lb = $("#lightbox");
  lb.innerHTML = `<img src="${url}" alt="" />`;
  lb.hidden = false;
}
$("#lightbox").addEventListener("click", () => {
  $("#lightbox").hidden = true;
  $("#lightbox").innerHTML = "";
});

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
const fmtDay = (ts) => {
  const d = new Date(ts);
  const today = new Date();
  if (d.toDateString() === today.toDateString()) return "Today";
  today.setDate(today.getDate() - 1);
  if (d.toDateString() === today.toDateString()) return "Yesterday";
  return d.toLocaleDateString([], { month: "long", day: "numeric" });
};
const fmtDur = (s) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}`;
const fmtSize = (b) => (b > 1048576 ? `${(b / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(b / 1024))} KB`);
