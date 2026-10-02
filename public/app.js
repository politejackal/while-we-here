// While We Here — client.
//
// The conversation lives only in this page's memory. It is sent, encrypted,
// straight to the other person in the room (through the relay, which can't read
// it). Nothing is written to storage, with one exception: during a page refresh
// the conversation is parked in sessionStorage for the few seconds it takes the
// page to come back, then removed immediately. Closing the tab discards it.

'use strict';

(() => {
  const $ = (id) => document.getElementById(id);
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // no 0/O, 1/I/L
  const CODE_LEN = 8;
  const KDF_ITERATIONS = 150_000;
  const STASH_KEY = 'wwh-refresh';
  const RECONNECT_FOR_MS = 30_000;
  const CONFIG = window.WWH_CONFIG || {};
  // The relay's base address: same origin when it serves this page, else from config.js.
  const RELAY = (CONFIG.relay || location.origin).replace(/\/+$/, '');
  const RELAY_WS = RELAY.replace(/^http/, 'ws') + '/ws';

  // ---------- Bytes ----------
  function toB64(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
  }
  const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const toB64url = (buf) => toB64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  // ---------- Codes ----------
  function generateCode() {
    let out = '';
    const limit = 256 - (256 % ALPHABET.length);
    while (out.length < CODE_LEN) {
      for (const v of crypto.getRandomValues(new Uint8Array(16))) {
        if (v < limit && out.length < CODE_LEN) out += ALPHABET[v % ALPHABET.length];
      }
    }
    return out;
  }
  const normalizeCode = (s) => s.toUpperCase().split('').filter((c) => ALPHABET.includes(c)).join('').slice(0, CODE_LEN);
  const formatCode = (c) => (c.length > 4 ? c.slice(0, 4) + '-' + c.slice(4) : c);

  // ---------- Crypto ----------
  // The code never leaves the browser. From it we derive, with a slow hash:
  //   roomId     -> sent to the server so it can match people up
  //   codeSecret -> mixed into every encryption key; the server never has it
  async function deriveFromCode(code) {
    const base = await crypto.subtle.importKey('raw', enc.encode(code), 'PBKDF2', false, ['deriveBits']);
    const run = (salt) => crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: KDF_ITERATIONS }, base, 256);
    const [id, secret] = await Promise.all([run('whilewehere/room-id/v1'), run('whilewehere/room-key/v1')]);
    return { roomId: toB64url(id), codeSecret: new Uint8Array(secret) };
  }

  // A fresh key pair for every page load. Each pair of people agrees a session
  // key with ECDH, salted with the code secret: without the code (which the
  // server doesn't have), a man in the middle ends up with the wrong key and
  // every message fails to decrypt.
  async function sessionKey(peerPubB64) {
    const peerPub = await crypto.subtle.importKey('raw', fromB64(peerPubB64), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerPub }, S.keyPair.privateKey, 256);
    const hkdf = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    const info = enc.encode('whilewehere/session/v1|' + [S.myPub, peerPubB64].sort().join('|'));
    return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: S.codeSecret, info },
      hkdf, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  // Encryption hides what you said, but not how much. So before sealing, every
  // payload is padded out to a fixed bucket size (512 B, 1 KB, 2 KB, ...). "ok"
  // and a long paragraph look identical to the relay. JSON ignores trailing
  // spaces, so the padding needs no unwrapping on the other side.
  function pad(json) {
    const bytes = enc.encode(json);
    const n = bytes.length;
    const size = n <= 65536 ? Math.max(512, 2 ** Math.ceil(Math.log2(n))) : Math.ceil(n / 65536) * 65536;
    const out = new Uint8Array(size).fill(0x20);
    out.set(bytes);
    return out;
  }

  async function seal(peer, obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(S.myPub) },
      peer.key, pad(JSON.stringify(obj)));
    return JSON.stringify({ k: 'box', iv: toB64(iv), ct: toB64(ct) });
  }

  async function open(peer, box) {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(box.iv), additionalData: enc.encode(peer.pub) },
      peer.key, fromB64(box.ct));
    return JSON.parse(dec.decode(pt));
  }

  // ---------- State ----------
  const S = {
    ws: null,
    code: '', roomId: '', codeSecret: null,
    keyPair: null, myPub: '',
    me: '', token: '',
    peers: new Map(),    // id -> { id, pub, key, newcomer, returning, historyBy, outbox }
    count: 0, size: 2, locked: false, history: true,
    items: [],           // { type: 'msg', id, author, text, at } | { type: 'note', text, icon, warn }
    inRoom: false, online: false, leaving: false,
    pending: null,
    reconnectDeadline: 0,
    inbound: Promise.resolve(),
  };
  const rendered = new Set();
  const pendingPeers = () => [...S.peers.values()].some((p) => !p.key);

  async function ensureKeyPair() {
    if (S.keyPair) return;
    S.keyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    S.myPub = toB64(await crypto.subtle.exportKey('raw', S.keyPair.publicKey));
  }

  // ---------- Server connection ----------
  function connect() {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(RELAY_WS);
      ws.onopen = () => resolve(ws);
      ws.onerror = () => reject('network');
      ws.onmessage = (e) => { let m; try { m = JSON.parse(e.data); } catch { return; } onServer(m); };
      ws.onclose = () => onClose(ws);
    });
  }
  const send = (msg) => { if (S.ws && S.ws.readyState === 1) S.ws.send(JSON.stringify(msg)); };

  function request(msg) {
    return new Promise((resolve, reject) => {
      S.pending = { resolve, reject };
      send(msg);
    });
  }

  const newPeer = (id, extra) => ({ id, pub: '', key: null, newcomer: false, returning: false, historyBy: '', outbox: [], ...extra });

  function onServer(m) {
    switch (m.t) {
      case 'joined': {
        S.me = m.you; S.token = m.token; S.inRoom = true; S.online = true;
        S.peers = new Map(m.peers.map((id) => [id, newPeer(id)]));
        if (m.peers.length) sayHello();
        S.pending?.resolve(m); S.pending = null;
        break;
      }
      case 'error':
        S.pending?.reject(m.code); S.pending = null;
        break;
      case 'room':
        S.count = m.count; S.size = m.size || 2; S.locked = m.locked; S.history = m.history;
        break;
      case 'peer-joined':
        S.peers.set(m.peer, newPeer(m.peer, { newcomer: true, returning: m.returning, historyBy: m.historyBy }));
        note(m.returning ? 'Someone came back.' : 'Someone joined.', 'person');
        sayHello(m.peer);
        break;
      case 'peer-left':
        S.peers.delete(m.peer);
        note(S.peers.size ? 'Someone left.' : "Someone left. You're the last one here.", 'logout');
        break;
      case 'relay':
        // Process in order; key derivation is async.
        S.inbound = S.inbound.then(() => onRelay(m.from, m.data)).catch(() => {});
        break;
    }
    updateChrome();
  }

  // Newcomers greet everyone; people already inside greet only the newcomer.
  function sayHello(to) { send({ t: 'relay', to, data: JSON.stringify({ k: 'hello', pub: S.myPub }) }); }

  async function sendTo(peer, obj) { send({ t: 'relay', to: peer.id, data: await seal(peer, obj) }); }

  async function onRelay(from, data) {
    const peer = S.peers.get(from);
    if (!peer) return;
    let env; try { env = JSON.parse(data); } catch { return; }

    if (env.k === 'hello' && typeof env.pub === 'string' && !peer.key) {
      peer.pub = env.pub;
      peer.key = await sessionKey(env.pub);
      if (S.peers.get(from) !== peer) return;
      let sentHistory = false;
      if (peer.newcomer && peer.historyBy === S.me) {
        // We've been here longest: hand over the conversation (or don't).
        if (S.history || peer.returning) { await sendTo(peer, { type: 'history', messages: messagesForHistory() }); sentHistory = true; }
        else await sendTo(peer, { type: 'fresh' });
      }
      // Anything we said while this key was being agreed on.
      if (!sentHistory) for (const m of peer.outbox) await sendTo(peer, { type: 'msg', id: m.id, text: m.text });
      peer.outbox = [];
      updateChrome();
      return;
    }

    if (env.k === 'box' && peer.key) {
      let body;
      try { body = await open(peer, env); } catch {
        note("A message couldn't be verified and was dropped. Someone may be using the wrong code.", 'error', true);
        return;
      }
      if (body.type === 'msg' && typeof body.text === 'string' && typeof body.id === 'string') {
        if (S.items.some((it) => it.id === body.id)) return;
        S.items.push({ type: 'msg', id: body.id, author: from, text: body.text.slice(0, 4000), at: Date.now() });
        render(true);
      } else if (body.type === 'history' && Array.isArray(body.messages)) {
        const history = body.messages
          .filter((x) => x && typeof x.text === 'string' && typeof x.id === 'string')
          .map((x) => ({ type: 'msg', id: x.id, author: String(x.author || ''), text: x.text.slice(0, 4000), at: 0 }));
        const known = new Set(history.map((x) => x.id));
        // Keep anything that reached us directly before the history did.
        const extra = S.items.filter((it) => it.type === 'note' || (it.type === 'msg' && !known.has(it.id)));
        S.items = history;
        rendered.clear();
        note(history.length ? "You're seeing the conversation so far." : "Nothing's been said yet.", 'history');
        S.items.push(...extra);
        render(true);
      } else if (body.type === 'fresh') {
        note("Fresh start. Earlier messages in this room weren't shared with you.", 'history');
      }
    }
  }

  function messagesForHistory() {
    return S.items.filter((it) => it.type === 'msg').map(({ id, author, text }) => ({ id, author, text }));
  }

  function onClose(ws) {
    if (ws !== S.ws) return;
    S.online = false;
    S.pending?.reject('network'); S.pending = null;
    if (!S.inRoom || S.leaving) return;
    S.peers = new Map();
    updateChrome();
    if (!S.reconnectDeadline) S.reconnectDeadline = Date.now() + RECONNECT_FOR_MS;
    setTimeout(reconnect, 1500);
  }

  async function reconnect() {
    if (!S.inRoom || S.leaving || S.online) return;
    try {
      S.ws = await connect();
      await request({ t: 'join', room: S.roomId, token: S.token });
      S.reconnectDeadline = 0;
      note("Reconnected.", 'check');
    } catch (err) {
      if (err === 'not_found') return endRoom('gone');
      if (err === 'full' || err === 'locked') return endRoom('displaced');
      if (Date.now() < S.reconnectDeadline) setTimeout(reconnect, 2000);
      else endRoom('lost');
    }
  }

  // ---------- Entering rooms ----------
  async function createRoom() {
    const size = roomSize();
    if (!size) return;
    const btn = $('create-btn');
    setBusy(btn, true);
    try {
      await ensureKeyPair();
      S.ws = await connect();
      for (let attempt = 0; ; attempt++) {
        S.code = generateCode();
        S.items = [];
        Object.assign(S, await deriveFromCode(S.code));
        try {
          await request({ t: 'create', room: S.roomId, history: size === 2 || $('create-history').checked, size });
          break;
        } catch (err) {
          if (err !== 'exists' || attempt > 4) throw err;
        }
      }
      enterRoomView();
    } catch {
      snackbar("Couldn't reach the server. Check your connection and try again.");
      closeSocket();
    } finally {
      setBusy(btn, false);
    }
  }

  async function joinRoom(e) {
    e.preventDefault();
    const code = normalizeCode($('code-input').value);
    if (code.length !== CODE_LEN) return fieldError(`Codes are ${CODE_LEN} letters and numbers.`);
    const btn = $('join-btn');
    setBusy(btn, true);
    try {
      await ensureKeyPair();
      const derived = await deriveFromCode(code);
      Object.assign(S, derived, { code });
      S.items = [];
      S.ws = await connect();
      await request({ t: 'join', room: derived.roomId });
      $('code-input').value = '';
      enterRoomView();
      note("You're in, anonymously. Nobody here can see your IP or who you are.", 'public_off');
    } catch (err) {
      closeSocket();
      const messages = {
        not_found: "No room with that code. It may have already gone out.",
        full: 'This room already has two people in it.',
        locked: "This room is locked. Nobody new can join.",
        rate_limited: 'Too many wrong codes. Wait a few minutes and try again.',
      };
      if (messages[err]) fieldError(messages[err]);
      else snackbar("Couldn't reach the server. Check your connection and try again.");
    } finally {
      setBusy(btn, false);
    }
  }

  async function resumeAfterRefresh(stash) {
    S.code = stash.code;
    S.token = stash.token;
    S.items = Array.isArray(stash.items) ? stash.items : [];
    show('room');
    $('status-text').textContent = 'Reconnecting…';
    try {
      await ensureKeyPair();
      Object.assign(S, await deriveFromCode(S.code));
      S.ws = await connect();
      await request({ t: 'join', room: S.roomId, token: S.token });
      enterRoomView();
    } catch (err) {
      closeSocket();
      S.items = [];
      endRoom(err === 'full' || err === 'locked' ? 'displaced' : 'gone');
    }
  }

  function enterRoomView() {
    S.inRoom = true; S.online = true; S.leaving = false;
    rendered.clear();
    $('room-code').textContent = formatCode(S.code);
    $('big-code').textContent = formatCode(S.code);
    $('room').classList.remove('dissolving');
    show('room');
    render(true);
    updateChrome();
    if (matchMedia('(pointer: fine)').matches) $('message-input').focus();
  }

  function closeSocket() {
    const ws = S.ws;
    S.ws = null;
    try { ws?.close(); } catch {}
  }

  let maxRoomSize = 50;

  // Returns the chosen size, or 0 (with the field marked) if the custom number isn't usable.
  function roomSize() {
    if (!$('size-custom').checked) return Number(document.querySelector('input[name=size]:checked').value);
    const n = Number($('custom-size').value);
    if (Number.isInteger(n) && n >= 2 && n <= maxRoomSize) return n;
    $('custom-size-field').classList.add('error');
    $('custom-size-support').textContent = `Pick a whole number from 2 to ${maxRoomSize}.`;
    $('custom-size').focus();
    return 0;
  }

  // The size the picker currently shows, without flagging errors (custom may be half-typed).
  function pickedSize() {
    if (!$('size-custom').checked) return Number(document.querySelector('input[name=size]:checked').value);
    return Number($('custom-size').value) || 0;
  }

  // With two people, the history choice doesn't come up: it's always shared.
  function syncSizePicker() {
    const custom = $('size-custom').checked;
    $('custom-size-field').hidden = !custom;
    $('history-row').hidden = pickedSize() <= 2;
    if (custom && !$('custom-size').value) $('custom-size').focus();
  }

  // ---------- Leaving ----------
  async function leave() {
    if (S.count <= 1 || !S.online) {
      const ok = await confirmDialog({
        icon: 'local_fire_department',
        title: 'Put out the fire?',
        body: "You're the last one here. Leaving destroys this conversation, and the code stops working forever. Nobody can get it back.",
        confirm: 'Leave and erase', danger: true,
      });
      if (!ok) return;
      S.leaving = true;
      send({ t: 'leave' });
      await dissolve();
      wipe();
      endRoom('gone');
    } else {
      S.leaving = true;
      send({ t: 'leave' });
      wipe();
      endRoom('left');
    }
  }

  function wipe() {
    closeSocket();
    Object.assign(S, { code: '', roomId: '', codeSecret: null, me: '', token: '', peers: new Map(), items: [],
      count: 0, inRoom: false, online: false, reconnectDeadline: 0 });
    rendered.clear();
    $('messages').textContent = '';
    $('room-code').textContent = $('big-code').textContent = '----';
  }

  function dissolve() {
    const room = $('room');
    const els = [...room.querySelectorAll('.msg, .note, .share-card:not([hidden])')];
    const n = els.length;
    els.forEach((el, i) => el.style.setProperty('--d', Math.round(((n - 1 - i) / Math.max(n, 1)) * 700)));
    room.classList.add('dissolving');
    return new Promise((r) => setTimeout(r, n ? 1900 : 700));
  }

  const ENDINGS = {
    gone: ["The fire's out", 'This room no longer exists. The messages, the code, the fact it was ever here: all gone. Nothing was kept, anywhere.'],
    left: ['You left the room', "Your copy of the conversation is gone. The room stays alive with the person still inside, until they leave too."],
    lost: ['Connection lost', "We couldn't reconnect in time. If you were the last one here, the room is gone."],
    displaced: ['Your seat was taken', 'Someone else is in the room now, or it was locked while you were away.'],
  };

  function endRoom(kind) {
    if (S.inRoom || S.ws) wipe();
    const [title, text] = ENDINGS[kind] || ENDINGS.gone;
    $('ended-title').textContent = title;
    $('ended-text').textContent = text;
    show('ended');
  }

  // ---------- Messages ----------
  function sendMessage(e) {
    e?.preventDefault();
    const input = $('message-input');
    const text = input.value.trim();
    if (!text || !canSend()) return;
    const msg = { type: 'msg', id: toB64url(crypto.getRandomValues(new Uint8Array(12))), author: S.me, text, at: Date.now() };
    S.items.push(msg);
    for (const peer of S.peers.values()) {
      if (peer.key) sendTo(peer, { type: 'msg', id: msg.id, text });
      else peer.outbox.push(msg);
    }
    input.value = '';
    autoGrow();
    render(true);
    updateChrome();
  }

  function note(text, icon, warn) {
    S.items.push({ type: 'note', text, icon, warn: Boolean(warn), id: 'n' + Math.random() });
    render(true);
  }

  const canSend = () => S.inRoom && S.online;

  const showShareCard = () => S.count <= 1 && !S.peers.size && !S.items.some((x) => x.type === 'msg');

  // No names, but in a group you still need to tell people apart.
  function authorTone(id) {
    let h = 0;
    for (const c of id) h = (h * 31 + c.charCodeAt(0)) >>> 0;
    return h % 6;
  }

  function relTime(at) { return at && Date.now() - at < 60_000 ? 'just now' : 'earlier'; }

  function render(stickToBottom) {
    const chat = $('chat');
    const nearBottom = chat.scrollHeight - chat.scrollTop - chat.clientHeight < 120;
    const list = $('messages');
    list.textContent = '';
    const items = S.items;
    items.forEach((it, i) => {
      if (it.type === 'note') {
        const li = document.createElement('li');
        li.className = 'note' + (it.warn ? ' warn' : '');
        if (it.icon) { const ic = document.createElement('span'); ic.className = 'icon'; ic.textContent = it.icon; li.append(ic); }
        li.append(document.createTextNode(it.text));
        list.append(li);
        rendered.add(it.id);
        return;
      }
      const prev = items[i - 1], next = items[i + 1];
      const start = !prev || prev.type !== 'msg' || prev.author !== it.author;
      const end = !next || next.type !== 'msg' || next.author !== it.author;
      const mine = it.author === S.me;
      const departed = !mine && !S.peers.has(it.author);
      const li = document.createElement('li');
      li.className = 'msg' + (mine ? ' mine' : '') + (departed ? ' departed' : '') +
        (start ? ' group-start' : '') + (end ? ' group-end' : '') + (rendered.has(it.id) ? '' : ' enter');
      if (start && !mine && (departed || S.size > 2)) {
        const label = document.createElement('div');
        label.className = 'msg-label';
        if (!departed) {
          const dot = document.createElement('span');
          dot.className = 'author-dot tone-' + authorTone(it.author);
          label.append(dot);
        }
        label.append(departed ? 'Someone who left' : 'Someone');
        li.append(label);
      }
      const bubble = document.createElement('div');
      bubble.className = 'bubble';
      bubble.textContent = it.text;
      li.append(bubble);
      if (end) {
        const t = document.createElement('div');
        t.className = 'msg-time';
        t.textContent = relTime(it.at);
        li.append(t);
      }
      list.append(li);
      rendered.add(it.id);
    });
    $('share-card').hidden = !showShareCard();
    if (stickToBottom || nearBottom) chat.scrollTop = chat.scrollHeight;
  }

  function updateChrome() {
    const status = $('status');
    const text = $('status-text');
    const alone = S.count <= 1;
    status.classList.toggle('two', S.online && !alone);
    status.classList.toggle('offline', !S.online);
    if (!S.online) text.textContent = 'Reconnecting…';
    else if (pendingPeers()) text.textContent = 'Connecting securely…';
    else if (alone) text.textContent = S.size === 2 ? 'Just you' : `Just you · room for ${S.size}`;
    else text.textContent = S.size === 2 ? '2 people here' : `${S.count} of ${S.size} here`;
    $('last-banner').hidden = !(S.inRoom && S.online && alone);
    $('lock-badge').hidden = !S.locked;
    $('lock-toggle').checked = S.locked;
    $('history-toggle').checked = S.history;
    $('history-item').hidden = S.size <= 2;
    $('lock-toggle').disabled = $('history-toggle').disabled = !S.online;
    $('send-btn').disabled = !$('message-input').value.trim() || !canSend();
    $('share-card').hidden = !showShareCard();
    $('share-text').textContent = S.size === 2
      ? 'Share this code with one other person. Say it out loud, text it, write it down.'
      : `Share this code with up to ${S.size - 1} other people. Say it out loud, text it, write it down.`;
  }

  // ---------- UI helpers ----------
  function show(view) {
    for (const v of ['home', 'room', 'ended']) $(v).hidden = v !== view;
    if (view === 'home') loadStats();
    window.scrollTo(0, 0);
  }

  function setBusy(btn, busy) {
    btn.disabled = busy;
    btn.classList.toggle('busy', busy);
    if (busy) { const s = document.createElement('span'); s.className = 'spinner'; btn.append(s); }
    else btn.querySelector('.spinner')?.remove();
  }

  function fieldError(msg) {
    $('code-field').classList.add('error');
    $('code-support').textContent = msg;
    $('code-input').focus();
  }

  let snackTimer;
  function snackbar(msg) {
    const el = $('snackbar');
    el.textContent = msg;
    el.hidden = false;
    clearTimeout(snackTimer);
    snackTimer = setTimeout(() => { el.hidden = true; }, 4000);
  }

  function confirmDialog({ icon, title, body, confirm, danger }) {
    closeMenu();
    return new Promise((resolve) => {
      $('dialog-icon').textContent = icon;
      $('dialog-title').textContent = title;
      $('dialog-body').textContent = body;
      const ok = $('dialog-confirm'), cancel = $('dialog-cancel');
      ok.textContent = confirm;
      ok.classList.toggle('danger', Boolean(danger));
      $('scrim').hidden = $('dialog').hidden = false;
      cancel.focus();
      const done = (v) => {
        $('scrim').hidden = $('dialog').hidden = true;
        ok.onclick = cancel.onclick = $('scrim').onclick = null;
        document.removeEventListener('keydown', onKey);
        resolve(v);
      };
      const onKey = (e) => { if (e.key === 'Escape') done(false); };
      document.addEventListener('keydown', onKey);
      ok.onclick = () => done(true);
      cancel.onclick = $('scrim').onclick = () => done(false);
    });
  }

  async function copyCode() {
    closeMenu();
    try { await navigator.clipboard.writeText(formatCode(S.code)); snackbar('Code copied'); }
    catch { snackbar(formatCode(S.code)); }
  }

  function closeMenu() { $('menu').hidden = true; $('menu-btn').setAttribute('aria-expanded', 'false'); }

  function autoGrow() {
    const ta = $('message-input');
    ta.style.height = 'auto';
    ta.style.height = Math.min(ta.scrollHeight, 160) + 'px';
  }

  function showRepo(url) {
    if (!url || !/^https:\/\//.test(url)) return;
    const a = $('repo-link'); a.href = url; a.hidden = false;
  }

  async function loadStats() {
    showRepo(CONFIG.repo);
    try {
      const r = await fetch(RELAY + '/stats', { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
      const { vanishedToday: n, repo, maxRoomSize: max } = await r.json();
      if (max >= 2) {
        maxRoomSize = max;
        $('custom-size').max = String(max);
        if (!$('custom-size-field').classList.contains('error')) $('custom-size-support').textContent = `From 2 to ${max}, including you`;
      }
      $('counter-number').textContent = n.toLocaleString();
      $('counter-text').textContent = n === 1 ? 'room has existed and vanished today.' : 'rooms have existed and vanished today.';
      showRepo(repo);
    } catch {}
  }

  // ---------- Wiring ----------
  $('create-btn').addEventListener('click', createRoom);
  document.querySelectorAll('input[name=size]').forEach((r) => r.addEventListener('change', syncSizePicker));
  $('custom-size').addEventListener('input', () => {
    $('custom-size-field').classList.remove('error');
    $('custom-size-support').textContent = `From 2 to ${maxRoomSize}, including you`;
    $('history-row').hidden = pickedSize() <= 2;
  });
  $('custom-size').addEventListener('keydown', (e) => { if (e.key === 'Enter') createRoom(); });
  $('join-form').addEventListener('submit', joinRoom);
  $('code-input').addEventListener('input', (e) => {
    $('code-field').classList.remove('error');
    $('code-support').textContent = 'Like KX7M-42QA';
    e.target.value = formatCode(normalizeCode(e.target.value));
  });
  $('code-input').addEventListener('paste', () => setTimeout(() => {
    const el = $('code-input'); el.value = formatCode(normalizeCode(el.value));
  }));

  $('leave-btn').addEventListener('click', leave);
  $('code-chip').addEventListener('click', copyCode);
  $('share-copy').addEventListener('click', copyCode);
  $('copy-item').addEventListener('click', copyCode);
  $('home-btn').addEventListener('click', () => show('home'));
  $('lock-toggle').addEventListener('change', (e) => send({ t: 'lock', value: e.target.checked }));
  $('history-toggle').addEventListener('change', (e) => send({ t: 'history', value: e.target.checked }));

  $('menu-btn').addEventListener('click', (e) => {
    e.stopPropagation();
    const menu = $('menu');
    menu.hidden = !menu.hidden;
    $('menu-btn').setAttribute('aria-expanded', String(!menu.hidden));
  });
  document.addEventListener('click', (e) => { if (!$('menu').hidden && !$('menu').contains(e.target)) closeMenu(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeMenu(); });

  $('composer').addEventListener('submit', sendMessage);
  $('message-input').addEventListener('input', () => { autoGrow(); updateChrome(); });
  $('message-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing && matchMedia('(pointer: fine)').matches) sendMessage(e);
  });
  $('chat').addEventListener('scroll', () => $('room').querySelector('.room-bar').classList.toggle('scrolled', $('chat').scrollTop > 4));

  // "just now" quietly becomes "earlier".
  setInterval(() => { if (S.inRoom) render(false); }, 30_000);

  // Last one here? Ask before the tab closes.
  window.addEventListener('beforeunload', (e) => {
    if (S.inRoom && !S.leaving && S.count <= 1 && S.items.some((x) => x.type === 'msg')) { e.preventDefault(); e.returnValue = ''; }
  });

  // Refresh grace: park the conversation for the reload, nothing more.
  window.addEventListener('pagehide', () => {
    if (!S.inRoom || S.leaving) return;
    try {
      sessionStorage.setItem(STASH_KEY, JSON.stringify({
        code: S.code, token: S.token, items: S.items.filter((x) => x.type === 'msg'),
      }));
    } catch {}
  });
  window.addEventListener('pageshow', (e) => { if (e.persisted && S.inRoom) location.reload(); });

  let stash = null;
  try { stash = JSON.parse(sessionStorage.getItem(STASH_KEY)); sessionStorage.removeItem(STASH_KEY); } catch {}
  if (stash && stash.code && stash.token) resumeAfterRefresh(stash);
  else show('home');
})();
