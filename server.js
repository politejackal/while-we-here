// While We Here — matchmaker server.
//
// This server never sees a message, a room code, or a name. It knows:
//   - a room ID (a slow hash of the code, computed in the browser)
//   - how many people are in that room right now, and how many it can hold
//   - whether the room is locked / shares history
// It forwards opaque, end-to-end encrypted blobs between the people in a
// room, so neither browser ever learns the other's IP address.
// When a room empties, its entry is deleted. Nothing is written to disk.
// There is no request logging anywhere in this file — check for yourself.

'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = Number(process.env.PORT) || 3000;
const GRACE_MS = 10_000;            // keep an empty room alive this long after a disconnect (refresh)
// A room's creator picks how many people it holds, from 2 up to this. Every message is
// encrypted once per person, so the ceiling is about keeping big rooms snappy.
const MAX_ROOM_SIZE = Math.max(2, Number(process.env.MAX_ROOM_SIZE) || 50);
const MAX_FRAME = 2 * 1024 * 1024;  // largest relayed blob (padded history in a big room can be large)
const GUESS_WINDOW_MS = 10 * 60_000;
const MAX_BAD_GUESSES = 8;          // wrong codes per window per client
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const REPO_URL = process.env.REPO_URL || '';
const PUBLIC_DIR = path.join(__dirname, 'public');

/** roomId -> { peers: Map<peerId, ws>, tokens: Map<token, peerId>, size, locked, history, reportedClosed, graceTimer } */
const rooms = new Map();

// The one number the site keeps. Resets at midnight UTC.
let vanished = { day: utcDay(), count: 0 };
function utcDay() { return new Date().toISOString().slice(0, 10); }
function bumpVanished() {
  if (vanished.day !== utcDay()) vanished = { day: utcDay(), count: 0 };
  vanished.count++;
}

// ---- Guess limiting -------------------------------------------------------
// Keyed by a salted hash of the client address. The salt is random, lives only
// in memory and rotates every window, so the table can't be mapped back to IPs
// later. Entries expire on their own.
let guessSalt = crypto.randomBytes(32);
let guesses = new Map();
setInterval(() => { guessSalt = crypto.randomBytes(32); guesses = new Map(); }, GUESS_WINDOW_MS).unref();

function clientKey(req) {
  let addr = req.socket.remoteAddress || '';
  if (TRUST_PROXY && req.headers['x-forwarded-for']) addr = String(req.headers['x-forwarded-for']).split(',')[0].trim();
  return crypto.createHmac('sha256', guessSalt).update(addr).digest('base64');
}
function isRateLimited(key) { return (guesses.get(key) || 0) >= MAX_BAD_GUESSES; }
function badGuess(key) { guesses.set(key, (guesses.get(key) || 0) + 1); }

// ---- Rooms ----------------------------------------------------------------
const ROOM_ID_RE = /^[A-Za-z0-9_-]{43}$/; // base64url SHA-256

function newId() { return crypto.randomBytes(9).toString('base64url'); }

function send(ws, msg) { if (ws.readyState === 1) ws.send(JSON.stringify(msg)); }

function broadcastState(room) {
  const state = { t: 'room', count: room.peers.size, size: room.size, locked: room.locked, history: room.history };
  for (const ws of room.peers.values()) send(ws, state);
}

function destroyRoom(roomId) {
  const room = rooms.get(roomId);
  if (!room) return;
  clearTimeout(room.graceTimer);
  rooms.delete(roomId);
  bumpVanished();
}

function addPeer(room, ws, peerId, returning) {
  clearTimeout(room.graceTimer);
  room.graceTimer = null;
  // The longest-present person hands the newcomer the history, so it's sent once.
  const historyBy = room.peers.keys().next().value;
  for (const other of room.peers.values()) send(other, { t: 'peer-joined', peer: peerId, returning, historyBy });
  const peers = [...room.peers.keys()];
  room.peers.set(peerId, ws);
  ws.room = room; ws.peerId = peerId;
  let token = [...room.tokens].find(([, id]) => id === peerId)?.[0];
  if (!token) { token = newId() + newId(); room.tokens.set(token, peerId); }
  send(ws, { t: 'joined', you: peerId, token, peers });
  broadcastState(room);
}

function removePeer(ws, explicit) {
  const room = ws.room;
  if (!room) return;
  ws.room = null;
  room.peers.delete(ws.peerId);
  if (explicit) {
    // Leaving on purpose gives up the right to slip back in.
    for (const [tok, id] of room.tokens) if (id === ws.peerId) room.tokens.delete(tok);
  }
  for (const other of room.peers.values()) send(other, { t: 'peer-left', peer: ws.peerId });
  if (room.peers.size === 0) {
    if (explicit) return destroyRoom(room.id);
    // Possibly just a refresh. Hold the room briefly for the same browser tab only.
    room.graceTimer = setTimeout(() => destroyRoom(room.id), GRACE_MS);
  } else {
    broadcastState(room);
  }
}

function handle(ws, msg) {
  switch (msg.t) {
    case 'create': {
      if (ws.room || !ROOM_ID_RE.test(msg.room)) return;
      if (rooms.has(msg.room)) return send(ws, { t: 'error', code: 'exists' });
      const size = Number.isInteger(msg.size) && msg.size >= 2 && msg.size <= MAX_ROOM_SIZE ? msg.size : 2;
      const room = { id: msg.room, peers: new Map(), tokens: new Map(), size, locked: false,
        history: msg.history !== false, reportedClosed: false, graceTimer: null };
      rooms.set(room.id, room);
      return addPeer(room, ws, newId(), false);
    }
    case 'join': {
      if (ws.room) return;
      if (isRateLimited(ws.clientKey)) return send(ws, { t: 'error', code: 'rate_limited' });
      if (!ROOM_ID_RE.test(msg.room)) return send(ws, { t: 'error', code: 'not_found' });
      const room = rooms.get(msg.room);
      const tokenPeer = room && typeof msg.token === 'string' ? room.tokens.get(msg.token) : undefined;
      // An empty room in its grace period only exists for the tab that just refreshed.
      if (!room || (room.peers.size === 0 && !tokenPeer)) {
        badGuess(ws.clientKey);
        return send(ws, { t: 'error', code: 'not_found' });
      }
      if (tokenPeer && room.peers.has(tokenPeer)) return send(ws, { t: 'error', code: 'full' });
      if (room.peers.size >= room.size) return send(ws, { t: 'error', code: 'full' });
      if (!tokenPeer && (room.locked || room.reportedClosed)) return send(ws, { t: 'error', code: 'locked' });
      return addPeer(room, ws, tokenPeer || newId(), Boolean(tokenPeer));
    }
    case 'relay': {
      const room = ws.room;
      if (!room || typeof msg.data !== 'string') return;
      for (const [id, other] of room.peers) {
        if (id !== ws.peerId && (!msg.to || msg.to === id)) send(other, { t: 'relay', from: ws.peerId, data: msg.data });
      }
      return;
    }
    case 'lock': {
      if (!ws.room) return;
      ws.room.locked = Boolean(msg.value);
      return broadcastState(ws.room);
    }
    case 'history': {
      if (!ws.room) return;
      ws.room.history = Boolean(msg.value);
      return broadcastState(ws.room);
    }
    case 'report': {
      // We have nothing to review. The only thing we can do is stop new people
      // from entering this room with its code.
      if (ws.room) ws.room.reportedClosed = true;
      return removePeer(ws, true);
    }
    case 'leave':
      return removePeer(ws, true);
  }
}

// ---- HTTP (static files + one stat) -------------------------------------
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.webmanifest': 'application/manifest+json' };

const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; style-src 'self'; font-src 'self'; " +
    "connect-src 'self' ws: wss:; img-src 'self' data:; " +
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'Permissions-Policy': 'interest-cohort=(), camera=(), microphone=(), geolocation=()',
  'Cache-Control': 'no-store',
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/stats') {
    if (vanished.day !== utcDay()) vanished = { day: utcDay(), count: 0 };
    // Public, cookie-free numbers, so a page hosted elsewhere (GitHub Pages) may read them.
    res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    return res.end(JSON.stringify({ vanishedToday: vanished.count, repo: REPO_URL, maxRoomSize: MAX_ROOM_SIZE }));
  }
  const rel = url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname).replace(/^\/+/, '');
  const file = path.join(PUBLIC_DIR, rel);
  if (!file.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(404); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, SECURITY_HEADERS); return res.end('Not here.'); }
    res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
});

// No compression: compressed sizes can leak hints about what's inside.
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: MAX_FRAME, perMessageDeflate: false });
wss.on('connection', (ws, req) => {
  ws.clientKey = clientKey(req);
  ws.alive = true;
  ws.on('pong', () => { ws.alive = true; });
  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if (msg && typeof msg === 'object') handle(ws, msg);
  });
  ws.on('close', () => removePeer(ws, false));
});

// Drop dead connections so empty rooms are noticed quickly.
setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.alive) { ws.terminate(); continue; }
    ws.alive = false; ws.ping();
  }
}, 15_000).unref();

server.listen(PORT, () => console.log(`While We Here is listening on http://localhost:${PORT}`));
