/**
 * ╔══════════════════════════════════════════════════════╗
 * ║   STICKMAN ARENA — Server v2.1 (Fixed)              ║
 * ║   Fixes:                                             ║
 * ║   - Rate limiting đăng nhập (brute-force protect)    ║
 * ║   - Timing-safe token comparison                     ║
 * ║   - WebSocket message validation & cheat-clamping    ║
 * ║   - playerId spoofing prevention                     ║
 * ║   - Orphan room cleanup cải tiến                     ║
 * ╚══════════════════════════════════════════════════════╝
 */
const { WebSocketServer, WebSocket } = require('ws');
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const PORT       = process.env.PORT || 3000;
const USERS_FILE = path.join(__dirname, 'users.json');
const SECRET     = process.env.JWT_SECRET || 'stickman_arena_2025_secret';

// ── Rate limiting ─────────────────────────────────────
// FIX #16: Chặn brute-force login
const loginAttempts = new Map();
const MAX_ATTEMPTS  = 10;
const WINDOW_MS     = 15 * 60 * 1000;

function checkRateLimit(ip) {
  const now = Date.now();
  const e = loginAttempts.get(ip);
  if (!e || now - e.firstAt > WINDOW_MS) { loginAttempts.set(ip, { count: 1, firstAt: now }); return true; }
  if (e.count >= MAX_ATTEMPTS) return false;
  e.count++; return true;
}
function resetRateLimit(ip) { loginAttempts.delete(ip); }
setInterval(() => {
  const now = Date.now();
  for (const [ip, e] of loginAttempts) if (now - e.firstAt > WINDOW_MS) loginAttempts.delete(ip);
}, 30 * 60 * 1000);

// ── User DB ───────────────────────────────────────────
function loadUsers() {
  try { if (fs.existsSync(USERS_FILE)) return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch {}
  return {};
}
function saveUsers(db) { fs.writeFileSync(USERS_FILE, JSON.stringify(db, null, 2)); }

// ── Crypto ────────────────────────────────────────────
function hashPw(pw) {
  return crypto.createHmac('sha256', SECRET).update(pw).digest('hex');
}
function signToken(payload) {
  const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const b = Buffer.from(JSON.stringify({ ...payload, iat: Date.now() })).toString('base64url');
  const s = crypto.createHmac('sha256', SECRET).update(`${h}.${b}`).digest('base64url');
  return `${h}.${b}.${s}`;
}
function verifyToken(token) {
  try {
    const [h, b, s] = (token || '').split('.');
    if (!h || !b || !s) return null;
    const expected = crypto.createHmac('sha256', SECRET).update(`${h}.${b}`).digest('base64url');
    // FIX #17: Timing-safe comparison thay vì ===
    const sBuf = Buffer.from(s, 'base64url');
    const eBuf = Buffer.from(expected, 'base64url');
    if (sBuf.length !== eBuf.length || !crypto.timingSafeEqual(sBuf, eBuf)) return null;
    const p = JSON.parse(Buffer.from(b, 'base64url').toString());
    if (Date.now() - p.iat > 30 * 24 * 60 * 60 * 1000) return null;
    return p;
  } catch { return null; }
}

// ── HTTP utils ────────────────────────────────────────
function parseBody(req) {
  return new Promise(res => {
    let d = '';
    req.on('data', c => { d += c; if (d.length > 1e4) d = ''; });
    req.on('end', () => { try { res(JSON.parse(d)); } catch { res({}); } });
  });
}
function json(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(obj));
}
function getToken(req) { return (req.headers.authorization || '').replace('Bearer ', ''); }
function getIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
}

// ── HTTP Server ───────────────────────────────────────
const httpServer = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];

  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type,Authorization' });
    return res.end();
  }

  if (req.method === 'GET' && (url === '/' || url === '/index.html')) {
    fs.readFile(path.join(__dirname, 'index.html'), (err, data) => {
      if (err) { res.writeHead(404); return res.end('Not found'); }
      res.writeHead(200, { 'Content-Type': 'text/html;charset=utf-8' });
      res.end(data);
    });
    return;
  }

  if (req.method === 'POST' && url === '/api/register') {
    const ip = getIp(req);
    if (!checkRateLimit(ip)) return json(res, 429, { error: 'Quá nhiều yêu cầu. Thử lại sau 15 phút.' });
    const { username, password } = await parseBody(req);
    if (!username || !password) return json(res, 400, { error: 'Thiếu tên đăng nhập hoặc mật khẩu' });
    if (username.length < 3 || username.length > 20) return json(res, 400, { error: 'Tên đăng nhập 3–20 ký tự' });
    if (!/^[a-zA-Z0-9_]+$/.test(username)) return json(res, 400, { error: 'Chỉ dùng chữ, số, dấu gạch dưới' });
    if (password.length < 6) return json(res, 400, { error: 'Mật khẩu tối thiểu 6 ký tự' });
    const db = loadUsers();
    const key = username.toLowerCase();
    if (db[key]) return json(res, 409, { error: 'Tên đăng nhập đã tồn tại' });
    db[key] = { username, password: hashPw(password), createdAt: Date.now(),
      campProgress: { cleared: [] }, stats: { wins: 0, losses: 0 } };
    saveUsers(db);
    resetRateLimit(ip);
    const token = signToken({ username });
    console.log(`[REGISTER] ${username}`);
    return json(res, 201, { token, username, campProgress: db[key].campProgress, stats: db[key].stats });
  }

  if (req.method === 'POST' && url === '/api/login') {
    const ip = getIp(req);
    if (!checkRateLimit(ip)) return json(res, 429, { error: 'Quá nhiều lần đăng nhập sai. Thử lại sau 15 phút.' });
    const { username, password } = await parseBody(req);
    if (!username || !password) return json(res, 400, { error: 'Thiếu thông tin' });
    const db = loadUsers();
    const user = db[username.toLowerCase()];
    if (!user || user.password !== hashPw(password)) return json(res, 401, { error: 'Sai tên đăng nhập hoặc mật khẩu' });
    resetRateLimit(ip);
    const token = signToken({ username: user.username });
    console.log(`[LOGIN] ${user.username}`);
    return json(res, 200, { token, username: user.username, campProgress: user.campProgress, stats: user.stats });
  }

  if (req.method === 'GET' && url === '/api/me') {
    const p = verifyToken(getToken(req));
    if (!p) return json(res, 401, { error: 'Unauthorized' });
    const db = loadUsers();
    const user = db[p.username.toLowerCase()];
    if (!user) return json(res, 404, { error: 'User not found' });
    return json(res, 200, { username: user.username, campProgress: user.campProgress, stats: user.stats });
  }

  if (req.method === 'POST' && url === '/api/progress') {
    const p = verifyToken(getToken(req));
    if (!p) return json(res, 401, { error: 'Unauthorized' });
    const { campProgress } = await parseBody(req);
    if (!campProgress || !Array.isArray(campProgress.cleared)) return json(res, 400, { error: 'Invalid data' });
    const db = loadUsers();
    const user = db[p.username.toLowerCase()];
    if (!user) return json(res, 404, { error: 'User not found' });
    // Validate: chỉ cho phép số nguyên 1-5
    user.campProgress = { cleared: campProgress.cleared.filter(x => Number.isInteger(x) && x >= 1 && x <= 5) };
    saveUsers(db);
    return json(res, 200, { ok: true });
  }

  if (req.method === 'POST' && url === '/api/stats') {
    const p = verifyToken(getToken(req));
    if (!p) return json(res, 401, { error: 'Unauthorized' });
    const { result, mode } = await parseBody(req);
    if (!['win', 'loss'].includes(result)) return json(res, 400, { error: 'Invalid result' });
    const db = loadUsers();
    const user = db[p.username.toLowerCase()];
    if (!user) return json(res, 404, { error: 'User not found' });
    if (result === 'win')  user.stats.wins++;
    if (result === 'loss') user.stats.losses++;
    const m = ['online', 'campaign', 'practice'].includes(mode) ? mode : 'practice';
    if (!user.stats[m]) user.stats[m] = { wins: 0, losses: 0 };
    if (result === 'win')  user.stats[m].wins++;
    if (result === 'loss') user.stats[m].losses++;
    saveUsers(db);
    return json(res, 200, { ok: true, stats: user.stats });
  }

  if (req.method === 'POST' && url === '/api/shop') {
    const p = verifyToken(getToken(req));
    if (!p) return json(res, 401, { error: 'Unauthorized' });
    const { shopData } = await parseBody(req);
    if (!shopData || typeof shopData !== 'object') return json(res, 400, { error: 'Invalid shopData' });
    // Clamp coins để tránh cheat
    if (typeof shopData.coins === 'number') shopData.coins = Math.max(0, Math.min(999999, Math.floor(shopData.coins)));
    const db = loadUsers();
    const user = db[p.username.toLowerCase()];
    if (!user) return json(res, 404, { error: 'User not found' });
    user.shopData = shopData;
    saveUsers(db);
    return json(res, 200, { ok: true });
  }

  if (req.method === 'GET' && url === '/api/shop') {
    const p = verifyToken(getToken(req));
    if (!p) return json(res, 401, { error: 'Unauthorized' });
    const db = loadUsers();
    const user = db[p.username.toLowerCase()];
    if (!user) return json(res, 404, { error: 'User not found' });
    return json(res, 200, { shopData: user.shopData || null });
  }

  if (req.method === 'GET' && url.startsWith('/api/leaderboard')) {
    const db = loadUsers();
    const players = Object.values(db).map(u => ({
      username: u.username,
      total:    { wins: u.stats?.wins || 0,           losses: u.stats?.losses || 0 },
      online:   { wins: u.stats?.online?.wins || 0,   losses: u.stats?.online?.losses || 0 },
      campaign: { wins: u.stats?.campaign?.wins || 0, losses: u.stats?.campaign?.losses || 0 },
      practice: { wins: u.stats?.practice?.wins || 0, losses: u.stats?.practice?.losses || 0 },
      coins:    u.shopData?.coins || 0,
    }));
    return json(res, 200, { players: players.filter(p => p.total.wins + p.total.losses > 0) });
  }

  json(res, 404, { error: 'Not found' });
});

// ── WebSocket ─────────────────────────────────────────
const wss = new WebSocketServer({ server: httpServer });
const queue = [], rooms = new Map();

// FIX #15: Validate và clamp game values để chặn cheat
const CLAMP_RULES = {
  x: [0, 1200], y: [0, 700], hp: [0, 300], armor: [0, 200],
  mag: [0, 50], ammo: [0, 500], dmg: [0, 100], newHp: [0, 300],
  vx: [-25, 25], vy: [-25, 25], sz: [1, 15], pw: [0, 1],
};
function sanitizeMsg(msg) {
  for (const [f, [lo, hi]] of Object.entries(CLAMP_RULES)) {
    if (typeof msg[f] === 'number') msg[f] = Math.max(lo, Math.min(hi, msg[f]));
  }
  return msg;
}

function genRoomId() {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let id;
  do { id = Array.from({ length: 4 }, () => c[Math.floor(Math.random() * c.length)]).join(''); }
  while (rooms.has(id));
  return id;
}
function send(ws, obj) { if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj)); }
function makeGameState() {
  return {
    players: [{ id: 1, x: 80, y: 80, hp: 70, gunId: 'smg' }, { id: 2, x: 970, y: 540, hp: 70, gunId: 'smg' }],
    obstacles: [
      { x: 525, y: 280, w: 50, h: 90 }, { x: 200, y: 180, w: 70, h: 70 }, { x: 160, y: 380, w: 55, h: 55 },
      { x: 320, y: 290, w: 45, h: 80 }, { x: 830, y: 180, w: 70, h: 70 }, { x: 880, y: 400, w: 55, h: 55 },
      { x: 730, y: 290, w: 45, h: 80 }, { x: 430, y: 100, w: 80, h: 45 }, { x: 590, y: 100, w: 80, h: 45 },
      { x: 430, y: 510, w: 80, h: 45 }, { x: 590, y: 510, w: 80, h: 45 }, { x: 310, y: 130, w: 45, h: 45 },
      { x: 745, y: 480, w: 45, h: 45 }, { x: 310, y: 470, w: 45, h: 45 }, { x: 745, y: 130, w: 45, h: 45 },
    ],
    items: [],
  };
}

wss.on('connection', (ws) => {
  ws.id = Math.random().toString(36).slice(2, 9);
  ws.roomId = null; ws.role = null; ws.isAlive = true; ws.username = null;
  ws.on('pong', () => { ws.isAlive = true; });
  ws.on('message', (raw) => {
    let m; try { m = JSON.parse(raw); } catch { return; }
    if (!m || typeof m.type !== 'string') return;
    sanitizeMsg(m);
    handleWsMsg(ws, m);
  });
  ws.on('close', () => handleDisconnect(ws));
  ws.on('error', () => {});
});

function handleWsMsg(ws, msg) {
  switch (msg.type) {
    case 'ping': send(ws, { type: 'pong' }); break;

    case 'auth': {
      const p = verifyToken(msg.token || '');
      if (p) { ws.username = p.username; send(ws, { type: 'auth_ok', username: p.username }); }
      else send(ws, { type: 'auth_fail' });
      break;
    }

    case 'find_match': {
      if (!queue.includes(ws)) queue.push(ws);
      if (queue.length >= 2) {
        const p1 = queue.shift(), p2 = queue.shift();
        const rid = genRoomId();
        rooms.set(rid, { host: p1, guest: p2, started: true, createdAt: Date.now() });
        p1.roomId = p2.roomId = rid; p1.role = 'host'; p2.role = 'guest';
        send(p1, { type: 'match_found', playerId: 1, roomId: rid, opponent: p2.username || '???' });
        send(p2, { type: 'match_found', playerId: 2, roomId: rid, opponent: p1.username || '???' });
        setTimeout(() => { const gs = makeGameState(); send(p1, { type: 'game_start', gameState: gs }); send(p2, { type: 'game_start', gameState: gs }); }, 800);
      }
      break;
    }

    case 'create_room': {
      if (ws.roomId) cleanupRoom(ws.roomId, ws);
      const rid = genRoomId();
      rooms.set(rid, { host: ws, guest: null, started: false, createdAt: Date.now() });
      ws.roomId = rid; ws.role = 'host';
      send(ws, { type: 'room_created', roomId: rid });
      break;
    }

    case 'join_room': {
      const rid = (msg.roomId || '').toUpperCase().trim();
      if (!/^[A-Z2-9]{4}$/.test(rid)) return send(ws, { type: 'room_not_found', roomId: rid });
      const room = rooms.get(rid);
      if (!room) return send(ws, { type: 'room_not_found', roomId: rid });
      if (room.guest || room.started) return send(ws, { type: 'room_full' });
      room.guest = ws; ws.roomId = rid; ws.role = 'guest';
      send(ws, { type: 'room_joined', roomId: rid });
      send(room.host, { type: 'player_joined', roomId: rid, opponent: ws.username || '???' });
      break;
    }

    case 'start_room': {
      const rid = msg.roomId || ws.roomId; const room = rooms.get(rid);
      if (!room || room.host !== ws || !room.guest) return;
      room.started = true;
      send(room.host, { type: 'match_found', playerId: 1, roomId: rid, opponent: room.guest.username || '???' });
      send(room.guest, { type: 'match_found', playerId: 2, roomId: rid, opponent: room.host.username || '???' });
      setTimeout(() => { const gs = makeGameState(); send(room.host, { type: 'game_start', gameState: gs }); send(room.guest, { type: 'game_start', gameState: gs }); }, 800);
      break;
    }

    case 'cancel_room': {
      const rid = msg.roomId || ws.roomId; const room = rooms.get(rid); if (!room) return;
      if (room.guest) send(room.guest, { type: 'player_left' });
      rooms.delete(rid); ws.roomId = null; break;
    }

    case 'leave_room': {
      const rid = msg.roomId || ws.roomId; const room = rooms.get(rid);
      if (!room || room.guest !== ws) return;
      room.guest = null; ws.roomId = null; send(room.host, { type: 'player_left_room' }); break;
    }

    case 'cancel': {
      const qi = queue.indexOf(ws); if (qi !== -1) queue.splice(qi, 1);
      if (ws.roomId) cleanupRoom(ws.roomId, ws); break;
    }

    case 'player_update': {
      const room = rooms.get(ws.roomId); if (!room) return;
      const isHost = room.host === ws;
      // FIX #15: Kiểm tra playerId phải khớp với role thực của ws
      const expectedId = isHost ? 1 : 2;
      if (msg.playerId !== expectedId) return;
      const other = isHost ? room.guest : room.host;
      if (other) send(other, { type: 'opponent_update', ...msg });
      break;
    }

    case 'bullet_spawn': {
      const room = rooms.get(ws.roomId); if (!room) return;
      const other = room.host === ws ? room.guest : room.host;
      if (other) send(other, { type: 'bullet_spawn', ...msg }); break;
    }

    case 'hit_event': {
      const room = rooms.get(ws.roomId); if (!room) return;
      const isHost = room.host === ws;
      const myId = isHost ? 1 : 2, oppId = isHost ? 2 : 1;
      // FIX #15: Chỉ shooter thật mới được gửi hit_event
      if (msg.shooterId !== myId || msg.targetId !== oppId) return;
      const other = isHost ? room.guest : room.host;
      if (other) send(other, { type: 'hit_event', ...msg }); break;
    }

    case 'game_over': {
      const room = rooms.get(ws.roomId); if (!room) return;
      const other = room.host === ws ? room.guest : room.host;
      if (other) send(other, { type: 'game_over', winnerId: msg.winnerId });
      rooms.delete(ws.roomId); ws.roomId = null; break;
    }
  }
}

function handleDisconnect(ws) {
  const qi = queue.indexOf(ws); if (qi !== -1) queue.splice(qi, 1);
  if (ws.roomId) cleanupRoom(ws.roomId, ws);
}
function cleanupRoom(rid, leaving) {
  const room = rooms.get(rid); if (!room) return;
  const other = room.host === leaving ? room.guest : room.host;
  if (other?.readyState === WebSocket.OPEN) { send(other, { type: 'player_left' }); other.roomId = null; }
  rooms.delete(rid); leaving.roomId = null;
}

// Heartbeat
setInterval(() => { wss.clients.forEach(ws => { if (!ws.isAlive) { ws.terminate(); return; } ws.isAlive = false; ws.ping(); }); }, 30000);

// FIX: Cleanup orphan rooms
setInterval(() => {
  const now = Date.now();
  for (const [rid, room] of rooms) {
    const dead = room.host?.readyState !== WebSocket.OPEN && room.guest?.readyState !== WebSocket.OPEN;
    const old  = now - (room.createdAt || 0) > 20 * 60 * 1000;
    if (dead || old) rooms.delete(rid);
  }
}, 60000);

httpServer.listen(PORT, () => {
  console.log(`\n╔══════════════════════════════════════════╗`);
  console.log(`║  STICKMAN ARENA Server v2.1 (Fixed)     ║`);
  console.log(`║  http://localhost:${PORT}                  ║`);
  console.log(`╚══════════════════════════════════════════╝\n`);
});