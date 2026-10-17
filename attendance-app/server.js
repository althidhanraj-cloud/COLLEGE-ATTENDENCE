const express = require('express'), Database = require('better-sqlite3'), crypto = require('crypto'), path = require('path');
const db = new Database(process.env.DB_FILE || 'attendance.db');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,role TEXT NOT NULL,username TEXT UNIQUE NOT NULL,name TEXT NOT NULL,hash TEXT NOT NULL,salt TEXT NOT NULL,owner INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS invites(code TEXT PRIMARY KEY,created_by INTEGER NOT NULL,expires INTEGER NOT NULL,used_by INTEGER);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS timetable(id INTEGER PRIMARY KEY,day INTEGER NOT NULL,start TEXT NOT NULL,end TEXT NOT NULL,subject TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pings(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL,date TEXT NOT NULL,time TEXT NOT NULL,lat REAL,lng REAL,acc REAL,dist REAL,inside INTEGER NOT NULL,kind TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS marks(user_id INTEGER NOT NULL,date TEXT NOT NULL,session TEXT NOT NULL,time TEXT NOT NULL,dist REAL,PRIMARY KEY(user_id,date,session));
CREATE INDEX IF NOT EXISTS pi ON pings(user_id,date);
`);

const DEFAULTS = { lat: '', lng: '', radius: '150', open: '08:30', split: '12:50', cutoff: '16:30' };
const getSettings = () => { const s = { ...DEFAULTS }; db.prepare('SELECT k,v FROM settings').all().forEach(r => s[r.k] = r.v); return s; };
const setSetting = (k, v) => db.prepare('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').run(k, String(v));

const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
function addUser(role, username, name, pw, owner = 0) {
  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO users(role,username,name,hash,salt,owner) VALUES(?,?,?,?,?,?)').run(role, username, name, hashPw(pw, salt), salt, owner);
}
function setPw(id, pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare('UPDATE users SET hash=?,salt=? WHERE id=?').run(hashPw(pw, salt), salt, id);
}
if (!db.prepare("SELECT 1 FROM users WHERE role='admin'").get()) {
  const u = process.env.ADMIN_USER || 'admin', p = process.env.ADMIN_PASS || 'admin123';
  addUser('admin', u, process.env.ADMIN_NAME || 'Owner Admin', p, 1);
  console.log(`Admin created: ${u} / ${p}  (change the password after first login)`);
}

function ist(d = new Date()) {
  const p = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Kolkata', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' })
    .formatToParts(d).reduce((o, x) => (o[x.type] = x.value, o), {});
  return { date: `${p.year}-${p.month}-${p.day}`, time: `${p.hour}:${p.minute}` };
}
const dist = (a, b, c, d) => { const R = 6371000, r = Math.PI / 180, x = (c - a) * r, y = (d - b) * r; const h = Math.sin(x / 2) ** 2 + Math.cos(a * r) * Math.cos(c * r) * Math.sin(y / 2) ** 2; return 2 * R * Math.asin(Math.sqrt(h)); };
const dow = date => new Date(date + 'T00:00:00Z').getUTCDay();

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function auth(role) {
  return (req, res, next) => {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    const row = db.prepare('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.created>?').get(t, Date.now() - 30 * 864e5);
    if (!row) return res.status(401).json({ error: 'Please log in again.' });
    if (role && row.role !== role) return res.status(403).json({ error: 'Not allowed.' });
    req.user = row; req.token = t; next();
  };
}

app.post('/api/login', (req, res) => {
  const { username, password, role } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(String(username || '').trim());
  if (!u || u.role !== role || hashPw(String(password || ''), u.salt) !== u.hash) return res.status(401).json({ error: 'Wrong ID or password.' });
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions(token,user_id,created) VALUES(?,?,?)').run(token, u.id, Date.now());
  res.json({ token, role: u.role, name: u.name, username: u.username, owner: !!u.owner });
});
app.post('/api/admin/register', (req, res) => {
  const { code, username, name, password } = req.body || {};
  const inv = db.prepare('SELECT * FROM invites WHERE code=? AND used_by IS NULL AND expires>?').get(String(code || '').trim().toUpperCase(), Date.now());
  if (!inv) return res.status(400).json({ error: 'Invalid, used or expired code.' });
  if (!username || !name || !password || password.length < 6) return res.status(400).json({ error: 'Fill all fields (password min 6 characters).' });
  try { addUser('admin', String(username).trim(), String(name).trim(), String(password)); } catch { return res.status(400).json({ error: 'That ID is already taken.' }); }
  db.prepare('UPDATE invites SET used_by=(SELECT id FROM users WHERE username=?) WHERE code=?').run(String(username).trim(), inv.code);
  res.json({ ok: 1 });
});
app.post('/api/logout', auth(), (req, res) => { db.prepare('DELETE FROM sessions WHERE token=?').run(req.token); res.json({ ok: 1 }); });

// ---------- student ----------
function dayInfo(uid, date) {
  const marks = db.prepare('SELECT session,time FROM marks WHERE user_id=? AND date=?').all(uid, date);
  return { morning: marks.find(m => m.session === 'morning')?.time || null, afternoon: marks.find(m => m.session === 'afternoon')?.time || null };
}
app.get('/api/status', auth('student'), (req, res) => {
  const s = getSettings(), n = ist();
  res.json({ name: req.user.name, roll: req.user.username, date: n.date, time: n.time, locationSet: s.lat !== '', open: s.open, split: s.split, cutoff: s.cutoff,
    session: n.time < s.split ? 'morning' : 'afternoon', isOpen: n.time >= s.open && n.time < s.cutoff, today: dayInfo(req.user.id, n.date) });
});
app.post('/api/checkin', auth('student'), (req, res) => {
  const s = getSettings(), n = ist(), { lat, lng, acc, kind } = req.body || {};
  if (s.lat === '') return res.status(400).json({ error: 'Class location is not set by the admin yet.' });
  if (n.time < s.open || n.time >= s.cutoff) return res.status(400).json({ error: `Attendance is closed (open ${s.open} to ${s.cutoff}).`, closed: true });
  if (![lat, lng].every(Number.isFinite)) return res.status(400).json({ error: 'Location missing.' });
  if (Number.isFinite(acc) && acc > 100) return res.status(400).json({ error: `GPS accuracy is too low (${Math.round(acc)} m). Turn on high accuracy and try again.` });
  const d = Math.round(dist(+s.lat, +s.lng, lat, lng)), inside = d <= +s.radius ? 1 : 0, k = kind === 'mark' ? 'mark' : 'ping';
  db.prepare('INSERT INTO pings(user_id,date,time,lat,lng,acc,dist,inside,kind) VALUES(?,?,?,?,?,?,?,?,?)').run(req.user.id, n.date, n.time, lat, lng, acc ?? null, d, inside, k);
  if (k === 'mark') {
    if (!inside) return res.status(403).json({ error: `You are ${d} m from the college. Attendance not marked.`, dist: d });
    const session = n.time < s.split ? 'morning' : 'afternoon';
    db.prepare('INSERT OR IGNORE INTO marks(user_id,date,session,time,dist) VALUES(?,?,?,?,?)').run(req.user.id, n.date, session, n.time, d);
    return res.json({ ok: 1, session, inside, dist: d, today: dayInfo(req.user.id, n.date) });
  }
  res.json({ ok: 1, inside, dist: d });
});

// ---------- reports ----------
function report(uid, from, to) {
  const tt = db.prepare('SELECT * FROM timetable ORDER BY start').all(), s = getSettings(), today = ist().date;
  const days = [], sum = { workingDays: 0, daysPresent: 0, morning: 0, afternoon: 0, periodsTotal: 0, periodsAttended: 0 };
  for (let t = Date.parse(from + 'T00:00:00Z'); t <= Date.parse(to + 'T00:00:00Z'); t += 864e5) {
    const date = new Date(t).toISOString().slice(0, 10);
    if (date > today) break;
    const periods = tt.filter(p => p.day === dow(date));
    if (!periods.length) continue;
    const m = dayInfo(uid, date), pings = db.prepare('SELECT time,inside FROM pings WHERE user_id=? AND date=?').all(uid, date);
    const rows = periods.map(p => {
      const inW = pings.filter(x => x.time >= p.start && x.time < p.end);
      const status = inW.some(x => x.inside) ? 'present' : (inW.length ? 'outside' : 'no data');
      return { start: p.start, end: p.end, subject: p.subject, session: p.start < s.split ? 'morning' : 'afternoon', status };
    });
    sum.workingDays++; sum.periodsTotal += rows.length; sum.periodsAttended += rows.filter(r => r.status === 'present').length;
    if (m.morning) sum.morning++; if (m.afternoon) sum.afternoon++; if (m.morning || m.afternoon) sum.daysPresent++;
    days.push({ date, morning: m.morning, afternoon: m.afternoon, periods: rows });
  }
  return { summary: sum, days };
}
const range = q => { const to = /^\d{4}-\d\d-\d\d$/.test(q.to) ? q.to : ist().date; const from = /^\d{4}-\d\d-\d\d$/.test(q.from) ? q.from : new Date(Date.parse(to) - 29 * 864e5).toISOString().slice(0, 10); return [from, to]; };
app.get('/api/my/report', auth('student'), (req, res) => res.json(report(req.user.id, ...range(req.query))));

// ---------- admin ----------
const admin = auth('admin');
const owner = (req, res, next) => req.user.owner ? next() : res.status(403).json({ error: 'Only the owner admin can do this.' });
app.post('/api/admin/invites', admin, owner, (req, res) => {
  const code = crypto.randomBytes(5).toString('hex').toUpperCase().slice(0, 8), expires = Date.now() + 24 * 36e5;
  db.prepare('INSERT INTO invites(code,created_by,expires) VALUES(?,?,?)').run(code, req.user.id, expires);
  res.json({ code, expires });
});
app.get('/api/admin/admins', admin, owner, (req, res) => res.json(db.prepare("SELECT id,username,name,owner FROM users WHERE role='admin' ORDER BY owner DESC,id").all()));
app.delete('/api/admin/admins/:id', admin, owner, (req, res) => {
  const id = +req.params.id;
  db.prepare("DELETE FROM users WHERE id=? AND role='admin' AND owner=0").run(id); db.prepare('DELETE FROM sessions WHERE user_id=?').run(id); res.json({ ok: 1 });
});
app.get('/api/admin/settings', admin, (req, res) => res.json(getSettings()));
app.post('/api/admin/settings', admin, (req, res) => {
  const b = req.body || {}, t = /^([01]\d|2[0-3]):[0-5]\d$/;
  if (b.lat !== '' && (!Number.isFinite(+b.lat) || Math.abs(+b.lat) > 90 || !Number.isFinite(+b.lng) || Math.abs(+b.lng) > 180)) return res.status(400).json({ error: 'Invalid latitude/longitude.' });
  if (![b.open, b.split, b.cutoff].every(x => t.test(x))) return res.status(400).json({ error: 'Times must be HH:MM (24-hour).' });
  ['lat', 'lng', 'radius', 'open', 'split', 'cutoff'].forEach(k => setSetting(k, b[k] ?? DEFAULTS[k]));
  res.json(getSettings());
});
app.get('/api/admin/students', admin, (req, res) => {
  const [from, to] = range(req.query);
  res.json(db.prepare("SELECT id,username,name FROM users WHERE role='student' ORDER BY username").all().map(u => ({ ...u, ...report(u.id, from, to).summary })));
});
app.post('/api/admin/students', admin, (req, res) => {
  let added = 0; const errors = [];
  for (const r of (req.body.rows || [])) {
    try { if (!r.username || !r.name || !r.password) throw 0; addUser('student', String(r.username).trim(), String(r.name).trim(), String(r.password)); added++; }
    catch { errors.push(r.username || '(blank)'); }
  }
  res.json({ added, errors });
});
app.post('/api/admin/students/:id/password', admin, (req, res) => {
  if (!req.body.password) return res.status(400).json({ error: 'Password required.' });
  setPw(+req.params.id, String(req.body.password)); db.prepare('DELETE FROM sessions WHERE user_id=?').run(+req.params.id); res.json({ ok: 1 });
});
app.delete('/api/admin/students/:id', admin, (req, res) => {
  const id = +req.params.id;
  [['pings'], ['marks'], ['sessions']].forEach(([t]) => db.prepare(`DELETE FROM ${t} WHERE user_id=?`).run(id));
  db.prepare("DELETE FROM users WHERE id=? AND role='student'").run(id); res.json({ ok: 1 });
});
app.get('/api/admin/students/:id/report', admin, (req, res) => {
  const u = db.prepare("SELECT id,username,name FROM users WHERE id=? AND role='student'").get(+req.params.id);
  if (!u) return res.status(404).json({ error: 'Not found.' });
  res.json({ student: u, ...report(u.id, ...range(req.query)) });
});
app.get('/api/admin/timetable', admin, (req, res) => res.json(db.prepare('SELECT day,start,end,subject FROM timetable ORDER BY day,start').all()));
app.post('/api/admin/timetable', admin, (req, res) => {
  const rows = req.body.rows || [], t = /^([01]\d|2[0-3]):[0-5]\d$/;
  if (!rows.every(r => r.day >= 0 && r.day <= 6 && t.test(r.start) && t.test(r.end) && r.start < r.end && r.subject)) return res.status(400).json({ error: 'Check the timetable lines.' });
  db.transaction(() => { db.prepare('DELETE FROM timetable').run(); const i = db.prepare('INSERT INTO timetable(day,start,end,subject) VALUES(?,?,?,?)'); rows.forEach(r => i.run(r.day, r.start, r.end, String(r.subject))); })();
  res.json({ ok: 1, count: rows.length });
});
app.post('/api/admin/password', admin, (req, res) => {
  if (!req.body.password || req.body.password.length < 6) return res.status(400).json({ error: 'Use at least 6 characters.' });
  setPw(req.user.id, req.body.password); res.json({ ok: 1 });
});

if (!db.prepare('SELECT 1 FROM timetable').get()) {
  const T = { 1: [['09:00','10:00','LA&C'],['10:00','11:00','AP'],['11:00','12:50','Advanced Physics Lab'],['13:45','14:40','CE'],['14:40','15:35','CPP'],['15:35','16:30','CPP']],
    2: [['09:00','10:00','CPP'],['10:00','11:00','AP'],['11:00','12:00','CE'],['12:00','12:50','LA&C'],['13:45','14:40','AI TOOLS'],['14:40','16:30','AI TOOLS Lab-3']],
    3: [['09:00','10:00','YOGA'],['10:00','11:00','CE'],['11:00','12:00','LA&C'],['12:00','12:50','AP'],['13:45','14:40','AP'],['14:40','15:35','CPP'],['15:35','16:30','SPORTS']],
    4: [['09:00','10:00','CE'],['10:00','11:00','AP'],['11:00','12:00','UHVP'],['12:00','12:50','DCA'],['13:45','14:40','CPP'],['14:40','15:35','LA&C'],['15:35','16:30','UHVP']],
    5: [['09:00','10:00','UHVP'],['10:00','11:00','CPP'],['11:00','12:50','CPP Lab-3'],['13:45','14:40','LA&C'],['14:40','15:35','AP'],['15:35','16:30','CE']],
    6: [['09:00','10:00','UHVP'],['10:00','11:00','CE'],['11:00','12:50','CE Lab-1'],['13:45','14:40','MENTORS'],['14:40','15:35','LA&C'],['15:35','16:30','LIBRARY']] };
  const ins = db.prepare('INSERT INTO timetable(day,start,end,subject) VALUES(?,?,?,?)');
  Object.entries(T).forEach(([d, ps]) => ps.forEach(p => ins.run(+d, ...p)));
}
app.listen(process.env.PORT || 3000, () => console.log('Running on port ' + (process.env.PORT || 3000)));
