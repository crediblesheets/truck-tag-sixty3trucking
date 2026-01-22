// server.js — Email/Password auth + your existing APIs (fixed cookies for cross-site)

// ----- imports -----
import 'dotenv/config';
import fs from 'fs';
import path from 'path';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import PDFDocument from 'pdfkit';
import multer from 'multer';

import {
  sb,
  // meta + lists
  getActiveDriverNames,
  getTrailerTypes,
  // admin tickets
  upsertAdminTicket,
  getAdminTicketByTicketNo,
  deleteAdminTicketAndStub,
  bulkUpsertAdminTickets,
} from './supabaseAdmin.js';

// ---------- constants / config ----------
const upload = multer({ limits: { fileSize: 10 * 1024 * 1024 } }); // 10MB
const SIGN_BUCKET = 'ticket-signatures';
const formPath = path.resolve('public/assets/forms/blank-ticket.jpg');

const {
  PORT = 8080,
  JWT_SECRET,
  NODE_ENV = 'development',
  FRONTEND_ORIGIN = '',   // e.g. http://localhost:5173 or https://yourapp.vercel.app
  COOKIE_DOMAIN = '',     // optional: .yourdomain.com (no domain = host-only)
} = process.env;

function isCrossSiteRequest(origin) {
  if (!origin) return false;
  try {
    // During local dev, our API origin is localhost:PORT
    const a = new URL(origin);
    const b = new URL(`http://localhost:${PORT}`);
    return a.host !== b.host;
  } catch {
    return true;
  }
}

/** Build cookie options for the current environment. */
function cookieOpts(origin) {
  const crossSite = isCrossSiteRequest(origin) || !!FRONTEND_ORIGIN;
  const sameSite = crossSite ? 'none' : 'lax';
  const secure = crossSite ? true : NODE_ENV === 'production';

  const base = {
    httpOnly: true,
    sameSite,  // 'lax' or 'none'
    secure,    // must be true if sameSite === 'none'
    path: '/',
  };
  if (COOKIE_DOMAIN) base.domain = COOKIE_DOMAIN;
  return base;
}

// ---------- PDF helpers ----------
const IMG_W = 5100;
const IMG_H = 6600;
const PDF_W = 612;
const PDF_H = 792;
const sx = PDF_W / IMG_W;
const sy = PDF_H / IMG_H;
const X = (px) => px * sx;
const Y = (px) => px * sy;

const COORD = {
  ticketNo: { x: 4007, y: 810 },
  dateMonth: { x: 509, y: 895 },
  dateDay: { x: 1068, y: 878 },
  dateYear: { x: 1483, y: 878 },

  truckNo: { x: 1144, y: 1039 },
  trailerType: { x: 3981, y: 1132 },
  subHauler: { x: 1220, y: 1403 },
  primeCarrier: { x: 1305, y: 1564 },
  shipper: { x: 1204, y: 1733 },
  origin: { x: 1170, y: 1886 },
  originCity: { x: 1187, y: 2055 },
  poNo: { x: 3465, y: 1395 },
  jobName: { x: 3558, y: 1556 },
  jobNo: { x: 3448, y: 1733 },
  destination: { x: 3414, y: 1903 },
  city: { x: 3371, y: 2055 },

  // table col centers (row 1)
  tbl_scaleTagNo: { x: 1102, y: 2504 },
  tbl_yardOrWeight: { x: 2017, y: 2513 },
  tbl_material: { x: 2813, y: 2513 },
  tbl_timeArrival: { x: 3431, y: 2496 },
  tbl_timeLeave: { x: 3812, y: 2513 },
  tbl_siteArrival: { x: 4134, y: 2513 },
  tbl_siteLeave: { x: 4506, y: 2504 },

  truckStart: { x: 704, y: 4663 },
  bridgefare: { x: 3863, y: 4663 },

  signedOutLoadedYes: { x: 2220, y: 4824 },
  signedOutLoadedNo: { x: 2203, y: 4833 },

  howManyTonsLoads: { x: 3625, y: 4833 },

  startTime: { x: 1127, y: 5028 },
  downtimeLunch: { x: 2262, y: 5028 },
  notes_mid: { x: 3236, y: 5045 },

  signOutTime: { x: 2059, y: 5222 },

  driverName: { x: 1441, y: 5485 },
  receivedBy: { x: 3956, y: 5485 },

  notes_big: { x: 831, y: 5866 },
};

// table layout (in source px)
const TABLE_FIRST_ROW_Y = 2504;
const TABLE_ROW_PX = 160;
const TABLE_MAX_ROWS = 11;
const TABLE_COLS = ['scaleTagNo', 'yardOrWeight', 'material', 'yardArrival', 'yardLeave', 'siteArrival', 'siteLeave'];
const TABLE_X_BY_COL = {
  scaleTagNo: COORD.tbl_scaleTagNo.x,
  yardOrWeight: COORD.tbl_yardOrWeight.x,
  material: COORD.tbl_material.x,
  yardArrival: COORD.tbl_timeArrival.x,
  yardLeave: COORD.tbl_timeLeave.x,
  siteArrival: COORD.tbl_siteArrival.x,
  siteLeave: COORD.tbl_siteLeave.x,
};

function drawText(doc, s, xpx, ypx, opts = {}) {
  if (s === undefined || s === null || String(s).trim() === '') return;
  doc.text(String(s), X(xpx), Y(ypx), { lineBreak: false, ...opts });
}
function toMDY(value) {
  if (!value) return { m: '', d: '', y: '' };
  const d = new Date(value);
  if (isNaN(d)) return { m: '', d: '', y: '' };
  return {
    m: String(d.getMonth() + 1).padStart(2, '0'),
    d: String(d.getDate()).padStart(2, '0'),
    y: String(d.getFullYear()).slice(-2),
  };
}
function hhmm(s) {
  if (!s) return '';
  const m = String(s).match(/^(\d{1,2}):(\d{2})/);
  if (m) return `${m[1].padStart(2, '0')}:${m[2]}`;
  return String(s);
}
async function sbDataToBuffer(data) {
  if (!data) return null;
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof Uint8Array) return Buffer.from(data);
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  if (typeof data.arrayBuffer === 'function') {
    const ab = await data.arrayBuffer();
    return Buffer.from(ab);
  }
  if (typeof data.pipe === 'function' || data[Symbol.asyncIterator]) {
    const chunks = [];
    for await (const chunk of data) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
  }
  return null;
}

// ---------- app ----------
const app = express();
app.get('/api/ping', (_req, res) => res.json({ pong: true }));
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// ----- CORS (replace your current allowlist/origin block with this) -----
const devOrigins = new Set([
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:3000',
  'http://127.0.0.1:3000',
]);
const explicit = new Set([FRONTEND_ORIGIN].filter(Boolean));

app.use(cors({
  origin: (origin, cb) => {
    // Allow no-origin (same-origin/fetch), dev, explicit FRONTEND_ORIGIN and any *.vercel.app
    if (!origin) return cb(null, true);
    try {
      const u = new URL(origin);
      if (u.hostname.endsWith('.vercel.app')) return cb(null, true);
      if (devOrigins.has(origin)) return cb(null, true);
      if (explicit.has(origin)) return cb(null, true);
    } catch { /* ignore */ }
    // If you want to be stricter, change the next line to:
    // return cb(new Error(`CORS blocked: ${origin}`));
    return cb(null, true);
  },
  credentials: true,
}));

app.use(express.static(path.resolve('public')));

// health
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, env: NODE_ENV, time: new Date().toISOString() });
});

// ---------- auth/session helpers ----------
const ltrim = (v) => String(v ?? '').trim().toLowerCase();
function signSession(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '2h' });
}
function verifySession(req, res, next) {
  const tok = req.cookies['t'];
  if (!tok) return res.status(401).json({ ok: false, message: 'No session' });
  try {
    req.user = jwt.verify(tok, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ ok: false, message: 'Invalid session' });
  }
}
async function ensureActiveUser(req, res, next) {
  try {
    const email = String(req.user?.email || '').toLowerCase();
    if (!email) return res.status(401).json({ ok: false, message: 'No session email' });

    const { data: u, error } = await sb
      .from('users')
      .select('full_name, email, role, active')
      .eq('email', email)
      .maybeSingle();

    if (error) throw error;
    if (!u || !u.active) {
      return res.status(403).json({ ok: false, message: 'Email not authorized or inactive.' });
    }

    req.user.role = ltrim(u.role) === 'admin' ? 'admin' : 'driver';
    req.user.fullName = u.full_name || req.user.fullName || email;
    next();
  } catch (e) {
    console.error('ensureActiveUser', e);
    return res.status(500).json({ ok: false, message: 'User check failed.' });
  }
}
function requireAdmin(req, res, next) {
  const role = String(req.user?.role || '').toLowerCase();
  if (role === 'admin') return next();
  return res.status(403).json({ ok: false, message: 'Admins only.' });
}

// ---------- AUTH ----------

// Email + password login
app.post('/api/auth/login', async (req, res) => {
  try {
    const em = String(req.body?.email || '').toLowerCase().trim();
    const pw = String(req.body?.password || '');

    if (!em) {
      return res.status(400).json({ ok: false, message: 'Email is required.' });
    }

    const { data: u, error } = await sb
      .from('users')
      .select('full_name, email, role, active, password_hash')
      .eq('email', em)
      .maybeSingle();

    if (error) throw error;
    if (!u || !u.active) {
      return res.status(403).json({ ok: false, message: 'Email not authorized or inactive.' });
    }

    const hasPw = !!(u.password_hash && String(u.password_hash).trim());
    if (!hasPw && pw.length === 0) {
      return res
        .status(409)
        .json({ ok: false, code: 'PASSWORD_NOT_SET', message: 'No password set. Create one now.' });
    }
    if (!hasPw) {
      return res.status(400).json({ ok: false, message: 'No password set. Leave password empty to create one.' });
    }

    const ok = await bcrypt.compare(pw, u.password_hash);
    if (!ok) {
      return res.status(401).json({ ok: false, message: 'Invalid email or password.' });
    }

    const role = (u.role || '').toLowerCase() === 'admin' ? 'admin' : 'driver';
    const token = signSession({ email: em, fullName: u.full_name || em, role });

    // FIX: set cookie with cross-site safe flags based on Origin
    const opts = cookieOpts(req.headers.origin);
    res.cookie('t', token, opts);

    return res.json({ ok: true, role });
  } catch (e) {
    console.error('POST /api/auth/login', e);
    return res.status(500).json({ ok: false, message: 'Login failed.' });
  }
});

function validatePassword(pw) {
  if (typeof pw !== 'string' || pw.length < 8) {
    return 'Password must be at least 8 characters.';
  }
  if (!/[A-Za-z]/.test(pw) || !/\d/.test(pw)) {
    return 'Use letters and at least one number.';
  }
  return null;
}

// First-time password setup (only allowed when account has no password yet)
app.post('/api/auth/set-password', async (req, res) => {
  try {
    const em = String(req.body?.email || '').toLowerCase().trim();
    const newPw = String(req.body?.newPassword || '');

    if (!em) return res.status(400).json({ ok: false, message: 'Email is required.' });
    const v = validatePassword(newPw);
    if (v) return res.status(400).json({ ok: false, message: v });

    const { data: u, error } = await sb
      .from('users')
      .select('full_name, email, role, active, password_hash')
      .eq('email', em)
      .maybeSingle();

    if (error) throw error;
    if (!u || !u.active) {
      return res.status(403).json({ ok: false, message: 'Email not authorized or inactive.' });
    }

    if (u.password_hash && String(u.password_hash).trim()) {
      return res.status(409).json({ ok: false, message: 'Password already set for this account.' });
    }

    const hash = await bcrypt.hash(newPw, 10);
    const { error: updErr } = await sb
      .from('users')
      .update({ password_hash: hash, updated_at: new Date().toISOString() })
      .eq('email', em);
    if (updErr) throw updErr;

    // Log them in right away (cookie with cross-site flags)
    const role = (u.role || '').toLowerCase() === 'admin' ? 'admin' : 'driver';
    const token = signSession({ email: em, fullName: u.full_name || em, role });

    const opts = cookieOpts(req.headers.origin);
    res.cookie('t', token, opts);

    return res.json({ ok: true, role });
  } catch (e) {
    console.error('POST /api/auth/set-password', e);
    return res.status(500).json({ ok: false, message: 'Could not set password.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  try {
    res.clearCookie('t', { path: '/' });
    res.json({ ok: true });
  } catch {
    res.json({ ok: true });
  }
});

// ======================== DRIVER API ========================
app.get('/api/me', verifySession, ensureActiveUser, async (req, res) => {
  try {
    const me = String(req.user.email).toLowerCase();

    const { data: tags, error: e1 } = await sb
      .from('driver_tags')
      .select('ticket_no, email, status, updated_at')
      .eq('status', 'Pending');
    if (e1) throw e1;

    if (!tags?.length) {
      return res.json({ ok: true, profile: req.user, tags: [] });
    }

    const ticketNos = tags.map((t) => t.ticket_no);

    const { data: at, error: e2 } = await sb
      .from('admin_tickets')
      .select('ticket_no, driver_name')
      .in('ticket_no', ticketNos);
    if (e2) throw e2;

    const byTicket = new Map(at.map((r) => [r.ticket_no, r.driver_name || '']));

    const names = Array.from(new Set(at.map((r) => r.driver_name).filter(Boolean)));
    let byDriverEmail = new Map();
    if (names.length) {
      const { data: us, error: e3 } = await sb
        .from('users')
        .select('full_name, email')
        .in('full_name', names);
      if (e3) throw e3;
      byDriverEmail = new Map(us.map((u) => [u.full_name, String(u.email || '').toLowerCase()]));
    }

    const mine = tags.filter((t) => {
      const dname = byTicket.get(t.ticket_no) || '';
      const email = byDriverEmail.get(dname) || '';
      return email === me;
    });

    const out = mine.map((r) => ({
      id: r.ticket_no,
      ticketNo: r.ticket_no,
      email: r.email || req.user.email,
      status: r.status || 'Pending',
      updatedAt: r.updated_at,
    }));

    return res.json({ ok: true, profile: req.user, tags: out });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: 'Failed to load data.' });
  }
});

// Driver tag values
app.get('/api/tags/:id/driver', verifySession, ensureActiveUser, async (req, res) => {
  try {
    const ticketNo = String(req.params.id);

    const { data, error } = await sb
      .from('driver_tags')
      .select(
        'bridgefare, signed_out_loaded, how_many_tons_loads, downtime_lunch, leave_yard_time, truck_stop, notes, sign_out_time, received_by, driver_signature, status, updated_at, email'
      )

      .eq('ticket_no', ticketNo)
      .maybeSingle();

    if (error) throw error;
    if (!data) {
      return res.status(404).json({ ok: false, message: 'Driver tag not found' });
    }

    const driver = {
      bridgefare: data.bridgefare ?? '',
      signedOutLoaded: data.signed_out_loaded ?? '',
      howManyTonsLoads: data.how_many_tons_loads ?? '',
      downtimeLunch: data.downtime_lunch ?? '',

      // NEW
      leaveYardTime: data.leave_yard_time ?? '',
      truckStop: data.truck_stop ?? '',

      notes: data.notes ?? '',
      signOutTime: data.sign_out_time ?? '',
      receivedBy: data.received_by ?? '',
      driverSignature: data.driver_signature ?? '',
      status: data.status ?? '',
      updatedAt: data.updated_at ?? '',
      email: (data.email || '').toLowerCase(),
    };


    return res.json({ ok: true, driver });
  } catch (e) {
    console.error('GET /api/tags/:id/driver', e);
    return res.status(500).json({ ok: false, message: 'Failed to load driver tag.' });
  }
});

// Admin edit of driver tag fields (Bridgefare, Signed Out Loaded, etc.) from Tag Lists
app.put('/api/admin/tags/:id/driver', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const ticketNo = String(req.params.id || '').trim();
    if (!ticketNo) {
      return res.status(400).json({ ok: false, message: 'Missing ticket number.' });
    }

    const {
      bridgefare,
      signedOutLoaded,
      howManyTonsLoads,
      downtimeLunch,
      // NEW
      leaveYardTime = '',
      truckStop = '',
      notes,
      signOutTime,
      receivedBy,
      driverSignature,
    } = req.body || {};

    const patch = {
      bridgefare,
      signed_out_loaded: signedOutLoaded,
      how_many_tons_loads: howManyTonsLoads,
      downtime_lunch: downtimeLunch,

      // NEW ✅
      leave_yard_time: leaveYardTime,
      truck_stop: truckStop,

      notes,
      sign_out_time: signOutTime,
      received_by: receivedBy,
      driver_signature: driverSignature,
      updated_at: new Date().toISOString(),
    };


    // remove undefined so we don’t touch untouched columns
    Object.keys(patch).forEach((k) => patch[k] === undefined && delete patch[k]);

    if (!Object.keys(patch).length) {
      return res.json({ ok: true });
    }

    const { data: existing, error: selErr } = await sb
      .from('driver_tags')
      .select('ticket_no')
      .eq('ticket_no', ticketNo)
      .maybeSingle();
    if (selErr) throw selErr;

    if (existing) {
      const { error: updErr } = await sb
        .from('driver_tags')
        .update(patch)
        .eq('ticket_no', ticketNo);
      if (updErr) throw updErr;
    } else {
      const row = {
        ticket_no: ticketNo,
        status: 'Pending',
        ...patch,
      };
      const { error: insErr } = await sb.from('driver_tags').insert(row);
      if (insErr) throw insErr;
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error('PUT /api/admin/tags/:id/driver', e);
    return res.status(500).json({ ok: false, message: 'Failed to update driver tag.' });
  }
});



// Proof upload
app.post(
  '/api/tags/:id/proof',
  verifySession,
  ensureActiveUser,
  upload.single('file'),
  async (req, res) => {
    try {
      const ticketNo = String(req.params.id);
      if (!req.file) return res.status(400).json({ ok: false, message: 'No file uploaded' });

      const ext = (req.file.originalname.split('.').pop() || 'bin').toLowerCase();
      const key = `tickets/${ticketNo}/proof-${Date.now()}.${ext}`;

      const { error: upErr } = await sb.storage.from('ticket-proofs').upload(key, req.file.buffer, {
        contentType: req.file.mimetype || 'application/octet-stream',
        upsert: true,
      });
      if (upErr) throw upErr;

      const { error: dbErr } = await sb
        .from('driver_tags')
        .update({
          proof_key: key,
          proof_mime: req.file.mimetype || null,
          proof_size: req.file.size || null,
          updated_at: new Date().toISOString(),
        })
        .eq('ticket_no', ticketNo);
      if (dbErr) throw dbErr;

      return res.json({ ok: true, key });
    } catch (e) {
      console.error('POST /api/tags/:id/proof', e);
      return res.status(500).json({ ok: false, message: 'Upload failed' });
    }
  }
);

// Signature upload
app.post(
  '/api/tags/:id/signature/:who',
  verifySession,
  ensureActiveUser,
  upload.single('file'),
  async (req, res) => {
    try {
      const ticketNo = String(req.params.id);
      const who = String(req.params.who || '').toLowerCase(); // 'driver' | 'received'
      if (!['driver', 'received'].includes(who)) {
        return res.status(400).json({ ok: false, message: 'Invalid signature type' });
      }
      if (!req.file) return res.status(400).json({ ok: false, message: 'No file uploaded' });

      const key = `tickets/${ticketNo}/sig-${who}-${Date.now()}.png`;

      const { error: upErr } = await sb.storage.from(SIGN_BUCKET).upload(key, req.file.buffer, {
        contentType: 'image/png',
        upsert: true,
      });
      if (upErr) throw upErr;

      const patch =
        who === 'driver'
          ? {
              signature_driver_key: key,
              signature_driver_mime: 'image/png',
              signature_driver_size: req.file.size || null,
              updated_at: new Date().toISOString(),
            }
          : {
              signature_received_key: key,
              signature_received_mime: 'image/png',
              signature_received_size: req.file.size || null,
              updated_at: new Date().toISOString(),
            };

      const { error: dbErr } = await sb.from('driver_tags').update(patch).eq('ticket_no', ticketNo);
      if (dbErr) throw dbErr;

      return res.json({ ok: true, key });
    } catch (e) {
      console.error('POST /api/tags/:id/signature/:who', e);
      return res.status(500).json({ ok: false, message: 'Signature upload failed' });
    }
  }
);

// Signed URL for proof
app.get('/api/tags/:id/proof-url', verifySession, ensureActiveUser, async (req, res) => {
  try {
    const ticketNo = String(req.params.id);
    const wantDownload =
      req.query.download === '1' || req.query.download === 'true' || req.query.download === 'yes';

    const { data, error } = await sb
      .from('driver_tags')
      .select('proof_key')
      .eq('ticket_no', ticketNo)
      .maybeSingle();
    if (error) throw error;

    const key = data?.proof_key || null;
    if (!key) return res.json({ ok: true, url: null });

    const filename = key.split('/').pop() || `ticket-${ticketNo}.jpg`;

    const { data: sign, error: sErr } = await sb.storage
      .from('ticket-proofs')
      .createSignedUrl(key, 60 * 60 * 24 * 7, wantDownload ? { download: filename } : undefined);
    if (sErr) throw sErr;

    return res.json({ ok: true, url: sign.signedUrl });
  } catch (e) {
    console.error('GET /api/tags/:id/proof-url', e);
    return res.status(500).json({ ok: false, message: 'Failed to create signed URL' });
  }
});

// Signed URL for signature
app.get('/api/tags/:id/signature-url/:who', verifySession, ensureActiveUser, async (req, res) => {
  try {
    const ticketNo = String(req.params.id);
    const who = String(req.params.who || '').toLowerCase();
    if (!['driver', 'received'].includes(who)) {
      return res.status(400).json({ ok: false, message: 'Invalid signature type' });
    }

    const { data, error } = await sb
      .from('driver_tags')
      .select('signature_driver_key, signature_received_key')
      .eq('ticket_no', ticketNo)
      .maybeSingle();
    if (error) throw error;

    const key = who === 'driver' ? data?.signature_driver_key : data?.signature_received_key;
    if (!key) return res.json({ ok: true, url: null });

    const filename = key.split('/').pop() || `ticket-${ticketNo}-sig-${who}.png`;
    const wantDownload =
      req.query.download === '1' || req.query.download === 'true' || req.query.download === 'yes';

    const { data: sign, error: sErr } = await sb.storage
      .from(SIGN_BUCKET)
      .createSignedUrl(key, 60 * 60 * 24 * 7, wantDownload ? { download: filename } : undefined);
    if (sErr) throw sErr;

    return res.json({ ok: true, url: sign.signedUrl });
  } catch (e) {
    console.error('GET /api/tags/:id/signature-url/:who', e);
    return res.status(500).json({ ok: false, message: 'Failed to create signed URL' });
  }
});

// Scale items
app.get('/api/tags/:id/scale-items', verifySession, ensureActiveUser, async (req, res) => {
  try {
    const ticketNo = String(req.params.id);
    const { data, error } = await sb
      .from('scale_tags')
      .select('id, ticket_no, scale_tag_no, yard_or_weight, material, yard_arrival, yard_leave, site_arrival, site_leave')
      .eq('ticket_no', ticketNo)
      .order('id', { ascending: true });
    if (error) throw error;

    const items = (data || []).map((r) => ({
      _row: r.id,
      scaleTagNo: r.scale_tag_no || '',
      yardOrWeight: r.yard_or_weight || '',
      material: r.material || '',
      yardArrival: r.yard_arrival || '',
      yardLeave: r.yard_leave || '',
      siteArrival: r.site_arrival || '',
      siteLeave: r.site_leave || '',
    }));

    return res.json({ ok: true, items });
  } catch (e) {
    console.error('GET /api/tags/:id/scale-items', e);
    return res.status(500).json({ ok: false, message: 'Failed to load scale items.' });
  }
});

app.post('/api/tags/:id/scale-items', verifySession, ensureActiveUser, async (req, res) => {
  try {
    const ticketNo = String(req.params.id || '').trim();
    const itemsIn = Array.isArray(req.body?.items) ? req.body.items : [];

    const bad = itemsIn.find(
      (it) =>
        !it ||
        !it.scaleTagNo ||
        !it.yardOrWeight ||
        !it.material ||
        !it.yardArrival ||
        !it.yardLeave ||
        !it.siteArrival ||
        !it.siteLeave
    );
    if (bad) {
      return res.status(400).json({ ok: false, message: 'All scale tag fields are required.' });
    }

    const rows = itemsIn.map((it) => ({
      ticket_no: ticketNo,
      scale_tag_no: String(it.scaleTagNo),
      yard_or_weight: String(it.yardOrWeight),
      material: String(it.material),
      yard_arrival: String(it.yardArrival),
      yard_leave: String(it.yardLeave),
      site_arrival: String(it.siteArrival),
      site_leave: String(it.siteLeave),
    }));

    const { error: delErr } = await sb.from('scale_tags').delete().eq('ticket_no', ticketNo);
    if (delErr) throw delErr;

    if (rows.length) {
      const { error: insErr } = await sb.from('scale_tags').insert(rows);
      if (insErr) throw insErr;
    }

    return res.json({ ok: true, saved: rows.length });
  } catch (e) {
    console.error('POST /api/tags/:id/scale-items', e);
    return res.status(500).json({ ok: false, message: 'Failed to save scale items.' });
  }
});

// Driver main form submit
app.post('/api/tags/:id/driver', verifySession, ensureActiveUser, async (req, res) => {
  try {
    const ticketNo = String(req.params.id);

    const { data: stub, error: e0 } = await sb
      .from('driver_tags')
      .select('ticket_no')
      .eq('ticket_no', ticketNo)
      .maybeSingle();
    if (e0) throw e0;
    if (!stub) return res.status(404).json({ ok: false, message: 'Ticket not found for this driver' });

    const {
      bridgefare = '',
      signedOutLoaded = '',
      howManyTonsLoads = '',
      downtimeLunch = '',

      // NEW ✅
      leaveYardTime = '',
      truckStop = '',

      notes = '',
      signOutTime = '',
      receivedBy = '',
      driverSignature = '',
      status = 'Done',
    } = req.body || {};


    const { error } = await sb
      .from('driver_tags')
      .update({
        email: String(req.user.email).toLowerCase(),
        bridgefare,
        signed_out_loaded: signedOutLoaded,
        how_many_tons_loads: howManyTonsLoads,
        downtime_lunch: downtimeLunch,
        // NEW
        leave_yard_time: leaveYardTime,
        truck_stop: truckStop,
        notes,
        sign_out_time: signOutTime,
        received_by: receivedBy,
        driver_signature: driverSignature,
        status,
        updated_at: new Date().toISOString(),
      })
      .eq('ticket_no', ticketNo);

    if (error) throw error;

    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: 'Save failed.' });
  }
});

// Admin: send a driver tag back to the driver (set status back to Pending)
app.post(
  '/api/admin/tags/:id/send-back',
  verifySession,
  ensureActiveUser,
  requireAdmin,
  async (req, res) => {
    try {
      const ticketNo = String(req.params.id || '').trim();
      if (!ticketNo) {
        return res
          .status(400)
          .json({ ok: false, message: 'Missing ticket number.' });
      }

      // Make sure a driver_tag row exists for this ticket
      const { data: existing, error: selErr } = await sb
        .from('driver_tags')
        .select('ticket_no,status')
        .eq('ticket_no', ticketNo)
        .maybeSingle();

      if (selErr) throw selErr;
      if (!existing) {
        return res
          .status(404)
          .json({ ok: false, message: 'No driver tag found for this ticket.' });
      }

      const patch = {
        status: 'Pending',
        updated_at: new Date().toISOString(),
      };

      const { error: updErr } = await sb
        .from('driver_tags')
        .update(patch)
        .eq('ticket_no', ticketNo);

      if (updErr) throw updErr;

      return res.json({ ok: true, status: 'Pending' });
    } catch (e) {
      console.error('POST /api/admin/tags/:id/send-back', e);
      return res
        .status(500)
        .json({ ok: false, message: 'Failed to send back ticket.' });
    }
  }
);



// ======================== ADMIN: USERS API ========================
app.get('/api/admin/users', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const q = String(req.query.q || '').trim().toLowerCase();
    const { data, error } = await sb
      .from('users')
      .select('email, full_name, role, active')
      .order('full_name', { ascending: true });
    if (error) throw error;

    const rows = (data || []).filter((r) => {
      if (!q) return true;
      const hay = `${r.full_name || ''} ${r.email || ''} ${r.role || ''}`.toLowerCase();
      return hay.includes(q);
    });

    res.json({ ok: true, users: rows });
  } catch (e) {
    console.error('GET /api/admin/users', e);
    res.status(500).json({ ok: false, message: 'Failed to load users.' });
  }
});

app.post('/api/admin/users', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const { email, fullName, role, active } = req.body || {};
    const em = String(email || '').toLowerCase().trim();
    const rn = ltrim(role);
    if (!em || !rn || !['admin', 'driver'].includes(rn)) {
      return res.status(400).json({ ok: false, message: 'email and role (admin|driver) are required.' });
    }
    const row = {
      email: em,
      full_name: fullName || em,
      role: rn,
      active: Boolean(active),
    };
    const { error } = await sb.from('users').upsert(row, { onConflict: 'email' });
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) {
    console.error('POST /api/admin/users', e);
    res.status(500).json({ ok: false, message: 'Failed to add user.' });
  }
});

app.put('/api/admin/users/:email', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const email = String(req.params.email || '').toLowerCase();
    const patch = {
      full_name: req.body?.fullName ?? undefined,
      role: req.body?.role ? ltrim(req.body.role) : undefined,
      active: typeof req.body?.active === 'boolean' ? req.body.active : undefined,
    };
    Object.keys(patch).forEach((k) => patch[k] === undefined && delete patch[k]);
    if (!Object.keys(patch).length) {
      return res.status(400).json({ ok: false, message: 'No fields to update.' });
    }
    const { error } = await sb.from('users').update(patch).eq('email', email);
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) {
    console.error('PUT /api/admin/users/:email', e);
    res.status(500).json({ ok: false, message: 'Failed to update user.' });
  }
});

app.delete('/api/admin/users', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const emails = Array.isArray(req.body?.emails) ? req.body.emails : [];
    const list = emails.map((e) => String(e || '').toLowerCase()).filter(Boolean);
    if (!list.length) return res.status(400).json({ ok: false, message: 'No emails provided.' });
    const { error } = await sb.from('users').delete().in('email', list);
    if (error) throw error;
    res.json({ ok: true, deleted: list.length });
  } catch (e) {
    console.error('DELETE /api/admin/users', e);
    res.status(500).json({ ok: false, message: 'Failed to delete users.' });
  }
});
// ----- ADMIN: user password management -----
app.post('/api/admin/users/:email/password', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const email = String(req.params.email || '').toLowerCase().trim();
    const newPw = String(req.body?.newPassword || '');

    if (!email) return res.status(400).json({ ok: false, message: 'Email is required.' });
    const v = validatePassword(newPw);
    if (v) return res.status(400).json({ ok: false, message: v });

    // make sure user exists & is active enough to matter (but allow inactive too)
    const { data: u, error: selErr } = await sb
      .from('users')
      .select('email')
      .eq('email', email)
      .maybeSingle();
    if (selErr) throw selErr;
    if (!u) return res.status(404).json({ ok: false, message: 'User not found.' });

    const hash = await bcrypt.hash(newPw, 10);
    const { error: updErr } = await sb
      .from('users')
      .update({ password_hash: hash, updated_at: new Date().toISOString() })
      .eq('email', email);
    if (updErr) throw updErr;

    return res.json({ ok: true, message: 'Password updated.' });
  } catch (e) {
    console.error('POST /api/admin/users/:email/password', e);
    return res.status(500).json({ ok: false, message: 'Failed to set password.' });
  }
});

// Clear password -> forces first-time setup via /api/auth/set-password
app.delete('/api/admin/users/:email/password', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const email = String(req.params.email || '').toLowerCase().trim();
    if (!email) return res.status(400).json({ ok: false, message: 'Email is required.' });

    const { data: u, error: selErr } = await sb
      .from('users')
      .select('email')
      .eq('email', email)
      .maybeSingle();
    if (selErr) throw selErr;
    if (!u) return res.status(404).json({ ok: false, message: 'User not found.' });

    const { error: updErr } = await sb
      .from('users')
      .update({ password_hash: null, updated_at: new Date().toISOString() })
      .eq('email', email);
    if (updErr) throw updErr;

    return res.json({ ok: true, message: 'Password cleared. User must set a new one next login.' });
  } catch (e) {
    console.error('DELETE /api/admin/users/:email/password', e);
    return res.status(500).json({ ok: false, message: 'Failed to clear password.' });
  }
});


// ======================== ADMIN: TICKETS API ========================
app.get('/api/admin/tags', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const { data: rows, error } = await sb
      .from('driver_tags')
      .select('ticket_no, email, status, updated_at')
      .order('updated_at', { ascending: false });
    if (error) throw error;

    const tickets = (rows || []).map((r) => r.ticket_no);
    let names = new Map();
    if (tickets.length) {
      const { data: at, error: e2 } = await sb
        .from('admin_tickets')
        .select('ticket_no, driver_name')
        .in('ticket_no', tickets);
      if (e2) throw e2;
      names = new Map(at.map((x) => [x.ticket_no, x.driver_name || '']));
    }

    const tags = (rows || []).map((r) => ({
      id: r.ticket_no,
      ticketNo: r.ticket_no,
      driverName: names.get(r.ticket_no) || '',
      email: r.email || '',
      status: r.status || 'Pending',
      updatedAt: r.updated_at,
    }));

    return res.json({ ok: true, profile: req.user, tags });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: 'Failed to load admin tags.' });
  }
});

app.get('/api/admin/meta', verifySession, ensureActiveUser, requireAdmin, async (_req, res) => {
  try {
    const [drivers, trailerTypes] = await Promise.all([getActiveDriverNames(), getTrailerTypes()]);
    return res.json({ ok: true, profile: _req.user, drivers, trailerTypes });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: 'Failed to load meta.' });
  }
});

app.post('/api/admin/tickets', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const p = req.body || {};
    if (!p.ticketNo || !p.driverName || !p.date) {
      return res.status(400).json({ ok: false, message: 'date, ticketNo and driverName are required.' });
    }
    const result = await upsertAdminTicket(p);
    return res.json({ ok: true, ...result });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: 'Failed to add ticket.' });
  }
});

app.get('/api/admin/tickets/:id', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id || '').trim();
    const t = await getAdminTicketByTicketNo(id);
    if (!t) return res.status(404).json({ ok: false, message: 'Not found' });
    return res.json({
      ok: true,
      ticket: {
        Date: t.date,
        'Ticket No': t.ticket_no,
        'Driver Name': t.driver_name,
        'Truck Start': t.truck_start,
        'Truck No': t.truck_no,
        'Trailer Type': t.trailer_type,
        'Sub Hauler': t.sub_hauler,
        'Prime Carrier': t.prime_carrier,
        Shipper: t.shipper,
        'Point of Origin': t.origin,
        'Origin City': t.origin_city,
        'PO No': t.po_no,
        'Job Name': t.job_name,
        'Job No': t.job_no,
        Destination: t.destination,
        City: t.city,
      },
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: 'Failed to load ticket.' });
  }
});

app.put('/api/admin/tickets/:id', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const ticketNo = String(req.params.id || '').trim();
    const b = req.body || {};
    const patch = {
      date: b.date ?? undefined,
      driver_name: b.driverName ?? undefined,
      truck_start: b.truckStart ?? undefined,
      truck_no: b.truckNo ?? undefined,
      trailer_type: b.trailerType ?? undefined,
      sub_hauler: b.subHauler ?? undefined,
      prime_carrier: b.primeCarrier ?? undefined,
      shipper: b.shipper ?? undefined,
      origin: b.origin ?? undefined,
      origin_city: b.originCity ?? undefined,
      po_no: b.poNo ?? undefined,
      job_name: b.jobName ?? undefined,
      job_no: b.jobNo ?? undefined,
      destination: b.destination ?? undefined,
      city: (b.city ?? b.destCity) ?? undefined,
    };
    Object.keys(patch).forEach((k) => patch[k] === undefined && delete patch[k]);

    const { data: upd, error: updErr } = await sb
      .from('admin_tickets')
      .update(patch)
      .eq('ticket_no', ticketNo)
      .select('ticket_no');
    if (updErr) throw updErr;

    if (!upd || upd.length === 0) {
      const row = { ticket_no: ticketNo, ...patch };
      const { error: upErr } = await sb.from('admin_tickets').upsert(row, { onConflict: 'ticket_no' });
      if (upErr) throw upErr;

      await sb.from('driver_tags').upsert({ ticket_no: ticketNo, status: 'Pending' }, { onConflict: 'ticket_no' });
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: 'Failed to update ticket.' });
  }
});

app.delete('/api/admin/tickets/:id', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    await deleteAdminTicketAndStub(req.params.id);
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: 'Failed to delete ticket.' });
  }
});

app.post('/api/admin/import-csv', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const csv = String(req.body?.csv || '');
    if (!csv.trim()) return res.status(400).json({ ok: false, message: 'Missing csv' });

    // --- tiny CSV parser (keeps quotes, handles commas in quotes) ---
    function parseCSV(text) {
      const rows = [];
      let row = [], cur = '', inQ = false;
      for (let i = 0; i < text.length; i++) {
        const c = text[i];
        if (inQ) {
          if (c === '"' && text[i + 1] === '"') { cur += '"'; i++; }
          else if (c === '"') { inQ = false; }
          else { cur += c; }
        } else {
          if (c === '"') inQ = true;
          else if (c === ',') { row.push(cur); cur = ''; }
          else if (c === '\n') { row.push(cur); rows.push(row); row = []; cur = ''; }
          else if (c === '\r') { /* ignore */ }
          else { cur += c; }
        }
      }
      row.push(cur);
      rows.push(row);
      return rows;
    }

    const rows = parseCSV(csv);

    // Canonicalize header names: keep letters/digits/_ and '#', drop everything else
    const canon = (s) => String(s || '').toLowerCase().replace(/[^\w#]+/g, '');

    // Header aliases → normalized keys we’ll use in `pick()`
    // Added mappings for "# 1 Material PO#" and "# 2 Material PO#"
    const ALIAS = new Map([
      ['date', 'date'],
      ['ticket#', 'ticket'],
      ['ticketno', 'ticket'],
      ['ticket', 'ticket'],
      ['drivernames', 'driver'],
      ['drivername', 'driver'],
      ['driver', 'driver'],
      ['starttime', 'start'],
      ['start', 'start'],
      ['equipmentnames', 'equip'],
      ['equipmentname', 'equip'],
      ['equipment', 'equip'],
      ['truckno', 'equip'],
      ['trucknumber', 'equip'],
      ['trucktype', 'trucktype'],
      ['trailertype', 'trucktype'],
      ['carriernames', 'carrier'],
      ['carriername', 'carrier'],
      ['primecarrier', 'carrier'],
      ['billto', 'billto'],
      ['shipper', 'billto'],
      ['loadedat', 'loadedat'],
      ['pointoforigin', 'loadedat'],
      ['po#', 'po'],
      ['ponumber', 'po'],
      ['po', 'po'],
      ['location', 'location'],
      ['jobname', 'location'],
      ['job#', 'jobno'],
      ['jobno', 'jobno'],
      ['unloadedat', 'unloaded'],
      ['destination', 'unloaded'],

      // --- Extra PO fields ---
      // Common canonical forms for "# 1 Material PO#" and "# 2 Material PO#"
      ['#1materialpo#', 'po1'],
      ['1materialpo#', 'po1'],
      ['materialpo#1', 'po1'],
      ['po#1material', 'po1'],
      ['materialpo1', 'po1'],

      ['#2materialpo#', 'po2'],
      ['2materialpo#', 'po2'],
      ['materialpo#2', 'po2'],
      ['po#2material', 'po2'],
      ['materialpo2', 'po2'],
    ]);

    // Locate header row
    let headerRow = -1, headerIdx = {};
    const needSome = ['date', 'ticket', 'driver'];
    for (let i = 0; i < Math.min(rows.length, 50); i++) {
      const r = rows[i] || [];
      const map = {};
      r.forEach((h, idx) => {
        const k = ALIAS.get(canon(h));
        if (k && map[k] === undefined) map[k] = idx;
      });
      if (needSome.every((k) => map[k] !== undefined)) {
        headerRow = i; headerIdx = map; break;
      }
    }
    if (headerRow < 0) {
      return res.status(400).json({ ok: false, message: 'Header row not found (looking for Date/Ticket#/Driver Names).' });
    }

    const pick = (r, key) => {
      const idx = headerIdx[key];
      if (idx === undefined) return '';
      return String(r[idx] ?? '').trim();
    };

    const items = [];
    let skippedCarrier = 0, invalid = 0;

    for (let i = headerRow + 1; i < rows.length; i++) {
      const r = rows[i] || [];
      if (!r.length || r.every((c) => String(c || '').trim() === '')) continue;

      const ticketNo = pick(r, 'ticket');
      const driverName = pick(r, 'driver');
      const date = pick(r, 'date');

      if (!ticketNo || !driverName || !date) { invalid++; continue; }

      const carrier = pick(r, 'carrier');
      if (carrier) { skippedCarrier++; continue; }

      // --- Build combined PO string: PO / PO1 / PO2 (skip empties, keep order) ---
      const mainPO = pick(r, 'po');
      const matPO1 = pick(r, 'po1');
      const matPO2 = pick(r, 'po2');
      const poParts = [mainPO, matPO1, matPO2].map(s => String(s || '').trim()).filter(Boolean);
      const poCombined = poParts.join(' / ');

      items.push({
        date,
        ticketNo,
        driverName,
        truckStart: pick(r, 'start'),
        truckNo: pick(r, 'equip'),
        trailerType: pick(r, 'trucktype'),
        subHauler: '',
        primeCarrier: 'Sixty-3 Trucking',
        shipper: pick(r, 'billto'),
        origin: pick(r, 'loadedat'),
        originCity: '',
        poNo: poCombined,               // ← combined value goes here
        jobName: pick(r, 'location'),
        jobNo: pick(r, 'jobno'),
        destination: pick(r, 'unloaded'),
        city: '',
      });
    }

    if (!items.length) {
      return res.json({ ok: true, summary: { added: 0, updated: 0, skippedCarrier, invalid } });
    }

    await bulkUpsertAdminTickets(items);

    return res.json({
      ok: true,
      summary: { added: undefined, updated: undefined, skippedCarrier, invalid },
    });
  } catch (e) {
    console.error('import-csv:', e);
    return res.status(500).json({ ok: false, message: 'Import failed.' });
  }
});


// ======================== COMMON TICKET READ & PDF ========================
app.get('/api/tickets/:id', verifySession, ensureActiveUser, async (req, res) => {
  try {
    const ticketNo = String(req.params.id || '').trim();
    const t = await getAdminTicketByTicketNo(ticketNo);
    if (!t) return res.status(404).json({ ok: false, message: 'Not found' });

    return res.json({
      ok: true,
      ticket: {
        Date: t.date,
        'Ticket No': t.ticket_no,
        'Driver Name': t.driver_name,
        'Truck Start': t.truck_start,
        'Truck No': t.truck_no,
        'Trailer Type': t.trailer_type,
        'Sub Hauler': t.sub_hauler,
        'Prime Carrier': t.prime_carrier,
        Shipper: t.shipper,
        'Point of Origin': t.origin,
        'Origin City': t.origin_city,
        'PO No': t.po_no,
        'Job Name': t.job_name,
        'Job No': t.job_no,
        Destination: t.destination,
        City: t.city,
      },
    });
  } catch (e) {
    console.error('GET /api/tickets/:id', e);
    return res.status(500).json({ ok: false, message: 'Failed to load ticket.' });
  }
});

app.get('/api/tags/:id/pdf', verifySession, ensureActiveUser, async (req, res) => {
  const ticketNo = String(req.params.id || '').trim();

  const COORD_PDF = {
    ticketNo: { x: 3710, y: 819 },
    dateMonth: { x: 518, y: 887 },
    dateDay: { x: 1077, y: 887 },
    dateYear: { x: 1491, y: 887 },

    truckNo: { x: 924, y: 1039 },
    trailerTypeLeft: { x: 941, y: 1217 },
    trailerTypeRight: { x: 3668, y: 1132 },

    subHauler: { x: 933, y: 1403 },
    primeCarrier: { x: 924, y: 1564 },
    shipper: { x: 941, y: 1717 },
    origin: { x: 950, y: 1903 },
    originCity: { x: 933, y: 2064 },

    poNo: { x: 3236, y: 1395 },
    jobName: { x: 3253, y: 1556 },
    jobNo: { x: 3244, y: 1725 },
    destination: { x: 3253, y: 1886 },
    city: { x: 3236, y: 2055 },

    tbl_scaleTagNo_r1: { x: 831, y: 2504 },
    tbl_yardOrWeight: { x: 1822, y: 2496 },
    tbl_material_guess: { x: 2584, y: 2504 },
    tbl_timeArrival: { x: 3431, y: 2496 },
    tbl_timeLeave: { x: 3778, y: 2496 },
    tbl_siteArrival: { x: 4125, y: 2513 },
    tbl_siteLeave: { x: 4506, y: 2496 },

    tbl_scaleTagNo_r2: { x: 789, y: 2623 },

    bridgefare: { x: 4023, y: 4630 },
    signedOutLoadedYes: { x: 1940, y: 4833 },
    signedOutLoadedNo: { x: 1949, y: 4833 },
    howManyTonsLoads: { x: 3498, y: 4833 },
    truckStart: { x: 704, y: 4663 },
    // ✅ NEW: Truck Stop Time (below TRUCK STOP)
    truckStopTime: { x: 1900, y: 4663 },
    startTime: { x: 1034, y: 5028 },
    downtimeLunch: { x: 1940, y: 5036 },
    notes_mid: { x: 2990, y: 5028 },
    signOutTime: { x: 1915, y: 5222 },

    driverName: { x: 1009, y: 5485 },
    receivedBy: { x: 3507, y: 5476 },
  };

  const TABLE_FIRST_ROW_Y2 = COORD_PDF.tbl_scaleTagNo_r1.y;
  const TABLE_ROW_PX2 = Math.max(1, Math.abs(COORD_PDF.tbl_scaleTagNo_r2.y - COORD_PDF.tbl_scaleTagNo_r1.y));
  const TABLE_MAX_ROWS2 = 11;
  const TABLE_X_BY_COL2 = {
    scale_tag_no: COORD_PDF.tbl_scaleTagNo_r1.x,
    yard_or_weight: COORD_PDF.tbl_yardOrWeight.x,
    material: COORD_PDF.tbl_material_guess.x,
    yard_arrival: COORD_PDF.tbl_timeArrival.x,
    yard_leave: COORD_PDF.tbl_timeLeave.x,
    site_arrival: COORD_PDF.tbl_siteArrival.x,
    site_leave: COORD_PDF.tbl_siteLeave.x,
  };

  try {
    if (!fs.existsSync(formPath)) {
      return res.status(500).json({ ok: false, message: 'Blank form not found' });
    }
    const bgBuffer = fs.readFileSync(formPath);

    // 🔁 FETCH admin, raw driver row, and scale rows
    const [{ data: admin, error: e1 }, { data: driverRow, error: e2 }, { data: scale, error: e3 }] = await Promise.all([
      sb.from('admin_tickets').select('*').eq('ticket_no', ticketNo).maybeSingle(),
      sb.from('driver_tags').select('*').eq('ticket_no', ticketNo).maybeSingle(),
      sb.from('scale_tags').select('*').eq('ticket_no', ticketNo).order('id', { ascending: true }),
    ]);

    if (e1 || e2 || e3) throw (e1 || e2 || e3);
    if (!admin) return res.status(404).json({ ok: false, message: 'Ticket not found' });

    // ✅ normalize driver object (same shape as /api/tags/:id/driver)
      const driver = driverRow
        ? {
            bridgefare: driverRow.bridgefare ?? '',
            signedOutLoaded: driverRow.signed_out_loaded ?? '',
            howManyTonsLoads: driverRow.how_many_tons_loads ?? '',
            downtimeLunch: driverRow.downtime_lunch ?? '',

            // ✅ NEW
            leaveYardTime: driverRow.leave_yard_time ?? '',
            truckStop: driverRow.truck_stop ?? '',

            notes: driverRow.notes ?? '',
            signOutTime: driverRow.sign_out_time ?? '',
            receivedBy: driverRow.received_by ?? '',
            driverSignature: driverRow.driver_signature ?? '',
            status: driverRow.status ?? '',
          }
        : null;

    const dl = req.query.download === '1' || req.query.download === 'true';

    const doc = new PDFDocument({ size: 'LETTER', margin: 0 });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `${dl ? 'attachment' : 'inline'}; filename="ticket-${ticketNo}.pdf"`);
    doc.on('error', (err) => {
      console.error('pdfkit error', err);
      try { res.end(); } catch {}
    });
    doc.pipe(res);

    doc.image(bgBuffer, 0, 0, { width: PDF_W, height: PDF_H });

    doc.fontSize(8).fillColor('#000');

    const mdy = toMDY(admin.date || admin.Date);
    doc.fontSize(10);
    drawText(doc, ticketNo, COORD_PDF.ticketNo.x, COORD_PDF.ticketNo.y);
    doc.fontSize(8);
    drawText(doc, mdy.m, COORD_PDF.dateMonth.x, COORD_PDF.dateMonth.y);
    drawText(doc, mdy.d, COORD_PDF.dateDay.x, COORD_PDF.dateDay.y);
    drawText(doc, mdy.y, COORD_PDF.dateYear.x, COORD_PDF.dateYear.y);

    drawText(doc, admin.truck_no, COORD_PDF.truckNo.x, COORD_PDF.truckNo.y);
    drawText(doc, admin.trailer_type, COORD_PDF.trailerTypeLeft.x, COORD_PDF.trailerTypeLeft.y);
    drawText(doc, admin.trailer_type, COORD_PDF.trailerTypeRight.x, COORD_PDF.trailerTypeRight.y);
    drawText(doc, admin.sub_hauler, COORD_PDF.subHauler.x, COORD_PDF.subHauler.y);
    drawText(doc, admin.prime_carrier, COORD_PDF.primeCarrier.x, COORD_PDF.primeCarrier.y);
    drawText(doc, admin.shipper, COORD_PDF.shipper.x, COORD_PDF.shipper.y);
    drawText(doc, admin.origin, COORD_PDF.origin.x, COORD_PDF.origin.y);
    drawText(doc, admin.origin_city, COORD_PDF.originCity.x, COORD_PDF.originCity.y);

    drawText(doc, admin.po_no, COORD_PDF.poNo.x, COORD_PDF.poNo.y);
    drawText(doc, admin.job_name, COORD_PDF.jobName.x, COORD_PDF.jobName.y);
    drawText(doc, admin.job_no, COORD_PDF.jobNo.x, COORD_PDF.jobNo.y);
    drawText(doc, admin.destination, COORD_PDF.destination.x, COORD_PDF.destination.y);
    drawText(doc, admin.city, COORD_PDF.city.x, COORD_PDF.city.y);

    // scale table
    doc.fontSize(7.5);
    const rows = Array.isArray(scale) ? scale : [];
    for (let i = 0; i < Math.min(rows.length, TABLE_MAX_ROWS2); i++) {
      const r = rows[i] || {};
      const yRowPx = TABLE_FIRST_ROW_Y2 + i * TABLE_ROW_PX2;
      drawText(doc, r.scale_tag_no, TABLE_X_BY_COL2.scale_tag_no, yRowPx);
      drawText(doc, r.yard_or_weight, TABLE_X_BY_COL2.yard_or_weight, yRowPx);
      drawText(doc, r.material, TABLE_X_BY_COL2.material, yRowPx);
      drawText(doc, r.yard_arrival, TABLE_X_BY_COL2.yard_arrival, yRowPx);
      drawText(doc, r.yard_leave, TABLE_X_BY_COL2.yard_leave, yRowPx);
      drawText(doc, r.site_arrival, TABLE_X_BY_COL2.site_arrival, yRowPx);
      drawText(doc, r.site_leave, TABLE_X_BY_COL2.site_leave, yRowPx);
    }

    // driver section (Bridgefare down)
    doc.fontSize(8);
    drawText(doc, admin.truck_start, COORD_PDF.truckStart.x, COORD_PDF.truckStart.y);
    drawText(doc, hhmm(driver?.truckStop), COORD_PDF.truckStopTime.x, COORD_PDF.truckStopTime.y);
    drawText(doc, driver?.bridgefare, COORD_PDF.bridgefare.x, COORD_PDF.bridgefare.y);
    drawText(doc, driver?.howManyTonsLoads, COORD_PDF.howManyTonsLoads.x, COORD_PDF.howManyTonsLoads.y);

    const sol = (driver?.signedOutLoaded || '').toString().toLowerCase();
    if (sol === 'yes') drawText(doc, '✓', COORD_PDF.signedOutLoadedYes.x, COORD_PDF.signedOutLoadedYes.y);
    else if (sol === 'no') drawText(doc, '✓', COORD_PDF.signedOutLoadedNo.x, COORD_PDF.signedOutLoadedNo.y);

    drawText(doc, hhmm(driver?.leaveYardTime), COORD_PDF.startTime.x, COORD_PDF.startTime.y);
    drawText(doc, driver?.downtimeLunch, COORD_PDF.downtimeLunch.x, COORD_PDF.downtimeLunch.y);
    drawText(doc, driver?.notes, COORD_PDF.notes_mid.x, COORD_PDF.notes_mid.y);
    drawText(doc, hhmm(driver?.signOutTime), COORD_PDF.signOutTime.x, COORD_PDF.signOutTime.y);

    drawText(doc, admin.driver_name, COORD_PDF.driverName.x, COORD_PDF.driverName.y);
    drawText(doc, driver?.receivedBy, COORD_PDF.receivedBy.x, COORD_PDF.receivedBy.y);

    const SIG_PT_WIDTH = X(900);
    const SIG_Y_OFFSET = -170;

    async function placeSig(key, name, nameCoordPx) {
      try {
        if (!key) return;
        const { data: file, error: sigErr } = await sb.storage.from(SIGN_BUCKET).download(key);
        if (sigErr || !file) return;

        const buf = await sbDataToBuffer(file);
        if (!buf || !buf.length) return;

        doc.fontSize(8);
        const nameWidthPt = doc.widthOfString(String(name || ''));
        const nameStartXPt = X(nameCoordPx.x);
        const nameCenterPt = nameStartXPt + nameWidthPt / 2;

        const xPt = nameCenterPt - SIG_PT_WIDTH / 2;
        const yPt = Y(nameCoordPx.y) + Y(SIG_Y_OFFSET);

        doc.image(buf, xPt, yPt, { width: SIG_PT_WIDTH });
      } catch (e) {
        console.warn('Signature render skipped:', e?.message || e);
      }
    }

    // signatures still use raw DB keys from driverRow
    await placeSig(driverRow?.signature_driver_key, admin.driver_name, COORD_PDF.driverName);
    await placeSig(driverRow?.signature_received_key, driver?.receivedBy, COORD_PDF.receivedBy);

    doc.end();
  } catch (e) {
    console.error('PDF route error', e);
    if (!res.headersSent) res.status(500).json({ ok: false, message: 'Failed to generate PDF' });
    try { res.end(); } catch {}
  }
});


// ======================== Page routing ========================
app.get('/driver-ticket', verifySession, ensureActiveUser, (_req, res) => {
  res.sendFile(path.resolve('public/driver-ticket.html'));
});
app.get('/admin', verifySession, ensureActiveUser, requireAdmin, (_req, res) => {
  res.sendFile(path.resolve('public/admin.html'));
});
app.get('/tag-lists', verifySession, ensureActiveUser, requireAdmin, (_req, res) => {
  res.sendFile(path.resolve('public/tag-lists.html'));
});
app.get('/admin/users', verifySession, ensureActiveUser, requireAdmin, (_req, res) => {
  res.sendFile(path.resolve('public/admin-users.html'));
});
app.get('/dashboard', verifySession, ensureActiveUser, (_req, res) => {
  res.sendFile(path.resolve('public/dashboard.html'));
});


// static fallback
app.get('*', (_req, res) => {
  res.sendFile(path.resolve('public/index.html'));
});

// local dev listener; Vercel uses the default export
if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`🚚 server running at http://localhost:${PORT}`);
  });
}

export default app;
