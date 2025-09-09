import fs from 'fs';
import PDFDocument from 'pdfkit';
import multer from 'multer';
const upload = multer({ limits: { fileSize: 10 * 1024 * 1024 } }); // 10MB

// add near other consts (after multer/upload, etc.)
const SIGN_BUCKET = 'ticket-signatures';


// server.js (Supabase-backed)
import 'dotenv/config';
import express from 'express';
import path from 'path';
const formPath = path.resolve('public/assets/forms/blank-ticket.jpg');
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import cors from 'cors';

import {
  sb,
  // meta + lists
  getActiveDriverNames,
  getTrailerTypes,
  // admin tickets
  upsertAdminTicket,
  getAdminTicketByTicketNo,
  updateAdminTicket,
  deleteAdminTicketAndStub,
  bulkUpsertAdminTickets,
} from './supabaseAdmin.js';


// ---------------- PDF helpers (place right after imports) ----------------
const IMG_W = 5100;   // your scanned image size
const IMG_H = 6600;
const PDF_W = 612;    // Letter in points
const PDF_H = 792;
const sx = PDF_W / IMG_W;
const sy = PDF_H / IMG_H;
const X = px => px * sx;
const Y = px => px * sy;

// measured click coordinates you collected
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
  signedOutLoadedNo:  { x: 2203, y: 4833 },

  howManyTonsLoads: { x: 3625, y: 4833 },

  startTime: { x: 1127, y: 5028 },
  downtimeLunch: { x: 2262, y: 5028 },
  notes_mid: { x: 3236, y: 5045 },

  signOutTime: { x: 2059, y: 5222 },

  driverName: { x: 1441, y: 5485 },
  receivedBy: { x: 3956, y: 5485 },

  notes_big: { x: 831, y: 5866 },
};

// table layout (in source pixels → will scale automatically)
const TABLE_FIRST_ROW_Y = 2504;
const TABLE_ROW_PX = 160;           // tweak +/– if rows are slightly off
const TABLE_MAX_ROWS = 11;
const TABLE_COLS = ['scaleTagNo', 'yardOrWeight', 'material', 'yardArrival', 'yardLeave', 'siteArrival', 'siteLeave'];
const TABLE_X_BY_COL = {
  scaleTagNo:   COORD.tbl_scaleTagNo.x,
  yardOrWeight: COORD.tbl_yardOrWeight.x,
  material:     COORD.tbl_material.x,
  yardArrival:  COORD.tbl_timeArrival.x,
  yardLeave:    COORD.tbl_timeLeave.x,
  siteArrival:  COORD.tbl_siteArrival.x,
  siteLeave:    COORD.tbl_siteLeave.x,
};

app.get('/api/health', (req, res) => {
  res.json({ ok: true, env: process.env.NODE_ENV, time: new Date().toISOString() });
});


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
  if (m) return `${m[1].padStart(2,'0')}:${m[2]}`;
  return String(s);
}

// Normalize Supabase Storage download() outputs to a Node Buffer for PDFKit
async function sbDataToBuffer(data) {
  if (!data) return null;
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof Uint8Array) return Buffer.from(data);
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  if (typeof data.arrayBuffer === 'function') {
    const ab = await data.arrayBuffer();
    return Buffer.from(ab);
  }
  // Node ReadableStream / AsyncIterable
  if (typeof data.pipe === 'function' || data[Symbol.asyncIterator]) {
    const chunks = [];
    for await (const chunk of data) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
  }
  return null;
}



const {
  PORT = 8080,
  GOOGLE_CLIENT_ID,
  JWT_SECRET,
  NODE_ENV = 'development',
} = process.env;

if (!GOOGLE_CLIENT_ID || !JWT_SECRET) {
  console.error('❌ Missing env vars. Check .env (GOOGLE_CLIENT_ID, JWT_SECRET)');
  process.exit(1);
}

const app = express();
app.use(express.json({ limit: '10mb' })); // allow large CSV bodies
app.use(cookieParser());
app.use(cors({ origin: false }));
app.use(express.static(path.resolve('public')));

const oauthClient = new OAuth2Client(GOOGLE_CLIENT_ID);

/* ---------------- helpers ---------------- */
function signSession(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '2h' });
}
function verifySession(req, res, next) {
  const tok = req.cookies['t'];
  if (!tok) return res.status(401).json({ ok: false, message: 'No session' });
  try { req.user = jwt.verify(tok, JWT_SECRET); next(); }
  catch { return res.status(401).json({ ok: false, message: 'Invalid session' }); }
}
const ltrim = (v) => String(v ?? '').trim().toLowerCase();

/**
 * Ensure cookie user still exists & is Active in Supabase `users`,
 * and refresh req.user.role/fullName on each request.
 * users: { email text pk/unique, full_name text, role text, active bool }
 */
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

/* ---------------- Auth: Google Sign-In -> cookie ---------------- */
app.post('/api/auth/google', async (req, res) => {
  try {
    const idToken = req.body?.idToken;
    if (!idToken) return res.status(400).json({ ok: false, message: 'Missing idToken' });

    const ticket = await oauthClient.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const email = String(payload.email || '').toLowerCase();

    // Look up in Supabase users table
    const { data: u, error } = await sb
      .from('users')
      .select('full_name, email, role, active')
      .eq('email', email)
      .maybeSingle();
    if (error) throw error;
    if (!u || !u.active) {
      return res.status(403).json({ ok: false, message: 'Email not authorized or inactive.' });
    }

    const role = ltrim(u.role) === 'admin' ? 'admin' : 'driver';
    const session = { email, fullName: u.full_name || email, role };
    const token = signSession(session);

    res.cookie('t', token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: NODE_ENV === 'production',
      path: '/',
    });

    return res.json({ ok: true, role });
  } catch (e) {
    console.error(e);
    return res.status(401).json({ ok: false, message: 'Token verification failed.' });
  }
});

/* ========================  DRIVER API  ======================== */

/**
 * GET /api/me
 * Returns current user + their PENDING tickets (from driver_tags),
 * filtered by matching email through a join with admin_tickets->users by driver_name.
 */
app.get('/api/me', verifySession, ensureActiveUser, async (req, res) => {
  try {
    const me = String(req.user.email).toLowerCase();

    // 1) get all driver_tags with status 'Pending'
    const { data: tags, error: e1 } = await sb
      .from('driver_tags')
      .select('ticket_no, email, status, updated_at')
      .eq('status', 'Pending');
    if (e1) throw e1;

    if (!tags?.length) {
      return res.json({ ok: true, profile: req.user, tags: [] });
    }

    const ticketNos = tags.map(t => t.ticket_no);
    // 2) get driver names for those tickets
    const { data: at, error: e2 } = await sb
      .from('admin_tickets')
      .select('ticket_no, driver_name')
      .in('ticket_no', ticketNos);
    if (e2) throw e2;

    const byTicket = new Map(at.map(r => [r.ticket_no, r.driver_name || '']));

    // 3) for driver_name -> find user emails once, build map
    const names = Array.from(new Set(at.map(r => r.driver_name).filter(Boolean)));
    let byDriverEmail = new Map();
    if (names.length) {
      const { data: us, error: e3 } = await sb
        .from('users')
        .select('full_name, email')
        .in('full_name', names);
      if (e3) throw e3;
      byDriverEmail = new Map(us.map(u => [u.full_name, String(u.email || '').toLowerCase()]));
    }

    // 4) filter to my tickets
    const mine = tags.filter(t => {
      const dname = byTicket.get(t.ticket_no) || '';
      const email = byDriverEmail.get(dname) || '';
      return email === me;
    });

    const out = mine.map(r => ({
      id: r.ticket_no,
      ticketNo: r.ticket_no,
      email: r.email || req.user.email, // may be empty in stub; fall back to me
      status: r.status || 'Pending',
      updatedAt: r.updated_at,
    }));

    return res.json({ ok: true, profile: req.user, tags: out });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: 'Failed to load data.' });
  }
});

/**
 * Scale items for a ticket (driver view)
 */
// GET driver tag values for a ticket
app.get('/api/tags/:id/driver', verifySession, ensureActiveUser, async (req, res) => {
  try {
    const ticketNo = String(req.params.id);

    const { data, error } = await sb
      .from('driver_tags')
      .select(
        'bridgefare, signed_out_loaded, how_many_tons_loads, downtime_lunch, notes, sign_out_time, received_by, driver_signature, status, updated_at, email'
      )
      .eq('ticket_no', ticketNo)
      .maybeSingle();

    if (error) throw error;
    if (!data) {
      return res.status(404).json({ ok: false, message: 'Driver tag not found' });
    }

    // Map DB snake_case -> frontend camelCase expected by fillDriverFieldsFromObject
    const driver = {
      bridgefare: data.bridgefare ?? '',
      signedOutLoaded: data.signed_out_loaded ?? '',
      howManyTonsLoads: data.how_many_tons_loads ?? '',
      downtimeLunch: data.downtime_lunch ?? '',
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

// POST /api/tags/:id/proof  (multipart form: field "file")
app.post('/api/tags/:id/proof',
  verifySession, ensureActiveUser,
  upload.single('file'),
  async (req, res) => {
    try {
      const ticketNo = String(req.params.id);
      if (!req.file) return res.status(400).json({ ok:false, message:'No file uploaded' });

      const ext = (req.file.originalname.split('.').pop() || 'bin').toLowerCase();
      const key = `tickets/${ticketNo}/proof-${Date.now()}.${ext}`;

      // Upload to Supabase Storage (service key via your sb client)
      const { error: upErr } = await sb.storage
        .from('ticket-proofs')
        .upload(key, req.file.buffer, {
          contentType: req.file.mimetype || 'application/octet-stream',
          upsert: true,
        });
      if (upErr) throw upErr;

      // Save key + metadata into driver_tags
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
      return res.status(500).json({ ok:false, message:'Upload failed' });
    }
  }
);

// POST /api/tags/:id/signature/:who  (who = 'driver' | 'received')
app.post('/api/tags/:id/signature/:who',
  verifySession, ensureActiveUser,
  upload.single('file'),
  async (req, res) => {
    try {
      const ticketNo = String(req.params.id);
      const who = String(req.params.who || '').toLowerCase(); // 'driver' | 'received'
      if (!['driver','received'].includes(who)) {
        return res.status(400).json({ ok:false, message:'Invalid signature type' });
      }
      if (!req.file) return res.status(400).json({ ok:false, message:'No file uploaded' });

      const ext = 'png'; // we save as PNG from canvas
      const key = `tickets/${ticketNo}/sig-${who}-${Date.now()}.${ext}`;

      // upload to private bucket
      const { error: upErr } = await sb.storage
        .from(SIGN_BUCKET)
        .upload(key, req.file.buffer, {
          contentType: 'image/png',
          upsert: true,
        });
      if (upErr) throw upErr;

      // update driver_tags row fields based on 'who'
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

      const { error: dbErr } = await sb
        .from('driver_tags')
        .update(patch)
        .eq('ticket_no', ticketNo);
      if (dbErr) throw dbErr;

      return res.json({ ok: true, key });
    } catch (e) {
      console.error('POST /api/tags/:id/signature/:who', e);
      return res.status(500).json({ ok:false, message:'Signature upload failed' });
    }
  }
);




// GET /api/tags/:id/proof-url  -> { url }
// GET /api/tags/:id/proof-url  -> { url }
app.get('/api/tags/:id/proof-url', verifySession, ensureActiveUser, async (req, res) => {
  try {
    const ticketNo = String(req.params.id);
    const wantDownload =
      req.query.download === '1' ||
      req.query.download === 'true' ||
      req.query.download === 'yes';

    const { data, error } = await sb
      .from('driver_tags')
      .select('proof_key')
      .eq('ticket_no', ticketNo)
      .maybeSingle();
    if (error) throw error;

    const key = data?.proof_key || null;
    if (!key) return res.json({ ok: true, url: null });

    const filename = key.split('/').pop() || `ticket-${ticketNo}.jpg`;

    // 7 days signed URL; set Content-Disposition when download=true
    const { data: sign, error: sErr } = await sb.storage
      .from('ticket-proofs')
      .createSignedUrl(
        key,
        60 * 60 * 24 * 7,
        wantDownload ? { download: filename } : undefined
      );
    if (sErr) throw sErr;

    return res.json({ ok: true, url: sign.signedUrl });
  } catch (e) {
    console.error('GET /api/tags/:id/proof-url', e);
    return res.status(500).json({ ok: false, message: 'Failed to create signed URL' });
  }
});

// GET /api/tags/:id/signature-url/:who  -> { url | null }
app.get('/api/tags/:id/signature-url/:who', verifySession, ensureActiveUser, async (req, res) => {
  try {
    const ticketNo = String(req.params.id);
    const who = String(req.params.who || '').toLowerCase(); // 'driver' | 'received'
    if (!['driver','received'].includes(who)) {
      return res.status(400).json({ ok:false, message:'Invalid signature type' });
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
    return res.status(500).json({ ok:false, message:'Failed to create signed URL' });
  }
});





  // Save / replace scale items for a ticket
  // Load scale items for a ticket
app.get('/api/tags/:id/scale-items', verifySession, ensureActiveUser, async (req, res) => {
  try {
    const ticketNo = String(req.params.id);
    const { data, error } = await sb
      .from('scale_tags')
      .select('id, ticket_no, scale_tag_no, yard_or_weight, material, yard_arrival, yard_leave, site_arrival, site_leave')
      .eq('ticket_no', ticketNo)
      .order('id', { ascending: true });
    if (error) throw error;

    const items = (data || []).map(r => ({
      _row: r.id,
      scaleTagNo:   r.scale_tag_no || '',
      yardOrWeight: r.yard_or_weight || '',
      material:     r.material || '',
      yardArrival:  r.yard_arrival || '',
      yardLeave:    r.yard_leave || '',
      siteArrival:  r.site_arrival || '',
      siteLeave:    r.site_leave || '',
    }));

    return res.json({ ok: true, items });
  } catch (e) {
    console.error('GET /api/tags/:id/scale-items', e);
    return res.status(500).json({ ok:false, message:'Failed to load scale items.' });
  }
});
// Save / replace scale items for a ticket
app.post('/api/tags/:id/scale-items', verifySession, ensureActiveUser, async (req, res) => {
  try {
    const ticketNo = String(req.params.id || '').trim();
    const itemsIn = Array.isArray(req.body?.items) ? req.body.items : [];

    // Basic validation: every item must be fully filled (the UI enforces this too)
    const bad = itemsIn.find(it =>
      !it ||
      !it.scaleTagNo || !it.yardOrWeight || !it.material ||
      !it.yardArrival || !it.yardLeave || !it.siteArrival || !it.siteLeave
    );
    if (bad) {
      return res.status(400).json({ ok: false, message: 'All scale tag fields are required.' });
    }

    // Map to DB column names
    const rows = itemsIn.map(it => ({
      ticket_no:     ticketNo,
      scale_tag_no:  String(it.scaleTagNo),
      yard_or_weight:String(it.yardOrWeight),
      material:      String(it.material),
      yard_arrival:  String(it.yardArrival),
      yard_leave:    String(it.yardLeave),
      site_arrival:  String(it.siteArrival),
      site_leave:    String(it.siteLeave),
    }));

    // Replace strategy: delete old → insert new
    const { error: delErr } = await sb
      .from('scale_tags')
      .delete()
      .eq('ticket_no', ticketNo);
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





/**
 * Driver main form submit (mark Done)
 */
app.post('/api/tags/:id/driver', verifySession, ensureActiveUser, async (req, res) => {
  try {
    const ticketNo = String(req.params.id);

    // Ensure the ticket exists as a stub
    const { data: stub, error: e0 } = await sb
      .from('driver_tags')
      .select('ticket_no')
      .eq('ticket_no', ticketNo)
      .maybeSingle();
    if (e0) throw e0;
    if (!stub) return res.status(404).json({ ok: false, message: 'Ticket not found for this driver' });

    // ADD: destructure optional proof fields from the body
    const {
  bridgefare = '',
  signedOutLoaded = '',
  howManyTonsLoads = '',
  downtimeLunch = '',
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

/* ========================  ADMIN: USERS API  ======================== */
/**
 * users table columns we use:
 *  - email (PK, text)
 *  - full_name (text)
 *  - role (text: 'admin'|'driver')
 *  - active (boolean)
 */

// List users (with optional ?q= search on name/email)
app.get('/api/admin/users', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const q = String(req.query.q || '').trim().toLowerCase();
    const { data, error } = await sb
      .from('users')
      .select('email, full_name, role, active')
      .order('full_name', { ascending: true });
    if (error) throw error;

    const rows = (data || []).filter(r => {
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

// Add (or upsert) a user
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

// Update a user
app.put('/api/admin/users/:email', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const email = String(req.params.email || '').toLowerCase();
    const patch = {
      full_name: req.body?.fullName ?? undefined,
      role: req.body?.role ? ltrim(req.body.role) : undefined,
      active: typeof req.body?.active === 'boolean' ? req.body.active : undefined,
    };
    Object.keys(patch).forEach(k => patch[k] === undefined && delete patch[k]);
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

// Bulk delete: body { emails: [...] }
app.delete('/api/admin/users', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const emails = Array.isArray(req.body?.emails) ? req.body.emails : [];
    const list = emails.map(e => String(e || '').toLowerCase()).filter(Boolean);
    if (!list.length) return res.status(400).json({ ok: false, message: 'No emails provided.' });
    const { error } = await sb.from('users').delete().in('email', list);
    if (error) throw error;
    res.json({ ok: true, deleted: list.length });
  } catch (e) {
    console.error('DELETE /api/admin/users', e);
    res.status(500).json({ ok: false, message: 'Failed to delete users.' });
  }
});

/* ========================  ADMIN: TICKETS API  ======================== */

/**
 * Admin list for the dashboard table.
 */
app.get('/api/admin/tags', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const { data: rows, error } = await sb
      .from('driver_tags')
      .select('ticket_no, email, status, updated_at')
      .order('updated_at', { ascending: false });
    if (error) throw error;

    const tickets = (rows || []).map(r => r.ticket_no);
    let names = new Map();
    if (tickets.length) {
      const { data: at, error: e2 } = await sb
        .from('admin_tickets')
        .select('ticket_no, driver_name')
        .in('ticket_no', tickets);
      if (e2) throw e2;
      names = new Map(at.map(x => [x.ticket_no, x.driver_name || '']));
    }

    const tags = (rows || []).map(r => ({
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

// Meta for dropdowns (drivers list, trailer types)
app.get('/api/admin/meta', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const [drivers, trailerTypes] = await Promise.all([
      getActiveDriverNames(),
      getTrailerTypes(),
    ]);
    return res.json({ ok: true, profile: req.user, drivers, trailerTypes });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: 'Failed to load meta.' });
  }
});

// Create ticket (upsert in admin_tickets; ensure driver_tags stub Pending)
app.post('/api/admin/tickets', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const p = req.body || {};
    if (!p.ticketNo || !p.driverName || !p.date) {
      return res.status(400).json({ ok: false, message: 'date, ticketNo and driverName are required.' });
    }
    const result = await upsertAdminTicket(p); // adds stub if not exists
    return res.json({ ok: true, ...result });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: 'Failed to add ticket.' });
  }
});

// Fetch one ticket (for preview/edit)
// Fetch one ticket (for preview/edit)
app.get('/api/admin/tickets/:id', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id || '').trim();
    const t = await getAdminTicketByTicketNo(id);
    if (!t) return res.status(404).json({ ok: false, message: 'Not found' });
    return res.json({ ok: true, ticket: {
      'Date': t.date,
      'Ticket No': t.ticket_no,
      'Driver Name': t.driver_name,
      'Truck Start': t.truck_start,
      'Truck No': t.truck_no,
      'Trailer Type': t.trailer_type,
      'Sub Hauler': t.sub_hauler,
      'Prime Carrier': t.prime_carrier,
      'Shipper': t.shipper,
      'Point of Origin': t.origin,
      'Origin City': t.origin_city,
      'PO No': t.po_no,
      'Job Name': t.job_name,
      'Job No': t.job_no,
      'Destination': t.destination,
      'City': t.city,
    }});
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: 'Failed to load ticket.' });
  }
});


// Update one ticket
// Update one ticket (create if missing)
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
    // remove undefined fields (don’t reset columns unintentionally)
    Object.keys(patch).forEach(k => patch[k] === undefined && delete patch[k]);

    // Try UPDATE first
    const { data: upd, error: updErr } = await sb
      .from('admin_tickets')
      .update(patch)
      .eq('ticket_no', ticketNo)
      .select('ticket_no'); // non-empty means a row changed
    if (updErr) throw updErr;

    if (!upd || upd.length === 0) {
      // Row didn’t exist → create it with ticket_no + patch
      const row = { ticket_no: ticketNo, ...patch };
      const { error: upErr } = await sb
        .from('admin_tickets')
        .upsert(row, { onConflict: 'ticket_no' });
      if (upErr) throw upErr;

      // Safety: ensure driver stub exists too
      await sb
        .from('driver_tags')
        .upsert({ ticket_no: ticketNo, status: 'Pending' }, { onConflict: 'ticket_no' });
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: 'Failed to update ticket.' });
  }
});


// Delete one ticket (also delete Driver stub)
app.delete('/api/admin/tickets/:id', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    await deleteAdminTicketAndStub(req.params.id);
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: 'Failed to delete ticket.' });
  }
});

/* ---------------- Import CSV → Admin Tickets (upsert) ---------------- */
app.post('/api/admin/import-csv', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const csv = String(req.body?.csv || '');
    if (!csv.trim()) return res.status(400).json({ ok: false, message: 'Missing csv' });

    // tiny CSV parser
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
          else if (c === '\r') { /* skip */ }
          else { cur += c; }
        }
      }
      row.push(cur); rows.push(row);
      return rows;
    }

    const rows = parseCSV(csv);

    // locate header row (tolerant)
    const canon = s => String(s || '').toLowerCase().replace(/[^\w#]+/g, '');
    const ALIAS = new Map([
      ['date','date'],
      ['ticket#','ticket'], ['ticketno','ticket'], ['ticket','ticket'],
      ['drivernames','driver'], ['drivername','driver'], ['driver','driver'],
      ['starttime','start'], ['start','start'],
      ['equipmentnames','equip'], ['equipmentname','equip'], ['equipment','equip'], ['truckno','equip'], ['trucknumber','equip'],
      ['trucktype','trucktype'], ['trailertype','trucktype'],
      ['carriernames','carrier'], ['carriername','carrier'], ['primecarrier','carrier'],
      ['billto','billto'], ['shipper','billto'],
      ['loadedat','loadedat'], ['pointoforigin','loadedat'],
      ['po#','po'], ['ponumber','po'], ['po','po'],
      ['location','location'], ['jobname','location'],
      ['job#','jobno'], ['jobno','jobno'],
      ['unloadedat','unloaded'], ['destination','unloaded'],
    ]);

    let headerRow = -1, headerIdx = {};
    const needSome = ['date', 'ticket', 'driver'];
    for (let i = 0; i < Math.min(rows.length, 50); i++) {
      const r = rows[i] || [];
      const map = {};
      r.forEach((h, idx) => {
        const k = ALIAS.get(canon(h));
        if (k && map[k] === undefined) map[k] = idx;
      });
      if (needSome.every(k => map[k] !== undefined)) {
        headerRow = i; headerIdx = map; break;
      }
    }
    if (headerRow < 0) {
      return res.status(400).json({ ok: false, message: 'Header row not found (looking for Date/Ticket#/Driver Names).' });
    }

    const pick = (r, key) => {
      const idx = headerIdx[key]; if (idx === undefined) return '';
      return String(r[idx] ?? '').trim();
    };

    const items = [];
    let skippedCarrier = 0, invalid = 0;

    for (let i = headerRow + 1; i < rows.length; i++) {
      const r = rows[i] || [];
      if (!r.length || r.every(c => String(c || '').trim() === '')) continue;

      const ticketNo   = pick(r, 'ticket');
      const driverName = pick(r, 'driver');
      const date       = pick(r, 'date');

      if (!ticketNo || !driverName || !date) { invalid++; continue; }

      const carrier = pick(r, 'carrier');
      if (carrier) { // if Carrier Names NOT empty → skip entire row
        skippedCarrier++;
        continue;
      }

      items.push({
        date,
        ticketNo,
        driverName,
        truckStart:  pick(r, 'start'),
        truckNo:     pick(r, 'equip'),
        trailerType: pick(r, 'trucktype'),
        subHauler:   '',                              // skip
        primeCarrier:'Sixty-3 Trucking',              // default
        shipper:     pick(r, 'billto'),               // Bill To → Shipper
        origin:      pick(r, 'loadedat'),             // Loaded At → Origin
        originCity:  '',                              // skip
        poNo:        pick(r, 'po'),                   // PO#
        jobName:     pick(r, 'location'),             // Location → Job Name
        jobNo:       pick(r, 'jobno'),                // Job #
        destination: pick(r, 'unloaded'),             // Unloaded At → Destination
        city:        '',                              // skip
      });
    }

    if (!items.length) {
      return res.json({ ok: true, summary: { added: 0, updated: 0, skippedCarrier, invalid } });
    }

    // Supabase bulk upsert (server-side)
    await bulkUpsertAdminTickets(items);

    return res.json({
      ok: true,
      summary: { added: undefined, updated: undefined, skippedCarrier, invalid }
    });
  } catch (e) {
    console.error('import-csv:', e);
    return res.status(500).json({ ok: false, message: 'Import failed.' });
  }
});

/* -------- Serve pages -------- */
// Serve driver ticket page
app.get('/driver-ticket', verifySession, ensureActiveUser, (_req, res) => {
  res.sendFile(path.resolve('public/driver-ticket.html'));
});


app.get('/admin', verifySession, ensureActiveUser, requireAdmin, (_req, res) => {
  res.sendFile(path.resolve('public/admin.html'));
});

app.get('/tag-lists', verifySession, ensureActiveUser, requireAdmin, (_req, res) => {
  res.sendFile(path.resolve('public/tag-lists.html'));
});

// NEW Users management page
// Serve the page
app.get('/admin/users', verifySession, ensureActiveUser, requireAdmin, (_req, res) => {
  res.sendFile(path.resolve('public/admin-users.html'));
});

// API
app.get('/api/admin/users', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await sb
      .from('users')
      .select('full_name, email, role, active, updated_at')
      .order('updated_at', { ascending: false });
    if (error) throw error;
    return res.json({ ok: true, profile: req.user, users: data || [] });
  } catch (e) {
    console.error(e); return res.status(500).json({ ok:false, message:'Failed to load users.' });
  }
});

app.post('/api/admin/users', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const { full_name, email, role='driver', active=true } = req.body || {};
    if (!full_name || !email) return res.status(400).json({ ok:false, message:'full_name and email are required.' });
    const payload = {
      full_name,
      email: String(email).toLowerCase(),
      role: String(role).toLowerCase()==='admin' ? 'admin' : 'driver',
      active: !!active,
      updated_at: new Date().toISOString()
    };
    const { error } = await sb.from('users').insert(payload).single();
    if (error) throw error;
    return res.json({ ok:true });
  } catch (e) {
    console.error(e); return res.status(500).json({ ok:false, message:'Create failed.' });
  }
});

app.put('/api/admin/users/:email', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const keyEmail = String(req.params.email || '').toLowerCase();
    const patch = {
      updated_at: new Date().toISOString()
    };
    if (req.body.full_name !== undefined) patch.full_name = req.body.full_name;
    if (req.body.role !== undefined) patch.role = String(req.body.role).toLowerCase()==='admin' ? 'admin' : 'driver';
    if (req.body.active !== undefined) patch.active = !!req.body.active;

    const { error } = await sb.from('users').update(patch).eq('email', keyEmail);
    if (error) throw error;
    return res.json({ ok:true });
  } catch (e) {
    console.error(e); return res.status(500).json({ ok:false, message:'Update failed.' });
  }
});

app.post('/api/admin/users/delete', verifySession, ensureActiveUser, requireAdmin, async (req, res) => {
  try {
    const emails = Array.isArray(req.body?.emails) ? req.body.emails.map(e => String(e).toLowerCase()) : [];
    if (!emails.length) return res.status(400).json({ ok:false, message:'No emails provided.' });
    const { error } = await sb.from('users').delete().in('email', emails);
    if (error) throw error;
    return res.json({ ok:true, deleted: emails.length });
  } catch (e) {
    console.error(e); return res.status(500).json({ ok:false, message:'Delete failed.' });
  }
});

// Read one ticket for authenticated users (driver or admin)
app.get('/api/tickets/:id', verifySession, ensureActiveUser, async (req, res) => {
  try {
    const ticketNo = String(req.params.id || '').trim();
    const t = await getAdminTicketByTicketNo(ticketNo);
    if (!t) return res.status(404).json({ ok: false, message: 'Not found' });

    // Same shape you return on the admin route:
    return res.json({
      ok: true,
      ticket: {
        'Date': t.date,
        'Ticket No': t.ticket_no,
        'Driver Name': t.driver_name,
        'Truck Start': t.truck_start,
        'Truck No': t.truck_no,
        'Trailer Type': t.trailer_type,
        'Sub Hauler': t.sub_hauler,
        'Prime Carrier': t.prime_carrier,
        'Shipper': t.shipper,
        'Point of Origin': t.origin,
        'Origin City': t.origin_city,
        'PO No': t.po_no,
        'Job Name': t.job_name,
        'Job No': t.job_no,
        'Destination': t.destination,
        'City': t.city,
      }
    });
  } catch (e) {
    console.error('GET /api/tickets/:id', e);
    return res.status(500).json({ ok: false, message: 'Failed to load ticket.' });
  }
});


// Generate ticket PDF (with signatures if present)
// PDF: render admin + driver + scale, and overlay signatures if present
app.get('/api/tags/:id/pdf', verifySession, ensureActiveUser, async (req, res) => {
  const ticketNo = String(req.params.id || '').trim();

  // coordinates (exactly as you measured)
  const COORD = {
    ticketNo:       { x: 3710, y: 819 },
    dateMonth:      { x:  518, y:  887 },
    dateDay:        { x: 1077, y:  887 },
    dateYear:       { x: 1491, y:  887 },

    truckNo:        { x:  924, y: 1039 },
    trailerTypeLeft:  { x:  941, y: 1217 },
    trailerTypeRight: { x: 3668, y: 1132 },

    subHauler:      { x:  933, y: 1403 },
    primeCarrier:   { x:  924, y: 1564 },
    shipper:        { x:  941, y: 1717 },
    origin:         { x:  950, y: 1903 },
    originCity:     { x:  933, y: 2064 },

    poNo:           { x: 3236, y: 1395 },
    jobName:        { x: 3253, y: 1556 },
    jobNo:          { x: 3244, y: 1725 },
    destination:    { x: 3253, y: 1886 },
    city:           { x: 3236, y: 2055 },

    // table col centers (first row)
    tbl_scaleTagNo_r1:  { x:  831, y: 2504 },
    tbl_yardOrWeight:   { x: 1822, y: 2496 },
    tbl_material_guess: { x: 2584, y: 2504 },
    tbl_timeArrival:    { x: 3431, y: 2496 },
    tbl_timeLeave:      { x: 3778, y: 2496 },
    tbl_siteArrival:    { x: 4125, y: 2513 },
    tbl_siteLeave:      { x: 4506, y: 2496 },

    tbl_scaleTagNo_r2:  { x:  789, y: 2623 }, // for row height

    // bottom sections
    bridgefare:         { x: 4023, y: 4630 },
    signedOutLoadedYes: { x: 1940, y: 4833 },
    signedOutLoadedNo:  { x: 1949, y: 4833 },
    howManyTonsLoads:   { x: 3498, y: 4833 },
    truckStart:         { x:  704, y: 4663 },
    startTime:          { x: 1034, y: 5028 },
    downtimeLunch:      { x: 1940, y: 5036 },
    notes_mid:          { x: 2990, y: 5028 },
    signOutTime:        { x: 1915, y: 5222 },

    driverName:         { x: 1009, y: 5485 },
    receivedBy:         { x: 3507, y: 5476 },
  };

  // table geometry (source pixels → auto-scales)
  const TABLE_FIRST_ROW_Y = COORD.tbl_scaleTagNo_r1.y;
  const TABLE_ROW_PX      = Math.max(1, Math.abs(COORD.tbl_scaleTagNo_r2.y - COORD.tbl_scaleTagNo_r1.y));
  const TABLE_MAX_ROWS    = 11;
  const TABLE_X_BY_COL = {
    scale_tag_no:   COORD.tbl_scaleTagNo_r1.x,
    yard_or_weight: COORD.tbl_yardOrWeight.x,
    material:       COORD.tbl_material_guess.x,
    yard_arrival:   COORD.tbl_timeArrival.x,
    yard_leave:     COORD.tbl_timeLeave.x,
    site_arrival:   COORD.tbl_siteArrival.x,
    site_leave:     COORD.tbl_siteLeave.x,
  };

  try {
    if (!fs.existsSync(formPath)) {
      return res.status(500).json({ ok: false, message: 'Blank form not found' });
    }
    const bgBuffer = fs.readFileSync(formPath);

    // fetch data
    const [{ data: admin, error: e1 }, { data: driver, error: e2 }, { data: scale, error: e3 }] =
      await Promise.all([
        sb.from('admin_tickets').select('*').eq('ticket_no', ticketNo).maybeSingle(),
        sb.from('driver_tags').select('*').eq('ticket_no', ticketNo).maybeSingle(),
        sb.from('scale_tags').select('*').eq('ticket_no', ticketNo).order('id', { ascending: true }),
      ]);
    if (e1 || e2 || e3) throw (e1 || e2 || e3);
    if (!admin) return res.status(404).json({ ok: false, message: 'Ticket not found' });

    const dl = req.query.download === '1' || req.query.download === 'true';

    const doc = new PDFDocument({ size: 'LETTER', margin: 0 });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `${dl ? 'attachment' : 'inline'}; filename="ticket-${ticketNo}.pdf"`);
    doc.on('error', (err) => { console.error('pdfkit error', err); try { res.end(); } catch {} });
    doc.pipe(res);

    // background
    doc.image(bgBuffer, 0, 0, { width: PDF_W, height: PDF_H });

    // text
    doc.fontSize(8).fillColor('#000');

    // header
    const mdy = toMDY(admin.date || admin.Date);
    doc.fontSize(10);
    drawText(doc, ticketNo, COORD.ticketNo.x, COORD.ticketNo.y);
    doc.fontSize(8);
    drawText(doc, mdy.m, COORD.dateMonth.x, COORD.dateMonth.y);
    drawText(doc, mdy.d, COORD.dateDay.x, COORD.dateDay.y);
    drawText(doc, mdy.y, COORD.dateYear.x, COORD.dateYear.y);

    // left column
    drawText(doc, admin.truck_no,      COORD.truckNo.x,      COORD.truckNo.y);
    drawText(doc, admin.trailer_type,  COORD.trailerTypeLeft.x,  COORD.trailerTypeLeft.y);
    drawText(doc, admin.trailer_type,  COORD.trailerTypeRight.x, COORD.trailerTypeRight.y);
    drawText(doc, admin.sub_hauler,    COORD.subHauler.x,    COORD.subHauler.y);
    drawText(doc, admin.prime_carrier, COORD.primeCarrier.x, COORD.primeCarrier.y);
    drawText(doc, admin.shipper,       COORD.shipper.x,      COORD.shipper.y);
    drawText(doc, admin.origin,        COORD.origin.x,       COORD.origin.y);
    drawText(doc, admin.origin_city,   COORD.originCity.x,   COORD.originCity.y);

    // right column
    drawText(doc, admin.po_no,         COORD.poNo.x,        COORD.poNo.y);
    drawText(doc, admin.job_name,      COORD.jobName.x,     COORD.jobName.y);
    drawText(doc, admin.job_no,        COORD.jobNo.x,       COORD.jobNo.y);
    drawText(doc, admin.destination,   COORD.destination.x, COORD.destination.y);
    drawText(doc, admin.city,          COORD.city.x,        COORD.city.y);

    // table rows
    doc.fontSize(7.5);
    const rows = Array.isArray(scale) ? scale : [];
    for (let i = 0; i < Math.min(rows.length, TABLE_MAX_ROWS); i++) {
      const r = rows[i] || {};
      const yRowPx = TABLE_FIRST_ROW_Y + i * TABLE_ROW_PX;
      drawText(doc, r.scale_tag_no,   TABLE_X_BY_COL.scale_tag_no,   yRowPx);
      drawText(doc, r.yard_or_weight, TABLE_X_BY_COL.yard_or_weight, yRowPx);
      drawText(doc, r.material,       TABLE_X_BY_COL.material,       yRowPx);
      drawText(doc, r.yard_arrival,   TABLE_X_BY_COL.yard_arrival,   yRowPx);
      drawText(doc, r.yard_leave,     TABLE_X_BY_COL.yard_leave,     yRowPx);
      drawText(doc, r.site_arrival,   TABLE_X_BY_COL.site_arrival,   yRowPx);
      drawText(doc, r.site_leave,     TABLE_X_BY_COL.site_leave,     yRowPx);
    }

    // bottom fields
    doc.fontSize(8);
    drawText(doc, admin.truck_start,           COORD.truckStart.x,   COORD.truckStart.y);
    drawText(doc, driver?.bridgefare,          COORD.bridgefare.x,   COORD.bridgefare.y);
    drawText(doc, driver?.how_many_tons_loads, COORD.howManyTonsLoads.x, COORD.howManyTonsLoads.y);

    const sol = (driver?.signed_out_loaded || '').toString().toLowerCase();
    if (sol === 'yes') drawText(doc, '✓', COORD.signedOutLoadedYes.x, COORD.signedOutLoadedYes.y);
    else if (sol === 'no') drawText(doc, '✓', COORD.signedOutLoadedNo.x, COORD.signedOutLoadedNo.y);

    drawText(doc, hhmm(admin.truck_start || admin.start_time), COORD.startTime.x,   COORD.startTime.y);
    drawText(doc, driver?.downtime_lunch,                      COORD.downtimeLunch.x, COORD.downtimeLunch.y);
    drawText(doc, driver?.notes,                               COORD.notes_mid.x,   COORD.notes_mid.y);
    drawText(doc, hhmm(driver?.sign_out_time),                 COORD.signOutTime.x, COORD.signOutTime.y);

    // names (drawn first; signatures should be transparent so they won't cover these)
    drawText(doc, admin.driver_name,   COORD.driverName.x,  COORD.driverName.y);
    drawText(doc, driver?.received_by, COORD.receivedBy.x,  COORD.receivedBy.y);

    // --- signatures (PNG with transparency) ---
    const SIG_PT_WIDTH = X(900);
    const SIG_Y_OFFSET = -170; // ~170px (source) above name baseline

    async function placeSig(key, name, nameCoordPx) {
      try {
        if (!key) return;
        const { data: file, error: sigErr } = await sb.storage.from(SIGN_BUCKET).download(key);
        if (sigErr || !file) return;

        const buf = await sbDataToBuffer(file);
        if (!buf || !buf.length) return;

        // center the image over the typed name
        doc.fontSize(8);
        const nameWidthPt  = doc.widthOfString(String(name || ''));
        const nameStartXPt = X(nameCoordPx.x);
        const nameCenterPt = nameStartXPt + nameWidthPt / 2;

        const xPt = nameCenterPt - SIG_PT_WIDTH / 2;
        const yPt = Y(nameCoordPx.y) + Y(SIG_Y_OFFSET);

        doc.image(buf, xPt, yPt, { width: SIG_PT_WIDTH });
      } catch (e) {
        console.warn('Signature render skipped:', e?.message || e);
      }
    }

    await placeSig(driver?.signature_driver_key,   admin.driver_name,   COORD.driverName);
    await placeSig(driver?.signature_received_key, driver?.received_by, COORD.receivedBy);

    doc.end();
  } catch (e) {
    console.error('PDF route error', e);
    if (!res.headersSent) res.status(500).json({ ok: false, message: 'Failed to generate PDF' });
    try { res.end(); } catch {}
  }
});







/* ---------------- static fallback ---------------- */
app.get('*', (_req, res) => {
  res.sendFile(path.resolve('public/index.html'));
});



// Only listen locally; on Vercel the API route will use the exported app.
if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`🚚 server running at http://localhost:${PORT}`);
  });
}

// 👇 add this export so Vercel can use your Express app
export default app;


