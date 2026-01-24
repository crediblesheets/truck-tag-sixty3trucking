// supabaseAdmin.js (SERVER-SIDE ONLY)
import 'dotenv/config';
import { createClient } from '@supabase/supabase-js';

const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = process.env;
if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in .env');
}

// Single shared client (service role; full DB access).
export const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
  global: { headers: { 'x-application-name': 'truck-tag-site/1.0' } },
});

/* ========= Small DB helpers (used by server.js routes) ========= */

/** Drivers dropdown = active users who are NOT admins */
export async function getActiveDriverNames() {
  const { data, error } = await sb
    .from('users')
    .select('full_name, role, active')
    .eq('active', true)
    .neq('role', 'admin');
  if (error) throw error;

  return (data || [])
    .map((u) => u.full_name)
    .filter(Boolean)
    .sort((a, b) => a.localeCompare(b));
}

/** Trailer types dropdown */
export async function getTrailerTypes() {
  const { data, error } = await sb
    .from('trailer_types')
    .select('name')
    .order('name', { ascending: true });
  if (error) throw error;

  return (data || []).map((t) => t.name);
}

/** Driver stubs table (used for the Admin list view similar to “Driver Tags”) */
export async function listDriverTags() {
  const { data, error } = await sb
    .from('driver_tags')
    .select('ticket_no, email, status, updated_at')
    .order('updated_at', { ascending: false });
  if (error) throw error;

  // Normalize to the shape your frontend already expects
  return (data || []).map((r) => ({
    id: r.ticket_no,
    ticketNo: r.ticket_no,
    driverName: '',         // not stored in driver_tags; available in admin_tickets
    email: r.email || '',
    status: r.status || 'Pending',
    updatedAt: r.updated_at,
  }));
}

/** Read one admin ticket by Ticket # */
export async function getAdminTicketByTicketNo(ticketNo) {
  const t = String(ticketNo || '').trim();
  const { data, error } = await sb
    .from('admin_tickets')
    .select('*')
    .eq('ticket_no', t)
    .maybeSingle();
  if (error) throw error;
  return data || null;
}


/** Upsert into admin_tickets; also ensure a driver_tags stub exists */
export async function upsertAdminTicket(p) {
  const row = {
    date: p.date || null,
    ticket_no: String(p.ticketNo || ''),
    driver_name: p.driverName || '',
    truck_start: p.truckStart || '',
    truck_no: p.truckNo || '',
    trailer_type: p.trailerType || '',
    sub_hauler: p.subHauler || '',
    prime_carrier: p.primeCarrier || '',
    shipper: p.shipper || '',
    origin: p.origin || '',
    origin_city: p.originCity || '',
    po_no: p.poNo || '',
    job_name: p.jobName || '',
    job_no: p.jobNo || '',
    destination: p.destination || '',
    city: p.city || p.destCity || '',
  };

  // Upsert by unique(ticket_no)
  const { error: upErr } = await sb
    .from('admin_tickets')
    .upsert(row, { onConflict: 'ticket_no' });
  if (upErr) throw upErr;

  // Ensure driver stub
  const { data: stub, error: selErr } = await sb
    .from('driver_tags')
    .select('ticket_no')
    .eq('ticket_no', row.ticket_no)
    .maybeSingle();
  if (selErr) throw selErr;

  if (!stub) {
    const { error: insErr } = await sb
      .from('driver_tags')
      .insert({ ticket_no: row.ticket_no, status: 'Pending' });
    if (insErr) throw insErr;
    return { added: true, updated: false };
  }
  return { added: false, updated: true };
}

/** Update fields of an existing admin ticket */
export async function updateAdminTicket(ticketNo, patch = {}) {
  // Never allow changing ticket_no via update filter
  const { error } = await sb
    .from('admin_tickets')
    .update(patch)
    .eq('ticket_no', String(ticketNo));
  if (error) throw error;
  return true;
}

/** Delete admin ticket + any driver stubs */
export async function deleteAdminTicketAndStub(ticketNo) {
  const t = String(ticketNo);

  const { error: e1 } = await sb.from('admin_tickets').delete().eq('ticket_no', t);
  if (e1) throw e1;

  const { error: e2 } = await sb.from('driver_tags').delete().eq('ticket_no', t);
  if (e2) throw e2;

  return true;
}

/** Bulk upsert admin tickets (used by CSV import). Returns {added, updated}. */
export async function bulkUpsertAdminTickets(items = []) {
  if (!items.length) return { added: 0, updated: 0 };

  // Upsert all rows in one shot (minimize rate limits)
  const rows = items.map((p) => ({
    date: p.date || null,
    ticket_no: String(p.ticketNo || ''),
    driver_name: p.driverName || '',
    truck_start: p.truckStart || '',
    truck_no: p.truckNo || '',
    trailer_type: p.trailerType || '',
    sub_hauler: p.subHauler || '',
    prime_carrier: p.primeCarrier || '',
    shipper: p.shipper || '',
    origin: p.origin || '',
    origin_city: p.originCity || '',
    po_no: p.poNo || '',
    job_name: p.jobName || '',
    job_no: p.jobNo || '',
    destination: p.destination || '',
    city: p.city || p.destCity || '',
  }));

  const { data, error } = await sb
    .from('admin_tickets')
    .upsert(rows, { onConflict: 'ticket_no' })
    .select('ticket_no'); // returns the affected keys
  if (error) throw error;

  // Ensure stubs for any new tickets (insert ignore via upsert on conflict)
  const stubs = rows.map((r) => ({ ticket_no: r.ticket_no, status: 'Pending' }));
  const { error: stubErr } = await sb
    .from('driver_tags')
    .upsert(stubs, { onConflict: 'ticket_no', ignoreDuplicates: true });
  if (stubErr) throw stubErr;

  // We can’t precisely know added vs updated without a pre-check;
  // if you need exact counts, do a select beforehand and compare.
  return { added: undefined, updated: undefined };
}


/* ========= Draft Tickets (no ticket_no yet) ========= */

/**
 * Create a draft ticket for a driver (no ticket #).
 * Returns the draft id (uuid).
 */
export async function createDraftTicket({ email = '', fullName = '' } = {}) {
  const row = {
    driver_email: String(email || '').trim().toLowerCase(),
    driver_name: String(fullName || '').trim(),
    status: 'Draft',
    tag_mode: 'scale',
    payload: {},
    items: [],
    updated_at: new Date().toISOString(),
  };

  const { data, error } = await sb
    .from('ticket_drafts')
    .insert(row)
    .select('id')
    .single();
  if (error) throw error;

  return data.id;
}

/** List drafts for Admin (you can filter by status: Draft, Sent, Converted) */
export async function listDraftTickets({ status } = {}) {
  let q = sb
    .from('ticket_drafts')
    .select('id, driver_email, driver_name, status, tag_mode, converted_ticket_no, updated_at, created_at')
    .order('updated_at', { ascending: false });

  if (status) q = q.eq('status', status);

  const { data, error } = await q;
  if (error) throw error;
  return data || [];
}

/** Get full draft (Admin or Driver open) */
export async function getDraftTicketById(id) {
  const { data, error } = await sb
    .from('ticket_drafts')
    .select('*')
    .eq('id', String(id))
    .maybeSingle();
  if (error) throw error;
  return data || null;
}

/**
 * Update draft (merge payload + items + tag_mode)
 * patch = { payloadPatch, items, tagMode, status }
 */
export async function updateDraftTicket(id, patch = {}) {
  const draft = await getDraftTicketById(id);
  if (!draft) throw new Error('Draft not found');

  const nextPayload = {
    ...(draft.payload || {}),
    ...(patch.payloadPatch || {}),
  };

  const upd = {
    payload: nextPayload,
    updated_at: new Date().toISOString(),
  };

  if (patch.items !== undefined) upd.items = Array.isArray(patch.items) ? patch.items : [];
  if (patch.tagMode) upd.tag_mode = String(patch.tagMode);
  if (patch.status) upd.status = String(patch.status);

  const { error } = await sb
    .from('ticket_drafts')
    .update(upd)
    .eq('id', String(id));
  if (error) throw error;

  return true;
}

/** Driver presses "Send Draft" -> Admin sees it under Draft Tickets */
export async function sendDraftTicketToAdmin(id) {
  const { error } = await sb
    .from('ticket_drafts')
    .update({
      status: 'Sent',
      sent_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    })
    .eq('id', String(id));
  if (error) throw error;
  return true;
}

/**
 * Admin converts Draft -> Normal Ticket tables.
 * - Requires ticketNo
 * - Writes admin_tickets
 * - Writes driver_tags (driver payload + tag_mode + status)
 * - Writes scale_tags (from draft items) if tag_mode==='scale' (or still write for equipment if you use same table)
 * - Marks draft Converted
 */
export async function convertDraftToTicket({ draftId, ticketNo, adminTicketPayload = {} }) {
  const tno = String(ticketNo || '').trim();
  if (!tno) throw new Error('Ticket No is required to submit.');

  // Ensure draft exists
  const draft = await getDraftTicketById(draftId);
  if (!draft) throw new Error('Draft not found');

  // Block duplicate ticket_no
  const existing = await getAdminTicketByTicketNo(tno);
  if (existing) throw new Error(`Ticket No ${tno} already exists.`);

  // 1) Create/Upsert admin ticket + stub
  await upsertAdminTicket({
    ...adminTicketPayload,
    ticketNo: tno,
  });

  // 2) Apply driver payload into driver_tags row
  // NOTE: adjust column names here if your driver_tags uses different names.
  const p = draft.payload || {};
  const driverPatch = {
    email: draft.driver_email || '',
    status: 'Pending',              // after admin submits, it becomes a normal pending ticket
    tag_mode: draft.tag_mode || 'scale',

    bridgefare: p.bridgefare ?? '',
    signedoutloaded: p.signedOutLoaded ?? p.signedoutloaded ?? '',
    howmanytonsloads: p.howManyTonsLoads ?? p.howmanytonsloads ?? '',
    downtimelunch: p.downtimeLunch ?? p.downtimelunch ?? '',
    leaveyardtime: p.leaveYardTime ?? p.leaveyardtime ?? '',
    truckstop: p.truckStop ?? p.truckstop ?? '',
    notes: p.notes ?? '',
    signouttime: p.signOutTime ?? p.signouttime ?? '',
    receivedby: p.receivedBy ?? p.receivedby ?? '',
    driversignature: p.driverSignature ?? p.driversignature ?? '',

    updated_at: new Date().toISOString(),
  };

  const { error: drvErr } = await sb
    .from('driver_tags')
    .update(driverPatch)
    .eq('ticket_no', tno);
  if (drvErr) throw drvErr;

  // 3) Write scale items (delete + insert)
  const items = Array.isArray(draft.items) ? draft.items : [];
  if (items.length) {
    // Remove any existing scale tags for safety
    await sb.from('scale_tags').delete().eq('ticket_no', tno);

    // Map into your scale_tags columns (adjust column names if needed)
    const rows = items.map((it) => ({
      ticket_no: tno,
      scale_tag_no: it.scaleTagNo || '',
      yard_or_weight: it.yardOrWeight || '',
      material: it.material || '',
      yard_arrival: it.yardArrival || '',
      yard_leave: it.yardLeave || '',
      site_arrival: it.siteArrival || '',
      site_leave: it.siteLeave || '',
    }));

    const { error: scErr } = await sb.from('scale_tags').insert(rows);
    if (scErr) throw scErr;
  }

  // 4) Mark draft converted
  const { error: dErr } = await sb
    .from('ticket_drafts')
    .update({
      status: 'Converted',
      converted_ticket_no: tno,
      converted_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    })
    .eq('id', String(draftId));
  if (dErr) throw dErr;

  return { ok: true, ticketNo: tno };
}
