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
