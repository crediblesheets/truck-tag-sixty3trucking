// api/auth/set-password.js
export const config = { runtime: 'nodejs' };

import supabase from '../_lib/supa.js';
import bcrypt from 'bcryptjs';
import { signToken, setAuthCookie } from '../_lib/jwt.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, message: 'Method Not Allowed' });
  }

  let body = req.body;
  if (typeof body !== 'object') {
    try { body = JSON.parse(req.body || '{}'); } catch { body = {}; }
  }
  let { email, newPassword } = body;
  email = String(email || '').trim().toLowerCase();

  if (!email || !newPassword) {
    return res.status(400).json({ ok: false, message: 'Email and newPassword are required.' });
  }
  if (newPassword.length < 8 || !/[A-Za-z]/.test(newPassword) || !/\d/.test(newPassword)) {
    return res.status(400).json({ ok: false, message: 'Password must be ≥ 8 chars and include a number.' });
  }

  const { data: user, error } = await supabase
    .from('users')
    .select('id,email,role,active')
    .eq('email', email)
    .maybeSingle();

  if (error) return res.status(500).json({ ok: false, message: 'Database error.' });
  if (!user || user.active === false) {
    return res.status(404).json({ ok: false, message: 'User not found or inactive.' });
  }

  const password_hash = await bcrypt.hash(newPassword, 10);
  const { error: upErr } = await supabase
    .from('users')
    .update({ password_hash })
    .eq('id', user.id)
    .limit(1);

  if (upErr) return res.status(500).json({ ok: false, message: 'Could not set password.' });

  const token = signToken(user);
  setAuthCookie(res, token);
  return res.status(200).json({ ok: true, role: user.role });
}
