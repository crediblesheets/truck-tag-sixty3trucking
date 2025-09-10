// api/auth/login.js
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
  let { email, password } = body;
  email = String(email || '').trim().toLowerCase();

  if (!email || !password) {
    return res.status(400).json({ ok: false, message: 'Email and password are required.' });
  }

  const { data: user, error } = await supabase
    .from('users')
    .select('id,email,role,active,password_hash')
    .eq('email', email)
    .maybeSingle();

  if (error) return res.status(500).json({ ok: false, message: 'Database error.' });
  if (!user || user.active === false) {
    return res.status(401).json({ ok: false, message: 'Invalid email or password.' });
  }

  if (!user.password_hash) {
    // Front-end opens “Create password” modal when it sees this code
    return res.status(200).json({ ok: false, code: 'PASSWORD_NOT_SET', message: 'Password not set.' });
  }

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ ok: false, message: 'Invalid email or password.' });

  const token = signToken(user);
  setAuthCookie(res, token);
  return res.status(200).json({ ok: true, role: user.role });
}
