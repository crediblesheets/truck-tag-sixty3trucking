// api/auth/set-password.js
import bcrypt from 'bcryptjs';
import { createClient } from '@supabase/supabase-js';
import { signSession, setSessionCookie } from '../_lib/jwt.js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, message: 'Method not allowed' });
  }

  try {
    const { email: rawEmail, newPassword = '' } = req.body || {};
    const email = String(rawEmail || '').trim().toLowerCase();

    if (!email || !newPassword) {
      return res.status(400).json({ ok: false, message: 'Email and new password required' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ ok: false, message: 'Password too short' });
    }

    // NOTE: "users" + "active"
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, role, active, password_hash')
      .eq('email', email)
      .maybeSingle();

    if (error || !user || !user.active) {
      return res.status(400).json({ ok: false, message: 'Account not found or inactive' });
    }

    if (user.password_hash) {
      return res.status(409).json({ ok: false, message: 'Password already set for this account.' });
    }

    const password_hash = await bcrypt.hash(newPassword, 10);
    const { error: upErr } = await supabase
      .from('users')
      .update({ password_hash })
      .eq('id', user.id);

    if (upErr) {
      console.error('[set-password] update error', upErr);
      return res.status(500).json({ ok: false, message: 'Could not save password' });
    }

    const token = signSession({ sub: user.id, role: user.role, email: user.email });
    setSessionCookie(res, token);

    return res.status(200).json({ ok: true, role: user.role });
  } catch (err) {
    console.error('[auth/set-password]', err);
    return res.status(500).json({ ok: false, message: 'Failed to set password' });
  }
}
