import bcrypt from 'bcryptjs';
import { createClient } from '@supabase/supabase-js';
import { signSession, setSessionCookie } from '..//_lib/jwt.js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, message: 'Method not allowed' });
  }

  try {
    const body = req.body || {};
    const email = (body.email || '').toLowerCase().trim();
    const newPassword = body.newPassword || '';

    if (!email || !newPassword) {
      return res.status(400).json({ ok: false, message: 'Email and new password required' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ ok: false, message: 'Password too short' });
    }

    // Find active user
    const { data: user, error } = await supabase
      .from('Users')
      .select('id,email,role,is_active')
      .eq('email', email)
      .maybeSingle();

    if (error) {
      console.error('[set-password] supabase error', error);
      return res.status(500).json({ ok: false, message: 'Failed to set password' });
    }
    if (!user || !user.is_active) {
      return res.status(400).json({ ok: false, message: 'Account not found or inactive' });
    }

    // Save hash
    const password_hash = await bcrypt.hash(newPassword, 10);
    const { error: upErr } = await supabase
      .from('Users')
      .update({ password_hash })
      .eq('id', user.id);

    if (upErr) {
      console.error('[set-password] update error', upErr);
      return res.status(500).json({ ok: false, message: 'Could not save password' });
    }

    // Issue session + cookie
    const token = signSession({ sub: user.id, role: user.role, email: user.email });
    setSessionCookie(res, token);

    return res.status(200).json({ ok: true, role: user.role });
  } catch (err) {
    console.error('[set-password] exception', err);
    return res.status(500).json({ ok: false, message: 'Failed to set password' });
  }
}
