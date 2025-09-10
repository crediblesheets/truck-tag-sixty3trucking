// api/auth/login.js
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
    const { email, password } = req.body || {};
    const em = String(email || '').trim().toLowerCase();
    if (!em || !password) {
      return res.status(400).json({ ok: false, message: 'Email and password required' });
    }

    // NOTE: your table is "users" and the active flag is "active"
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, role, active, password_hash')
      .eq('email', em)
      .maybeSingle();

    if (error || !user || !user.active) {
      return res.status(401).json({ ok: false, message: 'Invalid email or password' });
    }

    // no password set yet? tell the client to open the setup modal
    if (!user.password_hash) {
      return res
        .status(409)
        .json({ ok: false, code: 'PASSWORD_NOT_SET', message: 'Password not set' });
    }

    const ok = await bcrypt.compare(password, user.password_hash || '');
    if (!ok) {
      return res.status(401).json({ ok: false, message: 'Invalid email or password' });
    }

    // session cookie
    const token = signSession({ sub: user.id, role: user.role, email: user.email });
    setSessionCookie(res, token);

    return res.status(200).json({ ok: true, role: user.role });
  } catch (err) {
    console.error('[auth/login]', err);
    return res.status(500).json({ ok: false, message: 'Login failed' });
  }
}
