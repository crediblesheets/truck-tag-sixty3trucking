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
    const body = req.body || {};
    const email = (body.email || '').toLowerCase().trim();
    const password = body.password || '';

    if (!email || !password) {
      return res.status(400).json({ ok: false, message: 'Email and password required' });
    }

    // Look up user
    const { data: user, error } = await supabase
      .from('Users')
      .select('id,email,role,is_active,password_hash')
      .eq('email', email)
      .maybeSingle();

    if (error) {
      console.error('[login] supabase error', error);
      return res.status(500).json({ ok: false, message: 'Login failed' });
    }

    // Not found or inactive
    if (!user || !user.is_active) {
      return res.status(401).json({ ok: false, message: 'Invalid email or password' });
    }

    // If account has no password yet, tell the client to open the modal
    if (!user.password_hash) {
      return res.status(409).json({ ok: false, code: 'PASSWORD_NOT_SET', message: 'Password not set' });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ ok: false, message: 'Invalid email or password' });
    }

    // Issue session + cookie
    const token = signSession({ sub: user.id, role: user.role, email: user.email });
    setSessionCookie(res, token);

    return res.status(200).json({ ok: true, role: user.role });
  } catch (err) {
    console.error('[login] exception', err);
    return res.status(500).json({ ok: false, message: 'Login failed' });
  }
}
