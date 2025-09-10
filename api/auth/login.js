import bcrypt from 'bcryptjs';
import { createClient } from '@supabase/supabase-js';
import { signSession, setSessionCookie } from '../_lib/jwt.js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ ok: false, message: 'Method not allowed' });
    return;
  }

  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      res.status(400).json({ ok: false, message: 'Email and password required' });
      return;
    }

    // Get user
    const { data: user, error } = await supabase
      .from('Users')
      .select('id,email,role,is_active,password_hash')
      .eq('email', email.toLowerCase())
      .maybeSingle();

    if (error || !user || !user.is_active) {
      res.status(401).json({ ok: false, message: 'Invalid email or password' });
      return;
    }

    const ok = await bcrypt.compare(password, user.password_hash || '');
    if (!ok) {
      res.status(401).json({ ok: false, message: 'Invalid email or password' });
      return;
    }

    // Issue session
    const token = signSession({
      sub: user.id,
      role: user.role,
      email: user.email
    });
    setSessionCookie(res, token);

    res.status(200).json({ ok: true, role: user.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, message: 'Login failed' });
  }
}
