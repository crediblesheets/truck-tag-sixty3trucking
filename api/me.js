import { readCookie, verifySessionToken } from './_lib/jwt.js';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

export default async function handler(req, res) {
  const raw = readCookie(req);
  if (!raw) {
    res.status(401).json({ ok: false, message: 'No session' });
    return;
  }

  const session = verifySessionToken(raw);
  if (!session) {
    res.status(401).json({ ok: false, message: 'Invalid session' });
    return;
  }

  // Optional: pull latest role/active status
  const { data: user } = await supabase
    .from('Users')
    .select('id,email,role,is_active')
    .eq('id', session.sub)
    .maybeSingle();

  if (!user || !user.is_active) {
    res.status(401).json({ ok: false, message: 'Inactive' });
    return;
  }

  res.status(200).json({
    ok: true,
    profile: { id: user.id, email: user.email, role: user.role }
  });
}
