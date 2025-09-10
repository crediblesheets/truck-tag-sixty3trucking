// api/me.js
export const config = { runtime: 'nodejs' };

import supabase from './_lib/supa.js';
import { readAuth } from './_lib/jwt.js';

export default async function handler(req, res) {
  const claims = readAuth(req);
  if (!claims) return res.status(401).json({ ok: false, message: 'Not authenticated' });

  const { data: user, error } = await supabase
    .from('users')
    .select('id,email,role,active,name')
    .eq('id', claims.sub)
    .maybeSingle();

  if (error || !user || user.active === false) {
    return res.status(401).json({ ok: false, message: 'Invalid token' });
  }

  const profile = { id: user.id, email: user.email, role: user.role, name: user.name };
  res.status(200).json({ ok: true, profile });
}
