// api/me.js
import { createClient } from '@supabase/supabase-js';
import { readSessionFromReq } from './_lib/jwt.js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ ok: false, message: 'Method not allowed' });
  }

  try {
    const session = readSessionFromReq(req);
    if (!session) {
      return res.status(401).json({ ok: false, message: 'No session' });
    }

    const { data: user, error } = await supabase
      .from('Users')
      .select('id,email,role,is_active')
      .eq('id', session.sub)
      .maybeSingle();

    if (error || !user || !user.is_active) {
      return res.status(401).json({ ok: false, message: 'Invalid session' });
    }

    return res.status(200).json({ ok: true, profile: user });
  } catch (err) {
    console.error(err);
    return res.status(401).json({ ok: false, message: 'Invalid session' });
  }
}
