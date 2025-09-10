// api/_lib/jwt.js
import jwt from 'jsonwebtoken';

/** Sign a 30-day session JWT */
export function signSession(payload) {
  const key = process.env.JWT_SECRET;
  if (!key) throw new Error('JWT_SECRET not set');
  return jwt.sign(payload, key, { expiresIn: '30d' });
}

/** Verify session JWT. Returns payload or null. */
export function verifySession(token) {
  const key = process.env.JWT_SECRET;
  if (!key) return null;
  try {
    return jwt.verify(token, key);
  } catch {
    return null;
  }
}

/** Set HttpOnly cookie with the session token */
export function setSessionCookie(res, token) {
  const domain = process.env.COOKIE_DOMAIN || undefined; // usually empty on Vercel
  const parts = [
    `token=${token}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    `Max-Age=${60 * 60 * 24 * 30}` // 30 days
  ];
  if (domain) parts.push(`Domain=${domain}`);
  res.setHeader('Set-Cookie', parts.join('; '));
}

/** Clear the session cookie */
export function clearSessionCookie(res) {
  const domain = process.env.COOKIE_DOMAIN || undefined;
  const parts = [
    'token=',
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    'Max-Age=0'
  ];
  if (domain) parts.push(`Domain=${domain}`);
  res.setHeader('Set-Cookie', parts.join('; '));
}
