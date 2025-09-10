// api/_lib/jwt.js
import jwt from 'jsonwebtoken';

export function signSession(payload) {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error('JWT_SECRET is not set');
  return jwt.sign(payload, secret, { expiresIn: '30d' });
}

export function setSessionCookie(res, token) {
  const domain = process.env.COOKIE_DOMAIN || undefined; // usually empty on Vercel
  const parts = [
    `token=${token}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    'Max-Age=2592000' // 30d
  ];
  if (domain) parts.push(`Domain=${domain}`);
  res.setHeader('Set-Cookie', parts.join('; '));
}

export function readSessionFromReq(req) {
  const raw = req.headers.cookie || '';
  const token = raw
    .split(';')
    .map(s => s.trim())
    .find(s => s.startsWith('token='))?.slice(6);
  if (!token) return null;
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return null;
  }
}
