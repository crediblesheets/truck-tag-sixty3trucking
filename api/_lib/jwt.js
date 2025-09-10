// Consistent session helpers for all routes
import jwt from 'jsonwebtoken';

export const COOKIE_NAME = 'tt_session';
const WEEK = 60 * 60 * 24 * 7;

export function signSession(payload) {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error('JWT_SECRET is not set');
  return jwt.sign(payload, secret, { expiresIn: '7d' });
}

export function verifySessionToken(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return null;
  }
}

export function readCookie(req) {
  const raw = req.headers.cookie || '';
  const map = Object.fromEntries(
    raw.split(';').map((c) => c.trim().split('=').map(decodeURIComponent)).filter((a) => a[0])
  );
  return map[COOKIE_NAME] || null;
}

export function setSessionCookie(res, token) {
  const cookie = [
    `${encodeURIComponent(COOKIE_NAME)}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    `Max-Age=${WEEK}`
  ].join('; ');
  res.setHeader('Set-Cookie', cookie);
}

export function clearSessionCookie(res) {
  const cookie = [
    `${encodeURIComponent(COOKIE_NAME)}=`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    'Max-Age=0'
  ].join('; ');
  res.setHeader('Set-Cookie', cookie);
}
