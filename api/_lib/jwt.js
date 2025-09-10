// api/_lib/jwt.js
import jwt from 'jsonwebtoken';

export const COOKIE_NAME = 'tt_auth';
export const TOKEN_MAX_AGE = 60 * 60 * 24 * 7; // 7 days

function cookieString(value, maxAge = TOKEN_MAX_AGE) {
  return [
    `${COOKIE_NAME}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    `Max-Age=${maxAge}`,
  ].join('; ');
}

export function signToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: `${TOKEN_MAX_AGE}s` }
  );
}

export function setAuthCookie(res, token) {
  res.setHeader('Set-Cookie', cookieString(token));
}

export function clearAuthCookie(res) {
  res.setHeader('Set-Cookie', cookieString('', 0));
}

export function readAuth(req) {
  const cookies = req.headers.cookie || '';
  const m = cookies.match(new RegExp(`${COOKIE_NAME}=([^;]+)`));
  if (!m) return null;
  try {
    return jwt.verify(decodeURIComponent(m[1]), process.env.JWT_SECRET);
  } catch {
    return null;
  }
}
