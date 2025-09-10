// api/_lib/cookies.js
export function setAuthCookie(res, token) {
  const domain = process.env.COOKIE_DOMAIN || undefined; // usually blank on Vercel
  const parts = [
    `token=${token}`,
    'Path=/',          // <-- required so cookie is sent to the whole site
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    'Max-Age=2592000'  // 30 days
  ];
  if (domain) parts.push(`Domain=${domain}`);
  res.setHeader('Set-Cookie', parts.join('; '));
}
