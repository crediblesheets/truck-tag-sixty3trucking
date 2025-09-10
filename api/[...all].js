// api/[...all].js
import app from '../server.js';

// Vercel strips the '/api' prefix before calling this function.
// Put it back so Express routes like '/api/auth/login' match.
export default function handler(req, res) {
  if (!req.url.startsWith('/api')) {
    req.url = '/api' + (req.url === '/' ? '' : req.url);
  }
  return app(req, res);
}
