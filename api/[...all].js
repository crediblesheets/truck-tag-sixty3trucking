export const config = { runtime: 'nodejs18.x' };

import app from '../server.js';

// Vercel calls this without the '/api' prefix; put it back for Express.
export default function handler(req, res) {
  if (!req.url.startsWith('/api')) {
    req.url = '/api' + (req.url === '/' ? '' : req.url);
  }
  return app(req, res);
}
