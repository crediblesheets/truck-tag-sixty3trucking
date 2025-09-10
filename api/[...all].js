// Force Node (not Edge) runtime
export const config = { runtime: 'nodejs' };

import app from '../server.js';

// Vercel strips '/api' before invoking; add it back so Express routes match
export default function handler(req, res) {
  if (!req.url.startsWith('/api')) {
    req.url = '/api' + (req.url === '/' ? '' : req.url);
  }
  return app(req, res);
}
