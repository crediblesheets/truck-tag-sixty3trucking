// ✅ use a supported value (or delete this line entirely)
export const config = { runtime: 'nodejs' };

import app from '../server.js';

export default function handler(req, res) {
  if (!req.url.startsWith('/api')) {
    req.url = '/api' + (req.url === '/' ? '' : req.url);
  }
  return app(req, res);
}
