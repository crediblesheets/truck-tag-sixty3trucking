export const config = { runtime: 'nodejs' };

import app from '../server.js';

export default function handler(req, res) {
  // Do NOT change req.url here; just pass through to Express.
  return app(req, res);
}
