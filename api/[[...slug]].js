// api/[[...slug]].js
export const config = { runtime: 'nodejs20.x' }; // node runtime on Vercel

import app from '../server.js';

export default function handler(req, res) {
  // When called as /api/*, Vercel passes req.url like "/auth/login"
  // We need Express to see "/api/auth/login"
  const url = req.url || '/';
  if (!url.startsWith('/api')) {
    req.url = '/api' + (url.startsWith('/') ? url : '/' + url);
  }
  return app(req, res);
}
