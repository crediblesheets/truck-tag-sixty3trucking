// super-simple function to prove API works
export default function handler(req, res) {
  res.status(200).json({ ok: true, url: req.url, now: Date.now() });
}
