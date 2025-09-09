// public/api/[...all].js
import app from '../../server.js';   // <-- note the path goes two levels up
export default app;
export const config = { api: { bodyParser: false } };
