const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;

// ===== MongoDB (optional — only if MONGO_URI config var is set) =====
let mongoDb = null;
let mongoClient = null;
async function connectDb() {
    if (mongoDb) return mongoDb;
    if (!process.env.MONGO_URI) return null;
    if (!mongoClient) {
        const { MongoClient } = require('mongodb');
        mongoClient = new MongoClient(process.env.MONGO_URI);
        await mongoClient.connect();
        console.log('✅ MongoDB connected');
    }
    mongoDb = mongoClient.db('zeta_db');
    return mongoDb;
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.htm': 'text/html; charset=utf-8',
  '.css': 'text/css',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.mp4': 'video/mp4',
  '.apk': 'application/vnd.android.package-archive',
  '.zip': 'application/zip',
  '.pdf': 'application/pdf',
  '.txt': 'text/plain; charset=utf-8'
};

function sendJson(res, code, obj) {
    res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(obj));
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        let data = '';
        req.on('data', c => { data += c; if (data.length > 1e6) req.destroy(); });
        req.on('end', () => resolve(data));
        req.on('error', reject);
    });
}

const server = http.createServer(async (req, res) => {
  let urlPath = decodeURIComponent(req.url.split('?')[0]);
  if (urlPath === '/') urlPath = '/index.html';

  // ===== API: save photo link (from blur studio) =====
  if (urlPath === '/api/save-photo' && req.method === 'POST') {
    try {
        const body = JSON.parse(await readBody(req) || '{}');
        const { url, page, savedAt } = body;
        if (!url || !/^https?:\/\//i.test(url)) return sendJson(res, 400, { ok: false, error: 'Valid image URL එකක් නෑ' });
        const db = await connectDb();
        if (!db) return sendJson(res, 500, { ok: false, error: 'MongoDB configure කරලා නෑ (MONGO_URI)' });
        const result = await db.collection('photos').insertOne({
            url: String(url).slice(0, 2000),
            page: String(page || 'unknown').slice(0, 100),
            savedAt: savedAt ? new Date(savedAt) : new Date()
        });
        return sendJson(res, 200, { ok: true, id: result.insertedId });
    } catch (e) {
        console.error('save-photo error:', e);
        return sendJson(res, 500, { ok: false, error: 'Database error' });
    }
  }

  // ===== API: get saved photo links (for admin panel) =====
  if (urlPath === '/api/photos' && req.method === 'GET') {
    try {
        const db = await connectDb();
        if (!db) return sendJson(res, 500, { ok: false, error: 'MongoDB configure කරලා නෑ (MONGO_URI)' });
        const photos = await db.collection('photos').find({}).sort({ savedAt: -1 }).limit(200).toArray();
        return sendJson(res, 200, { ok: true, photos });
    } catch (e) {
        console.error('photos error:', e);
        return sendJson(res, 500, { ok: false, error: 'Database error' });
    }
  }

  // ===== static files =====
  const filePath = path.join(ROOT, urlPath);

  // block path traversal
  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end('<h1 style="font-family:sans-serif">404 - Page not found</h1>');
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    fs.createReadStream(filePath).pipe(res);
  });
});

server.listen(PORT, () => console.log('ZETA TOOLS running on port ' + PORT));