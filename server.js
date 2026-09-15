/* ZETA CHAT — Backend v7 (WhatsApp-style Status) */
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '25mb' }));
app.use(express.static(__dirname));

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/zetachat';
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err.message));

/* ============ SCHEMAS ============ */
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  username: { type: String, required: true, unique: true, lowercase: true, index: true },
  email: { type: String, required: true, unique: true, lowercase: true, index: true },
  password: { type: String, required: true },
  avatar: { type: String, default: null },
  color: { type: String, default: '#00A3FF' },
  about: { type: String, default: 'Hey there! I am using ZETA CHAT.' },
  phone: { type: String, default: '' },
  lastSeen: { type: Date, default: Date.now },
  theme: { type: String, default: 'dark' },
  sessions: [{ sessionId: String, device: String, browser: String, time: Date, current: Boolean }],
  loginHistory: [{ time: Date, device: String, browser: String, success: Boolean, reason: String }],
  createdAt: { type: Date, default: Date.now }
});

const MessageSchema = new mongoose.Schema({
  threadKey: { type: String, required: true, index: true },
  from: { type: String, required: true },
  to: { type: String, required: true },
  type: { type: String, default: 'text' },
  text: { type: String, default: '' },
  media: { type: String, default: null },
  fileSize: { type: String, default: '' },
  status: { type: String, default: 'sent' },
  starred: { type: Boolean, default: false },
  deleted: { type: Boolean, default: false },
  replyTo: { type: Object, default: null },
  time: { type: Date, default: Date.now, index: true }
});

const MetaSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  contactId: { type: String, required: true },
  threadKey: { type: String, required: true, index: true },
  pinned: { type: Boolean, default: false },
  muted: { type: Boolean, default: false },
  favorite: { type: Boolean, default: false },
  archived: { type: Boolean, default: false },
  blocked: { type: Boolean, default: false },
  unread: { type: Number, default: 0 }
});

const ContactRequestSchema = new mongoose.Schema({
  from: { type: String, required: true, index: true },
  to: { type: String, required: true, index: true },
  message: { type: String, default: '' },
  status: { type: String, default: 'pending' },
  time: { type: Date, default: Date.now }
});

const GroupSchema = new mongoose.Schema({
  name: { type: String, required: true },
  avatar: { type: String, default: null },
  color: { type: String, default: '#7C3AED' },
  members: [{ type: String }],
  admin: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const CallSchema = new mongoose.Schema({
  userId: String, contactId: String, name: String,
  kind: String, media: String, time: { type: Date, default: Date.now }
});

/* ============ STATUS SCHEMA (WhatsApp-style) ============ */
const StatusViewerSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  viewedAt: { type: Date, default: Date.now }
}, { _id: false });

const StatusSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  type: { type: String, enum: ['text', 'image', 'video'], required: true },
  content: { type: String, default: '' },     // text content
  media_url: { type: String, default: null }, // data URL for image/video
  color: { type: String, default: '#00A3FF' },// background color for text status
  caption: { type: String, default: '' },     // optional caption for media
  viewers: { type: [StatusViewerSchema], default: [] },
  created_at: { type: Date, default: Date.now, index: true },
  expires_at: { type: Date, required: true, index: true }
});
StatusSchema.index({ expires_at: 1 }, { expireAfterSeconds: 0 });

const User = mongoose.model('User', UserSchema);
const Message = mongoose.model('Message', MessageSchema);
const Meta = mongoose.model('Meta', MetaSchema);
const ContactRequest = mongoose.model('ContactRequest', ContactRequestSchema);
const Group = mongoose.model('Group', GroupSchema);
const Call = mongoose.model('Call', CallSchema);
const Status = mongoose.model('Status', StatusSchema);

const JWT_SECRET = process.env.JWT_SECRET || 'zeta_default_secret';

/* ============ HELPERS ============ */
function sanitize(u){
  const o = u.toObject ? u.toObject() : { ...u };
  delete o.password;
  return o;
}
function auth(req, res, next){
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch (e) { res.status(401).json({ error: 'Invalid token' }); }
}

/* ============ STATUS CLEANUP ============ */
async function cleanupExpiredStatuses(){
  try {
    const r = await Status.deleteMany({ expires_at: { $lt: new Date() } });
    if (r.deletedCount > 0) console.log('🧹 Cleaned', r.deletedCount, 'expired statuses');
  } catch(e){ console.error('Cleanup error:', e.message); }
}
// Run on start + every 5 min
cleanupExpiredStatuses();
setInterval(cleanupExpiredStatuses, 5 * 60 * 1000);

/* ============ HEALTH ============ */
app.get('/api/health', (req, res) => {
  res.json({ ok: true, db: mongoose.connection.readyState === 1 });
});

/* ============ AUTH ============ */
app.post('/api/register', async (req, res) => {
  try {
    const { name, username, email, password, avatar, color, phone } = req.body;
    if (!name || !username || !email || !password)
      return res.status(400).json({ error: 'සියලු fields පුරවන්න' });
    if (password.length < 6)
      return res.status(400).json({ error: 'පාස්වර්ඩ් අකුරු 6ට වැඩි' });
    const exists = await User.findOne({
      $or: [{ username: username.toLowerCase() }, { email: email.toLowerCase() }]
    });
    if (exists) return res.status(400).json({ error: 'Username හෝ email දැනටමත් තියෙනවා' });
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({
      name: name.trim(),
      username: username.toLowerCase().trim(),
      email: email.toLowerCase().trim(),
      password: hashed,
      avatar: avatar || null,
      color: color || '#00A3FF',
      phone: phone || '',
      lastSeen: new Date()
    });
    res.json({ success: true, userId: user._id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { identity, password, device, browser, remember } = req.body;
    if (!identity || !password) return res.status(400).json({ error: 'Missing fields' });
    const user = await User.findOne({
      $or: [{ username: identity.toLowerCase() }, { email: identity.toLowerCase() }]
    });
    if (!user) return res.status(400).json({ error: 'ගිණුමක් හමු වුනේ නෑ' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      user.loginHistory.unshift({ time: new Date(), device, browser, success: false, reason: 'වැරදි පාස්වර්ඩ්' });
      user.loginHistory = user.loginHistory.slice(0, 30);
      await user.save();
      return res.status(400).json({ error: 'පාස්වර්ඩ් එක වැරදියි' });
    }
    const sessionId = 's_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
    user.sessions.forEach(s => s.current = false);
    user.sessions.push({ sessionId, device, browser, time: new Date(), current: true });
    if (user.sessions.length > 8) {
      user.sessions.sort((a, b) => new Date(b.time) - new Date(a.time));
      user.sessions = user.sessions.slice(0, 8);
    }
    user.loginHistory.unshift({ time: new Date(), device, browser, success: true });
    user.loginHistory = user.loginHistory.slice(0, 30);
    user.lastSeen = new Date();
    await user.save();
    const token = jwt.sign({ userId: user._id.toString(), sessionId }, JWT_SECRET,
      { expiresIn: remember ? '30d' : '1d' });
    res.json({ success: true, token, sessionId, user: sanitize(user) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const session = user.sessions.find(s => s.sessionId === req.user.sessionId);
    if (!session) return res.status(401).json({ error: 'Session expired' });
    user.lastSeen = new Date();
    await user.save();
    res.json({ user: sanitize(user), sessionId: req.user.sessionId });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/heartbeat', auth, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.userId, { lastSeen: new Date() });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/offline', auth, async (req, res) => {
  try {
    const past = new Date(Date.now() - 120000);
    await User.findByIdAndUpdate(req.user.userId, { lastSeen: past });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/logout', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (user) {
      user.sessions = user.sessions.filter(s => s.sessionId !== req.user.sessionId);
      user.lastSeen = new Date(Date.now() - 120000);
      await user.save();
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/logout-all', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (user) {
      user.sessions = [];
      user.lastSeen = new Date(Date.now() - 120000);
      await user.save();
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/profile', auth, async (req, res) => {
  try {
    const { name, about, avatar, color, phone, theme } = req.body;
    const update = {};
    if (name !== undefined) update.name = name;
    if (about !== undefined) update.about = about;
    if (avatar !== undefined) update.avatar = avatar;
    if (color !== undefined) update.color = color;
    if (phone !== undefined) update.phone = phone;
    if (theme !== undefined) update.theme = theme;
    const user = await User.findByIdAndUpdate(req.user.userId, update, { new: true });
    res.json({ success: true, user: sanitize(user) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/change-password', auth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const ok = await bcrypt.compare(oldPassword, user.password);
    if (!ok) return res.status(400).json({ error: 'වත්මන් පාස්වර්ඩ් එක වැරදියි' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'අකුරු 6ට වැඩි' });
    user.password = await bcrypt.hash(newPassword, 10);
    user.sessions = user.sessions.filter(s => s.sessionId === req.user.sessionId);
    await user.save();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/forgot-password', async (req, res) => {
  try {
    const { identity, newPassword } = req.body;
    const user = await User.findOne({
      $or: [{ username: identity.toLowerCase() }, { email: identity.toLowerCase() }]
    });
    if (!user) return res.status(400).json({ error: 'ගිණුමක් හමු වුනේ නෑ' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'අකුරු 6ට වැඩි' });
    user.password = await bcrypt.hash(newPassword, 10);
    user.sessions = [];
    await user.save();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============ USERS ============ */
app.get('/api/users', auth, async (req, res) => {
  try {
    const users = await User.find({ _id: { $ne: req.user.userId } }).select('-password');
    res.json({ users });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============ CONTACT REQUESTS ============ */
app.post('/api/contact-requests', auth, async (req, res) => {
  try {
    const { to, message } = req.body;
    if (!to) return res.status(400).json({ error: 'Username/phone ඕන' });
    const target = await User.findOne({
      $or: [
        { username: to.toLowerCase() },
        { phone: to },
        { _id: mongoose.Types.ObjectId.isValid(to) ? to : null }
      ]
    });
    if (!target) return res.status(404).json({ error: 'ගිණුමක් හමු වුනේ නෑ' });
    if (target._id.toString() === req.user.userId)
      return res.status(400).json({ error: 'ඔබටම request යවන්න බෑ' });
    const existing = await ContactRequest.findOne({
      from: req.user.userId, to: target._id.toString(), status: 'pending'
    });
    if (existing) return res.status(400).json({ error: 'Request දැනටමත් යවලා තියෙනවා' });
    const reqDoc = await ContactRequest.create({
      from: req.user.userId,
      to: target._id.toString(),
      message: message || '',
      status: 'pending',
      time: new Date()
    });
    res.json({ success: true, request: reqDoc });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/contact-requests', auth, async (req, res) => {
  try {
    const incoming = await ContactRequest.find({ to: req.user.userId, status: 'pending' }).sort({ time: -1 });
    const outgoing = await ContactRequest.find({ from: req.user.userId, status: 'pending' }).sort({ time: -1 });
    const fromIds = incoming.map(r => r.from);
    const toIds = outgoing.map(r => r.to);
    const allIds = [...new Set([...fromIds, ...toIds])];
    const users = await User.find({ _id: { $in: allIds } }).select('-password');
    const uMap = {};
    users.forEach(u => { uMap[u._id.toString()] = sanitize(u); });
    res.json({
      incoming: incoming.map(r => ({
        _id: r._id, from: uMap[r.from] || null, to: uMap[r.to] || null,
        message: r.message, status: r.status, time: r.time
      })),
      outgoing: outgoing.map(r => ({
        _id: r._id, from: uMap[r.from] || null, to: uMap[r.to] || null,
        message: r.message, status: r.status, time: r.time
      }))
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/contact-requests/:id/accept', auth, async (req, res) => {
  try {
    const request = await ContactRequest.findById(req.params.id);
    if (!request) return res.status(404).json({ error: 'Not found' });
    if (request.to !== req.user.userId) return res.status(403).json({ error: 'Not allowed' });
    request.status = 'accepted';
    await request.save();
    const key = [request.from, request.to].sort().join('|');
    await Meta.findOneAndUpdate(
      { userId: req.user.userId, threadKey: key },
      { userId: req.user.userId, contactId: request.from, threadKey: key },
      { upsert: true }
    );
    await Meta.findOneAndUpdate(
      { userId: request.from, threadKey: key },
      { userId: request.from, contactId: request.to, threadKey: key },
      { upsert: true }
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/contact-requests/:id/decline', auth, async (req, res) => {
  try {
    const request = await ContactRequest.findById(req.params.id);
    if (!request) return res.status(404).json({ error: 'Not found' });
    if (request.to !== req.user.userId) return res.status(403).json({ error: 'Not allowed' });
    request.status = 'declined';
    await request.save();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============ MESSAGES ============ */
app.get('/api/messages/:contactId', auth, async (req, res) => {
  try {
    const key = [req.user.userId, req.params.contactId].sort().join('|');
    const messages = await Message.find({ threadKey: key }).sort({ time: 1 });
    res.json({ messages });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/messages', auth, async (req, res) => {
  try {
    const { to, type, text, media, fileSize, replyTo } = req.body;
    const key = [req.user.userId, to].sort().join('|');
    const message = await Message.create({
      threadKey: key, from: req.user.userId, to,
      type: type || 'text', text: text || '',
      media: media || null, fileSize: fileSize || '',
      replyTo: replyTo || null, status: 'sent', time: new Date()
    });
    res.json({ success: true, message });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/messages/:id', auth, async (req, res) => {
  try {
    const message = await Message.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!message) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true, message });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/messages/thread/:contactId', auth, async (req, res) => {
  try {
    const key = [req.user.userId, req.params.contactId].sort().join('|');
    await Message.deleteMany({ threadKey: key });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============ META ============ */
app.get('/api/meta', auth, async (req, res) => {
  try {
    const metas = await Meta.find({ userId: req.user.userId });
    const out = {};
    metas.forEach(m => {
      out[m.threadKey] = {
        pinned: m.pinned, muted: m.muted, favorite: m.favorite,
        archived: m.archived, blocked: m.blocked, unread: m.unread || 0
      };
    });
    res.json({ meta: out });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/meta/:contactId', auth, async (req, res) => {
  try {
    const key = [req.user.userId, req.params.contactId].sort().join('|');
    const meta = await Meta.findOneAndUpdate(
      { userId: req.user.userId, threadKey: key },
      {
        userId: req.user.userId,
        contactId: req.params.contactId,
        threadKey: key,
        pinned: req.body.pinned || false,
        muted: req.body.muted || false,
        favorite: req.body.favorite || false,
        archived: req.body.archived || false,
        blocked: req.body.blocked || false,
        unread: req.body.unread || 0
      },
      { upsert: true, new: true }
    );
    res.json({ success: true, meta });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/contacts/:contactId', auth, async (req, res) => {
  try {
    const cid = req.params.contactId;
    const key = [req.user.userId, cid].sort().join('|');
    await Meta.deleteMany({ userId: req.user.userId, threadKey: key });
    await Message.deleteMany({ threadKey: key });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============ GROUPS ============ */
app.get('/api/groups', auth, async (req, res) => {
  try {
    const groups = await Group.find({ members: req.user.userId });
    res.json({ groups });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/groups', auth, async (req, res) => {
  try {
    const { name, members, color } = req.body;
    if (!name) return res.status(400).json({ error: 'Group name ඕන' });
    const memberList = [req.user.userId, ...(members || [])];
    const group = await Group.create({
      name, members: memberList, admin: req.user.userId,
      color: color || '#7C3AED'
    });
    res.json({ success: true, group });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============ CALLS ============ */
app.get('/api/calls', auth, async (req, res) => {
  try {
    const calls = await Call.find({ userId: req.user.userId }).sort({ time: -1 }).limit(120);
    res.json({ calls });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/calls', auth, async (req, res) => {
  try {
    const call = await Call.create({ userId: req.user.userId, ...req.body });
    res.json({ success: true, call });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============================================================
   STATUS ROUTES (WhatsApp-style)
   ============================================================ */

/* --- Create Status --- */
app.post('/api/status', auth, async (req, res) => {
  try {
    const { type, content, media_url, color, caption } = req.body;
    if (!type || !['text', 'image', 'video'].includes(type))
      return res.status(400).json({ error: 'Invalid status type' });

    if (type === 'text'){
      if (!content || !content.trim())
        return res.status(400).json({ error: 'Text content required' });
      if (content.length > 300)
        return res.status(400).json({ error: 'Text 300 chars ට වඩා වැඩියි' });
    } else {
      if (!media_url) return res.status(400).json({ error: 'Media required' });

      // Validate data URL prefix
      if (type === 'image' && !media_url.startsWith('data:image/'))
        return res.status(400).json({ error: 'Invalid image format' });
      if (type === 'video' && !media_url.startsWith('data:video/'))
        return res.status(400).json({ error: 'Invalid video format' });

      // Size limits (base64 is ~1.37x original size)
      const sizeInBytes = Math.ceil(media_url.length * 0.75);
      if (type === 'image' && sizeInBytes > 5 * 1024 * 1024)
        return res.status(400).json({ error: 'Image 5MB ට වඩා ලොකුයි' });
      if (type === 'video' && sizeInBytes > 15 * 1024 * 1024)
        return res.status(400).json({ error: 'Video 15MB ට වඩා ලොකුයි' });
    }

    const now = new Date();
    const expires = new Date(now.getTime() + 24 * 60 * 60 * 1000);

    const status = await Status.create({
      userId: req.user.userId,
      type,
      content: content || '',
      media_url: media_url || null,
      color: color || '#00A3FF',
      caption: caption || '',
      viewers: [],
      created_at: now,
      expires_at: expires
    });

    res.json({ success: true, status });
  } catch (e) {
    console.error('Status create:', e);
    res.status(500).json({ error: e.message });
  }
});

/* --- Get all active statuses (grouped by user) --- */
app.get('/api/status', auth, async (req, res) => {
  try {
    const now = new Date();

    // Ensure expired are gone (belt + suspenders)
    await Status.deleteMany({ expires_at: { $lt: now } });

    const statuses = await Status.find({ expires_at: { $gt: now } })
      .sort({ created_at: 1 });

    // Group by userId
    const map = {};
    statuses.forEach(s => {
      const uid = s.userId;
      if (!map[uid]) map[uid] = [];
      map[uid].push({
        _id: s._id,
        userId: s.userId,
        type: s.type,
        content: s.content,
        media_url: s.media_url,
        color: s.color,
        caption: s.caption,
        created_at: s.created_at,
        expires_at: s.expires_at,
        viewerCount: (s.viewers || []).length,
        seenByMe: (s.viewers || []).some(v => v.userId === req.user.userId)
      });
    });

    // Fetch user info
    const uids = Object.keys(map);
    const users = await User.find({ _id: { $in: uids } }).select('-password');
    const userMap = {};
    users.forEach(u => {
      userMap[u._id.toString()] = {
        _id: u._id,
        name: u.name,
        username: u.username,
        avatar: u.avatar,
        color: u.color
      };
    });

    // Build output: my status separately
    let mine = null;
    const others = [];
    uids.forEach(uid => {
      const u = userMap[uid];
      if (!u) return;
      const entry = { user: u, statuses: map[uid] };
      if (uid === req.user.userId) mine = entry;
      else others.push(entry);
    });

    // Sort others: unseen first, then by latest status time
    others.sort((a, b) => {
      const aSeen = a.statuses.every(s => s.seenByMe);
      const bSeen = b.statuses.every(s => s.seenByMe);
      if (aSeen !== bSeen) return aSeen ? 1 : -1;
      const aTime = Math.max(...a.statuses.map(s => new Date(s.created_at).getTime()));
      const bTime = Math.max(...b.statuses.map(s => new Date(s.created_at).getTime()));
      return bTime - aTime;
    });

    res.json({ mine, others });
  } catch (e) {
    console.error('Status list:', e);
    res.status(500).json({ error: e.message });
  }
});

/* --- Mark status as viewed --- */
app.post('/api/status/:id/view', auth, async (req, res) => {
  try {
    const status = await Status.findById(req.params.id);
    if (!status) return res.status(404).json({ error: 'Status not found' });
    if (new Date(status.expires_at) < new Date())
      return res.status(410).json({ error: 'Status expired' });
    if (status.userId === req.user.userId)
      return res.json({ success: true, skipped: true }); // owner doesn't view own

    const already = (status.viewers || []).some(v => v.userId === req.user.userId);
    if (!already){
      status.viewers.push({ userId: req.user.userId, viewedAt: new Date() });
      await status.save();
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* --- Get viewers of my status --- */
app.get('/api/status/:id/viewers', auth, async (req, res) => {
  try {
    const status = await Status.findById(req.params.id);
    if (!status) return res.status(404).json({ error: 'Status not found' });
    if (status.userId !== req.user.userId)
      return res.status(403).json({ error: 'Not your status' });

    const viewerIds = (status.viewers || []).map(v => v.userId);
    const users = await User.find({ _id: { $in: viewerIds } }).select('-password');
    const map = {};
    users.forEach(u => { map[u._id.toString()] = sanitize(u); });

    const viewers = (status.viewers || []).map(v => ({
      user: map[v.userId] || { _id: v.userId, name: 'User', username: '' },
      viewedAt: v.viewedAt
    })).sort((a, b) => new Date(b.viewedAt) - new Date(a.viewedAt));

    res.json({
      viewers,
      viewCount: viewers.length,
      type: status.type,
      content: status.content,
      media_url: status.media_url
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* --- Delete status (owner only) --- */
app.delete('/api/status/:id', auth, async (req, res) => {
  try {
    const status = await Status.findById(req.params.id);
    if (!status) return res.status(404).json({ error: 'Not found' });
    if (status.userId !== req.user.userId)
      return res.status(403).json({ error: 'Not your status' });
    await Status.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* --- Delete ALL my statuses --- */
app.delete('/api/status/mine/all', auth, async (req, res) => {
  try {
    const r = await Status.deleteMany({ userId: req.user.userId });
    res.json({ success: true, deleted: r.deletedCount });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============ SPA ============ */
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  const p = path.join(__dirname, 'index.html');
  if (fs.existsSync(p)) res.sendFile(p);
  else res.status(404).send('index.html not found');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('');
  console.log('  🚀 ZETA CHAT v7 running');
  console.log('  📱 Open: http://localhost:' + PORT);
  console.log('  🎬 Status: enabled');
  console.log('');
});