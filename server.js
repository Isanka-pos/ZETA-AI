// server.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '15mb' }));

// ==================== MongoDB Connect ====================
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/zetachat')
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => { console.error('❌ MongoDB error:', err.message); process.exit(1); });

// ==================== Schemas ====================
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  username: { type: String, required: true, unique: true, lowercase: true, index: true },
  email: { type: String, required: true, unique: true, lowercase: true, index: true },
  password: { type: String, required: true },
  avatar: { type: String, default: null },
  color: { type: String, default: '#00A3FF' },
  about: { type: String, default: 'Hey there! I am using ZETA CHAT.' },
  sessions: [{
    sessionId: String,
    device: String,
    browser: String,
    time: { type: Date, default: Date.now },
    current: { type: Boolean, default: false }
  }],
  loginHistory: [{
    time: { type: Date, default: Date.now },
    device: String,
    browser: String,
    success: Boolean,
    reason: String
  }],
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
  unread: { type: Number, default: 0 }
});

const CallSchema = new mongoose.Schema({
  userId: String,
  contactId: String,
  name: String,
  kind: String,
  media: String,
  time: { type: Date, default: Date.now }
});

const StatusSchema = new mongoose.Schema({
  userId: String,
  text: String,
  time: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Message = mongoose.model('Message', MessageSchema);
const Meta = mongoose.model('Meta', MetaSchema);
const Call = mongoose.model('Call', CallSchema);
const Status = mongoose.model('Status', StatusSchema);

const JWT_SECRET = process.env.JWT_SECRET || 'zeta_secret';

// ==================== Auth Middleware ====================
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function sanitize(user) {
  const u = user.toObject ? user.toObject() : { ...user };
  delete u.password;
  return u;
}

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { name, username, email, password, avatar, color } = req.body;
    if (!name || !username || !email || !password)
      return res.status(400).json({ error: 'Missing required fields' });

    const exists = await User.findOne({
      $or: [{ username: username.toLowerCase() }, { email: email.toLowerCase() }]
    });
    if (exists) return res.status(400).json({ error: 'Username or email already exists' });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({
      name,
      username: username.toLowerCase(),
      email: email.toLowerCase(),
      password: hashed,
      avatar: avatar || null,
      color: color || '#00A3FF'
    });

    res.json({ success: true, userId: user._id });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { identity, password, device, browser, remember } = req.body;
    if (!identity || !password)
      return res.status(400).json({ error: 'Missing fields' });

    const user = await User.findOne({
      $or: [{ username: identity.toLowerCase() }, { email: identity.toLowerCase() }]
    });
    if (!user) return res.status(400).json({ error: 'User not found' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      user.loginHistory.unshift({
        time: new Date(), device, browser, success: false, reason: 'Wrong password'
      });
      user.loginHistory = user.loginHistory.slice(0, 30);
      await user.save();
      return res.status(400).json({ error: 'Wrong password' });
    }

    const sessionId = 's_' + Date.now() + Math.random().toString(36).slice(2, 8);
    user.sessions.forEach(s => s.current = false);
    user.sessions.push({ sessionId, device, browser, time: new Date(), current: true });
    if (user.sessions.length > 8) {
      user.sessions.sort((a, b) => new Date(b.time) - new Date(a.time));
      user.sessions = user.sessions.slice(0, 8);
    }
    user.loginHistory.unshift({ time: new Date(), device, browser, success: true });
    user.loginHistory = user.loginHistory.slice(0, 30);
    await user.save();

    const token = jwt.sign(
      { userId: user._id.toString(), sessionId },
      JWT_SECRET,
      { expiresIn: remember ? '30d' : '1d' }
    );

    res.json({
      success: true, token, sessionId,
      user: sanitize(user)
    });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Verify session / get me
app.get('/api/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const session = user.sessions.find(s => s.sessionId === req.user.sessionId);
    if (!session) return res.status(401).json({ error: 'Session expired' });

    res.json({ user: sanitize(user), sessionId: req.user.sessionId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Logout current device
app.post('/api/logout', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (user) {
      user.sessions = user.sessions.filter(s => s.sessionId !== req.user.sessionId);
      await user.save();
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Logout all devices
app.post('/api/logout-all', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (user) { user.sessions = []; await user.save(); }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Update profile
app.put('/api/profile', auth, async (req, res) => {
  try {
    const { name, about, avatar, color } = req.body;
    const update = {};
    if (name !== undefined) update.name = name;
    if (about !== undefined) update.about = about;
    if (avatar !== undefined) update.avatar = avatar;
    if (color !== undefined) update.color = color;

    const user = await User.findByIdAndUpdate(req.user.userId, update, { new: true });
    res.json({ success: true, user: sanitize(user) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Change password
app.post('/api/change-password', auth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const ok = await bcrypt.compare(oldPassword, user.password);
    if (!ok) return res.status(400).json({ error: 'Current password is wrong' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'Password too short' });

    user.password = await bcrypt.hash(newPassword, 10);
    user.sessions = user.sessions.filter(s => s.sessionId === req.user.sessionId);
    await user.save();

    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Forgot password (demo — production එකේ OTP/email verify ඕන)
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { identity, newPassword } = req.body;
    const user = await User.findOne({
      $or: [{ username: identity.toLowerCase() }, { email: identity.toLowerCase() }]
    });
    if (!user) return res.status(400).json({ error: 'User not found' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'Password too short' });

    user.password = await bcrypt.hash(newPassword, 10);
    user.sessions = [];
    await user.save();

    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== USER ROUTES ====================
app.get('/api/users', auth, async (req, res) => {
  try {
    const users = await User.find({ _id: { $ne: req.user.userId } }).select('-password');
    res.json({ users });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/users/:id', auth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json({ user });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== MESSAGE ROUTES ====================
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
      threadKey: key,
      from: req.user.userId,
      to,
      type: type || 'text',
      text: text || '',
      media: media || null,
      fileSize: fileSize || '',
      replyTo: replyTo || null,
      status: 'sent',
      time: new Date()
    });
    res.json({ success: true, message });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/messages/:id', auth, async (req, res) => {
  try {
    const message = await Message.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!message) return res.status(404).json({ error: 'Message not found' });
    res.json({ success: true, message });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/messages/:id', auth, async (req, res) => {
  try {
    await Message.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Clear chat
app.delete('/api/messages/thread/:contactId', auth, async (req, res) => {
  try {
    const key = [req.user.userId, req.params.contactId].sort().join('|');
    await Message.deleteMany({ threadKey: key });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== META ROUTES ====================
app.get('/api/meta', auth, async (req, res) => {
  try {
    const metas = await Meta.find({ userId: req.user.userId });
    const out = {};
    metas.forEach(m => {
      out[m.threadKey] = { pinned: m.pinned, muted: m.muted, unread: m.unread || 0 };
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
        ...req.body
      },
      { upsert: true, new: true }
    );
    res.json({ success: true, meta });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== CALLS ROUTES ====================
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

// ==================== STATUS ROUTES ====================
app.get('/api/status', auth, async (req, res) => {
  try {
    const statuses = await Status.find().sort({ time: -1 }).limit(50);
    res.json({ statuses });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/status', auth, async (req, res) => {
  try {
    const status = await Status.create({
      userId: req.user.userId,
      text: req.body.text,
      time: new Date()
    });
    res.json({ success: true, status });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== START ====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('🚀 ZETA CHAT backend running on http://localhost:' + PORT);
});
