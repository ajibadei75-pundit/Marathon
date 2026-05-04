/**
 * RunFest 2025 — server.js
 * Node.js + Express backend with MongoDB
 *
 * Run locally:  node server.js
 * Or with hot-reload: npx nodemon server.js
 */

require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'runfest2025_secret_change_me';

/* ============================================================
   MIDDLEWARE
   ============================================================ */
app.use(cors({ origin: process.env.FRONTEND_URL || '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public')); // serve frontend from /public

// Serve uploads
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
app.use('/uploads', express.static(uploadDir));

/* ============================================================
   DATABASE — MongoDB with Mongoose
   ============================================================ */
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/runfest2025', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB connected'))
.catch(err => console.error('❌ MongoDB error:', err));

/* ---- SCHEMAS ---- */

const registrationSchema = new mongoose.Schema({
  runnerId: { type: String, unique: true, required: true },
  fullName: { type: String, required: true, trim: true },
  phone: { type: String, required: true, trim: true, unique: true },
  email: { type: String, required: true, trim: true, lowercase: true, unique: true },
  department: { type: String, required: true, trim: true },
  level: { type: String, required: true },
  genotype: { type: String, required: true },
  hostel: { type: String, required: true, trim: true },
  naqeeb: { type: String, required: true, trim: true },
  healthCondition: { type: String, default: '' },
  dynamicFields: { type: Map, of: String, default: {} },
  registeredAt: { type: Date, default: Date.now }
});

const customFieldSchema = new mongoose.Schema({
  fieldId: { type: String, required: true, unique: true },
  label: { type: String, required: true },
  type: { type: String, required: true },
  options: { type: String, default: '' },
  required: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const imageSchema = new mongoose.Schema({
  imageId: { type: String, required: true, unique: true },
  filename: String,
  url: String,
  uploadedAt: { type: Date, default: Date.now }
});

const Registration = mongoose.model('Registration', registrationSchema);
const CustomField = mongoose.model('CustomField', customFieldSchema);
const Image = mongoose.model('Image', imageSchema);

/* ============================================================
   AUTH MIDDLEWARE
   ============================================================ */
function authRequired(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const decoded = jwt.verify(header.split(' ')[1], JWT_SECRET);
    req.admin = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

/* ============================================================
   UTILITIES
   ============================================================ */
function genRunnerId() {
  const num = Math.floor(10000 + Math.random() * 90000);
  return `RUN-${num}`;
}

async function uniqueRunnerId() {
  let id, exists;
  do {
    id = genRunnerId();
    exists = await Registration.findOne({ runnerId: id });
  } while (exists);
  return id;
}

/* ============================================================
   ROUTES — AUTH
   ============================================================ */

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const adminUser = process.env.ADMIN_USER || 'admin';
  const adminPassHash = process.env.ADMIN_PASS_HASH || '$2a$10$example'; // bcrypt hash

  // Simple check — for production use bcrypt.compare
  const plainPass = process.env.ADMIN_PASS || 'runfest2025';
  if (username === adminUser && password === plainPass) {
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '8h' });
    return res.json({ token });
  }
  return res.status(401).json({ error: 'Invalid credentials' });
});

/* ============================================================
   ROUTES — REGISTRATIONS
   ============================================================ */

// POST /api/register — public endpoint
app.post('/api/register', async (req, res) => {
  try {
    const {
      fullName, phone, email, department, level,
      genotype, hostel, naqeeb, healthCondition, dynamicFields
    } = req.body;

    // Validation
    if (!fullName || !phone || !email || !department || !level || !genotype || !hostel || !naqeeb) {
      return res.status(400).json({ error: 'All required fields must be filled.' });
    }

    // Duplicate checks
    const dupEmail = await Registration.findOne({ email: email.toLowerCase() });
    if (dupEmail) return res.status(409).json({ error: 'This email is already registered.' });

    const dupPhone = await Registration.findOne({ phone });
    if (dupPhone) return res.status(409).json({ error: 'This phone number is already registered.' });

    const runnerId = await uniqueRunnerId();

    const reg = new Registration({
      runnerId,
      fullName: fullName.trim(),
      phone: phone.trim(),
      email: email.trim().toLowerCase(),
      department: department.trim(),
      level,
      genotype,
      hostel: hostel.trim(),
      naqeeb: naqeeb.trim(),
      healthCondition: healthCondition || '',
      dynamicFields: dynamicFields || {}
    });

    await reg.save();
    return res.status(201).json({ runnerId, message: 'Registration successful!' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// GET /api/registrations — admin only
app.get('/api/registrations', authRequired, async (req, res) => {
  try {
    const { search, healthOnly, page = 1, limit = 100 } = req.query;
    let query = {};

    if (healthOnly === 'true') {
      query.healthCondition = { $ne: '' };
    }

    if (search) {
      const s = new RegExp(search, 'i');
      query.$or = [
        { fullName: s }, { email: s }, { runnerId: s }, { department: s }, { phone: s }
      ];
    }

    const regs = await Registration.find(query)
      .sort({ registeredAt: -1 })
      .limit(Number(limit))
      .skip((Number(page) - 1) * Number(limit));

    const total = await Registration.countDocuments(query);
    return res.json({ registrations: regs, total, page: Number(page) });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/registrations/count — public (for hero counter)
app.get('/api/registrations/count', async (req, res) => {
  try {
    const count = await Registration.countDocuments();
    return res.json({ count });
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/registrations/analytics — admin
app.get('/api/registrations/analytics', authRequired, async (req, res) => {
  try {
    const total = await Registration.countDocuments();
    const withHealth = await Registration.countDocuments({ healthCondition: { $ne: '' } });

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayCount = await Registration.countDocuments({ registeredAt: { $gte: today } });

    const levelAgg = await Registration.aggregate([
      { $group: { _id: '$level', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    const deptAgg = await Registration.aggregate([
      { $group: { _id: '$department', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    return res.json({
      total, withHealth, todayCount,
      byLevel: levelAgg,
      byDept: deptAgg,
      departments: deptAgg.length
    });
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/registrations/:id — admin
app.delete('/api/registrations/:id', authRequired, async (req, res) => {
  try {
    await Registration.findByIdAndDelete(req.params.id);
    return res.json({ message: 'Deleted.' });
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/registrations/export — CSV export, admin
app.get('/api/registrations/export', authRequired, async (req, res) => {
  try {
    const regs = await Registration.find().sort({ registeredAt: -1 });
    const headers = [
      'Runner ID', 'Full Name', 'Phone', 'Email', 'Department',
      'Level', 'Genotype', 'Hostel', 'Naqeeb Phone', 'Health Condition', 'Date'
    ];
    const rows = regs.map(r => [
      r.runnerId, r.fullName, r.phone, r.email, r.department,
      r.level, r.genotype, r.hostel, r.naqeeb, r.healthCondition,
      r.registeredAt.toISOString().slice(0, 10)
    ]);

    const csv = [headers, ...rows]
      .map(row => row.map(c => `"${String(c).replace(/"/g, '""')}"`).join(','))
      .join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=registrations.csv');
    return res.send(csv);
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

/* ============================================================
   ROUTES — CUSTOM FIELDS
   ============================================================ */

app.get('/api/custom-fields', async (req, res) => {
  const fields = await CustomField.find().sort({ createdAt: 1 });
  res.json(fields);
});

app.post('/api/custom-fields', authRequired, async (req, res) => {
  try {
    const { label, type, options, required } = req.body;
    const fieldId = Math.random().toString(36).substring(2, 9).toUpperCase();
    const field = new CustomField({ fieldId, label, type, options: options || '', required: !!required });
    await field.save();
    res.status(201).json(field);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/custom-fields/:id', authRequired, async (req, res) => {
  await CustomField.findByIdAndDelete(req.params.id);
  res.json({ message: 'Deleted.' });
});

/* ============================================================
   ROUTES — IMAGES
   ============================================================ */
const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname));
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) return cb(new Error('Images only'));
    cb(null, true);
  }
});

app.get('/api/images', async (req, res) => {
  const imgs = await Image.find().sort({ uploadedAt: -1 });
  res.json(imgs);
});

app.post('/api/images', authRequired, upload.single('image'), async (req, res) => {
  try {
    const imageId = Math.random().toString(36).substring(2, 9).toUpperCase();
    const url = `/uploads/${req.file.filename}`;
    const img = new Image({ imageId, filename: req.file.filename, url });
    await img.save();
    res.status(201).json(img);
  } catch (err) {
    res.status(500).json({ error: 'Upload failed' });
  }
});

app.delete('/api/images/:id', authRequired, async (req, res) => {
  try {
    const img = await Image.findById(req.params.id);
    if (img) {
      const filePath = path.join(uploadDir, img.filename);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      await Image.findByIdAndDelete(req.params.id);
    }
    res.json({ message: 'Deleted.' });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

/* ============================================================
   SERVE FRONTEND (production)
   ============================================================ */
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

/* ============================================================
   START SERVER
   ============================================================ */
app.listen(PORT, () => {
  console.log(`🏁 RunFest 2025 server running on http://localhost:${PORT}`);
});
