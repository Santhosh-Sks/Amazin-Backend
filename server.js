import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import nodemailer from 'nodemailer';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const app = express();

// Debug environment variables
console.log('🔍 Environment Debug:');
console.log('NODE_ENV:', process.env.NODE_ENV);
console.log('MONGO_URI:', process.env.MONGO_URI ? 'Set ✓' : 'Not Set ✗');
console.log('JWT_SECRET:', process.env.JWT_SECRET ? 'Set ✓' : 'Not Set ✗');
console.log('SMTP_USER:', process.env.SMTP_USER ? 'Set ✓' : 'Not Set ✗');
console.log('CORS_ORIGIN:', process.env.CORS_ORIGIN || 'Not Set (using defaults)');

// --- START: DYNAMIC CORS CONFIGURATION ---
const allowedOrigins = [];

// For local development, allow localhost origins
if (process.env.NODE_ENV !== 'production') {
  allowedOrigins.push('http://localhost:3000');
  allowedOrigins.push('http://localhost:5173');
  console.log('DEV MODE: Allowing localhost origins for CORS.');
}

// Add deployed frontend URL
allowedOrigins.push('https://amazin-frontend.vercel.app');

// Add the deployed frontend URL(s) from environment variables if they exist
if (process.env.CORS_ORIGIN) {
  const originsFromEnv = process.env.CORS_ORIGIN.split(',').map(origin => origin.trim());
  allowedOrigins.push(...originsFromEnv);
}

console.log('🌐 CORS Configuration:');
console.log('  Allowed Origins:', allowedOrigins.length > 0 ? allowedOrigins : ['No origin restrictions (allowing all)']);
console.log('  Credentials Enabled: true');
console.log('  Max Age: 86400 seconds (24 hours)');

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) {
      return callback(null, true);
    } else {
      const msg = `The CORS policy for this site does not allow access from the specified Origin: ${origin}`;
      return callback(new Error(msg), false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
    'Cache-Control',
    'X-Access-Token'
  ],
  exposedHeaders: [
    'Content-Length',
    'X-Kuma-Revision'
  ],
  maxAge: 86400, // 24 hours
  preflightContinue: false,
  optionsSuccessStatus: 200
}));
// --- END: DYNAMIC CORS CONFIGURATION ---

app.use(express.json());

// Additional CORS headers middleware to ensure headers are always present
app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // Set CORS headers for all responses
  if (origin && (allowedOrigins.includes(origin) || !origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  } else if (!origin) {
    res.header('Access-Control-Allow-Origin', '*');
  }
  
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS,PATCH');
  res.header('Access-Control-Allow-Headers', 'Origin,X-Requested-With,Content-Type,Accept,Authorization,Cache-Control,X-Access-Token');
  res.header('Access-Control-Expose-Headers', 'Content-Length,X-Kuma-Revision');
  res.header('Access-Control-Max-Age', '86400');
  
  next();
});

// Explicit preflight handler for all OPTIONS requests
app.options('*', (req, res) => {
  console.log('📋 Preflight request for:', req.path);
  res.status(200).send();
});

// --- START: DATABASE & MODELS ---
let MONGO_OK = false;
const MONGO_URI = process.env.MONGO_URI;

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin', 'customer'], default: 'customer' },
  isVerified: { type: Boolean, default: false },
  otpCode: { type: String },
  otpExpires: { type: Date },
  resetToken: { type: String },
  resetExpires: { type: Date },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Affiliate Click Schema
const affiliateClickSchema = new mongoose.Schema({
  asin: { type: String, required: true, index: true },
  clickedAt: { type: Date, default: Date.now }
});
const AffiliateClick = mongoose.model('AffiliateClick', affiliateClickSchema);

// MongoDB Connection with detailed debugging
async function connectMongoDB() {
  if (!MONGO_URI) {
    console.warn('⚠️ [MongoDB] URI not set. Using in-memory fallback.');
    return;
  }

  console.log('🔍 [MongoDB] Debug Info:');
  console.log('   URI exists:', !!MONGO_URI);
  console.log('   Host:', MONGO_URI.split('@')[1]?.split('/')[0]);
  
  try {
    console.log('🔄 [MongoDB] Attempting connection...');
    
    await mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 20000, // 20 seconds
      socketTimeoutMS: 45000,
      connectTimeoutMS: 20000,
      maxPoolSize: 10,
      minPoolSize: 5,
      retryWrites: true,
    });
    
    MONGO_OK = true;
    console.log('✅ [MongoDB] Connected successfully!');
    console.log('✅ [MongoDB] Database:', mongoose.connection.db.databaseName);
    
  } catch (error) {
    console.error('❌ [MongoDB] Connection failed:');
    console.error('   Error Type:', error.name);
    console.error('   Error Message:', error.message);
    
    if (error.name === 'MongoServerSelectionError') {
      console.error('💡 [MongoDB] This usually means:');
      console.error('   1. Check your internet connection');
      console.error('   2. Verify cluster is running in Atlas');
      console.error('   3. Check Network Access settings');
      console.error('   4. Verify username/password');
    }
    
    // Retry after 10 seconds
    console.log('🔄 [MongoDB] Retrying in 10 seconds...');
    setTimeout(connectMongoDB, 10000);
  }
}
// Start MongoDB connection
connectMongoDB();
// --- END: DATABASE & MODELS ---


// --- START: IN-MEMORY FALLBACK & HELPERS ---
const inMemoryUsers = new Map();

function cloneAndAttachSave(user) {
  const u = { ...user };
  u.save = async function () { 
    inMemoryUsers.set(this._id, { ...this }); 
    return this; 
  };
  return u;
}

function escapeRegex(s) { 
  return String(s || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); 
}

async function lookupUserByEmail(email) {
  if (!email) return null;
  
  if (MONGO_OK) {
    try {
      const query = { 
        email: { 
          $regex: '^' + escapeRegex(String(email)) + '$', 
          $options: 'i' 
        } 
      };
      return await User.findOne(query);
    } catch (error) { 
      console.error('[DB] lookupUserByEmail failed:', error.message); 
      return null;
    }
  }
  
  const found = Array.from(inMemoryUsers.values())
    .find(u => String(u.email).toLowerCase() === String(email).toLowerCase()) || null;
  return found ? cloneAndAttachSave(found) : null;
}

async function createUser(data) { 
  if (MONGO_OK) {
    return await User.create(data);
  }
  
  const id = String(Date.now()) + Math.floor(Math.random() * 1000); 
  const user = { _id: id, ...data }; 
  inMemoryUsers.set(id, user); 
  return cloneAndAttachSave(user); 
}

async function findUserById(id) { 
  if (MONGO_OK) {
    return await User.findById(id);
  }
  
  const u = inMemoryUsers.get(id) || null; 
  return u ? cloneAndAttachSave(u) : null; 
}
// --- END: IN-MEMORY FALLBACK & HELPERS ---


// --- START: SMTP CONFIGURATION ---
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_SECURE = process.env.SMTP_SECURE === 'true';
const SMTP_PORT = process.env.SMTP_PORT || (SMTP_SECURE ? '465' : '587');
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const FROM_EMAIL = process.env.APP_FROM_EMAIL || SMTP_USER;

function getMissingVars(fields) { 
  return fields.filter(f => !f.value).map(f => f.name); 
}

const missingVars = getMissingVars([
  { name: 'SMTP_HOST', value: SMTP_HOST },
  { name: 'SMTP_USER', value: SMTP_USER },
  { name: 'SMTP_PASS', value: SMTP_PASS }
]);

let transporter = null;

// Initialize SMTP with fallback
async function initializeSMTP() {
  if (missingVars.length === 0) {
    try {
      transporter = nodemailer.createTransport({ 
        host: SMTP_HOST, 
        port: Number(SMTP_PORT), 
        secure: SMTP_SECURE, 
        auth: { 
          user: SMTP_USER, 
          pass: SMTP_PASS 
        },
        connectionTimeout: 10000,
        greetingTimeout: 10000,
        socketTimeout: 10000
      });
      
      await transporter.verify();
      console.log('✅ [SMTP] Gmail transport verified');
      return;
    } catch (error) {
      console.error('❌ [SMTP] Gmail failed:', error.message);
    }
  } else {
    console.warn('⚠️ [SMTP] Missing env vars:', missingVars.join(', '));
  }

  // Fallback to Ethereal for development
  if (process.env.NODE_ENV !== 'production') {
    try {
      console.log('🔄 [SMTP] Setting up Ethereal test account...');
      const testAccount = await nodemailer.createTestAccount();
      
      transporter = nodemailer.createTransport({ 
        host: testAccount.smtp.host, 
        port: testAccount.smtp.port, 
        secure: testAccount.smtp.secure, 
        auth: { 
          user: testAccount.user, 
          pass: testAccount.pass 
        } 
      });
      
      transporter.testAccount = testAccount;
      await transporter.verify();
      console.log('✅ [SMTP] Ethereal test transport ready');
      console.log('📧 [SMTP] Preview emails at: https://ethereal.email');
    } catch (error) {
      console.error('❌ [SMTP] Ethereal fallback failed:', error.message);
    }
  }
}

// Start SMTP initialization
initializeSMTP();
// --- END: SMTP CONFIGURATION ---


// --- START: AUTH HELPERS & MIDDLEWARE ---
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-key-please-change-in-production';

function signToken(user) { 
  return jwt.sign(
    { 
      id: user._id, 
      role: user.role, 
      email: user.email 
    }, 
    JWT_SECRET, 
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  ); 
}

function authMiddleware(req, res, next) { 
  const authHeader = req.headers.authorization; 
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' }); 
  }
  
  const token = authHeader.split(' ')[1]; 
  try { 
    req.user = jwt.verify(token, JWT_SECRET); 
    next(); 
  } catch (error) { 
    return res.status(401).json({ error: 'Invalid token' }); 
  } 
}

function adminMiddleware(req, res, next) { 
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' }); 
  }
  next(); 
}

// Admin Configuration
const ADMIN_EMAILS = process.env.ADMIN_EMAILS 
  ? process.env.ADMIN_EMAILS.split(',').map(s => s.trim()).filter(Boolean) 
  : [];
// --- END: AUTH HELPERS & MIDDLEWARE ---


// --- START: EMAIL TEMPLATES & HELPERS ---
function otpHtmlTemplate(code, minutes) { 
  return `
    <!DOCTYPE html>
    <html>
      <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: #1e3a8a; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0;">
          <h1 style="margin: 0;">🛒 Amazin Mart</h1>
        </div>
        <div style="background: #f8fafc; padding: 30px; border-radius: 0 0 8px 8px; border: 1px solid #e2e8f0;">
          <h2 style="color: #1e40af; margin-top: 0;">Verification Code</h2>
          <p style="color: #64748b; margin-bottom: 20px;">
            Use the code below to verify your account. This code expires in ${minutes} minute(s).
          </p>
          <div style="background: #1e40af; color: white; padding: 20px; text-align: center; border-radius: 8px; font-size: 24px; font-weight: bold; letter-spacing: 2px; margin: 20px 0;">
            ${code}
          </div>
          <p style="color: #64748b; font-size: 14px; margin-bottom: 0;">
            If you didn't request this code, please ignore this email.
          </p>
        </div>
      </body>
    </html>
  `; 
}

async function sendEmailSafely({ to, subject, text, html }) { 
  if (!transporter) {
    throw new Error('No email transporter available'); 
  }
  
  const mailOptions = { 
    from: FROM_EMAIL, 
    to, 
    subject, 
    text, 
    html,
    replyTo: FROM_EMAIL
  }; 
  
  const info = await transporter.sendMail(mailOptions); 
  const result = { info }; 
  
  if (transporter.testAccount && nodemailer.getTestMessageUrl) {
    result.previewUrl = nodemailer.getTestMessageUrl(info) || null; 
    console.log('📧 Email preview:', result.previewUrl);
  }
  
  return result; 
}
// --- END: EMAIL TEMPLATES & HELPERS ---


// --- START: API ROUTES ---

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK',
    timestamp: new Date().toISOString(),
    mongodb: MONGO_OK,
    smtp: !!transporter,
    missingEnvVars: missingVars,
    environment: process.env.NODE_ENV,
    adminEmails: ADMIN_EMAILS.length
  });
});

// CORS Test Endpoint
app.get('/api/cors-test', (req, res) => {
  res.json({
    message: 'CORS is working correctly!',
    timestamp: new Date().toISOString(),
    origin: req.headers.origin || 'no-origin',
    allowedOrigins: allowedOrigins,
    corsHeaders: {
      'Access-Control-Allow-Origin': res.get('Access-Control-Allow-Origin'),
      'Access-Control-Allow-Credentials': res.get('Access-Control-Allow-Credentials'),
      'Access-Control-Allow-Methods': res.get('Access-Control-Allow-Methods'),
      'Access-Control-Allow-Headers': res.get('Access-Control-Allow-Headers')
    }
  });
});

// CORS Test POST Endpoint
app.post('/api/cors-test', (req, res) => {
  res.json({
    message: 'CORS POST request successful!',
    timestamp: new Date().toISOString(),
    origin: req.headers.origin || 'no-origin',
    body: req.body,
    allowedOrigins: allowedOrigins
  });
});

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    console.log('📝 Registration attempt:', { email: req.body?.email, name: req.body?.name, hasPassword: !!req.body?.password });
    const { email, password, name } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
    const existingUser = await lookupUserByEmail(email);
    if (existingUser) {
      console.log('❌ Registration failed: Email already exists', email);
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    console.log('🔐 Creating user account for:', email);
    const passwordHash = await bcrypt.hash(password, 12);
    const role = ADMIN_EMAILS.includes(email) ? 'admin' : 'customer';
    const user = await createUser({ email, passwordHash, name: name || email.split('@')[0], role });
    console.log('✅ User created successfully:', { id: user._id, email: user.email, role: user.role });
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + (Number(process.env.VITE_OTP_EXP_MINUTES || 5) * 60000));
    console.log('🔢 Generated OTP for', email, '- Code:', otpCode, '- Expires:', otpExpires);
    user.otpCode = otpCode;
    user.otpExpires = otpExpires;
    await user.save();
    console.log('💾 OTP saved to user record');
    let emailResult = null;
    if (transporter) {
      try {
        emailResult = await sendEmailSafely({ to: email, subject: 'Verify Your Amazin Mart Account', text: `Your verification code is: ${otpCode}`, html: otpHtmlTemplate(otpCode, 5) });
        console.log('✅ OTP email sent to:', email);
      } catch (emailError) {
        console.error('❌ Failed to send OTP email:', emailError.message);
      }
    }
    const response = { 
      success: true, 
      needsVerification: true,
      message: 'Registration successful. Please check your email for verification code.', 
      isAdmin: role === 'admin',
      email: email // Include email for frontend to use in OTP verification
    };
    if (emailResult?.previewUrl) response.previewUrl = emailResult.previewUrl;
    
    console.log('✅ Registration successful - Sending response:', { 
      success: response.success, 
      needsVerification: response.needsVerification, 
      email: response.email, 
      isAdmin: response.isAdmin 
    });
    res.json(response);
  } catch (error) { 
    console.error('Registration error:', error); 
    res.status(500).json({ error: 'Registration failed', details: process.env.NODE_ENV !== 'production' ? error.message : undefined }); 
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, asAdmin } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
    const user = await lookupUserByEmail(email);
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) return res.status(400).json({ error: 'Invalid credentials' });
    if (asAdmin && user.role !== 'admin') return res.status(403).json({ error: 'Admin access denied' });
    if (user.isVerified) {
      const token = signToken(user);
      return res.json({ success: true, token, user: { id: user._id, email: user.email, name: user.name, role: user.role } });
    }
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + (Number(process.env.VITE_OTP_EXP_MINUTES || 5) * 60000));
    user.otpCode = otpCode;
    user.otpExpires = otpExpires;
    await user.save();
    let emailResult = null;
    if (transporter) {
      try {
        emailResult = await sendEmailSafely({ to: email, subject: 'Your Login Verification Code', text: `Your verification code is: ${otpCode}`, html: otpHtmlTemplate(otpCode, 5) });
        console.log('✅ Login OTP sent to:', email);
      } catch (emailError) {
        console.error('❌ Failed to send login OTP:', emailError.message);
      }
    }
    const response = { needsVerification: true, message: 'Please check your email for verification code.' };
    if (emailResult?.previewUrl) response.previewUrl = emailResult.previewUrl;
    res.json(response);
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed', details: process.env.NODE_ENV !== 'production' ? error.message : undefined });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, code } = req.body || {};
    if (!email || !code) return res.status(400).json({ error: 'Email and verification code are required' });
    const user = await lookupUserByEmail(email);
    if (!user) return res.status(400).json({ error: 'User not found' });
    if (!user.otpCode || !user.otpExpires || new Date() > user.otpExpires || user.otpCode !== code) {
      return res.status(400).json({ error: 'Invalid or expired verification code' });
    }
    user.isVerified = true;
    user.otpCode = undefined;
    user.otpExpires = undefined;
    await user.save();
    const token = signToken(user);
    res.json({ success: true, token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

app.post('/api/auth/resend', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'Email is required' });
    const user = await lookupUserByEmail(email);
    if (!user) return res.status(400).json({ error: 'User not found' });
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + (Number(process.env.VITE_OTP_EXP_MINUTES || 5) * 60000));
    user.otpCode = otpCode;
    user.otpExpires = otpExpires;
    await user.save();
    let emailResult = null;
    if (transporter) {
      try {
        emailResult = await sendEmailSafely({ to: email, subject: 'New Verification Code - Amazin Mart', text: `Your new verification code is: ${otpCode}`, html: otpHtmlTemplate(otpCode, 5) });
        console.log('✅ Resent OTP to:', email);
      } catch (emailError) {
        console.error('❌ Failed to resend OTP:', emailError.message);
        return res.status(500).json({ error: 'Failed to send verification email' });
      }
    }
    const response = { ok: true };
    if (emailResult?.previewUrl) response.previewUrl = emailResult.previewUrl;
    res.json(response);
  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({ error: 'Failed to resend verification code' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await findUserById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user: { id: user._id, name: user.name, email: user.email, role: user.role, isVerified: user.isVerified } });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Affiliate Routes
app.post('/api/affiliate/click', async (req, res) => {
  try {
    const { asin } = req.body;
    if (!asin) return res.status(400).json({ error: 'ASIN is required' });
    await AffiliateClick.create({ asin });
    res.status(201).json({ success: true, message: 'Click recorded' });
  } catch (error) {
    console.error('Affiliate click error:', error);
    res.status(500).json({ error: 'Failed to record click' });
  }
});

app.get('/api/affiliate/count', async (req, res) => {
  try {
    const { asin } = req.query;
    if (!asin) return res.status(400).json({ error: 'ASIN query parameter is required' });
    const count = await AffiliateClick.countDocuments({ asin });
    res.json({ asin, count });
  } catch (error) {
    console.error('Affiliate count error:', error);
    res.status(500).json({ error: 'Failed to get count' });
  }
});

// --- END: API ROUTES ---


// --- START: ERROR HANDLING & SERVER BOOT ---

// Handle 404 routes
app.use('*', (req, res) => {
  res.status(404).json({ error: `Route not found: ${req.method} ${req.originalUrl}` });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  
  // Handle CORS errors specifically
  if (error.message && error.message.includes('CORS policy')) {
    console.error('❌ CORS Error:', error.message);
    console.error('   Request Origin:', req.headers.origin);
    console.error('   Allowed Origins:', allowedOrigins);
    return res.status(403).json({ 
      error: 'CORS policy violation', 
      message: 'This origin is not allowed by the CORS policy',
      origin: req.headers.origin,
      allowedOrigins: allowedOrigins
    });
  }
  
  res.status(500).json({ 
    error: 'Internal server error', 
    details: process.env.NODE_ENV !== 'production' ? error.message : undefined 
  });
});

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server listening on port ${PORT}`);
  console.log(`   Environment: ${process.env.NODE_ENV}`);
  
  if (MONGO_OK) {
    console.log('✅ MongoDB: Connected');
  } else {
    console.log('❌ MongoDB: Disconnected (using in-memory fallback)');
  }
  
  if (transporter) {
    console.log('✅ Email: Ready');
  } else {
    console.log('❌ Email: Not configured');
  }
  
  console.log('📋 Available routes:');
  console.log('  GET  /api/health');
  console.log('  GET  /api/cors-test');
  console.log('  POST /api/cors-test');
  console.log('  POST /api/auth/register');
  console.log('  POST /api/auth/login');
  console.log('  POST /api/auth/verify-otp');
  console.log('  POST /api/auth/resend');
  console.log('  GET  /api/auth/me');
  console.log('  POST /api/affiliate/click');
  console.log('  GET  /api/affiliate/count');
});
// --- END: ERROR HANDLING & SERVER BOOT ---