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

// CORS configuration
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://amazin-frontend.vercel.app',
    'https://amazin-mart.vercel.app'
  ],
  credentials: true
}));

app.use(express.json());

// MongoDB Connection with better error handling
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

// MongoDB Connection with retry logic - FIXED: Removed deprecated options
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

// In-memory fallback for development
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

// SMTP Configuration with better error handling
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

// JWT and Auth Helpers
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
  if (!authHeader) {
    return res.status(401).json({ error: 'Unauthorized' }); 
  }
  
  const token = authHeader.replace('Bearer ', ''); 
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

// Email Templates
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

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body || {};
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Check if user already exists
    const existingUser = await lookupUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 12);
    
    // Determine role
    const role = ADMIN_EMAILS.includes(email) ? 'admin' : 'customer';
    
    // Create user
    const user = await createUser({ 
      email, 
      passwordHash, 
      name: name || email.split('@')[0], 
      role 
    });

    // Generate OTP
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + (Number(process.env.VITE_OTP_EXP_MINUTES || 5) * 60000));
    
    user.otpCode = otpCode;
    user.otpExpires = otpExpires;
    await user.save();

    // Send OTP email
    let emailResult = null;
    if (transporter) {
      try {
        emailResult = await sendEmailSafely({ 
          to: email, 
          subject: 'Verify Your Amazin Mart Account', 
          text: `Your verification code is: ${otpCode}`, 
          html: otpHtmlTemplate(otpCode, Math.max(1, Math.round((otpExpires - Date.now()) / 60000))) 
        });
        console.log('✅ OTP email sent to:', email);
      } catch (emailError) {
        console.error('❌ Failed to send OTP email:', emailError.message);
      }
    }

    const response = { 
      success: true, 
      message: 'Registration successful. Please check your email for verification code.',
      isAdmin: role === 'admin'
    };
    
    if (emailResult?.previewUrl) {
      response.previewUrl = emailResult.previewUrl;
    }

    res.json(response);

  } catch (error) { 
    console.error('Registration error:', error); 
    res.status(500).json({ 
      error: 'Registration failed', 
      details: process.env.NODE_ENV !== 'production' ? error.message : undefined 
    }); 
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, asAdmin } = req.body || {};
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = await lookupUserByEmail(email);
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Check admin access if requested
    if (asAdmin && user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access denied' });
    }

    // If user is verified, return token
    if (user.isVerified) {
      const token = signToken(user);
      return res.json({ 
        success: true,
        token, 
        user: { 
          id: user._id,
          email: user.email, 
          name: user.name, 
          role: user.role 
        } 
      });
    }

    // Send OTP for unverified users
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + (Number(process.env.VITE_OTP_EXP_MINUTES || 5) * 60000));
    
    user.otpCode = otpCode;
    user.otpExpires = otpExpires;
    await user.save();

    let emailResult = null;
    if (transporter) {
      try {
        emailResult = await sendEmailSafely({ 
          to: email, 
          subject: 'Your Login Verification Code', 
          text: `Your verification code is: ${otpCode}`, 
          html: otpHtmlTemplate(otpCode, Math.max(1, Math.round((otpExpires - Date.now()) / 60000))) 
        });
        console.log('✅ Login OTP sent to:', email);
      } catch (emailError) {
        console.error('❌ Failed to send login OTP:', emailError.message);
      }
    }

    const response = { 
      needsVerification: true, 
      message: 'Please check your email for verification code.' 
    };
    
    if (emailResult?.previewUrl) {
      response.previewUrl = emailResult.previewUrl;
    }

    res.json(response);

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      error: 'Login failed',
      details: process.env.NODE_ENV !== 'production' ? error.message : undefined
    });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, code } = req.body || {};
    
    if (!email || !code) {
      return res.status(400).json({ error: 'Email and verification code are required' });
    }

    const user = await lookupUserByEmail(email);
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    // Check OTP validity
    if (!user.otpCode || !user.otpExpires) {
      return res.status(400).json({ error: 'No verification code found' });
    }

    if (new Date() > user.otpExpires) {
      return res.status(400).json({ error: 'Verification code expired' });
    }

    if (user.otpCode !== code) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    // Verify user
    user.isVerified = true;
    user.otpCode = undefined;
    user.otpExpires = undefined;
    await user.save();

    // Generate JWT token
    const token = signToken(user);

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

app.post('/api/auth/resend', async (req, res) => {
  try {
    const { email } = req.body || {};
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const user = await lookupUserByEmail(email);
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    // Generate new OTP
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + (Number(process.env.VITE_OTP_EXP_MINUTES || 5) * 60000));
    
    user.otpCode = otpCode;
    user.otpExpires = otpExpires;
    await user.save();

    let emailResult = null;
    if (transporter) {
      try {
        emailResult = await sendEmailSafely({ 
          to: email, 
          subject: 'New Verification Code - Amazin Mart', 
          text: `Your new verification code is: ${otpCode}`, 
          html: otpHtmlTemplate(otpCode, Math.max(1, Math.round((otpExpires - Date.now()) / 60000))) 
        });
        console.log('✅ Resent OTP to:', email);
      } catch (emailError) {
        console.error('❌ Failed to resend OTP:', emailError.message);
        return res.status(500).json({ error: 'Failed to send verification email' });
      }
    }

    const response = { ok: true };
    if (emailResult?.previewUrl) {
      response.previewUrl = emailResult.previewUrl;
    }

    res.json(response);

  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({ error: 'Failed to resend verification code' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await findUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Handle 404 routes
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ 
    error: 'Internal server error',
    details: process.env.NODE_ENV !== 'production' ? error.message : undefined
  });
});

// Start server
const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
  
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
  console.log('  POST /api/auth/register');
  console.log('  POST /api/auth/login');
  console.log('  POST /api/auth/verify-otp');
  console.log('  POST /api/auth/resend');
  console.log('  GET  /api/auth/me');
});