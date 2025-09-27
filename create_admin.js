import 'dotenv/config';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import User from './models/User.js';

async function main(){
  const [, , email, password, ...rest] = process.argv;
  const name = rest.join(' ') || '';
  if (!email || !password) {
    console.log('Usage: node create_admin.js <email> <password> [name]');
    process.exit(1);
  }
  const MONGO = process.env.MONGO_URI || process.env.VITE_MONGO_URI;
  if (!MONGO) {
    console.error('MONGO_URI not set in .env');
    process.exit(1);
  }
  try {
    await mongoose.connect(MONGO);
    console.log('[Mongo] Connected');
    const existing = await User.findOne({ email });
    if (existing) {
      console.error('User already exists:', email);
      process.exit(1);
    }
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, passwordHash: hash, name, role: 'admin', isVerified: true });
    console.log('Admin created:', user.email);
    process.exit(0);
  } catch (e) {
    console.error('Failed to create admin:', e.message);
    process.exit(1);
  } finally {
    try { await mongoose.disconnect(); } catch {};
  }
}

main();
