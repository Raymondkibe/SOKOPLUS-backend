// ============================================
// SOKOPLUS COMPLETE BACKEND API - ALL FEATURES
// ============================================
// Deployment: Deploy this file as api/index.js on Vercel
// Database: Uses Supabase PostgreSQL

const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

// ============================================
// SECURITY & MIDDLEWARE CONFIGURATION
// ============================================

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:", "http:"],
      connectSrc: ["'self'", "https://wpjudwfhractgwbncigz.supabase.co"]
    }
  }
}));

// CORS configuration
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://sokoplus.vercel.app', 'https://sokoplus.app']
    : ['http://localhost:3000', 'http://localhost:5000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// ============================================
// SUPABASE & JWT CONFIGURATION
// ============================================

// Initialize Supabase clients
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || 'https://wpjudwfhractgwbncigz.supabase.co';
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || 'sb_publishable_SCOwNx8jmmernQql90sbpA_XfnytFSV';
const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY || 'sb_secret_04K4X8vurSRohLxzQMzlLw_-8Httq16';

const supabase = createClient(supabaseUrl, supabaseAnonKey);
const supabaseAdmin = createClient(supabaseUrl, supabaseSecretKey);

// JWT configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// ============================================
// FILE UPLOAD CONFIGURATION
// ============================================

const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 10 // Max 10 files
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|mp4|mov|avi/;
    const extname = allowedTypes.test(file.originalname.toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (extname && mimetype) {
      return cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only images, videos, PDF and DOC files are allowed.'));
    }
  }
});

// ============================================
// AUTHENTICATION MIDDLEWARE
// ============================================

const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ 
        success: false, 
        message: 'Access token required' 
      });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Fetch user from database
    const { data: user, error } = await supabaseAdmin
      .from('users')
      .select('*')
      .eq('id', decoded.userId)
      .single();
    
    if (error || !user) {
      return res.status(401).json({ 
        success: false, 
        message: 'User not found' 
      });
    }
    
    if (user.status !== 'active') {
      return res.status(403).json({ 
        success: false, 
        message: 'Account is suspended' 
      });
    }
    
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ 
      success: false, 
      message: 'Invalid or expired token' 
    });
  }
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ 
      success: false, 
      message: 'Admin access required' 
    });
  }
  next();
};

// ============================================
// UTILITY FUNCTIONS
// ============================================

const generateReferralCode = (name) => {
  const random = Math.random().toString(36).substring(2, 8).toUpperCase();
  const initials = name.split(' ').map(n => n[0]).join('').toUpperCase();
  return initials + random;
};

const validatePhone = (phone) => {
  return /^2547\d{8}$/.test(phone);
};

const formatPrice = (price) => {
  return new Intl.NumberFormat('en-KE', {
    style: 'currency',
    currency: 'KES'
  }).format(price);
};

const calculateBoostExpiry = () => {
  const expiry = new Date();
  expiry.setDate(expiry.getDate() + 7); // 7 days from now
  return expiry;
};

const generateSlug = (title) => {
  return title
    .toLowerCase()
    .replace(/[^\w\s]/g, '')
    .replace(/\s+/g, '-')
    .substring(0, 100);
};

// ============================================
// DATABASE INITIALIZATION
// ============================================

const initializeDatabase = async () => {
  console.log('🔄 Initializing SOKOPLUS database...');
  
  try {
    // Users table
    await supabaseAdmin.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(100) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        phone VARCHAR(20) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        profile_picture TEXT,
        location VARCHAR(100),
        bio TEXT,
        business_name VARCHAR(100),
        referral_code VARCHAR(20) UNIQUE NOT NULL,
        referral_from VARCHAR(20),
        subscription_active BOOLEAN DEFAULT false,
        subscription_type VARCHAR(20) DEFAULT 'weekly',
        subscription_expires_at TIMESTAMPTZ,
        upgraded BOOLEAN DEFAULT false,
        upgraded_at TIMESTAMPTZ,
        earnings_balance DECIMAL(10,2) DEFAULT 0,
        earnings_total DECIMAL(10,2) DEFAULT 0,
        earnings_withdrawn DECIMAL(10,2) DEFAULT 0,
        role VARCHAR(20) DEFAULT 'user',
        verified BOOLEAN DEFAULT false,
        status VARCHAR(20) DEFAULT 'active',
        last_login TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // Posts table
    await supabaseAdmin.query(`
      CREATE TABLE IF NOT EXISTS posts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        type VARCHAR(20) NOT NULL CHECK (type IN ('product', 'social', 'job', 'service')),
        title VARCHAR(255),
        slug VARCHAR(300) UNIQUE,
        content TEXT,
        description TEXT,
        price DECIMAL(10,2),
        price_min DECIMAL(10,2),
        price_max DECIMAL(10,2),
        salary_min DECIMAL(10,2),
        salary_max DECIMAL(10,2),
        category VARCHAR(50),
        tags VARCHAR(100)[] DEFAULT '{}',
        location VARCHAR(100),
        whatsapp VARCHAR(20) NOT NULL,
        company VARCHAR(100),
        job_type VARCHAR(20),
        apply_link VARCHAR(255),
        images TEXT[] DEFAULT '{}',
        videos TEXT[] DEFAULT '{}',
        boosted BOOLEAN DEFAULT false,
        boost_expires_at TIMESTAMPTZ,
        featured BOOLEAN DEFAULT false,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        views INTEGER DEFAULT 0,
        likes INTEGER DEFAULT 0,
        shares INTEGER DEFAULT 0,
        saves INTEGER DEFAULT 0,
        status VARCHAR(20) DEFAULT 'active',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // Payments table
    await supabaseAdmin.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        amount DECIMAL(10,2) NOT NULL,
        type VARCHAR(20) NOT NULL CHECK (type IN ('subscription', 'boost', 'upgrade')),
        transaction_code VARCHAR(100) UNIQUE NOT NULL,
        status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'failed', 'refunded')),
        post_id UUID REFERENCES posts(id) ON DELETE SET NULL,
        mpesa_receipt VARCHAR(100),
        processed_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // Withdrawals table
    await supabaseAdmin.query(`
      CREATE TABLE IF NOT EXISTS withdrawals (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        amount DECIMAL(10,2) NOT NULL,
        fee DECIMAL(10,2) DEFAULT 0,
        net_amount DECIMAL(10,2) NOT NULL,
        mpesa_number VARCHAR(20) NOT NULL,
        mpesa_transaction_id VARCHAR(100),
        status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'processing', 'completed', 'failed')),
        processed_by UUID REFERENCES users(id),
        processed_at TIMESTAMPTZ,
        completed_at TIMESTAMPTZ,
        notes TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // Referrals table
    await supabaseAdmin.query(`
      CREATE TABLE IF NOT EXISTS referrals (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        referrer_id UUID REFERENCES users(id) ON DELETE CASCADE,
        referred_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        commission DECIMAL(10,2) NOT NULL,
        type VARCHAR(20) DEFAULT 'subscription' CHECK (type IN ('subscription', 'upgrade')),
        status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'paid', 'cancelled')),
        paid_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(referrer_id, referred_user_id, type)
      )
    `);

    // Shops table
    await supabaseAdmin.query(`
      CREATE TABLE IF NOT EXISTS shops (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE UNIQUE,
        name VARCHAR(100) NOT NULL,
        slug VARCHAR(150) UNIQUE,
        description TEXT,
        category VARCHAR(50),
        logo TEXT,
        banner TEXT,
        whatsapp VARCHAR(20) NOT NULL,
        email VARCHAR(255),
        location VARCHAR(100),
        business_hours VARCHAR(100),
        social_links JSONB DEFAULT '{}',
        rating DECIMAL(3,2) DEFAULT 0,
        total_ratings INTEGER DEFAULT 0,
        total_sales INTEGER DEFAULT 0,
        total_revenue DECIMAL(10,2) DEFAULT 0,
        verified BOOLEAN DEFAULT false,
        featured BOOLEAN DEFAULT false,
        status VARCHAR(20) DEFAULT 'active',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // Shop products table
    await supabaseAdmin.query(`
      CREATE TABLE IF NOT EXISTS shop_products (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        shop_id UUID REFERENCES shops(id) ON DELETE CASCADE,
        post_id UUID REFERENCES posts(id) ON DELETE CASCADE,
        sku VARCHAR(100),
        stock_quantity INTEGER DEFAULT 0,
        low_stock_threshold INTEGER DEFAULT 5,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(shop_id, post_id)
      )
    `);

    // CVs table
    await supabaseAdmin.query(`
      CREATE TABLE IF NOT EXISTS cvs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        file_url TEXT NOT NULL,
        file_name VARCHAR(255),
        file_size INTEGER,
        summary TEXT,
        skills TEXT[] DEFAULT '{}',
        experience VARCHAR(50),
        education VARCHAR(100),
        expected_salary DECIMAL(10,2),
        location VARCHAR(100),
        views INTEGER DEFAULT 0,
        downloads INTEGER DEFAULT 0,
        uploaded_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        status VARCHAR(20) DEFAULT 'active'
      )
    `);

    // Orders table
    await supabaseAdmin.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        order_number VARCHAR(50) UNIQUE NOT NULL,
        user_id UUID REFERENCES users(id) ON DELETE SET NULL,
        shop_id UUID REFERENCES shops(id) ON DELETE SET NULL,
        post_id UUID REFERENCES posts(id) ON DELETE SET NULL,
        quantity INTEGER DEFAULT 1,
        unit_price DECIMAL(10,2) NOT NULL,
        total_price DECIMAL(10,2) NOT NULL,
        shipping_fee DECIMAL(10,2) DEFAULT 0,
        tax DECIMAL(10,2) DEFAULT 0,
        discount DECIMAL(10,2) DEFAULT 0,
        final_price DECIMAL(10,2) NOT NULL,
        customer_name VARCHAR(100) NOT NULL,
        customer_phone VARCHAR(20) NOT NULL,
        customer_email VARCHAR(255),
        shipping_address TEXT,
        payment_method VARCHAR(50),
        payment_status VARCHAR(20) DEFAULT 'pending',
        order_status VARCHAR(20) DEFAULT 'pending',
        notes TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // Reviews table
    await supabaseAdmin.query(`
      CREATE TABLE IF NOT EXISTS reviews (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        post_id UUID REFERENCES posts(id) ON DELETE CASCADE,
        shop_id UUID REFERENCES shops(id) ON DELETE CASCADE,
        rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
        comment TEXT,
        images TEXT[] DEFAULT '{}',
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // Notifications table
    await supabaseAdmin.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(50) NOT NULL,
        title VARCHAR(255) NOT NULL,
        message TEXT NOT NULL,
        data JSONB DEFAULT '{}',
        read BOOLEAN DEFAULT false,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // Messages table
    await supabaseAdmin.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        sender_id UUID REFERENCES users(id) ON DELETE CASCADE,
        receiver_id UUID REFERENCES users(id) ON DELETE CASCADE,
        post_id UUID REFERENCES posts(id) ON DELETE SET NULL,
        message TEXT NOT NULL,
        read BOOLEAN DEFAULT false,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // Saved items table
    await supabaseAdmin.query(`
      CREATE TABLE IF NOT EXISTS saved_items (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        post_id UUID REFERENCES posts(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_id, post_id)
      )
    `);

    // Reports table
    await supabaseAdmin.query(`
      CREATE TABLE IF NOT EXISTS reports (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        reporter_id UUID REFERENCES users(id) ON DELETE CASCADE,
        reported_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
        reported_post_id UUID REFERENCES posts(id) ON DELETE SET NULL,
        report_type VARCHAR(50) NOT NULL,
        description TEXT NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        resolved_by UUID REFERENCES users(id),
        resolved_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // Analytics table
    await supabaseAdmin.query(`
      CREATE TABLE IF NOT EXISTS analytics (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        post_id UUID REFERENCES posts(id) ON DELETE CASCADE,
        shop_id UUID REFERENCES shops(id) ON DELETE CASCADE,
        event_type VARCHAR(50) NOT NULL,
        event_data JSONB DEFAULT '{}',
        ip_address VARCHAR(45),
        user_agent TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    // Create indexes
    await supabaseAdmin.query(`
      CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts(user_id);
      CREATE INDEX IF NOT EXISTS idx_posts_type ON posts(type);
      CREATE INDEX IF NOT EXISTS idx_posts_category ON posts(category);
      CREATE INDEX IF NOT EXISTS idx_posts_boosted ON posts(boosted);
      CREATE INDEX IF NOT EXISTS idx_posts_status ON posts(status);
      CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at);
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code);
      CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);
      CREATE INDEX IF NOT EXISTS idx_withdrawals_status ON withdrawals(status);
      CREATE INDEX IF NOT EXISTS idx_orders_order_number ON orders(order_number);
      CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id);
      CREATE INDEX IF NOT EXISTS idx_messages_sender_receiver ON messages(sender_id, receiver_id);
      CREATE INDEX IF NOT EXISTS idx_analytics_user_id ON analytics(user_id);
    `);

    console.log('✅ Database initialization completed successfully!');
    
    // Create default admin user if not exists
    const adminEmail = 'admin@sokoplus.com';
    const { data: existingAdmin } = await supabaseAdmin
      .from('users')
      .select('id')
      .eq('email', adminEmail)
      .single();
    
    if (!existingAdmin) {
      const adminPassword = await bcrypt.hash('Admin@123', 10);
      const adminUser = {
        id: uuidv4(),
        name: 'SOKOPLUS Admin',
        email: adminEmail,
        phone: '254712345678',
        password_hash: adminPassword,
        referral_code: 'ADMIN001',
        role: 'admin',
        verified: true,
        subscription_active: true,
        upgraded: true,
        created_at: new Date().toISOString()
      };
      
      await supabaseAdmin.from('users').insert([adminUser]);
      console.log('👑 Default admin user created');
    }
    
  } catch (error) {
    console.error('❌ Database initialization error:', error.message);
  }
};

// Initialize database on startup
initializeDatabase();

// ============================================
// HEALTH CHECK ENDPOINT
// ============================================

app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: '🚀 SOKOPLUS API is running',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// ============================================
// AUTHENTICATION ENDPOINTS
// ============================================

// Register new user
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, phone, password, referralCode, location, businessName } = req.body;
    
    // Validation
    if (!name || !email || !phone || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Name, email, phone, and password are required' 
      });
    }
    
    if (!validatePhone(phone)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid phone number format. Use: 2547XXXXXXXX' 
      });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 6 characters' 
      });
    }
    
    // Check existing user
    const { data: existingUser } = await supabaseAdmin
      .from('users')
      .select('id')
      .or(`email.eq.${email},phone.eq.${phone}`)
      .single();
    
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        message: 'User with this email or phone already exists' 
      });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    
    // Generate referral code
    const userReferralCode = generateReferralCode(name);
    
    // Create user
    const newUser = {
      id: uuidv4(),
      name,
      email,
      phone,
      password_hash: passwordHash,
      location: location || '',
      business_name: businessName || '',
      referral_code: userReferralCode,
      referral_from: referralCode || null,
      created_at: new Date().toISOString()
    };
    
    const { error: userError } = await supabaseAdmin
      .from('users')
      .insert([newUser]);
    
    if (userError) throw userError;
    
    // Handle referral
    if (referralCode) {
      const { data: referrer } = await supabaseAdmin
        .from('users')
        .select('id')
        .eq('referral_code', referralCode)
        .eq('status', 'active')
        .single();
      
      if (referrer) {
        const newReferral = {
          id: uuidv4(),
          referrer_id: referrer.id,
          referred_user_id: newUser.id,
          commission: 25.00,
          type: 'subscription',
          created_at: new Date().toISOString()
        };
        
        await supabaseAdmin.from('referrals').insert([newReferral]);
      }
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { userId: newUser.id, email: newUser.email, role: 'user' },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    // Remove password from response
    const { password_hash, ...userWithoutPassword } = newUser;
    
    res.status(201).json({
      success: true,
      message: 'Registration successful',
      user: userWithoutPassword,
      token
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Registration failed. Please try again.' 
    });
  }
});

// Login user
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and password are required' 
      });
    }
    
    // Find user
    const { data: user, error } = await supabaseAdmin
      .from('users')
      .select('*')
      .eq('email', email)
      .single();
    
    if (error || !user) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid email or password' 
      });
    }
    
    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid email or password' 
      });
    }
    
    // Check account status
    if (user.status !== 'active') {
      return res.status(403).json({ 
        success: false, 
        message: 'Account is not active. Please contact support.' 
      });
    }
    
    // Update last login
    await supabaseAdmin
      .from('users')
      .update({ 
        last_login: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })
      .eq('id', user.id);
    
    // Generate token
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    // Remove password from response
    const { password_hash, ...userWithoutPassword } = user;
    
    res.json({
      success: true,
      message: 'Login successful',
      user: userWithoutPassword,
      token
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Login failed. Please try again.' 
    });
  }
});

// Forgot password request
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email is required' 
      });
    }
    
    // Check if user exists
    const { data: user } = await supabaseAdmin
      .from('users')
      .select('id, name, email')
      .eq('email', email)
      .single();
    
    if (!user) {
      // Return success even if user doesn't exist for security
      return res.json({
        success: true,
        message: 'If your email exists, you will receive a password reset link'
      });
    }
    
    // Generate reset token
    const resetToken = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    // In production, send email with reset link
    // For now, return token (in production, send email)
    res.json({
      success: true,
      message: 'Password reset link generated',
      resetToken,
      userId: user.id
    });
    
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to process request' 
    });
  }
});

// Reset password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword, confirmPassword } = req.body;
    
    if (!token || !newPassword || !confirmPassword) {
      return res.status(400).json({ 
        success: false, 
        message: 'All fields are required' 
      });
    }
    
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ 
        success: false, 
        message: 'Passwords do not match' 
      });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 6 characters' 
      });
    }
    
    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (error) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid or expired token' 
      });
    }
    
    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(newPassword, salt);
    
    // Update password
    const { error: updateError } = await supabaseAdmin
      .from('users')
      .update({ 
        password_hash: passwordHash,
        updated_at: new Date().toISOString()
      })
      .eq('id', decoded.userId);
    
    if (updateError) throw updateError;
    
    res.json({
      success: true,
      message: 'Password reset successful'
    });
    
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to reset password' 
    });
  }
});

// Get user profile
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const { data: user, error } = await supabaseAdmin
      .from('users')
      .select(`
        *,
        shop:shops(*),
        stats:posts(count)
      `)
      .eq('id', req.user.id)
      .single();
    
    if (error || !user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }
    
    const { password_hash, ...userWithoutPassword } = user;
    
    res.json({
      success: true,
      user: userWithoutPassword
    });
    
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch profile' 
    });
  }
});

// Update user profile
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const { name, phone, location, bio, businessName, profilePicture } = req.body;
    
    const updateData = {
      updated_at: new Date().toISOString()
    };
    
    if (name) updateData.name = name;
    if (phone) {
      if (!validatePhone(phone)) {
        return res.status(400).json({ 
          success: false, 
          message: 'Invalid phone number format' 
        });
      }
      updateData.phone = phone;
    }
    if (location) updateData.location = location;
    if (bio) updateData.bio = bio;
    if (businessName) updateData.business_name = businessName;
    if (profilePicture) updateData.profile_picture = profilePicture;
    
    const { data: updatedUser, error } = await supabaseAdmin
      .from('users')
      .update(updateData)
      .eq('id', req.user.id)
      .select()
      .single();
    
    if (error) throw error;
    
    const { password_hash, ...userWithoutPassword } = updatedUser;
    
    res.json({
      success: true,
      message: 'Profile updated successfully',
      user: userWithoutPassword
    });
    
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to update profile' 
    });
  }
});

// Change password
app.put('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ 
        success: false, 
        message: 'Current and new password are required' 
      });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({ 
        success: false, 
        message: 'New password must be at least 6 characters' 
      });
    }
    
    // Get current password hash
    const { data: user } = await supabaseAdmin
      .from('users')
      .select('password_hash')
      .eq('id', req.user.id)
      .single();
    
    // Verify current password
    const isValid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ 
        success: false, 
        message: 'Current password is incorrect' 
      });
    }
    
    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const newPasswordHash = await bcrypt.hash(newPassword, salt);
    
    // Update password
    await supabaseAdmin
      .from('users')
      .update({ 
        password_hash: newPasswordHash,
        updated_at: new Date().toISOString()
      })
      .eq('id', req.user.id);
    
    res.json({
      success: true,
      message: 'Password changed successfully'
    });
    
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to change password' 
    });
  }
});

// ============================================
// POST MANAGEMENT ENDPOINTS
// ============================================

// Create a new post
app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    // Check subscription
    if (!req.user.subscription_active && !req.user.upgraded) {
      return res.status(403).json({ 
        success: false, 
        message: 'Active subscription required to post' 
      });
    }
    
    const postData = {
      id: uuidv4(),
      ...req.body,
      user_id: req.user.id,
      slug: generateSlug(req.body.title || 'post'),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    // Validate based on post type
    const validationErrors = [];
    
    if (postData.type === 'product') {
      if (!postData.price) validationErrors.push('Price is required for products');
      if (!postData.category) validationErrors.push('Category is required');
    }
    
    if (postData.type === 'service') {
      if (!postData.price_min || !postData.price_max) {
        validationErrors.push('Price range is required for services');
      }
    }
    
    if (postData.type === 'job') {
      if (!postData.salary_min || !postData.salary_max) {
        validationErrors.push('Salary range is required for jobs');
      }
      if (!postData.company) validationErrors.push('Company name is required');
    }
    
    if (validationErrors.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: validationErrors.join(', ') 
      });
    }
    
    // Handle boost
    if (postData.boosted) {
      if (!req.user.upgraded) {
        // Non-premium users need to pay for boost
        // Create pending payment
        const boostPayment = {
          id: uuidv4(),
          user_id: req.user.id,
          amount: 100.00,
          type: 'boost',
          transaction_code: `BOOST-${Date.now()}`,
          status: 'pending',
          post_id: postData.id,
          created_at: new Date().toISOString()
        };
        
        await supabaseAdmin.from('payments').insert([boostPayment]);
      }
      postData.boost_expires_at = calculateBoostExpiry();
    }
    
    const { data: post, error } = await supabaseAdmin
      .from('posts')
      .insert([postData])
      .select()
      .single();
    
    if (error) throw error;
    
    // If shop exists, link to shop
    const { data: shop } = await supabaseAdmin
      .from('shops')
      .select('id')
      .eq('user_id', req.user.id)
      .single();
    
    if (shop && (postData.type === 'product' || postData.type === 'service')) {
      const shopProduct = {
        id: uuidv4(),
        shop_id: shop.id,
        post_id: post.id,
        created_at: new Date().toISOString()
      };
      
      await supabaseAdmin.from('shop_products').insert([shopProduct]);
    }
    
    // Create notification
    const notification = {
      id: uuidv4(),
      user_id: req.user.id,
      type: 'post_created',
      title: 'Post Created Successfully',
      message: `Your ${postData.type} post "${postData.title}" has been created.`,
      data: { postId: post.id, postType: postData.type },
      created_at: new Date().toISOString()
    };
    
    await supabaseAdmin.from('notifications').insert([notification]);
    
    res.status(201).json({
      success: true,
      message: 'Post created successfully',
      post
    });
    
  } catch (error) {
    console.error('Post creation error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to create post' 
    });
  }
});

// Get all posts with filters
app.get('/api/posts', async (req, res) => {
  try {
    const { 
      type, 
      category, 
      search, 
      minPrice, 
      maxPrice, 
      location,
      userId,
      boosted,
      featured,
      page = 1, 
      limit = 20,
      sortBy = 'created_at',
      sortOrder = 'desc'
    } = req.query;
    
    let query = supabase
      .from('posts')
      .select(`
        *,
        user:users(id, name, profile_picture, verified, business_name),
        shop:shops(id, name, logo, verified)
      `, { count: 'exact' })
      .eq('status', 'active');
    
    // Apply filters
    if (type) query = query.eq('type', type);
    if (category) query = query.eq('category', category);
    if (location) query = query.ilike('location', `%${location}%`);
    if (userId) query = query.eq('user_id', userId);
    if (boosted === 'true') query = query.eq('boosted', true);
    if (featured === 'true') query = query.eq('featured', true);
    
    if (search) {
      query = query.or(
        `title.ilike.%${search}%,description.ilike.%${search}%,content.ilike.%${search}%,tags.cs.{${search}}`
      );
    }
    
    if (minPrice) query = query.gte('price', minPrice);
    if (maxPrice) query = query.lte('price', maxPrice);
    
    // Apply sorting
    if (sortBy === 'price') {
      query = query.order('price', { ascending: sortOrder === 'asc' });
    } else if (sortBy === 'views') {
      query = query.order('views', { ascending: sortOrder === 'asc' });
    } else {
      query = query.order(sortBy, { ascending: sortOrder === 'asc' });
    }
    
    // Apply pagination
    const from = (page - 1) * limit;
    const to = from + limit - 1;
    query = query.range(from, to);
    
    const { data: posts, error, count } = await query;
    
    if (error) throw error;
    
    res.json({
      success: true,
      posts: posts || [],
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count || 0,
        pages: Math.ceil((count || 0) / limit)
      }
    });
    
  } catch (error) {
    console.error('Posts fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch posts' 
    });
  }
});

// Get single post
app.get('/api/posts/:id', async (req, res) => {
  try {
    const postId = req.params.id;
    
    const { data: post, error } = await supabase
      .from('posts')
      .select(`
        *,
        user:users(*),
        shop:shops(*),
        related:posts!related(*)
      `)
      .eq('id', postId)
      .single();
    
    if (error || !post) {
      return res.status(404).json({ 
        success: false, 
        message: 'Post not found' 
      });
    }
    
    // Increment view count
    await supabaseAdmin.rpc('increment', {
      table_name: 'posts',
      id: postId,
      column: 'views'
    });
    
    // Log analytics
    const analytics = {
      id: uuidv4(),
      post_id: postId,
      event_type: 'post_view',
      event_data: { userId: req.user?.id || null },
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      created_at: new Date().toISOString()
    };
    
    await supabaseAdmin.from('analytics').insert([analytics]);
    
    res.json({
      success: true,
      post
    });
    
  } catch (error) {
    console.error('Post fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch post' 
    });
  }
});

// Update post
app.put('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const postId = req.params.id;
    
    // Check ownership
    const { data: existingPost } = await supabaseAdmin
      .from('posts')
      .select('user_id')
      .eq('id', postId)
      .single();
    
    if (!existingPost || existingPost.user_id !== req.user.id) {
      return res.status(403).json({ 
        success: false, 
        message: 'Not authorized to update this post' 
      });
    }
    
    const updateData = {
      ...req.body,
      updated_at: new Date().toISOString()
    };
    
    if (updateData.title) {
      updateData.slug = generateSlug(updateData.title);
    }
    
    const { data: post, error } = await supabaseAdmin
      .from('posts')
      .update(updateData)
      .eq('id', postId)
      .select()
      .single();
    
    if (error) throw error;
    
    res.json({
      success: true,
      message: 'Post updated successfully',
      post
    });
    
  } catch (error) {
    console.error('Post update error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to update post' 
    });
  }
});

// Delete post
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const postId = req.params.id;
    
    // Check ownership or admin
    const { data: existingPost } = await supabaseAdmin
      .from('posts')
      .select('user_id')
      .eq('id', postId)
      .single();
    
    if (!existingPost) {
      return res.status(404).json({ 
        success: false, 
        message: 'Post not found' 
      });
    }
    
    if (existingPost.user_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false, 
        message: 'Not authorized to delete this post' 
      });
    }
    
    // Soft delete
    await supabaseAdmin
      .from('posts')
      .update({ 
        status: 'deleted',
        updated_at: new Date().toISOString()
      })
      .eq('id', postId);
    
    res.json({
      success: true,
      message: 'Post deleted successfully'
    });
    
  } catch (error) {
    console.error('Post delete error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to delete post' 
    });
  }
});

// Like/unlike post
app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
  try {
    const postId = req.params.id;
    
    // Check if already liked
    const { data: post } = await supabaseAdmin
      .from('posts')
      .select('likes')
      .eq('id', postId)
      .single();
    
    if (!post) {
      return res.status(404).json({ 
        success: false, 
        message: 'Post not found' 
      });
    }
    
    // Toggle like
    await supabaseAdmin.rpc('increment', {
      table_name: 'posts',
      id: postId,
      column: 'likes'
    });
    
    res.json({
      success: true,
      message: 'Post liked'
    });
    
  } catch (error) {
    console.error('Like error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to like post' 
    });
  }
});

// Save/unsave post
app.post('/api/posts/:id/save', authenticateToken, async (req, res) => {
  try {
    const postId = req.params.id;
    
    // Check if already saved
    const { data: existing } = await supabaseAdmin
      .from('saved_items')
      .select('id')
      .eq('user_id', req.user.id)
      .eq('post_id', postId)
      .single();
    
    if (existing) {
      // Unsave
      await supabaseAdmin
        .from('saved_items')
        .delete()
        .eq('id', existing.id);
      
      await supabaseAdmin.rpc('decrement', {
        table_name: 'posts',
        id: postId,
        column: 'saves'
      });
      
      return res.json({
        success: true,
        message: 'Post unsaved',
        saved: false
      });
    } else {
      // Save
      const savedItem = {
        id: uuidv4(),
        user_id: req.user.id,
        post_id: postId,
        created_at: new Date().toISOString()
      };
      
      await supabaseAdmin.from('saved_items').insert([savedItem]);
      
      await supabaseAdmin.rpc('increment', {
        table_name: 'posts',
        id: postId,
        column: 'saves'
      });
      
      return res.json({
        success: true,
        message: 'Post saved',
        saved: true
      });
    }
    
  } catch (error) {
    console.error('Save error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to save post' 
    });
  }
});

// Boost post
app.post('/api/posts/:id/boost', authenticateToken, async (req, res) => {
  try {
    const postId = req.params.id;
    
    // Check ownership
    const { data: post } = await supabaseAdmin
      .from('posts')
      .select('user_id, boosted')
      .eq('id', postId)
      .single();
    
    if (!post || post.user_id !== req.user.id) {
      return res.status(403).json({ 
        success: false, 
        message: 'Not authorized to boost this post' 
      });
    }
    
    if (post.boosted) {
      return res.status(400).json({ 
        success: false, 
        message: 'Post is already boosted' 
      });
    }
    
    // Check if user is premium (free boost)
    if (req.user.upgraded) {
      // Free boost for premium users
      await supabaseAdmin
        .from('posts')
        .update({
          boosted: true,
          boost_expires_at: calculateBoostExpiry(),
          updated_at: new Date().toISOString()
        })
        .eq('id', postId);
      
      return res.json({
        success: true,
        message: 'Post boosted successfully (free for premium users)'
      });
    }
    
    // Non-premium users need to pay
    // Check balance
    if (req.user.earnings_balance < 100) {
      return res.status(400).json({ 
        success: false, 
        message: 'Insufficient balance. Need KES 100 to boost.' 
      });
    }
    
    // Deduct from balance and boost
    await supabaseAdmin
      .from('users')
      .update({
        earnings_balance: req.user.earnings_balance - 100,
        updated_at: new Date().toISOString()
      })
      .eq('id', req.user.id);
    
    await supabaseAdmin
      .from('posts')
      .update({
        boosted: true,
        boost_expires_at: calculateBoostExpiry(),
        updated_at: new Date().toISOString()
      })
      .eq('id', postId);
    
    // Record payment
    const payment = {
      id: uuidv4(),
      user_id: req.user.id,
      amount: 100.00,
      type: 'boost',
      transaction_code: `BOOST-${Date.now()}-${postId}`,
      status: 'approved',
      post_id: postId,
      processed_at: new Date().toISOString(),
      created_at: new Date().toISOString()
    };
    
    await supabaseAdmin.from('payments').insert([payment]);
    
    res.json({
      success: true,
      message: 'Post boosted successfully'
    });
    
  } catch (error) {
    console.error('Boost error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to boost post' 
    });
  }
});

// Get user's saved posts
app.get('/api/posts/saved', authenticateToken, async (req, res) => {
  try {
    const { data: savedItems } = await supabaseAdmin
      .from('saved_items')
      .select(`
        post:posts(*, user:users(id, name, profile_picture))
      `)
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });
    
    const posts = savedItems?.map(item => item.post) || [];
    
    res.json({
      success: true,
      posts
    });
    
  } catch (error) {
    console.error('Saved posts error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch saved posts' 
    });
  }
});

// ============================================
// PAYMENT & SUBSCRIPTION ENDPOINTS
// ============================================

// Subscribe to platform
app.post('/api/payments/subscribe', authenticateToken, async (req, res) => {
  try {
    const { transactionCode } = req.body;
    
    if (!transactionCode) {
      return res.status(400).json({ 
        success: false, 
        message: 'Transaction code is required' 
      });
    }
    
    // Check if already subscribed
    if (req.user.subscription_active) {
      return res.status(400).json({ 
        success: false, 
        message: 'You already have an active subscription' 
      });
    }
    
    const payment = {
      id: uuidv4(),
      user_id: req.user.id,
      amount: 50.00,
      type: 'subscription',
      transaction_code: transactionCode,
      status: 'pending',
      created_at: new Date().toISOString()
    };
    
    const { error } = await supabaseAdmin
      .from('payments')
      .insert([payment]);
    
    if (error) throw error;
    
    // Send notification to admin
    const adminNotification = {
      id: uuidv4(),
      user_id: req.user.id,
      type: 'subscription_request',
      title: 'New Subscription Request',
      message: `User ${req.user.name} has requested subscription. Transaction: ${transactionCode}`,
      data: { paymentId: payment.id, userId: req.user.id },
      created_at: new Date().toISOString()
    };
    
    await supabaseAdmin.from('notifications').insert([adminNotification]);
    
    res.json({
      success: true,
      message: 'Subscription request submitted for admin approval',
      payment
    });
    
  } catch (error) {
    console.error('Subscription error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to process subscription' 
    });
  }
});

// Upgrade to premium
app.post('/api/payments/upgrade', authenticateToken, async (req, res) => {
  try {
    const { transactionCode } = req.body;
    
    if (!transactionCode) {
      return res.status(400).json({ 
        success: false, 
        message: 'Transaction code is required' 
      });
    }
    
    // Check if already upgraded
    if (req.user.upgraded) {
      return res.status(400).json({ 
        success: false, 
        message: 'You are already upgraded' 
      });
    }
    
    const payment = {
      id: uuidv4(),
      user_id: req.user.id,
      amount: 200.00,
      type: 'upgrade',
      transaction_code: transactionCode,
      status: 'pending',
      created_at: new Date().toISOString()
    };
    
    const { error } = await supabaseAdmin
      .from('payments')
      .insert([payment]);
    
    if (error) throw error;
    
    // Handle referral commission for upgrade
    if (req.user.referral_from) {
      const { data: referrer } = await supabaseAdmin
        .from('users')
        .select('id')
        .eq('referral_code', req.user.referral_from)
        .single();
      
      if (referrer) {
        const referral = {
          id: uuidv4(),
          referrer_id: referrer.id,
          referred_user_id: req.user.id,
          commission: 100.00,
          type: 'upgrade',
          status: 'pending',
          created_at: new Date().toISOString()
        };
        
        await supabaseAdmin.from('referrals').insert([referral]);
      }
    }
    
    // Send notification to admin
    const adminNotification = {
      id: uuidv4(),
      user_id: req.user.id,
      type: 'upgrade_request',
      title: 'New Upgrade Request',
      message: `User ${req.user.name} has requested upgrade to premium. Transaction: ${transactionCode}`,
      data: { paymentId: payment.id, userId: req.user.id },
      created_at: new Date().toISOString()
    };
    
    await supabaseAdmin.from('notifications').insert([adminNotification]);
    
    res.json({
      success: true,
      message: 'Upgrade request submitted for admin approval',
      payment
    });
    
  } catch (error) {
    console.error('Upgrade error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to process upgrade' 
    });
  }
});

// Get user payments
app.get('/api/payments', authenticateToken, async (req, res) => {
  try {
    const { data: payments } = await supabaseAdmin
      .from('payments')
      .select('*')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });
    
    res.json({
      success: true,
      payments: payments || []
    });
    
  } catch (error) {
    console.error('Payments fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch payments' 
    });
  }
});

// ============================================
// WITHDRAWAL ENDPOINTS
// ============================================

// Request withdrawal
app.post('/api/withdrawals', authenticateToken, async (req, res) => {
  try {
    const { amount, mpesaNumber } = req.body;
    
    if (!amount || amount < 100) {
      return res.status(400).json({ 
        success: false, 
        message: 'Minimum withdrawal is KES 100' 
      });
    }
    
    if (!mpesaNumber || !validatePhone(mpesaNumber)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Valid M-Pesa number required (format: 2547XXXXXXXX)' 
      });
    }
    
    // Check balance
    if (amount > req.user.earnings_balance) {
      return res.status(400).json({ 
        success: false, 
        message: 'Insufficient balance' 
      });
    }
    
    // Calculate fee (10%)
    const fee = amount * 0.10;
    const netAmount = amount - fee;
    
    const withdrawal = {
      id: uuidv4(),
      user_id: req.user.id,
      amount: parseFloat(amount),
      fee: parseFloat(fee.toFixed(2)),
      net_amount: parseFloat(netAmount.toFixed(2)),
      mpesa_number: mpesaNumber,
      status: 'pending',
      created_at: new Date().toISOString()
    };
    
    const { error } = await supabaseAdmin
      .from('withdrawals')
      .insert([withdrawal]);
    
    if (error) throw error;
    
    // Send notification to admin
    const adminNotification = {
      id: uuidv4(),
      user_id: req.user.id,
      type: 'withdrawal_request',
      title: 'New Withdrawal Request',
      message: `User ${req.user.name} has requested KES ${amount} withdrawal to ${mpesaNumber}`,
      data: { withdrawalId: withdrawal.id, userId: req.user.id },
      created_at: new Date().toISOString()
    };
    
    await supabaseAdmin.from('notifications').insert([adminNotification]);
    
    res.json({
      success: true,
      message: 'Withdrawal request submitted for admin approval',
      withdrawal
    });
    
  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to process withdrawal' 
    });
  }
});

// Get user withdrawals
app.get('/api/withdrawals', authenticateToken, async (req, res) => {
  try {
    const { data: withdrawals } = await supabaseAdmin
      .from('withdrawals')
      .select('*')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });
    
    res.json({
      success: true,
      withdrawals: withdrawals || []
    });
    
  } catch (error) {
    console.error('Withdrawals fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch withdrawals' 
    });
  }
});

// ============================================
// SHOP MANAGEMENT ENDPOINTS
// ============================================

// Create or update shop
app.post('/api/shops', authenticateToken, async (req, res) => {
  try {
    // Check if user is premium
    if (!req.user.upgraded) {
      return res.status(403).json({ 
        success: false, 
        message: 'Premium upgrade required to create shop' 
      });
    }
    
    const shopData = {
      id: uuidv4(),
      user_id: req.user.id,
      ...req.body,
      slug: generateSlug(req.body.name),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    // Check if shop exists
    const { data: existingShop } = await supabaseAdmin
      .from('shops')
      .select('id')
      .eq('user_id', req.user.id)
      .single();
    
    let result;
    if (existingShop) {
      // Update
      const { data, error } = await supabaseAdmin
        .from('shops')
        .update({
          ...req.body,
          slug: generateSlug(req.body.name),
          updated_at: new Date().toISOString()
        })
        .eq('id', existingShop.id)
        .select()
        .single();
      
      result = data;
      if (error) throw error;
    } else {
      // Create
      const { data, error } = await supabaseAdmin
        .from('shops')
        .insert([shopData])
        .select()
        .single();
      
      result = data;
      if (error) throw error;
    }
    
    res.json({
      success: true,
      message: existingShop ? 'Shop updated successfully' : 'Shop created successfully',
      shop: result
    });
    
  } catch (error) {
    console.error('Shop error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to process shop request' 
    });
  }
});

// Get user's shop
app.get('/api/shops/me', authenticateToken, async (req, res) => {
  try {
    const { data: shop, error } = await supabaseAdmin
      .from('shops')
      .select(`
        *,
        products:shop_products(count),
        reviews:reviews(count)
      `)
      .eq('user_id', req.user.id)
      .single();
    
    if (error && error.code !== 'PGRST116') throw error;
    
    // Get shop stats
    let stats = {};
    if (shop) {
      const { count: productsCount } = await supabaseAdmin
        .from('shop_products')
        .select('*', { count: 'exact', head: true })
        .eq('shop_id', shop.id);
      
      const { count: servicesCount } = await supabaseAdmin
        .from('posts')
        .select('*', { count: 'exact', head: true })
        .eq('user_id', req.user.id)
        .eq('type', 'service');
      
      stats = {
        productsCount: productsCount || 0,
        servicesCount: servicesCount || 0,
        totalSales: shop.total_sales || 0,
        totalRevenue: shop.total_revenue || 0,
        rating: shop.rating || 0
      };
    }
    
    res.json({
      success: true,
      shop: shop || null,
      stats
    });
    
  } catch (error) {
    console.error('Shop fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch shop' 
    });
  }
});

// Get shop by ID or slug
app.get('/api/shops/:identifier', async (req, res) => {
  try {
    const { identifier } = req.params;
    
    let query;
    if (identifier.includes('-')) {
      // Probably a slug
      query = supabaseAdmin
        .from('shops')
        .select(`
          *,
          user:users(name, profile_picture, verified),
          products:shop_products(post:posts(*))
        `)
        .eq('slug', identifier)
        .eq('status', 'active');
    } else {
      // Probably an ID
      query = supabaseAdmin
        .from('shops')
        .select(`
          *,
          user:users(name, profile_picture, verified),
          products:shop_products(post:posts(*))
        `)
        .eq('id', identifier)
        .eq('status', 'active');
    }
    
    const { data: shop, error } = await query.single();
    
    if (error || !shop) {
      return res.status(404).json({ 
        success: false, 
        message: 'Shop not found' 
      });
    }
    
    res.json({
      success: true,
      shop
    });
    
  } catch (error) {
    console.error('Shop fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch shop' 
    });
  }
});

// Get shop products
app.get('/api/shops/:id/products', async (req, res) => {
  try {
    const shopId = req.params.id;
    
    const { data: shopProducts } = await supabaseAdmin
      .from('shop_products')
      .select(`
        post:posts(*, user:users(name, profile_picture))
      `)
      .eq('shop_id', shopId)
      .order('created_at', { ascending: false });
    
    const products = shopProducts?.map(item => item.post) || [];
    
    res.json({
      success: true,
      products
    });
    
  } catch (error) {
    console.error('Shop products error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch shop products' 
    });
  }
});

// ============================================
// CV MANAGEMENT ENDPOINTS
// ============================================

// Upload CV
app.post('/api/cvs', authenticateToken, async (req, res) => {
  try {
    const { title, summary, skills, experience, education, expectedSalary, location, fileUrl, fileName, fileSize } = req.body;
    
    if (!title || !fileUrl) {
      return res.status(400).json({ 
        success: false, 
        message: 'Title and file URL are required' 
      });
    }
    
    const cvData = {
      id: uuidv4(),
      user_id: req.user.id,
      title,
      file_url: fileUrl,
      file_name: fileName || 'cv',
      file_size: fileSize || 0,
      summary: summary || '',
      skills: skills ? skills.split(',').map(s => s.trim()) : [],
      experience: experience || '',
      education: education || '',
      expected_salary: expectedSalary ? parseFloat(expectedSalary) : null,
      location: location || '',
      uploaded_at: new Date().toISOString(),
      status: 'active'
    };
    
    const { data: cv, error } = await supabaseAdmin
      .from('cvs')
      .insert([cvData])
      .select()
      .single();
    
    if (error) throw error;
    
    res.status(201).json({
      success: true,
      message: 'CV uploaded successfully',
      cv
    });
    
  } catch (error) {
    console.error('CV upload error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to upload CV' 
    });
  }
});

// Get user's CVs
app.get('/api/cvs', authenticateToken, async (req, res) => {
  try {
    const { data: cvs } = await supabaseAdmin
      .from('cvs')
      .select('*')
      .eq('user_id', req.user.id)
      .eq('status', 'active')
      .order('uploaded_at', { ascending: false });
    
    res.json({
      success: true,
      cvs: cvs || []
    });
    
  } catch (error) {
    console.error('CVs fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch CVs' 
    });
  }
});

// Get CV by ID
app.get('/api/cvs/:id', async (req, res) => {
  try {
    const cvId = req.params.id;
    
    const { data: cv, error } = await supabaseAdmin
      .from('cvs')
      .select('*')
      .eq('id', cvId)
      .eq('status', 'active')
      .single();
    
    if (error || !cv) {
      return res.status(404).json({ 
        success: false, 
        message: 'CV not found' 
      });
    }
    
    // Increment views
    await supabaseAdmin.rpc('increment', {
      table_name: 'cvs',
      id: cvId,
      column: 'views'
    });
    
    res.json({
      success: true,
      cv
    });
    
  } catch (error) {
    console.error('CV fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch CV' 
    });
  }
});

// Delete CV
app.delete('/api/cvs/:id', authenticateToken, async (req, res) => {
  try {
    const cvId = req.params.id;
    
    // Check ownership
    const { data: cv } = await supabaseAdmin
      .from('cvs')
      .select('user_id')
      .eq('id', cvId)
      .single();
    
    if (!cv || cv.user_id !== req.user.id) {
      return res.status(403).json({ 
        success: false, 
        message: 'Not authorized to delete this CV' 
      });
    }
    
    // Soft delete
    await supabaseAdmin
      .from('cvs')
      .update({ 
        status: 'deleted',
        updated_at: new Date().toISOString()
      })
      .eq('id', cvId);
    
    res.json({
      success: true,
      message: 'CV deleted successfully'
    });
    
  } catch (error) {
    console.error('CV delete error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to delete CV' 
    });
  }
});

// ============================================
// ORDER MANAGEMENT ENDPOINTS
// ============================================

// Create order
app.post('/api/orders', authenticateToken, async (req, res) => {
  try {
    const { postId, quantity, shippingAddress, customerName, customerPhone, customerEmail, notes } = req.body;
    
    if (!postId || !quantity || !customerName || !customerPhone) {
      return res.status(400).json({ 
        success: false, 
        message: 'Required fields: postId, quantity, customerName, customerPhone' 
      });
    }
    
    // Get post details
    const { data: post } = await supabaseAdmin
      .from('posts')
      .select('*, user:users(*), shop:shops(*)')
      .eq('id', postId)
      .single();
    
    if (!post) {
      return res.status(404).json({ 
        success: false, 
        message: 'Post not found' 
      });
    }
    
    // Generate order number
    const orderNumber = `ORD-${Date.now()}-${Math.random().toString(36).substring(2, 7).toUpperCase()}`;
    
    // Calculate prices
    const unitPrice = post.price || post.price_min || 0;
    const totalPrice = unitPrice * quantity;
    const shippingFee = 0; // Could be calculated based on location
    const tax = totalPrice * 0.16; // 16% VAT for Kenya
    const finalPrice = totalPrice + shippingFee + tax;
    
    const orderData = {
      id: uuidv4(),
      order_number: orderNumber,
      user_id: req.user.id,
      shop_id: post.shop?.id || null,
      post_id: postId,
      quantity,
      unit_price: unitPrice,
      total_price: totalPrice,
      shipping_fee: shippingFee,
      tax: tax,
      final_price: finalPrice,
      customer_name: customerName,
      customer_phone: customerPhone,
      customer_email: customerEmail || req.user.email,
      shipping_address: shippingAddress || '',
      payment_method: 'mpesa',
      payment_status: 'pending',
      order_status: 'pending',
      notes: notes || '',
      created_at: new Date().toISOString()
    };
    
    const { data: order, error } = await supabaseAdmin
      .from('orders')
      .insert([orderData])
      .select()
      .single();
    
    if (error) throw error;
    
    // Send notifications
    const buyerNotification = {
      id: uuidv4(),
      user_id: req.user.id,
      type: 'order_created',
      title: 'Order Created',
      message: `Your order #${orderNumber} has been created successfully.`,
      data: { orderId: order.id, orderNumber },
      created_at: new Date().toISOString()
    };
    
    await supabaseAdmin.from('notifications').insert([buyerNotification]);
    
    if (post.user_id) {
      const sellerNotification = {
        id: uuidv4(),
        user_id: post.user_id,
        type: 'new_order',
        title: 'New Order Received',
        message: `You have a new order #${orderNumber} for "${post.title}".`,
        data: { orderId: order.id, orderNumber, postId },
        created_at: new Date().toISOString()
      };
      
      await supabaseAdmin.from('notifications').insert([sellerNotification]);
    }
    
    res.status(201).json({
      success: true,
      message: 'Order created successfully',
      order
    });
    
  } catch (error) {
    console.error('Order creation error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to create order' 
    });
  }
});

// Get user's orders
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const { type = 'buyer' } = req.query;
    
    let query;
    if (type === 'buyer') {
      // Orders where user is buyer
      query = supabaseAdmin
        .from('orders')
        .select(`
          *,
          post:posts(*, user:users(name, profile_picture)),
          shop:shops(name, logo)
        `)
        .eq('user_id', req.user.id);
    } else {
      // Orders where user is seller
      query = supabaseAdmin
        .from('orders')
        .select(`
          *,
          post:posts(*, user:users(name, profile_picture)),
          shop:shops(name, logo)
        `)
        .eq('post.user_id', req.user.id);
    }
    
    const { data: orders } = await query.order('created_at', { ascending: false });
    
    res.json({
      success: true,
      orders: orders || []
    });
    
  } catch (error) {
    console.error('Orders fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch orders' 
    });
  }
});

// Update order status
app.put('/api/orders/:id/status', authenticateToken, async (req, res) => {
  try {
    const orderId = req.params.id;
    const { status, notes } = req.body;
    
    if (!status) {
      return res.status(400).json({ 
        success: false, 
        message: 'Status is required' 
      });
    }
    
    // Get order to check ownership
    const { data: order } = await supabaseAdmin
      .from('orders')
      .select('*, post:posts(user_id)')
      .eq('id', orderId)
      .single();
    
    if (!order) {
      return res.status(404).json({ 
        success: false, 
        message: 'Order not found' 
      });
    }
    
    // Check if user is seller or admin
    const isSeller = order.post?.user_id === req.user.id;
    const isBuyer = order.user_id === req.user.id;
    const isAdmin = req.user.role === 'admin';
    
    if (!isSeller && !isBuyer && !isAdmin) {
      return res.status(403).json({ 
        success: false, 
        message: 'Not authorized to update this order' 
      });
    }
    
    const updateData = {
      order_status: status,
      updated_at: new Date().toISOString()
    };
    
    if (notes) updateData.notes = notes;
    
    const { data: updatedOrder } = await supabaseAdmin
      .from('orders')
      .update(updateData)
      .eq('id', orderId)
      .select()
      .single();
    
    // Send notification to other party
    const notificationTo = isSeller ? order.user_id : order.post?.user_id;
    if (notificationTo) {
      const notification = {
        id: uuidv4(),
        user_id: notificationTo,
        type: 'order_updated',
        title: 'Order Status Updated',
        message: `Order #${order.order_number} status updated to: ${status}`,
        data: { orderId: order.id, orderNumber: order.order_number, status },
        created_at: new Date().toISOString()
      };
      
      await supabaseAdmin.from('notifications').insert([notification]);
    }
    
    res.json({
      success: true,
      message: 'Order status updated',
      order: updatedOrder
    });
    
  } catch (error) {
    console.error('Order update error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to update order' 
    });
  }
});

// ============================================
// REVIEWS & RATINGS ENDPOINTS
// ============================================

// Create review
app.post('/api/reviews', authenticateToken, async (req, res) => {
  try {
    const { postId, shopId, rating, comment, images } = req.body;
    
    if (!rating || (rating < 1 || rating > 5)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Rating must be between 1 and 5' 
      });
    }
    
    // Check if user has purchased the item
    if (postId) {
      const { data: order } = await supabaseAdmin
        .from('orders')
        .select('id')
        .eq('post_id', postId)
        .eq('user_id', req.user.id)
        .eq('order_status', 'completed')
        .single();
      
      if (!order) {
        return res.status(403).json({ 
          success: false, 
          message: 'You must have purchased this item to review it' 
        });
      }
    }
    
    const reviewData = {
      id: uuidv4(),
      user_id: req.user.id,
      post_id: postId || null,
      shop_id: shopId || null,
      rating: parseInt(rating),
      comment: comment || '',
      images: images || [],
      status: 'active',
      created_at: new Date().toISOString()
    };
    
    const { data: review, error } = await supabaseAdmin
      .from('reviews')
      .insert([reviewData])
      .select(`
        *,
        user:users(name, profile_picture)
      `)
      .single();
    
    if (error) throw error;
    
    // Update shop rating if applicable
    if (shopId) {
      const { data: shopReviews } = await supabaseAdmin
        .from('reviews')
        .select('rating')
        .eq('shop_id', shopId)
        .eq('status', 'active');
      
      if (shopReviews && shopReviews.length > 0) {
        const totalRating = shopReviews.reduce((sum, r) => sum + r.rating, 0);
        const averageRating = totalRating / shopReviews.length;
        
        await supabaseAdmin
          .from('shops')
          .update({
            rating: averageRating,
            total_ratings: shopReviews.length,
            updated_at: new Date().toISOString()
          })
          .eq('id', shopId);
      }
    }
    
    res.status(201).json({
      success: true,
      message: 'Review submitted successfully',
      review
    });
    
  } catch (error) {
    console.error('Review error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to submit review' 
    });
  }
});

// Get reviews
app.get('/api/reviews', async (req, res) => {
  try {
    const { postId, shopId, userId, page = 1, limit = 20 } = req.query;
    
    let query = supabaseAdmin
      .from('reviews')
      .select(`
        *,
        user:users(name, profile_picture),
        post:posts(title, images)
      `, { count: 'exact' })
      .eq('status', 'active');
    
    if (postId) query = query.eq('post_id', postId);
    if (shopId) query = query.eq('shop_id', shopId);
    if (userId) query = query.eq('user_id', userId);
    
    query = query.order('created_at', { ascending: false })
      .range((page - 1) * limit, page * limit - 1);
    
    const { data: reviews, error, count } = await query;
    
    if (error) throw error;
    
    res.json({
      success: true,
      reviews: reviews || [],
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count || 0,
        pages: Math.ceil((count || 0) / limit)
      }
    });
    
  } catch (error) {
    console.error('Reviews fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch reviews' 
    });
  }
});

// ============================================
// NOTIFICATION ENDPOINTS
// ============================================

// Get user notifications
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const { unreadOnly = 'false', page = 1, limit = 20 } = req.query;
    
    let query = supabaseAdmin
      .from('notifications')
      .select('*', { count: 'exact' })
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });
    
    if (unreadOnly === 'true') {
      query = query.eq('read', false);
    }
    
    query = query.range((page - 1) * limit, page * limit - 1);
    
    const { data: notifications, error, count } = await query;
    
    if (error) throw error;
    
    res.json({
      success: true,
      notifications: notifications || [],
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count || 0,
        pages: Math.ceil((count || 0) / limit)
      }
    });
    
  } catch (error) {
    console.error('Notifications error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch notifications' 
    });
  }
});

// Mark notification as read
app.put('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const notificationId = req.params.id;
    
    await supabaseAdmin
      .from('notifications')
      .update({ read: true })
      .eq('id', notificationId)
      .eq('user_id', req.user.id);
    
    res.json({
      success: true,
      message: 'Notification marked as read'
    });
    
  } catch (error) {
    console.error('Notification read error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to update notification' 
    });
  }
});

// Mark all notifications as read
app.put('/api/notifications/read-all', authenticateToken, async (req, res) => {
  try {
    await supabaseAdmin
      .from('notifications')
      .update({ read: true })
      .eq('user_id', req.user.id)
      .eq('read', false);
    
    res.json({
      success: true,
      message: 'All notifications marked as read'
    });
    
  } catch (error) {
    console.error('Notifications read all error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to update notifications' 
    });
  }
});

// Delete notification
app.delete('/api/notifications/:id', authenticateToken, async (req, res) => {
  try {
    const notificationId = req.params.id;
    
    await supabaseAdmin
      .from('notifications')
      .delete()
      .eq('id', notificationId)
      .eq('user_id', req.user.id);
    
    res.json({
      success: true,
      message: 'Notification deleted'
    });
    
  } catch (error) {
    console.error('Notification delete error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to delete notification' 
    });
  }
});

// ============================================
// MESSAGING ENDPOINTS
// ============================================

// Send message
app.post('/api/messages', authenticateToken, async (req, res) => {
  try {
    const { receiverId, postId, message } = req.body;
    
    if (!receiverId || !message) {
      return res.status(400).json({ 
        success: false, 
        message: 'Receiver ID and message are required' 
      });
    }
    
    // Don't allow messaging yourself
    if (receiverId === req.user.id) {
      return res.status(400).json({ 
        success: false, 
        message: 'Cannot send message to yourself' 
      });
    }
    
    const messageData = {
      id: uuidv4(),
      sender_id: req.user.id,
      receiver_id: receiverId,
      post_id: postId || null,
      message,
      created_at: new Date().toISOString()
    };
    
    const { data: newMessage, error } = await supabaseAdmin
      .from('messages')
      .insert([messageData])
      .select(`
        *,
        sender:users(name, profile_picture),
        receiver:users(name, profile_picture)
      `)
      .single();
    
    if (error) throw error;
    
    // Create notification for receiver
    const notification = {
      id: uuidv4(),
      user_id: receiverId,
      type: 'new_message',
      title: 'New Message',
      message: `You have a new message from ${req.user.name}`,
      data: { messageId: newMessage.id, senderId: req.user.id },
      created_at: new Date().toISOString()
    };
    
    await supabaseAdmin.from('notifications').insert([notification]);
    
    res.status(201).json({
      success: true,
      message: 'Message sent successfully',
      message: newMessage
    });
    
  } catch (error) {
    console.error('Message error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to send message' 
    });
  }
});

// Get conversations
app.get('/api/messages/conversations', authenticateToken, async (req, res) => {
  try {
    // Get distinct conversations
    const { data: conversations } = await supabaseAdmin
      .from('messages')
      .select(`
        receiver:users!messages_receiver_id_fkey(id, name, profile_picture),
        sender:users!messages_sender_id_fkey(id, name, profile_picture)
      `)
      .or(`sender_id.eq.${req.user.id},receiver_id.eq.${req.user.id}`);
    
    // Process to get unique conversations
    const uniqueConversations = [];
    const seenUsers = new Set();
    
    conversations?.forEach(conv => {
      const otherUser = conv.receiver.id === req.user.id ? conv.sender : conv.receiver;
      
      if (!seenUsers.has(otherUser.id)) {
        seenUsers.add(otherUser.id);
        uniqueConversations.push({
          user: otherUser,
          unreadCount: 0 // You would calculate this
        });
      }
    });
    
    res.json({
      success: true,
      conversations: uniqueConversations
    });
    
  } catch (error) {
    console.error('Conversations error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch conversations' 
    });
  }
});

// Get messages with a user
app.get('/api/messages/:userId', authenticateToken, async (req, res) => {
  try {
    const otherUserId = req.params.userId;
    
    const { data: messages } = await supabaseAdmin
      .from('messages')
      .select(`
        *,
        sender:users(name, profile_picture),
        receiver:users(name, profile_picture)
      `)
      .or(
        `and(sender_id.eq.${req.user.id},receiver_id.eq.${otherUserId}),` +
        `and(sender_id.eq.${otherUserId},receiver_id.eq.${req.user.id})`
      )
      .order('created_at', { ascending: true });
    
    // Mark messages as read
    await supabaseAdmin
      .from('messages')
      .update({ read: true })
      .eq('receiver_id', req.user.id)
      .eq('sender_id', otherUserId)
      .eq('read', false);
    
    res.json({
      success: true,
      messages: messages || []
    });
    
  } catch (error) {
    console.error('Messages error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch messages' 
    });
  }
});

// ============================================
// STATISTICS & ANALYTICS ENDPOINTS
// ============================================

// Get platform stats
app.get('/api/stats', async (req, res) => {
  try {
    const [
      { count: totalUsers },
      { count: totalPosts },
      { count: activeTransactions },
      { data: earningsData },
      { count: totalShops },
      { count: todayPosts }
    ] = await Promise.all([
      supabaseAdmin.from('users').select('*', { count: 'exact', head: true }),
      supabaseAdmin.from('posts').select('*', { count: 'exact', head: true }).eq('status', 'active'),
      supabaseAdmin.from('payments').select('*', { count: 'exact', head: true }).eq('status', 'pending'),
      supabaseAdmin.from('withdrawals').select('amount').eq('status', 'approved'),
      supabaseAdmin.from('shops').select('*', { count: 'exact', head: true }).eq('status', 'active'),
      supabaseAdmin.from('posts').select('*', { count: 'exact', head: true })
        .eq('status', 'active')
        .gte('created_at', new Date().toISOString().split('T')[0])
    ]);
    
    const totalEarnings = earningsData?.reduce((sum, item) => sum + (item.amount || 0), 0) || 0;
    
    res.json({
      success: true,
      stats: {
        totalUsers: totalUsers || 0,
        totalPosts: totalPosts || 0,
        totalEarnings,
        activeTransactions: activeTransactions || 0,
        totalShops: totalShops || 0,
        todayPosts: todayPosts || 0
      }
    });
    
  } catch (error) {
    console.error('Stats fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch statistics' 
    });
  }
});

// Get user dashboard stats
app.get('/api/users/stats', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const [
      { count: productsCount },
      { count: servicesCount },
      { count: jobsCount },
      { count: socialCount },
      { count: totalReferrals },
      { data: referralsData },
      { data: withdrawalsData },
      { data: ordersData },
      { data: viewsData }
    ] = await Promise.all([
      supabaseAdmin.from('posts').select('*', { count: 'exact', head: true })
        .eq('user_id', userId).eq('type', 'product').eq('status', 'active'),
      supabaseAdmin.from('posts').select('*', { count: 'exact', head: true })
        .eq('user_id', userId).eq('type', 'service').eq('status', 'active'),
      supabaseAdmin.from('posts').select('*', { count: 'exact', head: true })
        .eq('user_id', userId).eq('type', 'job').eq('status', 'active'),
      supabaseAdmin.from('posts').select('*', { count: 'exact', head: true })
        .eq('user_id', userId).eq('type', 'social').eq('status', 'active'),
      supabaseAdmin.from('referrals').select('*', { count: 'exact', head: true })
        .eq('referrer_id', userId).eq('status', 'approved'),
      supabaseAdmin.from('referrals').select('commission')
        .eq('referrer_id', userId).eq('status', 'approved'),
      supabaseAdmin.from('withdrawals').select('amount')
        .eq('user_id', userId).eq('status', 'approved'),
      supabaseAdmin.from('orders').select('final_price')
        .eq('post.user_id', userId).eq('order_status', 'completed'),
      supabaseAdmin.from('posts').select('views')
        .eq('user_id', userId).eq('status', 'active')
    ]);
    
    const totalEarned = referralsData?.reduce((sum, item) => sum + (item.commission || 0), 0) || 0;
    const totalWithdrawn = withdrawalsData?.reduce((sum, item) => sum + (item.amount || 0), 0) || 0;
    const totalSales = ordersData?.reduce((sum, item) => sum + (item.final_price || 0), 0) || 0;
    const totalViews = viewsData?.reduce((sum, item) => sum + (item.views || 0), 0) || 0;
    const availableBalance = totalEarned - totalWithdrawn;
    
    res.json({
      success: true,
      stats: {
        productsCount: productsCount || 0,
        servicesCount: servicesCount || 0,
        jobsCount: jobsCount || 0,
        socialCount: socialCount || 0,
        totalViews,
        totalReferrals: totalReferrals || 0,
        totalEarned,
        totalWithdrawn,
        totalSales,
        availableBalance
      }
    });
    
  } catch (error) {
    console.error('User stats error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch user statistics' 
    });
  }
});

// Get analytics
app.get('/api/analytics', authenticateToken, async (req, res) => {
  try {
    const { timeframe = '7d' } = req.query;
    
    let dateFilter = new Date();
    switch (timeframe) {
      case '24h':
        dateFilter.setDate(dateFilter.getDate() - 1);
        break;
      case '7d':
        dateFilter.setDate(dateFilter.getDate() - 7);
        break;
      case '30d':
        dateFilter.setDate(dateFilter.getDate() - 30);
        break;
      default:
        dateFilter.setDate(dateFilter.getDate() - 7);
    }
    
    const { data: analytics } = await supabaseAdmin
      .from('analytics')
      .select('*')
      .eq('user_id', req.user.id)
      .gte('created_at', dateFilter.toISOString())
      .order('created_at', { ascending: false });
    
    res.json({
      success: true,
      analytics: analytics || []
    });
    
  } catch (error) {
    console.error('Analytics error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch analytics' 
    });
  }
});

// ============================================
// REFERRAL SYSTEM ENDPOINTS
// ============================================

// Get referral stats
app.get('/api/referrals/stats', authenticateToken, async (req, res) => {
  try {
    const { data: referrals } = await supabaseAdmin
      .from('referrals')
      .select('*')
      .eq('referrer_id', req.user.id)
      .order('created_at', { ascending: false });
    
    const stats = {
      total: referrals?.length || 0,
      pending: referrals?.filter(r => r.status === 'pending').length || 0,
      approved: referrals?.filter(r => r.status === 'approved').length || 0,
      paid: referrals?.filter(r => r.status === 'paid').length || 0,
      totalCommission: referrals?.reduce((sum, r) => sum + (r.commission || 0), 0) || 0
    };
    
    res.json({
      success: true,
      stats,
      referrals: referrals || []
    });
    
  } catch (error) {
    console.error('Referral stats error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch referral stats' 
    });
  }
});

// Get referral link
app.get('/api/referrals/link', authenticateToken, async (req, res) => {
  try {
    const referralLink = `${process.env.FRONTEND_URL || 'https://sokoplus.vercel.app'}/register?ref=${req.user.referral_code}`;
    
    res.json({
      success: true,
      referralCode: req.user.referral_code,
      referralLink
    });
    
  } catch (error) {
    console.error('Referral link error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to generate referral link' 
    });
  }
});

// ============================================
// ADMIN ENDPOINTS
// ============================================

// Admin dashboard stats
app.get('/api/admin/stats', authenticateToken, isAdmin, async (req, res) => {
  try {
    const [
      { count: totalUsers },
      { count: totalPosts },
      { count: pendingApprovals },
      { data: revenueData },
      { count: pendingWithdrawals },
      { data: recentUsers },
      { data: recentPayments }
    ] = await Promise.all([
      supabaseAdmin.from('users').select('*', { count: 'exact', head: true }),
      supabaseAdmin.from('posts').select('*', { count: 'exact', head: true }),
      supabaseAdmin.from('payments').select('*', { count: 'exact', head: true }).eq('status', 'pending'),
      supabaseAdmin.from('payments').select('amount').eq('status', 'approved'),
      supabaseAdmin.from('withdrawals').select('*', { count: 'exact', head: true }).eq('status', 'pending'),
      supabaseAdmin.from('users').select('*').order('created_at', { ascending: false }).limit(10),
      supabaseAdmin.from('payments').select('*, user:users(name)').order('created_at', { ascending: false }).limit(10)
    ]);
    
    const totalRevenue = revenueData?.reduce((sum, item) => sum + (item.amount || 0), 0) || 0;
    
    res.json({
      success: true,
      stats: {
        totalUsers: totalUsers || 0,
        totalPosts: totalPosts || 0,
        pendingApprovals: pendingApprovals || 0,
        totalRevenue,
        pendingWithdrawals: pendingWithdrawals || 0
      },
      recentUsers: recentUsers || [],
      recentPayments: recentPayments || []
    });
    
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch admin statistics' 
    });
  }
});

// Get all users (admin)
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50, search, status, role } = req.query;
    
    let query = supabaseAdmin
      .from('users')
      .select('*', { count: 'exact' })
      .neq('role', 'superadmin'); // Don't show superadmins
    
    if (search) {
      query = query.or(`name.ilike.%${search}%,email.ilike.%${search}%,phone.ilike.%${search}%`);
    }
    
    if (status) query = query.eq('status', status);
    if (role) query = query.eq('role', role);
    
    query = query.order('created_at', { ascending: false })
      .range((page - 1) * limit, page * limit - 1);
    
    const { data: users, error, count } = await query;
    
    if (error) throw error;
    
    res.json({
      success: true,
      users: users || [],
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count || 0,
        pages: Math.ceil((count || 0) / limit)
      }
    });
    
  } catch (error) {
    console.error('Admin users error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch users' 
    });
  }
});

// Update user (admin)
app.put('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const updateData = req.body;
    
    const { data: user, error } = await supabaseAdmin
      .from('users')
      .update({
        ...updateData,
        updated_at: new Date().toISOString()
      })
      .eq('id', userId)
      .select()
      .single();
    
    if (error) throw error;
    
    res.json({
      success: true,
      message: 'User updated successfully',
      user
    });
    
  } catch (error) {
    console.error('Admin user update error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to update user' 
    });
  }
});

// Get all payments (admin)
app.get('/api/admin/payments', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { status, type, page = 1, limit = 50 } = req.query;
    
    let query = supabaseAdmin
      .from('payments')
      .select('*, user:users(name, email, phone)', { count: 'exact' });
    
    if (status) query = query.eq('status', status);
    if (type) query = query.eq('type', type);
    
    query = query.order('created_at', { ascending: false })
      .range((page - 1) * limit, page * limit - 1);
    
    const { data: payments, error, count } = await query;
    
    if (error) throw error;
    
    res.json({
      success: true,
      payments: payments || [],
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count || 0,
        pages: Math.ceil((count || 0) / limit)
      }
    });
    
  } catch (error) {
    console.error('Admin payments error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch payments' 
    });
  }
});

// Approve payment (admin)
app.put('/api/admin/payments/:id/approve', authenticateToken, isAdmin, async (req, res) => {
  try {
    const paymentId = req.params.id;
    
    // Get payment
    const { data: payment } = await supabaseAdmin
      .from('payments')
      .select('*')
      .eq('id', paymentId)
      .single();
    
    if (!payment) {
      return res.status(404).json({ 
        success: false, 
        message: 'Payment not found' 
      });
    }
    
    // Update payment
    await supabaseAdmin
      .from('payments')
      .update({ 
        status: 'approved',
        processed_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })
      .eq('id', paymentId);
    
    // Update user based on payment type
    if (payment.type === 'subscription') {
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7); // 7 days
      
      await supabaseAdmin
        .from('users')
        .update({
          subscription_active: true,
          subscription_expires_at: expiresAt.toISOString(),
          updated_at: new Date().toISOString()
        })
        .eq('id', payment.user_id);
      
      // Handle referral
      const { data: user } = await supabaseAdmin
        .from('users')
        .select('referral_from')
        .eq('id', payment.user_id)
        .single();
      
      if (user?.referral_from) {
        const { data: referrer } = await supabaseAdmin
          .from('users')
          .select('id')
          .eq('referral_code', user.referral_from)
          .single();
        
        if (referrer) {
          // Update referral
          await supabaseAdmin
            .from('referrals')
            .update({
              status: 'approved',
              updated_at: new Date().toISOString()
            })
            .eq('referrer_id', referrer.id)
            .eq('referred_user_id', payment.user_id)
            .eq('type', 'subscription');
          
          // Update referrer earnings
          await supabaseAdmin.rpc('increment_earnings', {
            user_id: referrer.id,
            amount: 25.00
          });
        }
      }
    } else if (payment.type === 'upgrade') {
      await supabaseAdmin
        .from('users')
        .update({
          upgraded: true,
          upgraded_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        })
        .eq('id', payment.user_id);
    }
    
    res.json({
      success: true,
      message: 'Payment approved successfully'
    });
    
  } catch (error) {
    console.error('Payment approval error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to approve payment' 
    });
  }
});

// Get all withdrawals (admin)
app.get('/api/admin/withdrawals', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { status, page = 1, limit = 50 } = req.query;
    
    let query = supabaseAdmin
      .from('withdrawals')
      .select('*, user:users(name, email, phone)', { count: 'exact' });
    
    if (status) query = query.eq('status', status);
    
    query = query.order('created_at', { ascending: false })
      .range((page - 1) * limit, page * limit - 1);
    
    const { data: withdrawals, error, count } = await query;
    
    if (error) throw error;
    
    res.json({
      success: true,
      withdrawals: withdrawals || [],
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count || 0,
        pages: Math.ceil((count || 0) / limit)
      }
    });
    
  } catch (error) {
    console.error('Admin withdrawals error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch withdrawals' 
    });
  }
});

// Approve withdrawal (admin)
app.put('/api/admin/withdrawals/:id/approve', authenticateToken, isAdmin, async (req, res) => {
  try {
    const withdrawalId = req.params.id;
    const { mpesaTransactionId } = req.body;
    
    // Get withdrawal
    const { data: withdrawal } = await supabaseAdmin
      .from('withdrawals')
      .select('*')
      .eq('id', withdrawalId)
      .single();
    
    if (!withdrawal) {
      return res.status(404).json({ 
        success: false, 
        message: 'Withdrawal not found' 
      });
    }
    
    // Update withdrawal
    const updateData = {
      status: 'approved',
      processed_by: req.user.id,
      processed_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    if (mpesaTransactionId) {
      updateData.mpesa_transaction_id = mpesaTransactionId;
      updateData.status = 'processing';
    }
    
    await supabaseAdmin
      .from('withdrawals')
      .update(updateData)
      .eq('id', withdrawalId);
    
    // Send notification to user
    const notification = {
      id: uuidv4(),
      user_id: withdrawal.user_id,
      type: 'withdrawal_approved',
      title: 'Withdrawal Approved',
      message: `Your withdrawal of KES ${withdrawal.amount} has been approved and is being processed.`,
      data: { withdrawalId: withdrawal.id },
      created_at: new Date().toISOString()
    };
    
    await supabaseAdmin.from('notifications').insert([notification]);
    
    res.json({
      success: true,
      message: 'Withdrawal approved successfully'
    });
    
  } catch (error) {
    console.error('Withdrawal approval error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to approve withdrawal' 
    });
  }
});

// Complete withdrawal (admin)
app.put('/api/admin/withdrawals/:id/complete', authenticateToken, isAdmin, async (req, res) => {
  try {
    const withdrawalId = req.params.id;
    
    // Update withdrawal
    await supabaseAdmin
      .from('withdrawals')
      .update({ 
        status: 'completed',
        completed_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })
      .eq('id', withdrawalId);
    
    res.json({
      success: true,
      message: 'Withdrawal marked as completed'
    });
    
  } catch (error) {
    console.error('Withdrawal complete error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to complete withdrawal' 
    });
  }
});

// Get all reports (admin)
app.get('/api/admin/reports', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { status, page = 1, limit = 50 } = req.query;
    
    let query = supabaseAdmin
      .from('reports')
      .select(`
        *,
        reporter:users!reports_reporter_id_fkey(name, email),
        reported_user:users!reports_reported_user_id_fkey(name, email),
        reported_post:posts(title)
      `, { count: 'exact' });
    
    if (status) query = query.eq('status', status);
    
    query = query.order('created_at', { ascending: false })
      .range((page - 1) * limit, page * limit - 1);
    
    const { data: reports, error, count } = await query;
    
    if (error) throw error;
    
    res.json({
      success: true,
      reports: reports || [],
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count || 0,
        pages: Math.ceil((count || 0) / limit)
      }
    });
    
  } catch (error) {
    console.error('Admin reports error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch reports' 
    });
  }
});

// Resolve report (admin)
app.put('/api/admin/reports/:id/resolve', authenticateToken, isAdmin, async (req, res) => {
  try {
    const reportId = req.params.id;
    const { action, notes } = req.body;
    
    await supabaseAdmin
      .from('reports')
      .update({ 
        status: 'resolved',
        resolved_by: req.user.id,
        resolved_at: new Date().toISOString(),
        notes: notes || ''
      })
      .eq('id', reportId);
    
    // Take action based on report
    if (action === 'suspend_user') {
      const { data: report } = await supabaseAdmin
        .from('reports')
        .select('reported_user_id')
        .eq('id', reportId)
        .single();
      
      if (report?.reported_user_id) {
        await supabaseAdmin
          .from('users')
          .update({ status: 'suspended' })
          .eq('id', report.reported_user_id);
      }
    } else if (action === 'remove_post') {
      const { data: report } = await supabaseAdmin
        .from('reports')
        .select('reported_post_id')
        .eq('id', reportId)
        .single();
      
      if (report?.reported_post_id) {
        await supabaseAdmin
          .from('posts')
          .update({ status: 'removed' })
          .eq('id', report.reported_post_id);
      }
    }
    
    res.json({
      success: true,
      message: 'Report resolved successfully'
    });
    
  } catch (error) {
    console.error('Report resolve error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to resolve report' 
    });
  }
});

// ============================================
// FILE UPLOAD ENDPOINTS
// ============================================

// Upload file
app.post('/api/upload', authenticateToken, upload.array('files', 10), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'No files uploaded' 
      });
    }
    
    const uploads = [];
    
    for (const file of req.files) {
      const fileName = `${uuidv4()}-${file.originalname}`;
      const filePath = `uploads/${req.user.id}/${fileName}`;
      
      // Upload to Supabase Storage
      const { data, error } = await supabaseAdmin.storage
        .from('sokoplus')
        .upload(filePath, file.buffer, {
          contentType: file.mimetype,
          upsert: false
        });
      
      if (error) throw error;
      
      // Get public URL
      const { data: urlData } = supabaseAdmin.storage
        .from('sokoplus')
        .getPublicUrl(filePath);
      
      uploads.push({
        originalName: file.originalname,
        fileName,
        url: urlData.publicUrl,
        size: file.size,
        mimetype: file.mimetype
      });
    }
    
    res.json({
      success: true,
      message: 'Files uploaded successfully',
      uploads
    });
    
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to upload files' 
    });
  }
});

// ============================================
// SEARCH ENDPOINTS
// ============================================

// Global search
app.get('/api/search', async (req, res) => {
  try {
    const { q, type, category, location, minPrice, maxPrice } = req.query;
    
    if (!q) {
      return res.status(400).json({ 
        success: false, 
        message: 'Search query is required' 
      });
    }
    
    // Search posts
    let postsQuery = supabase
      .from('posts')
      .select(`
        *,
        user:users(name, profile_picture),
        shop:shops(name, logo)
      `)
      .eq('status', 'active')
      .or(`title.ilike.%${q}%,description.ilike.%${q}%,content.ilike.%${q}%,tags.cs.{${q}}`);
    
    if (type) postsQuery = postsQuery.eq('type', type);
    if (category) postsQuery = postsQuery.eq('category', category);
    if (location) postsQuery = postsQuery.ilike('location', `%${location}%`);
    if (minPrice) postsQuery = postsQuery.gte('price', minPrice);
    if (maxPrice) postsQuery = postsQuery.lte('price', maxPrice);
    
    const { data: posts } = await postsQuery.limit(50);
    
    // Search shops
    const { data: shops } = await supabase
      .from('shops')
      .select('*')
      .eq('status', 'active')
      .or(`name.ilike.%${q}%,description.ilike.%${q}%`);
    
    // Search users (only basic info)
    const { data: users } = await supabase
      .from('users')
      .select('id, name, profile_picture, business_name, verified')
      .eq('status', 'active')
      .ilike('name', `%${q}%`)
      .limit(20);
    
    res.json({
      success: true,
      results: {
        posts: posts || [],
        shops: shops || [],
        users: users || []
      }
    });
    
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to perform search' 
    });
  }
});

// ============================================
// REPORTING ENDPOINTS
// ============================================

// Report content
app.post('/api/reports', authenticateToken, async (req, res) => {
  try {
    const { reportedUserId, reportedPostId, reportType, description } = req.body;
    
    if (!reportType || !description) {
      return res.status(400).json({ 
        success: false, 
        message: 'Report type and description are required' 
      });
    }
    
    const reportData = {
      id: uuidv4(),
      reporter_id: req.user.id,
      reported_user_id: reportedUserId || null,
      reported_post_id: reportedPostId || null,
      report_type: reportType,
      description,
      created_at: new Date().toISOString()
    };
    
    const { data: report, error } = await supabaseAdmin
      .from('reports')
      .insert([reportData])
      .select()
      .single();
    
    if (error) throw error;
    
    // Send notification to admin
    const adminNotification = {
      id: uuidv4(),
      type: 'new_report',
      title: 'New Report Submitted',
      message: `A new ${reportType} report has been submitted.`,
      data: { reportId: report.id },
      created_at: new Date().toISOString()
    };
    
    await supabaseAdmin.from('notifications').insert([adminNotification]);
    
    res.status(201).json({
      success: true,
      message: 'Report submitted successfully',
      report
    });
    
  } catch (error) {
    console.error('Report error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to submit report' 
    });
  }
});

// ============================================
// ERROR HANDLING MIDDLEWARE
// ============================================

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'API endpoint not found',
    path: req.originalUrl
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('🚨 Global error:', err);
  
  // Handle multer errors
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        message: 'File too large. Maximum size is 10MB.'
      });
    }
    if (err.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({
        success: false,
        message: 'Too many files. Maximum is 10 files.'
      });
    }
  }
  
  // Handle JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      message: 'Invalid token'
    });
  }
  
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      success: false,
      message: 'Token expired'
    });
  }
  
  // Default error
  res.status(500).json({
    success: false,
    message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  });
});

// ============================================
// SERVER CONFIGURATION
// ============================================

const PORT = process.env.PORT || 3001;

// For Vercel deployment, export the app
if (process.env.VERCEL) {
  module.exports = app;
} else {
  // For local development
  app.listen(PORT, () => {
    console.log(`🚀 SOKOPLUS Backend running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
    console.log(`🔗 Supabase URL: ${supabaseUrl}`);
    console.log(`👤 Admin email: admin@sokoplus.com`);
    console.log(`🔑 Admin password: Admin@123`);
  });
}
