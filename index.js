// Load environment variables
require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const admin = require('firebase-admin');
const { body, validationResult } = require('express-validator');

const app = express();

// Environment variables with fallbacks
const MONGODB_URI = process.env.MONGODB_URI;
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Validate required environment variables
if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI is required in environment variables');
  process.exit(1);
}

// Initialize Firebase Admin SDK
try {
  const serviceAccount = {
    type: process.env.FIREBASE_TYPE,
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
    auth_uri: process.env.FIREBASE_AUTH_URI,
    token_uri: process.env.FIREBASE_TOKEN_URI,
    auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_CERT_URL,
    client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL,
    universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN || 'googleapis.com'
  };

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  
  console.log('✅ Firebase Admin SDK initialized successfully');
} catch (error) {
  console.error('❌ Firebase Admin SDK initialization error:', error);
  process.exit(1);
}

// CORS configuration - support multiple origins
const corsOrigins = process.env.CORS_ORIGIN 
  ? process.env.CORS_ORIGIN.split(',').map(origin => origin.trim())
  : ['http://localhost:3000'];

// Middleware
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    if (corsOrigins.includes(origin) || NODE_ENV === 'development') {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// MongoDB Connection - Optimized for serverless (Vercel)
let cachedDb = null;

async function connectToDatabase() {
  if (cachedDb && mongoose.connection.readyState === 1) {
    return cachedDb;
  }

  try {
    const options = {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000
    };

    await mongoose.connect(MONGODB_URI, options);
    cachedDb = mongoose.connection;
    console.log('✅ MongoDB Connected Successfully');
    return cachedDb;
  } catch (error) {
    console.error('❌ MongoDB Connection Error:', error);
    throw error;
  }
}

// Connect to database on startup (for localhost)
if (NODE_ENV !== 'production' || process.env.VERCEL !== '1') {
  connectToDatabase().catch(err => {
    console.error('Failed to connect to MongoDB:', err);
  });
}

// MongoDB Schemas
const userSchema = new mongoose.Schema({
  firebaseUid: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  image: { type: String, default: '' },
  provider: { type: String, default: 'firebase' }, // 'google', 'email', etc.
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date, default: Date.now }
});

const blogPostSchema = new mongoose.Schema({
  authorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  excerpt: { type: String, required: true, maxlength: 150 },
  content: { type: String, required: true },
  category: { 
    type: String, 
    required: true,
    enum: ['Freestyle', 'Racing', 'Cinematic', 'Builds', 'Reviews', 'Tips']
  },
  tags: [{ type: String }],
  featuredImage: { type: String, default: '' },
  readTime: { type: Number, default: 5 },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  viewCount: { type: Number, default: 0 },
  status: { type: String, enum: ['published', 'draft'], default: 'published' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const BlogPost = mongoose.model('BlogPost', blogPostSchema);

// Firebase Authentication Middleware
const authenticateFirebaseToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    // Verify Firebase ID token
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = {
      firebaseUid: decodedToken.uid,
      email: decodedToken.email,
      name: decodedToken.name || decodedToken.email?.split('@')[0]
    };
    next();
  } catch (error) {
    console.error('Firebase token verification error:', error);
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Database connection middleware for serverless functions
const ensureDbConnection = async (req, res, next) => {
  try {
    await connectToDatabase();
    next();
  } catch (error) {
    res.status(500).json({ error: 'Database connection failed' });
  }
};

// ==================== AUTH ROUTES ====================

// Sync Firebase user with MongoDB (called after Firebase authentication on client)
app.post('/api/auth/sync', ensureDbConnection, authenticateFirebaseToken, async (req, res) => {
  try {
    const { firebaseUid, email, name, image, provider } = req.user;

    let user = await User.findOne({ firebaseUid });
    
    if (!user) {
      // Create new user
      user = new User({
        firebaseUid,
        email,
        name: name || email?.split('@')[0],
        image: image || '',
        provider: provider || 'firebase'
      });
      await user.save();
      console.log('✅ New user created:', email);
    } else {
      // Update existing user
      user.name = name || user.name;
      user.image = image || user.image;
      user.lastLogin = Date.now();
      await user.save();
      console.log('✅ User updated:', email);
    }

    res.json({
      message: 'User synced successfully',
      user: {
        id: user._id,
        firebaseUid: user.firebaseUid,
        email: user.email,
        name: user.name,
        image: user.image
      }
    });
  } catch (error) {
    console.error('User sync error:', error);
    res.status(500).json({ error: 'Server error during user sync' });
  }
});

// Get current user (with MongoDB data)
app.get('/api/auth/me', ensureDbConnection, authenticateFirebaseToken, async (req, res) => {
  try {
    const user = await User.findOne({ firebaseUid: req.user.firebaseUid });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found in database' });
    }

    res.json({
      user: {
        id: user._id,
        firebaseUid: user.firebaseUid,
        email: user.email,
        name: user.name,
        image: user.image,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify Firebase token (health check for auth)
app.get('/api/auth/verify', authenticateFirebaseToken, (req, res) => {
  res.json({
    message: 'Token is valid',
    user: req.user
  });
});

// ==================== BLOG POST ROUTES ====================

// Get all blog posts (with filters, search, sort)
app.get('/api/blogs', ensureDbConnection, async (req, res) => {
  try {
    const { search, category, sortBy, status } = req.query;
    
    let query = {};
    
    // Search by title or content
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { content: { $regex: search, $options: 'i' } },
        { excerpt: { $regex: search, $options: 'i' } }
      ];
    }
    
    // Filter by category
    if (category && category !== 'All') {
      query.category = category;
    }
    
    // Filter by status (default: published only)
    query.status = status || 'published';
    
    // Sort options
    let sortOptions = {};
    if (sortBy === 'likes') {
      sortOptions = { likes: -1 };
    } else if (sortBy === 'views') {
      sortOptions = { viewCount: -1 };
    } else {
      sortOptions = { createdAt: -1 }; // Latest by default
    }
    
    const blogs = await BlogPost.find(query)
      .populate('authorId', 'name email image')
      .sort(sortOptions)
      .lean();
    
    // Add like count to each blog
    const blogsWithCounts = blogs.map(blog => ({
      ...blog,
      likeCount: blog.likes.length,
      commentCount: 0 // Placeholder for future comments feature
    }));
    
    res.json({ blogs: blogsWithCounts, total: blogsWithCounts.length });
  } catch (error) {
    console.error('Get blogs error:', error);
    res.status(500).json({ error: 'Error fetching blog posts' });
  }
});

// Get single blog post by ID
app.get('/api/blogs/:id', ensureDbConnection, async (req, res) => {
  try {
    const blog = await BlogPost.findById(req.params.id)
      .populate('authorId', 'name email image');
    
    if (!blog) {
      return res.status(404).json({ error: 'Blog post not found' });
    }
    
    // Increment view count
    blog.viewCount += 1;
    await blog.save();
    
    res.json({ 
      blog: {
        ...blog.toObject(),
        likeCount: blog.likes.length
      }
    });
  } catch (error) {
    console.error('Get blog error:', error);
    res.status(500).json({ error: 'Error fetching blog post' });
  }
});

// Create new blog post (protected)
app.post('/api/blogs', ensureDbConnection, authenticateFirebaseToken, [
  body('title').trim().notEmpty().withMessage('Title required'),
  body('excerpt').trim().notEmpty().isLength({ max: 150 }).withMessage('Excerpt required (max 150 chars)'),
  body('content').trim().notEmpty().withMessage('Content required'),
  body('category').isIn(['Freestyle', 'Racing', 'Cinematic', 'Builds', 'Reviews', 'Tips']).withMessage('Valid category required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    // Get MongoDB user ID from Firebase UID
    const user = await User.findOne({ firebaseUid: req.user.firebaseUid });
    if (!user) {
      return res.status(404).json({ error: 'User not found. Please sync your account first.' });
    }

    const { title, excerpt, content, category, tags, featuredImage, readTime, status } = req.body;
    
    const blogPost = new BlogPost({
      authorId: user._id,
      title,
      excerpt,
      content,
      category,
      tags: tags || [],
      featuredImage: featuredImage || '',
      readTime: readTime || Math.ceil(content.split(' ').length / 200), // Auto-calculate
      status: status || 'published'
    });
    
    await blogPost.save();
    
    const populatedBlog = await BlogPost.findById(blogPost._id)
      .populate('authorId', 'name email image');
    
    res.status(201).json({ 
      message: 'Blog post created successfully',
      blog: populatedBlog
    });
  } catch (error) {
    console.error('Create blog error:', error);
    res.status(500).json({ error: 'Error creating blog post' });
  }
});

// Update blog post (protected, author only)
app.put('/api/blogs/:id', ensureDbConnection, authenticateFirebaseToken, async (req, res) => {
  try {
    const blog = await BlogPost.findById(req.params.id);
    
    if (!blog) {
      return res.status(404).json({ error: 'Blog post not found' });
    }
    
    // Get MongoDB user
    const user = await User.findOne({ firebaseUid: req.user.firebaseUid });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (blog.authorId.toString() !== user._id.toString()) {
      return res.status(403).json({ error: 'Not authorized to update this post' });
    }
    
    const { title, excerpt, content, category, tags, featuredImage, readTime, status } = req.body;
    
    if (title) blog.title = title;
    if (excerpt) blog.excerpt = excerpt;
    if (content) blog.content = content;
    if (category) blog.category = category;
    if (tags) blog.tags = tags;
    if (featuredImage !== undefined) blog.featuredImage = featuredImage;
    if (readTime) blog.readTime = readTime;
    if (status) blog.status = status;
    
    blog.updatedAt = Date.now();
    await blog.save();
    
    const populatedBlog = await BlogPost.findById(blog._id)
      .populate('authorId', 'name email image');
    
    res.json({ 
      message: 'Blog post updated successfully',
      blog: populatedBlog
    });
  } catch (error) {
    console.error('Update blog error:', error);
    res.status(500).json({ error: 'Error updating blog post' });
  }
});

// Delete blog post (protected, author only)
app.delete('/api/blogs/:id', ensureDbConnection, authenticateFirebaseToken, async (req, res) => {
  try {
    const blog = await BlogPost.findById(req.params.id);
    
    if (!blog) {
      return res.status(404).json({ error: 'Blog post not found' });
    }
    
    // Get MongoDB user
    const user = await User.findOne({ firebaseUid: req.user.firebaseUid });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (blog.authorId.toString() !== user._id.toString()) {
      return res.status(403).json({ error: 'Not authorized to delete this post' });
    }
    
    await BlogPost.findByIdAndDelete(req.params.id);
    
    res.json({ message: 'Blog post deleted successfully' });
  } catch (error) {
    console.error('Delete blog error:', error);
    res.status(500).json({ error: 'Error deleting blog post' });
  }
});

// Get user's own blog posts (protected)
app.get('/api/blogs/user/my-posts', ensureDbConnection, authenticateFirebaseToken, async (req, res) => {
  try {
    // Get MongoDB user
    const user = await User.findOne({ firebaseUid: req.user.firebaseUid });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const blogs = await BlogPost.find({ authorId: user._id })
      .sort({ createdAt: -1 })
      .lean();
    
    const blogsWithStats = blogs.map(blog => ({
      ...blog,
      likeCount: blog.likes.length,
      commentCount: 0
    }));
    
    const totalLikes = blogsWithStats.reduce((sum, blog) => sum + blog.likeCount, 0);
    const totalViews = blogsWithStats.reduce((sum, blog) => sum + blog.viewCount, 0);
    
    res.json({ 
      blogs: blogsWithStats,
      stats: {
        totalPosts: blogsWithStats.length,
        totalLikes,
        totalViews
      }
    });
  } catch (error) {
    console.error('Get user posts error:', error);
    res.status(500).json({ error: 'Error fetching user posts' });
  }
});

// Like/Unlike blog post (protected)
app.post('/api/blogs/:id/like', ensureDbConnection, authenticateFirebaseToken, async (req, res) => {
  try {
    const blog = await BlogPost.findById(req.params.id);
    
    if (!blog) {
      return res.status(404).json({ error: 'Blog post not found' });
    }
    
    // Get MongoDB user
    const user = await User.findOne({ firebaseUid: req.user.firebaseUid });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const userId = user._id;
    const likeIndex = blog.likes.indexOf(userId);
    
    if (likeIndex > -1) {
      // Unlike
      blog.likes.splice(likeIndex, 1);
      await blog.save();
      res.json({ message: 'Blog post unliked', liked: false, likeCount: blog.likes.length });
    } else {
      // Like
      blog.likes.push(userId);
      await blog.save();
      res.json({ message: 'Blog post liked', liked: true, likeCount: blog.likes.length });
    }
  } catch (error) {
    console.error('Toggle like error:', error);
    res.status(500).json({ error: 'Error toggling like' });
  }
});

// Get community stats
app.get('/api/stats', ensureDbConnection, async (req, res) => {
  try {
    const totalPosts = await BlogPost.countDocuments({ status: 'published' });
    const totalUsers = await User.countDocuments();
    
    const allBlogs = await BlogPost.find({ status: 'published' }).lean();
    const totalLikes = allBlogs.reduce((sum, blog) => sum + blog.likes.length, 0);
    
    res.json({
      stats: {
        totalPosts,
        totalUsers,
        totalLikes,
        categories: 6 // Fixed count of categories
      }
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Error fetching stats' });
  }
});

// Get popular categories with post counts
app.get('/api/categories', ensureDbConnection, async (req, res) => {
  try {
    const categories = await BlogPost.aggregate([
      { $match: { status: 'published' } },
      { $group: { _id: '$category', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    res.json({ categories });
  } catch (error) {
    console.error('Get categories error:', error);
    res.status(500).json({ error: 'Error fetching categories' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Project FPV Backend is running with Firebase Authentication!',
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
    ...(NODE_ENV === 'development' && { stack: err.stack })
  });
});

// Export for Vercel serverless functions
module.exports = app;

// Start server only if not in Vercel production environment
if (process.env.VERCEL !== '1') {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📡 API ready at http://localhost:${PORT}/api`);
    console.log(`🌍 Environment: ${NODE_ENV}`);
    console.log(`🔥 Firebase Authentication: Enabled`);
  });
} else {
  console.log('✅ Serverless function ready for Vercel with Firebase');
}