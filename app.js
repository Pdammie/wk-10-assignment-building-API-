const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// App setup
const app = express();
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/secure-blog', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('MongoDB Connected'))
  .catch(err => console.error(err));

// User Model
const userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
});
const User = mongoose.model('User', userSchema);

// Blog Model
const blogSchema = new mongoose.Schema({
  title: String,
  content: String,
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
});
const Blog = mongoose.model('Blog', blogSchema);

// Middleware - Authenticate
const authenticate = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Access Denied' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    const user = await User.findById(decoded.id);
    if (!user) return res.status(401).json({ message: 'Invalid token user' });
    req.user = user;
    next();
  } catch (err) {
    res.status(400).json({ message: 'Invalid Token' });
  }
};

// Middleware - Role Check
const authorize = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ message: 'Forbidden' });
  }
  next();
};

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  const { firstName, lastName, email, password } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ firstName, lastName, email, password: hashed });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'secret', { expiresIn: '1h' });
  res.json({ token });
});

// Blog Routes
app.post('/api/blogs', authenticate, async (req, res) => {
  const { title, content } = req.body;
  const blog = new Blog({ title, content, author: req.user._id });
  await blog.save();
  res.status(201).json(blog);
});

app.delete('/api/blogs/:id', authenticate, async (req, res) => {
  const blog = await Blog.findById(req.params.id);
  if (!blog) return res.status(404).json({ message: 'Blog not found' });

  if (blog.author.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Forbidden' });
  }

  await blog.deleteOne();
  res.json({ message: 'Blog deleted' });
});

app.get('/api/blogs', async (req, res) => {
  const blogs = await Blog.find().populate('author', 'firstName lastName email');
  res.json(blogs);
});

app.get('/api/blogs/my-posts', authenticate, async (req, res) => {
  const blogs = await Blog.find({ author: req.user._id });
  res.json(blogs);
});

// Admin - Delete User
app.delete('/api/users/:id', authenticate, authorize('admin'), async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).json({ message: 'User not found' });

  await user.deleteOne();
  res.json({ message: 'User deleted' });
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

