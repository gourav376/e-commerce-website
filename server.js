require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static('public'));

// 1. Database Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected!'))
  .catch(err => console.log('DB Error:', err));

// 2. Database Models
const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' } // 'user' or 'admin'
}));

const Product = mongoose.model('Product', new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  stock: { type: Number, default: 10 }
}));

const Order = mongoose.model('Order', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  items: Array,
  total: Number,
  status: { type: String, default: 'Processing' }
}));

// 3. Security Middleware (Verifies who is making the request)
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'supersecretkey');
    next();
  } catch (err) {
    res.status(400).json({ error: 'Invalid token' });
  }
};

// 4. API Routes
// Auth: Register
app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashedPassword, role });
  await user.save();
  res.json({ message: 'User registered successfully' });
});

// Auth: Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET || 'supersecretkey');
  res.json({ token, role: user.role });
});

// Products: Get all (Public)
app.get('/api/products', async (req, res) => {
  const products = await Product.find();
  res.json(products);
});

// Products: Create (Admin Only)
app.post('/api/products', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  const product = new Product(req.body);
  await product.save();
  res.json(product);
});

// Orders: Checkout (Logged in users)
app.post('/api/orders', authenticate, async (req, res) => {
  const { items, total } = req.body;
  const order = new Order({ userId: req.user.id, items, total });
  await order.save();
  res.json({ message: 'Order placed successfully!', order });
});

// Fallback to frontend
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
