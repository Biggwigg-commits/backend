const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const stripe = require('stripe');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8001;

// Initialize Stripe
const stripeClient = stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_dummy_key');

// Middleware
app.use(helmet());
app.use(morgan('combined'));
app.use(cors({
  origin: '*',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000 // limit each IP to 1000 requests per windowMs
});
app.use(limiter);

// Multer for file uploads
const upload = multer({
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'), false);
    }
  }
});

// MongoDB connection
mongoose.connect(process.env.MONGO_URL || 'mongodb://localhost:27017/paymedb', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

mongoose.connection.on('connected', () => {
  console.log('Connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

// Utility functions
const generateCardNumber = () => {
  return `4${Math.floor(Math.random() * 900) + 100} ${Math.floor(Math.random() * 9000) + 1000} ${Math.floor(Math.random() * 9000) + 1000} ${Math.floor(Math.random() * 9000) + 1000}`;
};

const generateCVV = () => {
  return Math.floor(Math.random() * 900) + 100;
};

const generateExpiry = () => {
  const currentYear = new Date().getFullYear() % 100;
  const expiryYear = (currentYear + Math.floor(Math.random() * 3) + 3) % 100;
  const expiryMonth = Math.floor(Math.random() * 12) + 1;
  return `${expiryMonth.toString().padStart(2, '0')}/${expiryYear.toString().padStart(2, '0')}`;
};

// Mongoose Schemas
const userSchema = new mongoose.Schema({
  user_id: { type: String, default: () => uuidv4(), unique: true },
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true, unique: true },
  password_hash: { type: String, required: true },
  balance: { type: Number, default: 0 },
  profile_picture: { type: String, default: null },
  created_at: { type: Date, default: Date.now },
  is_verified: { type: Boolean, default: false }
});

const virtualCardSchema = new mongoose.Schema({
  card_id: { type: String, default: () => uuidv4(), unique: true },
  user_id: { type: String, required: true },
  card_number: { type: String, required: true },
  card_holder_name: { type: String, required: true },
  cvv: { type: String, required: true },
  expiry_date: { type: String, required: true },
  is_locked: { type: Boolean, default: false },
  monthly_spend: { type: Number, default: 0 },
  created_at: { type: Date, default: Date.now }
});

const transactionSchema = new mongoose.Schema({
  transaction_id: { type: String, default: () => uuidv4(), unique: true },
  sender_id: { type: String, required: true },
  recipient_id: { type: String, default: null },
  recipient_identifier: { type: String, default: null },
  amount: { type: Number, required: true },
  fee: { type: Number, default: 0 },
  transaction_type: { type: String, required: true }, // 'send', 'receive', 'add_funds', 'withdraw', 'request', 'card_purchase'
  status: { type: String, default: 'pending' }, // 'pending', 'completed', 'failed', 'cancelled'
  description: { type: String, default: null },
  created_at: { type: Date, default: Date.now },
  completed_at: { type: Date, default: null },
  stripe_payment_intent_id: { type: String, default: null },
  card_id: { type: String, default: null }
});

const moneyRequestSchema = new mongoose.Schema({
  request_id: { type: String, default: () => uuidv4(), unique: true },
  requester_id: { type: String, required: true },
  requestee_id: { type: String, default: null },
  requestee_identifier: { type: String, required: true },
  amount: { type: Number, required: true },
  description: { type: String, default: null },
  status: { type: String, default: 'pending' }, // 'pending', 'paid', 'declined', 'cancelled'
  created_at: { type: Date, default: Date.now },
  expires_at: { type: Date, default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) }
});

const connectedAccountSchema = new mongoose.Schema({
  account_id: { type: String, default: () => uuidv4(), unique: true },
  user_id: { type: String, required: true },
  account_type: { type: String, required: true }, // 'bank_account', 'debit_card'
  account_name: { type: String, required: true },
  account_number: { type: String, required: true },
  routing_number: { type: String, default: null },
  last_four: { type: String, required: true },
  is_default: { type: Boolean, default: false },
  is_verified: { type: Boolean, default: false },
  stripe_account_id: { type: String, default: null },
  created_at: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', userSchema);
const VirtualCard = mongoose.model('VirtualCard', virtualCardSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const MoneyRequest = mongoose.model('MoneyRequest', moneyRequestSchema);
const ConnectedAccount = mongoose.model('ConnectedAccount', connectedAccountSchema);

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ detail: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key-change-in-production', (err, user) => {
    if (err) {
      return res.status(403).json({ detail: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Validation schemas
const registerSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  email: Joi.string().email().required(),
  phone: Joi.string().pattern(/^[\d\+\-\s\(\)]{10,15}$/).required(),
  password: Joi.string().min(6).required()
});

const loginSchema = Joi.object({
  identifier: Joi.string().required(),
  password: Joi.string().required()
});

// Routes

// Root endpoint
app.get('/api/', (req, res) => {
  res.json({ message: 'PayMe API v2.0 - Your Digital Wallet (Node.js)' });
});

// Authentication Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { error, value } = registerSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ detail: error.details[0].message });
    }

    const { username, email, phone, password } = value;

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email }, { phone }, { username }]
    });

    if (existingUser) {
      return res.status(400).json({ detail: 'User already exists' });
    }

    // Hash password
    const password_hash = await bcrypt.hash(password, 12);

    // Create user
    const user = new User({
      username,
      email,
      phone,
      password_hash
    });

    await user.save();

    // Create virtual card
    const virtualCard = new VirtualCard({
      user_id: user.user_id,
      card_number: generateCardNumber(),
      card_holder_name: username.toUpperCase(),
      cvv: generateCVV().toString(),
      expiry_date: generateExpiry()
    });

    await virtualCard.save();


    // Create JWT token
    const token = jwt.sign(
      { user_id: user.user_id },
      process.env.JWT_SECRET || 'your-secret-key-change-in-production',
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        user_id: user.user_id,
        username: user.username,
        email: user.email,
        phone: user.phone,
        balance: user.balance,
        profile_picture: user.profile_picture,
        invite_code: user.invite_code
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ detail: error.details[0].message });
    }

    const { identifier, password } = value;

    // Find user by email, phone, or username
    const user = await User.findOne({
      $or: [{ email: identifier }, { phone: identifier }, { username: identifier }]
    });

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ detail: 'Invalid credentials' });
    }

    // Create JWT token
    const token = jwt.sign(
      { user_id: user.user_id },
      process.env.JWT_SECRET || 'your-secret-key-change-in-production',
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        user_id: user.user_id,
        username: user.username,
        email: user.email,
        phone: user.phone,
        balance: user.balance,
        profile_picture: user.profile_picture,
        invite_code: user.invite_code
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// User Profile Routes
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ user_id: req.user.user_id });
    if (!user) {
      return res.status(404).json({ detail: 'User not found' });
    }

    res.json({
      user_id: user.user_id,
      username: user.username,
      email: user.email,
      phone: user.phone,
      balance: user.balance,
      profile_picture: user.profile_picture,
      invite_code: user.invite_code,
      created_at: user.created_at
    });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

app.post('/api/user/profile-picture', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    let profilePicture = null;

    if (req.file) {
      // Convert image to base64
      profilePicture = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
    } else if (req.body.profile_picture) {
      profilePicture = req.body.profile_picture;
    } else {
      return res.status(400).json({ detail: 'No image provided' });
    }

    await User.findOneAndUpdate(
      { user_id: req.user.user_id },
      { profile_picture: profilePicture }
    );

    res.json({ message: 'Profile picture updated successfully' });
  } catch (error) {
    console.error('Profile picture update error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

app.get('/api/user/search', authenticateToken, async (req, res) => {
  try {
    const { query } = req.query;
    if (!query || query.length < 2) {
      return res.json([]);
    }

    const users = await User.find({
      $and: [
        { user_id: { $ne: req.user.user_id } },
        {
          $or: [
            { username: { $regex: query, $options: 'i' } },
            { email: { $regex: query, $options: 'i' } },
            { phone: { $regex: query, $options: 'i' } }
          ]
        }
      ]
    }).limit(10);

    res.json(users.map(user => ({
      user_id: user.user_id,
      username: user.username,
      email: user.email.substring(0, 3) + '***@' + user.email.split('@')[1],
      phone: user.phone.substring(0, 3) + '***' + user.phone.slice(-4),
      profile_picture: user.profile_picture
    })));
  } catch (error) {
    console.error('User search error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Virtual Card Routes
app.get('/api/card', authenticateToken, async (req, res) => {
  try {
    let card = await VirtualCard.findOne({ user_id: req.user.user_id });

    if (!card) {
      const user = await User.findOne({ user_id: req.user.user_id });
      card = new VirtualCard({
        user_id: req.user.user_id,
        card_number: generateCardNumber(),
        card_holder_name: user.username.toUpperCase(),
        cvv: generateCVV().toString(),
        expiry_date: generateExpiry()
      });
      await card.save();
    }

    res.json({
      card_id: card.card_id,
      card_number: card.card_number,
      card_holder_name: card.card_holder_name,
      cvv: card.cvv,
      expiry_date: card.expiry_date,
      is_locked: card.is_locked,
      monthly_spend: card.monthly_spend
    });
  } catch (error) {
    console.error('Card fetch error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

app.post('/api/card/lock', authenticateToken, async (req, res) => {
  try {
    const card = await VirtualCard.findOne({ user_id: req.user.user_id });
    if (!card) {
      return res.status(404).json({ detail: 'Card not found' });
    }

    const newLockStatus = !card.is_locked;
    await VirtualCard.findOneAndUpdate(
      { user_id: req.user.user_id },
      { is_locked: newLockStatus }
    );

    res.json({
      message: `Card ${newLockStatus ? 'locked' : 'unlocked'} successfully`,
      is_locked: newLockStatus
    });
  } catch (error) {
    console.error('Card lock error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

app.post('/api/card/purchase', authenticateToken, async (req, res) => {
  try {
    const { amount, merchant, description } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ detail: 'Invalid amount' });
    }

    // Check card status
    const card = await VirtualCard.findOne({ user_id: req.user.user_id });
    if (!card) {
      return res.status(404).json({ detail: 'Card not found' });
    }

    if (card.is_locked) {
      return res.status(400).json({ detail: 'Card is locked' });
    }

    // Check user balance
    const user = await User.findOne({ user_id: req.user.user_id });
    if (user.balance < amount) {
      return res.status(400).json({ 
        detail: `Insufficient balance. Current: $${user.balance.toFixed(2)}, Required: $${amount.toFixed(2)}` 
      });
    }

    // Process purchase
    const transaction = new Transaction({
      sender_id: req.user.user_id,
      amount,
      transaction_type: 'card_purchase',
      status: 'completed',
      description: `Purchase at ${merchant}`,
      completed_at: new Date(),
      card_id: card.card_id
    });

    await transaction.save();

    // Update balances
    await User.findOneAndUpdate(
      { user_id: req.user.user_id },
      { $inc: { balance: -amount } }
    );

    await VirtualCard.findOneAndUpdate(
      { user_id: req.user.user_id },
      { $inc: { monthly_spend: amount } }
    );

    res.json({
      message: 'Purchase completed successfully',
      transaction_id: transaction.transaction_id,
      amount,
      merchant,
      new_balance: user.balance - amount
    });
  } catch (error) {
    console.error('Card purchase error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

app.get('/api/card/spending', authenticateToken, async (req, res) => {
  try {
    const startOfMonth = new Date();
    startOfMonth.setDate(1);
    startOfMonth.setHours(0, 0, 0, 0);

    const cardTransactions = await Transaction.find({
      sender_id: req.user.user_id,
      transaction_type: 'card_purchase',
      created_at: { $gte: startOfMonth }
    });

    const totalSpent = cardTransactions.reduce((sum, txn) => sum + txn.amount, 0);

    // Calculate top merchants
    const merchantSpending = {};
    cardTransactions.forEach(txn => {
      const merchant = txn.description.replace('Purchase at ', '') || 'Unknown';
      merchantSpending[merchant] = (merchantSpending[merchant] || 0) + txn.amount;
    });

    const topMerchants = Object.entries(merchantSpending)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 5)
      .map(([name, amount]) => ({ name, amount }));

    res.json({
      monthly_total: totalSpent,
      transaction_count: cardTransactions.length,
      top_merchants: topMerchants,
      current_month: startOfMonth.toLocaleDateString('en-US', { month: 'long', year: 'numeric' })
    });
  } catch (error) {
    console.error('Card spending error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Payment Routes
app.post('/api/payments/send', authenticateToken, async (req, res) => {
  try {
    const { recipient_identifier, amount, description } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ detail: 'Amount must be positive' });
    }

    const fee = amount * 0.005; // 0.5%
    const totalAmount = amount + fee;

    const user = await User.findOne({ user_id: req.user.user_id });
    if (user.balance < totalAmount) {
      return res.status(400).json({ 
        detail: `Insufficient balance. Current: $${user.balance.toFixed(2)}, Required: $${totalAmount.toFixed(2)}` 
      });
    }

    // Find recipient
    const recipient = await User.findOne({
      $or: [
        { email: recipient_identifier },
        { phone: recipient_identifier },
        { username: recipient_identifier }
      ]
    });

    if (!recipient) {
      return res.status(404).json({ detail: 'Recipient not found' });
    }

    if (recipient.user_id === req.user.user_id) {
      return res.status(400).json({ detail: 'Cannot send money to yourself' });
    }

    // Create transaction
    const transaction = new Transaction({
      sender_id: req.user.user_id,
      recipient_id: recipient.user_id,
      recipient_identifier,
      amount,
      fee,
      transaction_type: 'send',
      status: 'completed',
      description,
      completed_at: new Date()
    });

    await transaction.save();

    // Update balances
    await User.findOneAndUpdate(
      { user_id: req.user.user_id },
      { $inc: { balance: -totalAmount } }
    );

    await User.findOneAndUpdate(
      { user_id: recipient.user_id },
      { $inc: { balance: amount } }
    );

    res.json({
      message: 'Money sent successfully',
      transaction_id: transaction.transaction_id,
      amount,
      fee,
      recipient: recipient.username
    });
  } catch (error) {
    console.error('Send money error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Request Money Routes
app.post('/api/payments/request', authenticateToken, async (req, res) => {
  try {
    const { requestee_identifier, amount, description } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ detail: 'Amount must be positive' });
    }

    const requestee = await User.findOne({
      $or: [
        { email: requestee_identifier },
        { phone: requestee_identifier },
        { username: requestee_identifier }
      ]
    });

    if (!requestee) {
      return res.status(404).json({ detail: 'User not found' });
    }

    if (requestee.user_id === req.user.user_id) {
      return res.status(400).json({ detail: 'Cannot request money from yourself' });
    }

    const moneyRequest = new MoneyRequest({
      requester_id: req.user.user_id,
      requestee_id: requestee.user_id,
      requestee_identifier,
      amount,
      description
    });

    await moneyRequest.save();

    res.json({
      message: 'Money request sent successfully',
      request_id: moneyRequest.request_id,
      amount,
      requestee: requestee.username
    });
  } catch (error) {
    console.error('Request money error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

app.get('/api/payments/requests/received', authenticateToken, async (req, res) => {
  try {
    const requests = await MoneyRequest.find({
      requestee_id: req.user.user_id,
      status: 'pending'
    }).sort({ created_at: -1 });

    const formattedRequests = await Promise.all(requests.map(async (req) => {
      const requester = await User.findOne({ user_id: req.requester_id });
      return {
        request_id: req.request_id,
        amount: req.amount,
        description: req.description || '',
        status: req.status,
        created_at: req.created_at,
        expires_at: req.expires_at,
        requester: {
          username: requester.username,
          profile_picture: requester.profile_picture
        }
      };
    }));

    res.json(formattedRequests);
  } catch (error) {
    console.error('Get received requests error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

app.post('/api/payments/requests/pay', authenticateToken, async (req, res) => {
  try {
    const { request_id } = req.body;

    const requestDoc = await MoneyRequest.findOne({
      request_id,
      requestee_id: req.user.user_id,
      status: 'pending'
    });

    if (!requestDoc) {
      return res.status(404).json({ detail: 'Request not found or already processed' });
    }

    const user = await User.findOne({ user_id: req.user.user_id });
    const fee = requestDoc.amount * 0.005;
    const totalAmount = requestDoc.amount + fee;

    if (user.balance < totalAmount) {
      return res.status(400).json({ 
        detail: `Insufficient balance. Current: $${user.balance.toFixed(2)}, Required: $${totalAmount.toFixed(2)}` 
      });
    }

    // Update balances
    await User.findOneAndUpdate(
      { user_id: req.user.user_id },
      { $inc: { balance: -totalAmount } }
    );

    await User.findOneAndUpdate(
      { user_id: requestDoc.requester_id },
      { $inc: { balance: requestDoc.amount } }
    );

    // Mark request as paid
    await MoneyRequest.findOneAndUpdate(
      { request_id },
      { status: 'paid' }
    );

    // Create transaction
    const transaction = new Transaction({
      sender_id: req.user.user_id,
      recipient_id: requestDoc.requester_id,
      amount: requestDoc.amount,
      fee,
      transaction_type: 'send',
      status: 'completed',
      description: `Payment for request: ${requestDoc.description || ''}`,
      completed_at: new Date()
    });

    await transaction.save();

    res.json({
      message: 'Request paid successfully',
      transaction_id: transaction.transaction_id,
      amount: requestDoc.amount,
      fee
    });
  } catch (error) {
    console.error('Pay request error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Add Funds
app.post('/api/payments/add-funds', authenticateToken, async (req, res) => {
  try {
    const { amount, payment_method_id } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ detail: 'Invalid amount' });
    }

    // Mock successful payment for demo
    const transaction = new Transaction({
      sender_id: req.user.user_id,
      amount,
      transaction_type: 'add_funds',
      status: 'completed',
      description: 'Added funds via card',
      completed_at: new Date(),
      stripe_payment_intent_id: `pi_demo_${uuidv4().substring(0, 16)}`
    });

    await transaction.save();

    const updatedUser = await User.findOneAndUpdate(
      { user_id: req.user.user_id },
      { $inc: { balance: amount } },
      { new: true }
    );

    res.json({
      message: 'Funds added successfully',
      amount,
      new_balance: updatedUser.balance
    });
  } catch (error) {
    console.error('Add funds error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Connected Accounts Routes
app.post('/api/accounts/connect', authenticateToken, async (req, res) => {
  try {
    const { account_type, account_name, account_number, routing_number } = req.body;

    if (!account_name || !account_number) {
      return res.status(400).json({ detail: 'Account name and number are required' });
    }

    if (account_type === 'bank_account' && !routing_number) {
      return res.status(400).json({ detail: 'Routing number is required for bank accounts' });
    }

    const connectedAccount = new ConnectedAccount({
      user_id: req.user.user_id,
      account_type,
      account_name,
      account_number,
      routing_number,
      last_four: account_number.slice(-4),
      is_verified: true, // Auto-verify for demo
      stripe_account_id: `acct_${uuidv4().substring(0, 16)}`
    });

    await connectedAccount.save();

    res.json({
      message: 'Account connected successfully',
      account_id: connectedAccount.account_id,
      account_name: connectedAccount.account_name,
      account_type: connectedAccount.account_type
    });
  } catch (error) {
    console.error('Connect account error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

app.get('/api/accounts/connected', authenticateToken, async (req, res) => {
  try {
    const accounts = await ConnectedAccount.find({ user_id: req.user.user_id });

    res.json(accounts.map(account => ({
      account_id: account.account_id,
      account_name: account.account_name,
      account_type: account.account_type,
      last_four: account.last_four,
      is_default: account.is_default,
      is_verified: account.is_verified
    })));
  } catch (error) {
    console.error('Get connected accounts error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

app.post('/api/payments/withdraw', authenticateToken, async (req, res) => {
  try {
    const { amount, account_id, transfer_speed = 'standard' } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ detail: 'Amount must be positive' });
    }

    const user = await User.findOne({ user_id: req.user.user_id });
    const account = await ConnectedAccount.findOne({
      account_id,
      user_id: req.user.user_id
    });

    if (!account) {
      return res.status(404).json({ detail: 'Connected account not found' });
    }

    // Calculate fees
    let fee = 0;
    if (transfer_speed === 'instant') {
      fee = Math.max(0.25, amount * 0.015);
    }

    const totalAmount = amount + fee;

    if (user.balance < totalAmount) {
      return res.status(400).json({ 
        detail: `Insufficient balance. Current: $${user.balance.toFixed(2)}, Required: $${totalAmount.toFixed(2)}` 
      });
    }

    // Create withdrawal transaction
    const transaction = new Transaction({
      sender_id: req.user.user_id,
      amount,
      fee,
      transaction_type: 'withdraw',
      status: 'completed',
      description: `Withdrawal to ${account.account_name} (${transfer_speed})`,
      completed_at: new Date()
    });

    await transaction.save();

    await User.findOneAndUpdate(
      { user_id: req.user.user_id },
      { $inc: { balance: -totalAmount } }
    );

    res.json({
      message: 'Withdrawal completed successfully',
      transaction_id: transaction.transaction_id,
      amount,
      fee,
      transfer_speed,
      estimated_arrival: transfer_speed === 'standard' ? '1-3 business days' : 'Within minutes'
    });
  } catch (error) {
    console.error('Withdraw error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Transaction History
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;

    const transactions = await Transaction.find({
      $or: [
        { sender_id: req.user.user_id },
        { recipient_id: req.user.user_id }
      ]
    }).sort({ created_at: -1 }).limit(limit);

    const formattedTransactions = await Promise.all(transactions.map(async (txn) => {
      const formattedTxn = {
        transaction_id: txn.transaction_id,
        amount: txn.amount,
        fee: txn.fee || 0,
        type: txn.transaction_type,
        status: txn.status,
        description: txn.description || '',
        created_at: txn.created_at,
        is_outgoing: txn.sender_id === req.user.user_id
      };

      // Add sender/recipient info
      if (formattedTxn.is_outgoing && txn.recipient_id) {
        const recipient = await User.findOne({ user_id: txn.recipient_id });
        if (recipient) {
          formattedTxn.recipient = {
            username: recipient.username,
            profile_picture: recipient.profile_picture
          };
        }
      } else if (!formattedTxn.is_outgoing && txn.sender_id !== req.user.user_id) {
        const sender = await User.findOne({ user_id: txn.sender_id });
        if (sender) {
          formattedTxn.sender = {
            username: sender.username,
            profile_picture: sender.profile_picture
          };
        }
      }

      return formattedTxn;
    }));

    res.json(formattedTransactions);
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({ detail: 'Internal server error' });
  }
});


// Error handling middleware
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ detail: 'File size too large' });
    }
  }
  
  console.error('Unhandled error:', error);
  res.status(500).json({ detail: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ detail: 'Endpoint not found' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`PayMe API server running on port ${PORT}`);
});

module.exports = app;