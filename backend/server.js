require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

const app = express();
app.use(cors());
app.use(express.json());

// Connect MongoDB
if (!MONGO_URI) {
  console.error('DB Error: MONGO_URI is not set. Create backend/.env with your Atlas URI.');
  process.exit(1);
}
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('DB Error:', err));

// User model for auth (email optional so mobile app keeps username/password fields)
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  email: { type: String, unique: true, lowercase: true, trim: true, sparse: true },
  passwordHash: { type: String, required: true },
  clientId: { type: Number, unique: true, index: true },
  fullName: { type: String, trim: true },
  phone: { type: String, trim: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Note model
const Note = mongoose.model('Note', new mongoose.Schema({
  title: String,
  content: String
}));

// Finance models
const expenseSchema = new mongoose.Schema({
  ownerId: { type: Number, required: true, index: true },
  description: { type: String, required: true, trim: true },
  category: { type: String, required: true, trim: true },
  amount: { type: Number, required: true, min: 0 },
  dateUtc: { type: Number, required: true },
  createdAt: { type: Date, default: Date.now }
});
expenseSchema.index({ ownerId: 1, dateUtc: -1 });
const Expense = mongoose.model('Expense', expenseSchema);

const incomeSchema = new mongoose.Schema({
  ownerId: { type: Number, required: true, index: true },
  title: { type: String, required: true, trim: true },
  category: { type: String, required: true, trim: true },
  amount: { type: Number, required: true, min: 0 },
  dateUtc: { type: Number, required: true },
  createdAt: { type: Date, default: Date.now }
});
incomeSchema.index({ ownerId: 1, dateUtc: -1 });
const Income = mongoose.model('Income', incomeSchema);

const budgetSchema = new mongoose.Schema({
  ownerId: { type: Number, required: true },
  monthKey: { type: Number, required: true },
  category: { type: String, required: true, trim: true },
  limitAmount: { type: Number, required: true, min: 0 },
  updatedAt: { type: Date, default: Date.now }
});
budgetSchema.index({ ownerId: 1, monthKey: 1, category: 1 }, { unique: true });
const Budget = mongoose.model('Budget', budgetSchema);

const savingsGoalSchema = new mongoose.Schema({
  ownerId: { type: Number, required: true, index: true },
  title: { type: String, required: true, trim: true },
  targetAmount: { type: Number, required: true, min: 0 },
  iconKey: { type: String, trim: true },
  createdAtUtc: { type: Number },
  deadlineUtc: { type: Number },
  cadence: { type: Number },
  createdAt: { type: Date, default: Date.now }
});
const SavingsGoal = mongoose.model('SavingsGoal', savingsGoalSchema);

const savingsContributionSchema = new mongoose.Schema({
  ownerId: { type: Number, required: true, index: true },
  goalId: { type: mongoose.Schema.Types.ObjectId, ref: 'SavingsGoal', index: true },
  amount: { type: Number, required: true, min: 0 },
  dateUtc: { type: Number, required: true },
  isAuto: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});
savingsContributionSchema.index({ ownerId: 1, dateUtc: -1 });
const SavingsContribution = mongoose.model('SavingsContribution', savingsContributionSchema);

const savingsMonthlyGoalSchema = new mongoose.Schema({
  ownerId: { type: Number, required: true },
  monthKey: { type: Number, required: true },
  targetAmount: { type: Number, required: true, min: 0 },
  updatedAt: { type: Date, default: Date.now }
});
savingsMonthlyGoalSchema.index({ ownerId: 1, monthKey: 1 }, { unique: true });
const SavingsMonthlyGoal = mongoose.model('SavingsMonthlyGoal', savingsMonthlyGoalSchema);

const sourceSchema = new mongoose.Schema({
  ownerId: { type: Number, required: true, index: true },
  type: { type: String, required: true, enum: ['income', 'expense'] },
  label: { type: String, required: true, trim: true }
}, { timestamps: true });
sourceSchema.index({ ownerId: 1, type: 1, label: 1 }, { unique: true });
const Source = mongoose.model('Source', sourceSchema);

const createToken = (user) => jwt.sign(
  { sub: user._id.toString(), clientId: user.clientId, username: user.username },
  JWT_SECRET,
  { expiresIn: '7d' }
);
const toPublicUser = (user) => ({
  id: user.clientId,
  username: user.username,
  email: user.email,
  fullName: user.fullName,
  phone: user.phone
});

const authRequired = (req, res, next) => {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { id: payload.sub, clientId: payload.clientId, username: payload.username };
    return next();
  } catch (err) {
    console.error('Auth error', err);
    return res.status(401).json({ message: 'Invalid token' });
  }
};

const authRouter = express.Router();
const financeRouter = express.Router();

// Auth: register
authRouter.post('/register', async (req, res) => {
  try {
    const { username, email, password, fullName, phone } = req.body;
    const cleanUsername = (username || '').trim();
    const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : undefined;
    const cleanFullName = typeof fullName === 'string' ? fullName.trim() : undefined;
    const cleanPhone = typeof phone === 'string' ? phone.trim() : undefined;

    if (!cleanUsername || !password) {
      return res.status(400).json({ message: 'username and password are required' });
    }

    const search = [{ username: cleanUsername }];
    if (cleanEmail) search.push({ email: cleanEmail });

    const existingUser = await User.findOne({ $or: search });
    if (existingUser) {
      return res.status(409).json({ message: 'User already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const last = await User.findOne().sort({ clientId: -1 }).select('clientId').lean();
    const nextClientId = last && typeof last.clientId === 'number' ? last.clientId + 1 : 1;
    const user = await User.create({
      username: cleanUsername,
      email: cleanEmail,
      passwordHash,
      clientId: nextClientId,
      fullName: cleanFullName,
      phone: cleanPhone
    });
    const token = createToken(user);

    return res.status(201).json({
      message: 'Registered successfully',
      user: toPublicUser(user),
      token
    });
  } catch (err) {
    console.error('Register error', err);
    return res.status(500).json({ message: 'Unexpected error' });
  }
});

// Auth: login
authRouter.post('/login', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if ((!username && !email) || !password) {
      return res.status(400).json({ message: 'username (or email) and password are required' });
    }

    const query = username
      ? { username: username.trim() }
      : { email: typeof email === 'string' ? email.trim().toLowerCase() : email };
    const user = await User.findOne(query);
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Assign a clientId for older accounts if missing
    if (typeof user.clientId !== 'number') {
      const last = await User.findOne().sort({ clientId: -1 }).select('clientId').lean();
      const nextClientId = last && typeof last.clientId === 'number' ? last.clientId + 1 : 1;
      user.clientId = nextClientId;
      await user.save();
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = createToken(user);

    return res.json({
      message: 'Login successful',
      user: toPublicUser(user),
      token
    });
  } catch (err) {
    console.error('Login error', err);
    return res.status(500).json({ message: 'Unexpected error' });
  }
});

// Auth: fetch user by numeric clientId (for "remember me" lookup)
authRouter.get('/user/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id) || id <= 0) {
      return res.status(400).json({ message: 'Invalid id' });
    }
    const user = await User.findOne({ clientId: id }).lean();
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    return res.json({ user: toPublicUser(user) });
  } catch (err) {
    console.error('Fetch user error', err);
    return res.status(500).json({ message: 'Unexpected error' });
  }
});

// Auth: get current user via JWT
authRouter.get('/me', authRequired, async (req, res) => {
  try {
    const user = await User.findOne({ clientId: req.user.clientId }).lean();
    if (!user) return res.status(404).json({ message: 'User not found' });
    return res.json({ user: toPublicUser(user) });
  } catch (err) {
    console.error('Auth me error', err);
    return res.status(500).json({ message: 'Unexpected error' });
  }
});

// Auth: update profile (username/fullName/email/phone)
authRouter.put('/profile', authRequired, async (req, res) => {
  try {
    const { username, fullName, email, phone } = req.body;
    const update = {};
    const cleanUsername = typeof username === 'string' ? username.trim() : undefined;
    const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : undefined;
    const cleanFullName = typeof fullName === 'string' ? fullName.trim() : undefined;
    const cleanPhone = typeof phone === 'string' ? phone.trim() : undefined;
    if (cleanUsername) update.username = cleanUsername;
    if (cleanEmail !== undefined) update.email = cleanEmail;
    if (cleanFullName !== undefined) update.fullName = cleanFullName;
    if (cleanPhone !== undefined) update.phone = cleanPhone;
    if (Object.keys(update).length === 0) return res.status(400).json({ message: 'No changes provided' });

    const existingUsername = update.username
      ? await User.findOne({ username: update.username, clientId: { $ne: req.user.clientId } }).lean()
      : null;
    if (existingUsername) return res.status(409).json({ message: 'Username already exists' });

    const existingEmail = update.email
      ? await User.findOne({ email: update.email, clientId: { $ne: req.user.clientId } }).lean()
      : null;
    if (existingEmail) return res.status(409).json({ message: 'Email already exists' });

    const user = await User.findOneAndUpdate({ clientId: req.user.clientId }, { $set: update }, { new: true });
    if (!user) return res.status(404).json({ message: 'User not found' });
    return res.json({ user: toPublicUser(user) });
  } catch (err) {
    console.error('Update profile error', err);
    return res.status(500).json({ message: 'Unexpected error' });
  }
});

// Notes: list
app.get('/notes', async (req, res) => {
  const notes = await Note.find();
  res.json(notes);
});

// Notes: create
app.post('/notes', async (req, res) => {
  const note = new Note(req.body);
  await note.save();
  res.json({ message: 'Note added!', note });
});

// Expenses
financeRouter.get('/expenses', authRequired, async (req, res) => {
  const ownerId = req.user.clientId;
  const expenses = await Expense.find({ ownerId }).sort({ dateUtc: -1 }).lean();
  res.json({ expenses });
});

financeRouter.post('/expenses', authRequired, async (req, res) => {
  try {
    const ownerId = req.user.clientId;
    const { description, amount, category, dateUtc } = req.body;
    const amountNum = Number(amount);
    const dateNum = Number(dateUtc);
    if (!description || !category || !Number.isFinite(amountNum) || !Number.isFinite(dateNum)) {
      return res.status(400).json({ message: 'Missing/invalid fields' });
    }
    const expense = await Expense.create({ ownerId, description, amount: amountNum, category, dateUtc: dateNum });
    res.status(201).json({ expense });
  } catch (err) {
    console.error('Create expense error', err);
    res.status(500).json({ message: 'Unexpected error' });
  }
});

financeRouter.put('/expenses/:id', authRequired, async (req, res) => {
  try {
    const ownerId = req.user.clientId;
    const { description, amount, category, dateUtc } = req.body;
    const update = {};
    if (description) update.description = description;
    if (category) update.category = category;
    if (Number.isFinite(Number(amount))) update.amount = Number(amount);
    if (Number.isFinite(Number(dateUtc))) update.dateUtc = Number(dateUtc);
    const expense = await Expense.findOneAndUpdate({ _id: req.params.id, ownerId }, update, { new: true });
    if (!expense) return res.status(404).json({ message: 'Expense not found' });
    res.json({ expense });
  } catch (err) {
    console.error('Update expense error', err);
    res.status(500).json({ message: 'Unexpected error' });
  }
});

financeRouter.delete('/expenses/:id', authRequired, async (req, res) => {
  try {
    const ownerId = req.user.clientId;
    const result = await Expense.findOneAndDelete({ _id: req.params.id, ownerId });
    if (!result) return res.status(404).json({ message: 'Expense not found' });
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('Delete expense error', err);
    res.status(500).json({ message: 'Unexpected error' });
  }
});

// Incomes
financeRouter.get('/incomes', authRequired, async (req, res) => {
  const ownerId = req.user.clientId;
  const incomes = await Income.find({ ownerId }).sort({ dateUtc: -1 }).lean();
  res.json({ incomes });
});

financeRouter.post('/incomes', authRequired, async (req, res) => {
  try {
    const ownerId = req.user.clientId;
    const { title, category, amount, dateUtc } = req.body;
    const amountNum = Number(amount);
    const dateNum = Number(dateUtc);
    if (!title || !category || !Number.isFinite(amountNum) || !Number.isFinite(dateNum)) {
      return res.status(400).json({ message: 'Missing/invalid fields' });
    }
    const income = await Income.create({ ownerId, title, category, amount: amountNum, dateUtc: dateNum });
    res.status(201).json({ income });
  } catch (err) {
    console.error('Create income error', err);
    res.status(500).json({ message: 'Unexpected error' });
  }
});

financeRouter.put('/incomes/:id', authRequired, async (req, res) => {
  try {
    const ownerId = req.user.clientId;
    const { title, category, amount, dateUtc } = req.body;
    const update = {};
    if (title) update.title = title;
    if (category) update.category = category;
    if (Number.isFinite(Number(amount))) update.amount = Number(amount);
    if (Number.isFinite(Number(dateUtc))) update.dateUtc = Number(dateUtc);
    const income = await Income.findOneAndUpdate({ _id: req.params.id, ownerId }, update, { new: true });
    if (!income) return res.status(404).json({ message: 'Income not found' });
    res.json({ income });
  } catch (err) {
    console.error('Update income error', err);
    res.status(500).json({ message: 'Unexpected error' });
  }
});

financeRouter.delete('/incomes/:id', authRequired, async (req, res) => {
  try {
    const ownerId = req.user.clientId;
    const result = await Income.findOneAndDelete({ _id: req.params.id, ownerId });
    if (!result) return res.status(404).json({ message: 'Income not found' });
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('Delete income error', err);
    res.status(500).json({ message: 'Unexpected error' });
  }
});

// Budgets
financeRouter.get('/budgets', authRequired, async (req, res) => {
  const ownerId = req.user.clientId;
  const filter = { ownerId };
  if (Number.isFinite(Number(req.query.monthKey))) filter.monthKey = Number(req.query.monthKey);
  const budgets = await Budget.find(filter).lean();
  res.json({ budgets });
});

financeRouter.post('/budgets', authRequired, async (req, res) => {
  try {
    const ownerId = req.user.clientId;
    const { monthKey, category, limitAmount } = req.body;
    const limit = Number(limitAmount);
    const month = Number(monthKey);
    const normCategory = normalizeCategoryLabel(category);
    if (!Number.isFinite(month) || !normCategory || !Number.isFinite(limit)) {
      return res.status(400).json({ message: 'Missing/invalid fields' });
    }
    const budget = await Budget.findOneAndUpdate(
      { ownerId, monthKey: month, category: normCategory },
      { $set: { limitAmount: limit, category: normCategory, updatedAt: new Date() } },
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );
    res.status(201).json({ budget });
  } catch (err) {
    console.error('Upsert budget error', err);
    res.status(500).json({ message: 'Unexpected error' });
  }
});

const deleteBudgetEntry = async (filters) => {
  for (const filter of filters) {
    const found = await Budget.findOne(filter);
    if (found) {
      await Budget.deleteOne({ _id: found._id });
      return found;
    }
  }
  return null;
};

financeRouter.delete('/budgets/:id', authRequired, async (req, res) => {
  try {
    const ownerId = req.user.clientId;
    const result = await Budget.findOneAndDelete({ _id: req.params.id, ownerId });
    if (!result) return res.status(404).json({ message: 'Budget not found' });
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('Delete budget error', err);
    res.status(500).json({ message: 'Unexpected error' });
  }
});

// Budget delete by composite key (monthKey + category), tolerant for older data
financeRouter.delete('/budgets', authRequired, async (req, res) => {
  try {
    const ownerId = req.user.clientId;
    const monthKey = Number(req.query.monthKey);
    const rawCategory = (req.query.category || '').toString();
    const category = normalizeCategoryLabel(rawCategory);
    if (!Number.isFinite(monthKey) || !category) {
      return res.status(400).json({ message: 'monthKey and category are required' });
    }

    const regexCat = new RegExp(`^${escapeRegex(category)}$`, 'i');
    const filters = [
      { ownerId, monthKey, category },
      { ownerId, monthKey, category: regexCat },
      { monthKey, category },
      { monthKey, category: regexCat }
    ];
    const result = await deleteBudgetEntry(filters);
    if (!result) return res.status(404).json({ message: 'Budget not found' });
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('Delete budget (composite) error', err);
    res.status(500).json({ message: 'Unexpected error' });
  }
});

// Savings goals
financeRouter.get('/savings/goals', authRequired, async (req, res) => {
  const ownerId = req.user.clientId;
  const goals = await SavingsGoal.find({ ownerId }).sort({ createdAt: -1 }).lean();
  res.json({ goals });
});

financeRouter.post('/savings/goals', authRequired, async (req, res) => {
  try {
    const ownerId = req.user.clientId;
    const { title, targetAmount, iconKey, createdAtUtc, deadlineUtc, cadence } = req.body;
    const normalizedTitle = normalizeGoalTitle(title);
    const target = Number(targetAmount);
    if (!normalizedTitle || !Number.isFinite(target)) {
      return res.status(400).json({ message: 'Missing/invalid fields' });
    }
    const goal = await SavingsGoal.create({ ownerId, title: normalizedTitle, targetAmount: target, iconKey, createdAtUtc, deadlineUtc, cadence });
    res.status(201).json({ goal });
  } catch (err) {
    console.error('Create savings goal error', err);
    res.status(500).json({ message: 'Unexpected error' });
  }
});

financeRouter.put('/savings/goals/:id', authRequired, async (req, res) => {
  try {
    const ownerId = req.user.clientId;
    const update = {};
    ['title', 'iconKey', 'cadence'].forEach((k) => {
      if (req.body[k] !== undefined) update[k] = k === 'title' ? normalizeGoalTitle(req.body[k]) : req.body[k];
    });
    if (Number.isFinite(req.body.targetAmount)) update.targetAmount = req.body.targetAmount;
    if (Number.isFinite(Number(req.body.deadlineUtc))) update.deadlineUtc = Number(req.body.deadlineUtc);
    const goal = await SavingsGoal.findOneAndUpdate({ _id: req.params.id, ownerId }, update, { new: true });
    if (!goal) return res.status(404).json({ message: 'Goal not found' });
    res.json({ goal });
  } catch (err) {
    console.error('Update savings goal error', err);
    res.status(500).json({ message: 'Unexpected error' });
  }
});

financeRouter.delete('/savings/goals/:id', authRequired, async (req, res) => {
  try {
    const ownerId = req.user.clientId;
    const result = await SavingsGoal.findOneAndDelete({ _id: req.params.id, ownerId });
    if (!result) return res.status(404).json({ message: 'Goal not found' });
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('Delete savings goal error', err);
    res.status(500).json({ message: 'Unexpected error' });
  }
});

// Delete savings goal by title (useful when client lacks Mongo _id)
financeRouter.delete('/savings/goals', authRequired, async (req, res) => {
  try {
    const ownerId = req.user.clientId;
    const title = normalizeGoalTitle(req.query.title);
    if (!title) return res.status(400).json({ message: 'title is required' });
    const regexTitle = new RegExp(`^${escapeRegex(title)}$`, 'i');
    const goal = await SavingsGoal.findOneAndDelete({ ownerId, title: regexTitle });
    if (!goal) return res.status(404).json({ message: 'Goal not found' });
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('Delete savings goal (title) error', err);
    res.status(500).json({ message: 'Unexpected error' });
  }
});

// Savings contributions
financeRouter.get('/savings/contributions', authRequired, async (req, res) => {
  const ownerId = req.user.clientId;
  const filter = { ownerId };
  if (req.query.goalId) filter.goalId = req.query.goalId;
  const contributions = await SavingsContribution.find(filter).sort({ dateUtc: -1 }).lean();
  res.json({ contributions });
});

financeRouter.post('/savings/contributions', authRequired, async (req, res) => {
  try {
    const ownerId = req.user.clientId;
    const { goalId, amount, dateUtc, isAuto } = req.body;
    const amountNum = Number(amount);
    const dateNum = Number(dateUtc);
    if (!Number.isFinite(amountNum) || !Number.isFinite(dateNum)) {
      return res.status(400).json({ message: 'Missing/invalid fields' });
    }
    const contribution = await SavingsContribution.create({
      ownerId,
      goalId: goalId || undefined,
      amount: amountNum,
      dateUtc: dateNum,
      isAuto: Boolean(isAuto)
    });
    res.status(201).json({ contribution });
  } catch (err) {
    console.error('Create contribution error', err);
    res.status(500).json({ message: 'Unexpected error' });
  }
});

financeRouter.delete('/savings/contributions/:id', authRequired, async (req, res) => {
  try {
    const ownerId = req.user.clientId;
    const result = await SavingsContribution.findOneAndDelete({ _id: req.params.id, ownerId });
    if (!result) return res.status(404).json({ message: 'Contribution not found' });
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('Delete contribution error', err);
    res.status(500).json({ message: 'Unexpected error' });
  }
});

// Savings monthly goals
financeRouter.get('/savings/monthly-goals', authRequired, async (req, res) => {
  const ownerId = req.user.clientId;
  const filter = { ownerId };
  if (Number.isFinite(Number(req.query.monthKey))) filter.monthKey = Number(req.query.monthKey);
  const monthlyGoals = await SavingsMonthlyGoal.find(filter).lean();
  res.json({ monthlyGoals });
});

financeRouter.post('/savings/monthly-goals', authRequired, async (req, res) => {
  try {
    const ownerId = req.user.clientId;
    const { monthKey, targetAmount } = req.body;
    const month = Number(monthKey);
    const target = Number(targetAmount);
    if (!Number.isFinite(month) || !Number.isFinite(target)) {
      return res.status(400).json({ message: 'Missing/invalid fields' });
    }
    const monthlyGoal = await SavingsMonthlyGoal.findOneAndUpdate(
      { ownerId, monthKey: month },
      { $set: { targetAmount: target, updatedAt: new Date() } },
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );
    res.status(201).json({ monthlyGoal });
  } catch (err) {
    console.error('Upsert monthly goal error', err);
    res.status(500).json({ message: 'Unexpected error' });
  }
});

// Custom sources (income/expense) tied to user
const normalizeSourceLabel = (value) => {
  if (!value || typeof value !== 'string') return '';
  return value.trim().replace(/\s+/g, ' ');
};
const isValidSourceType = (value) => value === 'income' || value === 'expense';
const normalizeCategoryLabel = (value) => {
  if (!value || typeof value !== 'string') return '';
  return value.trim().replace(/\s+/g, ' ');
};
const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const normalizeGoalTitle = normalizeCategoryLabel;

financeRouter.get('/sources', authRequired, async (req, res) => {
  const ownerId = req.user.clientId;
  const filter = { ownerId };
  if (isValidSourceType(req.query.type)) filter.type = req.query.type;
  const sources = await Source.find(filter).sort({ label: 1 }).lean();
  res.json({ sources });
});

financeRouter.post('/sources', authRequired, async (req, res) => {
  try {
    const ownerId = req.user.clientId;
    const type = req.body.type;
    const label = normalizeSourceLabel(req.body.label);
    if (!isValidSourceType(type) || !label) {
      return res.status(400).json({ message: 'type (income/expense) and label are required' });
    }
    const existing = await Source.findOne({ ownerId, type, label }).lean();
    if (existing) return res.status(409).json({ message: 'Source already exists' });
    const source = await Source.create({ ownerId, type, label });
    res.status(201).json({ source });
  } catch (err) {
    console.error('Create source error', err);
    res.status(500).json({ message: 'Unexpected error' });
  }
});

financeRouter.put('/sources/:id', authRequired, async (req, res) => {
  try {
    const ownerId = req.user.clientId;
    const update = {};
    if (req.body.type && isValidSourceType(req.body.type)) update.type = req.body.type;
    if (req.body.label !== undefined) {
      const label = normalizeSourceLabel(req.body.label);
      if (!label) return res.status(400).json({ message: 'Label cannot be empty' });
      update.label = label;
    }
    if (Object.keys(update).length === 0) return res.status(400).json({ message: 'No changes provided' });

    const source = await Source.findOne({ _id: req.params.id, ownerId });
    if (!source) return res.status(404).json({ message: 'Source not found' });
    if (update.type) source.type = update.type;
    if (update.label) source.label = update.label;
    await source.save();
    res.json({ source });
  } catch (err) {
    if (err && err.code === 11000) {
      return res.status(409).json({ message: 'Source already exists' });
    }
    console.error('Update source error', err);
    res.status(500).json({ message: 'Unexpected error' });
  }
});

financeRouter.delete('/sources/:id', authRequired, async (req, res) => {
  try {
    const ownerId = req.user.clientId;
    const result = await Source.findOneAndDelete({ _id: req.params.id, ownerId });
    if (!result) return res.status(404).json({ message: 'Source not found' });
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('Delete source error', err);
    res.status(500).json({ message: 'Unexpected error' });
  }
});

// Routers
app.use('/auth', authRouter);
app.use('/', financeRouter); // finance endpoints already namespaced (/expenses, /incomes, /budgets, /savings/...)

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error', err);
  res.status(500).json({ message: 'Unexpected error' });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
