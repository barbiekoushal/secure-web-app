require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const helmet = require('helmet');
const csurf = require('csurf');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middlewares
app.use(helmet());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Limit repeated requests (basic protection)
const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 10,
  message: { message: 'Too many requests, try again later.' }
});

// Session setup
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: './' }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 2 * 60 * 60 * 1000 } // 2 hours
}));

// CSRF protection
const csrfProtection = csurf({ cookie: true });

// Database connection
const db = new sqlite3.Database('./database.db', err => {
  if (err) console.error('❌ Database error:', err);
  else console.log('✅ Connected to SQLite database');
});

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
)`);

// Routes
app.get('/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Signup route
app.post('/signup', authLimiter, csrfProtection,
  body('username').trim().isLength({ min: 3 }).isAlphanumeric(),
  body('password').isLength({ min: 6 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { username, password } = req.body;
    bcrypt.hash(password, 12, (err, hashed) => {
      if (err) return res.status(500).json({ message: 'Error hashing password' });

      db.run(`INSERT INTO users (username, password) VALUES (?, ?)`,
        [username, hashed],
        function (err) {
          if (err) return res.status(400).json({ message: 'Username already exists' });
          req.session.user = { id: this.lastID, username };
          res.json({ message: 'Signup successful' });
        });
    });
  });

// Login route
app.post('/login', authLimiter, csrfProtection,
  body('username').isLength({ min: 3 }),
  body('password').isLength({ min: 1 }),
  (req, res) => {
    const { username, password } = req.body;

    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
      if (err) return res.status(500).json({ message: 'Database error' });
      if (!user) return res.status(400).json({ message: 'Invalid username' });

      bcrypt.compare(password, user.password, (err, same) => {
        if (!same) return res.status(400).json({ message: 'Wrong password' });
        req.session.user = { id: user.id, username: user.username };
        res.json({ message: 'Login successful' });
      });
    });
  });

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ message: 'Logged out' });
  });
});

// Protected route (welcome)
app.get('/api/welcome', (req, res) => {
  if (req.session.user) {
    res.json({ message: `Welcome ${req.session.user.username}` });
  } else {
    res.status(401).json({ message: 'Not logged in' });
  }
});

app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
