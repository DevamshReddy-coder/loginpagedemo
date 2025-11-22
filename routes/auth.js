// routes/auth.js
const express = require('express');
const router = express.Router();
const pool = require('../db'); // expects module.exports = { query: (text, params) => pool.query(text, params), pool }
const bcrypt = require('bcrypt'); // or 'bcryptjs' if you installed that
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

// Register (kept for manual registration)
router.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    const exists = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (exists.rows.length) return res.status(409).json({ error: 'User already exists' });

    const hash = await bcrypt.hash(password, 10);
    const insert = await pool.query(
      'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email, created_at',
      [name || null, email, hash]
    );

    const user = insert.rows[0];
    return res.status(201).json({ message: 'User created', user });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Login (auto-create if not found)
router.post('/login', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    // 1) find user
    const result = await pool.query(
      'SELECT id, password_hash, name, created_at, last_login FROM users WHERE email = $1',
      [email]
    );

    let user = result.rows[0];

    if (!user) {
      // user not found -> create
      const hash = await bcrypt.hash(password, 10);
      const ins = await pool.query(
        'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, created_at',
        [name || null, email, hash]
      );
      const userId = ins.rows[0].id;

      // update last_login and return exact DB timestamp
      const upd = await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1 RETURNING last_login', [userId]);

      const token = jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: '8h' });

      const userObj = {
        id: userId,
        name: name || null,
        email,
        created_at: ins.rows[0].created_at,
        last_login: upd.rows[0].last_login
      };

      return res.json({ message: 'Logged in (user created)', token, user: userObj });
    }

    // user exists -> validate password
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    // update last_login and fetch exact timestamp
    const upd = await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1 RETURNING last_login', [user.id]);

    const token = jwt.sign({ userId: user.id, email }, JWT_SECRET, { expiresIn: '8h' });

    const userDetails = {
      id: user.id,
      name: user.name,
      email,
      created_at: user.created_at,
      last_login: upd.rows[0].last_login
    };

    return res.json({ message: 'Logged in', token, user: userDetails });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
