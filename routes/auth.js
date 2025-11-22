// routes/auth.js
const express = require('express');
const router = express.Router();
const pool = require('../db');           // your db pool (mysql2/promise)
const bcrypt = require('bcrypt');       // or 'bcryptjs' if you installed it
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

// register (optional)
router.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    const [rows] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (rows.length) return res.status(409).json({ error: 'User already exists' });

    const hash = await bcrypt.hash(password, 10);
    const [result] = await pool.query('INSERT INTO users (name,email,password_hash) VALUES (?,?,?)', [name||null, email, hash]);

    return res.status(201).json({ message: 'User created', user: { id: result.insertId, name: name||null, email } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// login -> if user not found, create user (store credentials), then login
router.post('/login', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    // try find user
    const [rows] = await pool.query('SELECT id, password_hash, name, created_at, last_login FROM users WHERE email = ?', [email]);
    let user = rows[0];

    if (!user) {
      // not found -> create user with hashed password
      const hash = await bcrypt.hash(password, 10);
      const [r] = await pool.query('INSERT INTO users (name,email,password_hash) VALUES (?,?,?)', [name||null, email, hash]);
      const userId = r.insertId;

      // set last_login
      await pool.query('UPDATE users SET last_login = NOW() WHERE id = ?', [userId]);

      const token = jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: '8h' });
      const created = new Date().toISOString();
      const userObj = { id: userId, name: name||null, email, created_at: created, last_login: created };

      return res.json({ message: 'Logged in (user created)', token, user: userObj });
    }

    // user exists -> validate password
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    // update last_login
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);

    const token = jwt.sign({ userId: user.id, email }, JWT_SECRET, { expiresIn: '8h' });
    const userDetails = {
      id: user.id,
      name: user.name,
      email,
      created_at: user.created_at,
      last_login: new Date().toISOString()
    };

    return res.json({ message: 'Logged in', token, user: userDetails });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
