// server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

const authRoutes = require('./routes/auth');      // make sure routes/auth.js exists
// optional: create if you want profile fetching

const app = express();

// ---------- Middleware ----------
app.use(cors()); // allow requests from any origin for dev; restrict in production
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files from project root so login.html is available at "/"
app.use(express.static(path.join(__dirname)));

// ---------- Routes ----------
app.use('/api/auth', authRoutes);
// Optional root route — serve login.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// Healthcheck
app.get('/health', (req, res) => {
  res.json({ status: 'ok', env: process.env.NODE_ENV || 'development' });
});

// ---------- Error handler ----------
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Server error' });
});

// ---------- Start server ----------
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`loginpagedemo running — http://localhost:${PORT}`);
  console.log('Environment:', process.env.NODE_ENV || 'development');
  console.log('Using DB:', process.env.DB_HOST, process.env.DB_NAME ? `DB=${process.env.DB_NAME}` : '');
});

// Graceful shutdown
function shutdown(signal) {
  console.log(`Received ${signal}. Shutting down server...`);
  server.close(() => {
    console.log('HTTP server closed.');
    process.exit(0);
  });
  // Force exit if not closed in 10s
  setTimeout(() => {
    console.error('Forcing shutdown.');
    process.exit(1);
  }, 10000).unref();
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
