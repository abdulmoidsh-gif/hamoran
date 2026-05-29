'use strict';
/**
 * hamoran-secure/server/index.js
 * Main Express server.
 *
 * Security stack (in order):
 * 1. HTTPS redirect (production)
 * 2. Helmet (security headers: CSP, HSTS, X-Frame-Options, etc.)
 * 3. CORS (explicit allowlist — no wildcards)
 * 4. Cookie parser
 * 5. Global rate limiter
 * 6. Body parser (with size limit)
 * 7. Routes
 * 8. 404 handler
 * 9. Error handler (no stack traces to client)
 */

require('dotenv').config({ path: require('path').join(__dirname, '../.env') });

// Validate required environment variables before starting
const REQUIRED_ENV = [
  'ADMIN_EMAIL',
  'ADMIN_PASSWORD_HASH',
  'JWT_ACCESS_SECRET',
  'JWT_REFRESH_SECRET',
  'CSRF_SECRET',
];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`[STARTUP ERROR] Missing required environment variable: ${key}`);
    console.error('Copy .env.example to .env and fill in all values.');
    process.exit(1);
  }
}

const express      = require('express');
const helmet       = require('helmet');
const cors         = require('cors');
const cookieParser = require('cookie-parser');
const path         = require('path');

const { globalLimiter, publicLimiter } = require('../middleware/rateLimiter');
const { notFound, errorHandler }       = require('../middleware/errorHandler');
const { csrfTokenRoute }               = require('../middleware/csrf');

const authRouter    = require('../routes/auth');
const contactRouter = require('../routes/contact');
const chatRouter    = require('../routes/chat');
const adminRouter   = require('../routes/admin');

const app  = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

// ── 1. HTTPS redirect ─────────────────────────────────────
if (process.env.FORCE_HTTPS === 'true') {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] === 'http' || req.protocol === 'http') {
      return res.redirect(301, `https://${req.headers.host}${req.url}`);
    }
    next();
  });
}

// ── 2. Trust proxy (for IP detection behind load balancers) ─
app.set('trust proxy', 1);

// ── 3. Helmet (security headers) ──────────────────────────
const ALLOWED_ORIGINS_RAW = process.env.ALLOWED_ORIGINS || 'http://localhost:3000';
const ALLOWED_ORIGINS = ALLOWED_ORIGINS_RAW.split(',').map(o => o.trim());

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      [
        "'self'",
        "'unsafe-inline'",  // Required for inline scripts in static HTML — lock down in production
        'https://cdnjs.cloudflare.com',
      ],
      styleSrc:       ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:        ["'self'", 'https://fonts.gstatic.com'],
      imgSrc:         ["'self'", 'data:', 'blob:'],
      connectSrc:     ["'self'"],
      frameAncestors: ["'none'"],
      formAction:     ["'self'"],
      baseUri:        ["'self'"],
      upgradeInsecureRequests: isProd ? [] : null,
    },
    reportOnly: false,
  },
  hsts: isProd ? {
    maxAge: parseInt(process.env.HSTS_MAX_AGE || '31536000', 10),
    includeSubDomains: true,
    preload: true,
  } : false,
  frameguard:       { action: 'deny' },
  noSniff:          true,
  xssFilter:        true,
  referrerPolicy:   { policy: 'strict-origin-when-cross-origin' },
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
}));

// Add Permissions-Policy separately (helmet doesn't include it by default)
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  next();
});

// ── 4. CORS ───────────────────────────────────────────────
app.use(cors({
  origin(origin, callback) {
    // Allow requests with no origin (mobile apps, curl, server-to-server)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(new Error(`CORS: Origin ${origin} not allowed`));
  },
  credentials: true,         // Required for cookies
  methods:     ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-CSRF-Token'],
  exposedHeaders: ['RateLimit-Limit', 'RateLimit-Remaining', 'RateLimit-Reset', 'Retry-After'],
}));

// ── 5. Cookie parser ──────────────────────────────────────
app.use(cookieParser());

// ── 6. Global rate limiter ────────────────────────────────
app.use('/api', globalLimiter);

// ── 7. Body parser (with size limits) ────────────────────
app.use(express.json({ limit: '10kb' }));       // Prevent JSON payload attacks
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ── 8. Static files ───────────────────────────────────────
app.use(express.static(path.join(__dirname, '../public'), {
  etag:         true,
  lastModified: true,
  maxAge:       isProd ? '1d' : 0,
  // Never serve directory listings
  index:        ['index.html'],
}));

// ── 9. API Routes ─────────────────────────────────────────
app.get('/api/csrf-token', publicLimiter, csrfTokenRoute);
app.use('/api/auth',    authRouter);
app.use('/api/contact', contactRouter);
app.use('/api/chat',    chatRouter);
app.use('/api/admin',   adminRouter);

// Health check (no auth — used by load balancers)
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ── 10. SPA fallback ──────────────────────────────────────
// Serve index.html for any non-API route (SPA routing) - Express 5 compatible
app.use((req, res, next) => {
  if (req.path.startsWith('/api')) return next();
  if (req.method !== 'GET') return next();
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ── 11. 404 + Error handlers ──────────────────────────────
app.use(notFound);
app.use(errorHandler);

// ── Start server ──────────────────────────────────────────
const server = app.listen(PORT, () => {
  console.info(`[SERVER] Hamoran running on port ${PORT} (${process.env.NODE_ENV || 'development'})`);
  console.info(`[SERVER] HTTPS enforcement: ${process.env.FORCE_HTTPS === 'true' ? 'ON' : 'OFF'}`);
  if (!isProd) {
    console.info(`[SERVER] Admin login: http://localhost:${PORT}/admin.html`);
    console.info(`[SERVER] API: http://localhost:${PORT}/api/health`);
  }
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.info('[SERVER] SIGTERM received — shutting down gracefully');
  server.close(() => process.exit(0));
});

process.on('unhandledRejection', (reason) => {
  // Log but never crash the server in production for unhandled rejections
  console.error('[SERVER] Unhandled rejection:', reason?.message || reason);
});

module.exports = app;
