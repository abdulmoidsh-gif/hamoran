'use strict';
/**
 * hamoran-secure/middleware/csrf.js
 * CSRF protection using the Double-Submit Cookie pattern.
 *
 * How it works:
 * 1. On GET /api/csrf-token, server sets __Host-csrf cookie (HttpOnly=false so JS can read it)
 *    and returns the token in the response body.
 * 2. On state-changing requests (POST/PUT/PATCH/DELETE), client must send
 *    X-CSRF-Token header with the token.
 * 3. Server compares header value against cookie value using constant-time comparison.
 *
 * This is safe because:
 * - An attacker's page cannot read the cookie (SameSite=Strict + CORS)
 * - An attacker cannot set the X-CSRF-Token header on cross-origin requests
 */
const crypto = require('crypto');

const CSRF_SECRET = process.env.CSRF_SECRET;

// Generate a CSRF token (HMAC of session ID)
function generateCsrfToken(sessionId) {
  if (!CSRF_SECRET) throw new Error('CSRF_SECRET not configured');
  return crypto
    .createHmac('sha256', CSRF_SECRET)
    .update(sessionId)
    .digest('hex');
}

// Constant-time comparison to prevent timing attacks
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) {
    // Still run comparison to prevent timing leak on length
    crypto.timingSafeEqual(Buffer.from(a.padEnd(64, '0')), Buffer.from(b.padEnd(64, '0')));
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/**
 * csrfTokenRoute
 * GET /api/csrf-token
 * Issues a CSRF token tied to the user's session.
 */
function csrfTokenRoute(req, res) {
  // Use access token cookie as the session anchor, or generate a random ID
  const sessionId = req.cookies?.ham_access || crypto.randomBytes(16).toString('hex');
  const token = generateCsrfToken(sessionId);

  // Set the cookie (readable by JS so the frontend can include it in headers)
  res.cookie('__Host-csrf', token, {
    httpOnly: false,       // JS must be able to read this
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Strict',
    maxAge: 60 * 60 * 1000, // 1 hour
    path: '/',
  });

  res.json({ csrfToken: token });
}

/**
 * verifyCsrf
 * Middleware: validates CSRF token on state-changing requests.
 */
function verifyCsrf(req, res, next) {
  // Skip for safe methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

  const headerToken = req.headers['x-csrf-token'];
  const cookieToken = req.cookies?.['__Host-csrf'];

  if (!headerToken || !cookieToken) {
    return res.status(403).json({
      error: 'CSRF validation failed',
      message: 'Invalid or missing CSRF token.',
    });
  }

  if (!safeCompare(headerToken, cookieToken)) {
    return res.status(403).json({
      error: 'CSRF validation failed',
      message: 'CSRF token mismatch.',
    });
  }

  next();
}

module.exports = { csrfTokenRoute, verifyCsrf, generateCsrfToken };
