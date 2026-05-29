'use strict';
/**
 * hamoran-secure/routes/auth.js
 * Authentication API routes.
 *
 * POST /api/auth/login   — validate credentials, issue JWT in HttpOnly cookie
 * POST /api/auth/refresh — exchange refresh token for new access token
 * POST /api/auth/logout  — revoke refresh token server-side, clear cookies
 * GET  /api/auth/me      — return current user info (requires auth)
 */
const express  = require('express');
const bcrypt   = require('bcryptjs');
const router   = express.Router();

const {
  createAccessToken,
  createRefreshToken,
  verifyRefreshToken,
  revokeRefreshToken,
  accessTokenCookieOpts,
  refreshTokenCookieOpts,
  clearCookieOpts,
} = require('../utils/jwt');

const { validate, LoginSchema } = require('../utils/validators');
const { requireAuth }           = require('../middleware/auth');
const { authLimiter }           = require('../middleware/rateLimiter');
const { createError }           = require('../middleware/errorHandler');

// ── Admin credential store (single user — Super Admin) ────
// In production, replace with a database user lookup
function getAdminRecord() {
  const email = process.env.ADMIN_EMAIL;
  const hash  = process.env.ADMIN_PASSWORD_HASH;
  if (!email || !hash) throw new Error('Admin credentials not configured in environment');
  return { id: 'superadmin', email, passwordHash: hash, role: 'superadmin', name: 'Moid' };
}

// ── POST /api/auth/login ───────────────────────────────────
router.post('/login', authLimiter, async (req, res, next) => {
  try {
    // 1. Validate input
    const { success, data, errors } = validate(LoginSchema, req.body);
    if (!success) {
      return res.status(400).json({
        error: 'Validation failed',
        errors,
      });
    }

    // 2. Look up admin record
    let admin;
    try {
      admin = getAdminRecord();
    } catch {
      return next(createError('Authentication service unavailable', 503));
    }

    // 3. Email check (constant-time via bcrypt doing the work)
    const emailMatches = data.email.toLowerCase() === admin.email.toLowerCase();

    // 4. Password check with bcrypt (always run even if email wrong — prevents timing attack)
    const passwordHash = emailMatches ? admin.passwordHash : '$2b$12$invalidhashfortimingneutrality000000000000000000000000';
    const passwordOk   = await bcrypt.compare(data.password, passwordHash);

    // 5. Reject if either check failed
    if (!emailMatches || !passwordOk) {
      // Generic message — never reveal which field was wrong
      return res.status(401).json({
        error: 'Authentication failed',
        message: 'Invalid email or password.',
      });
    }

    // 6. Issue tokens
    const accessPayload = {
      sub:   admin.id,
      email: admin.email,
      role:  admin.role,
      name:  admin.name,
    };
    const accessToken              = createAccessToken(accessPayload);
    const { token: refreshToken }  = createRefreshToken(admin.id);

    // 7. Set HttpOnly cookies
    res.cookie('ham_access',  accessToken,  accessTokenCookieOpts());
    res.cookie('ham_refresh', refreshToken, refreshTokenCookieOpts());

    // 8. Return safe user info (no tokens in body)
    return res.status(200).json({
      message: 'Login successful',
      user: {
        id:    admin.id,
        email: admin.email,
        name:  admin.name,
        role:  admin.role,
      },
    });

  } catch (err) {
    next(err);
  }
});

// ── POST /api/auth/refresh ────────────────────────────────
router.post('/refresh', async (req, res, next) => {
  try {
    const refreshToken = req.cookies?.ham_refresh;

    if (!refreshToken) {
      return res.status(401).json({
        error: 'No refresh token',
        message: 'Please log in again.',
        code: 'NO_REFRESH_TOKEN',
      });
    }

    const result = verifyRefreshToken(refreshToken);

    if (!result.valid) {
      // Clear invalid cookies
      res.clearCookie('ham_access',  clearCookieOpts());
      res.clearCookie('ham_refresh', { ...clearCookieOpts(), path: '/api/auth' });

      const msg = result.error === 'revoked'
        ? 'Session has been revoked. Please log in again.'
        : 'Session expired. Please log in again.';

      return res.status(401).json({ error: 'Refresh failed', message: msg, code: result.error.toUpperCase() });
    }

    // Revoke old refresh token (rotation — prevents replay)
    revokeRefreshToken(result.payload.jti);

    // Get admin record to issue fresh tokens
    const admin = getAdminRecord();

    // Issue new token pair
    const accessPayload = {
      sub:   admin.id,
      email: admin.email,
      role:  admin.role,
      name:  admin.name,
    };
    const newAccessToken              = createAccessToken(accessPayload);
    const { token: newRefreshToken }  = createRefreshToken(admin.id);

    res.cookie('ham_access',  newAccessToken,  accessTokenCookieOpts());
    res.cookie('ham_refresh', newRefreshToken, refreshTokenCookieOpts());

    return res.status(200).json({ message: 'Token refreshed' });

  } catch (err) {
    next(err);
  }
});

// ── POST /api/auth/logout ─────────────────────────────────
router.post('/logout', requireAuth, async (req, res, next) => {
  try {
    // Revoke refresh token server-side so it cannot be reused
    const refreshToken = req.cookies?.ham_refresh;
    if (refreshToken) {
      const result = verifyRefreshToken(refreshToken);
      if (result.valid && result.payload?.jti) {
        revokeRefreshToken(result.payload.jti);
      }
    }

    // Clear both cookies
    res.clearCookie('ham_access',  clearCookieOpts());
    res.clearCookie('ham_refresh', { ...clearCookieOpts(), path: '/api/auth' });
    res.clearCookie('__Host-csrf', { sameSite: 'Strict', secure: process.env.NODE_ENV === 'production' });

    return res.status(200).json({ message: 'Logged out successfully' });

  } catch (err) {
    next(err);
  }
});

// ── GET /api/auth/me ──────────────────────────────────────
router.get('/me', requireAuth, (req, res) => {
  // Return verified user info from the JWT payload (already verified by requireAuth)
  const { sub: id, email, role, name } = req.user;
  res.json({ id, email, role, name });
});

module.exports = router;
