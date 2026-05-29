'use strict';
/**
 * hamoran-secure/middleware/auth.js
 * Server-side JWT verification middleware.
 *
 * Reads access token from HttpOnly cookie only.
 * Never accepts tokens from request body, query params, or headers
 * (prevents XSS-exfiltrated token reuse).
 *
 * Usage:
 *   router.get('/admin/leads', requireAuth, requireAdmin, handler)
 */
const { verifyAccessToken } = require('../utils/jwt');

// ── SUPER ADMIN EMAIL (from env, never from client) ──────
const SUPER_ADMIN_EMAIL = process.env.ADMIN_EMAIL;

/**
 * requireAuth
 * Validates the access token from the HttpOnly cookie.
 * Sets req.user on success.
 */
function requireAuth(req, res, next) {
  const token = req.cookies?.ham_access;

  if (!token) {
    return res.status(401).json({
      error: 'Authentication required',
      message: 'Please log in to continue.',
    });
  }

  const result = verifyAccessToken(token);

  if (!result.valid) {
    // Clear invalid/expired cookie
    res.clearCookie('ham_access', { httpOnly: true, sameSite: 'Strict' });

    if (result.error === 'expired') {
      return res.status(401).json({
        error: 'Token expired',
        message: 'Your session has expired. Please refresh or log in again.',
        code: 'TOKEN_EXPIRED',
      });
    }
    return res.status(401).json({
      error: 'Invalid token',
      message: 'Authentication failed. Please log in again.',
    });
  }

  // Attach verified user payload to request
  req.user = result.payload;
  next();
}

/**
 * requireAdmin
 * Verifies the user has admin role.
 * Must be used AFTER requireAuth.
 */
function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  if (req.user.role !== 'admin' && req.user.role !== 'superadmin') {
    return res.status(403).json({
      error: 'Forbidden',
      message: 'You do not have permission to access this resource.',
    });
  }
  next();
}

/**
 * requireSuperAdmin
 * Verifies the user is the Super Admin (Moid).
 * Used for sensitive ops: credential changes, user deletion, etc.
 */
function requireSuperAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  if (req.user.role !== 'superadmin' || req.user.email !== SUPER_ADMIN_EMAIL) {
    return res.status(403).json({
      error: 'Forbidden',
      message: 'This action requires Super Admin authority.',
    });
  }
  next();
}

/**
 * optionalAuth
 * Attaches user if authenticated, but does not block unauthenticated requests.
 */
function optionalAuth(req, res, next) {
  const token = req.cookies?.ham_access;
  if (!token) return next();
  const result = verifyAccessToken(token);
  if (result.valid) req.user = result.payload;
  next();
}

module.exports = { requireAuth, requireAdmin, requireSuperAdmin, optionalAuth };
