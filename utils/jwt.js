'use strict';
/**
 * hamoran-secure/utils/jwt.js
 * Secure JWT handling:
 * - Access tokens: 15-minute expiry, signed with separate secret
 * - Refresh tokens: 7-day expiry, stored server-side (revocable)
 * - Refresh token blacklist: in-memory (dev) or file-backed (prod)
 */
const jwt    = require('jsonwebtoken');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const ACCESS_SECRET  = process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const ACCESS_EXPIRY  = process.env.JWT_ACCESS_EXPIRY  || '15m';
const REFRESH_EXPIRY = process.env.JWT_REFRESH_EXPIRY || '7d';

// ── Token store (issued refresh tokens — enables server-side invalidation) ──
const TOKEN_FILE = path.join(__dirname, '../data/refresh-tokens.json');

let _tokenStore = null;

function loadTokenStore() {
  if (_tokenStore) return _tokenStore;
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      _tokenStore = new Set(JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8')));
    } else {
      _tokenStore = new Set();
    }
  } catch {
    _tokenStore = new Set();
  }
  return _tokenStore;
}

function saveTokenStore() {
  try {
    const dir = path.dirname(TOKEN_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(TOKEN_FILE, JSON.stringify([...loadTokenStore()]), 'utf8');
  } catch (err) {
    console.error('[JWT] Failed to persist token store:', err.message);
  }
}

function issueRefreshToken(jti) {
  loadTokenStore().add(jti);
  saveTokenStore();
}

function revokeRefreshToken(jti) {
  loadTokenStore().delete(jti);
  saveTokenStore();
}

function isRefreshTokenValid(jti) {
  return loadTokenStore().has(jti);
}

// Purge expired tokens from store (run periodically)
function purgeExpiredTokens() {
  const store = loadTokenStore();
  let removed = 0;
  for (const jti of store) {
    // JTI format: <userId>:<timestamp>
    const [, ts] = jti.split(':');
    const issued = parseInt(ts, 10);
    // 7-day expiry
    if (Date.now() - issued > 7 * 24 * 60 * 60 * 1000) {
      store.delete(jti);
      removed++;
    }
  }
  if (removed > 0) saveTokenStore();
}

// Run purge every 6 hours
setInterval(purgeExpiredTokens, 6 * 60 * 60 * 1000);

// ── Token creation ─────────────────────────────────────────
function createAccessToken(payload) {
  if (!ACCESS_SECRET) throw new Error('JWT_ACCESS_SECRET not configured');
  return jwt.sign(
    { ...payload, type: 'access' },
    ACCESS_SECRET,
    {
      expiresIn: ACCESS_EXPIRY,
      algorithm: 'HS256',
      issuer: 'hamoran-api',
      audience: 'hamoran-client',
    }
  );
}

function createRefreshToken(userId) {
  if (!REFRESH_SECRET) throw new Error('JWT_REFRESH_SECRET not configured');
  const jti = `${userId}:${Date.now()}:${crypto.randomBytes(16).toString('hex')}`;
  const token = jwt.sign(
    { sub: userId, jti, type: 'refresh' },
    REFRESH_SECRET,
    {
      expiresIn: REFRESH_EXPIRY,
      algorithm: 'HS256',
      issuer: 'hamoran-api',
      audience: 'hamoran-client',
    }
  );
  issueRefreshToken(jti);
  return { token, jti };
}

// ── Token verification ─────────────────────────────────────
function verifyAccessToken(token) {
  if (!ACCESS_SECRET) throw new Error('JWT_ACCESS_SECRET not configured');
  try {
    const payload = jwt.verify(token, ACCESS_SECRET, {
      algorithms: ['HS256'],
      issuer: 'hamoran-api',
      audience: 'hamoran-client',
    });
    if (payload.type !== 'access') throw new Error('Wrong token type');
    return { valid: true, payload };
  } catch (err) {
    return { valid: false, error: err.name === 'TokenExpiredError' ? 'expired' : 'invalid' };
  }
}

function verifyRefreshToken(token) {
  if (!REFRESH_SECRET) throw new Error('JWT_REFRESH_SECRET not configured');
  try {
    const payload = jwt.verify(token, REFRESH_SECRET, {
      algorithms: ['HS256'],
      issuer: 'hamoran-api',
      audience: 'hamoran-client',
    });
    if (payload.type !== 'refresh') throw new Error('Wrong token type');
    // Server-side check: token must be in our issued-token store
    if (!isRefreshTokenValid(payload.jti)) {
      return { valid: false, error: 'revoked' };
    }
    return { valid: true, payload };
  } catch (err) {
    return { valid: false, error: err.name === 'TokenExpiredError' ? 'expired' : 'invalid' };
  }
}

// ── Cookie config ──────────────────────────────────────────
function accessTokenCookieOpts() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Strict',
    maxAge: 15 * 60 * 1000, // 15 minutes
    path: '/',
  };
}

function refreshTokenCookieOpts() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: '/api/auth', // scope refresh token to auth routes only
  };
}

function clearCookieOpts() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Strict',
    path: '/',
  };
}

module.exports = {
  createAccessToken,
  createRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  revokeRefreshToken,
  accessTokenCookieOpts,
  refreshTokenCookieOpts,
  clearCookieOpts,
};
