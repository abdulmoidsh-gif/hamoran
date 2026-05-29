'use strict';
const { rateLimit } = require('express-rate-limit');

const ipKey = (req) => req.ip || 'unknown';

function make({ windowMs, max, message, keyFn }) {
  return rateLimit({
    windowMs, max,
    standardHeaders: true, legacyHeaders: false,
    keyGenerator: keyFn || ipKey,
    handler(req, res) {
      res.set('Retry-After', String(Math.ceil(windowMs / 1000)));
      res.status(429).json({ error: 'Too many requests', message, retryAfterSeconds: Math.ceil(windowMs/1000) });
    },
  });
}

module.exports = {
  authLimiter:    make({ windowMs: 60000,  max: 5,    message: 'Too many login attempts. Wait 1 minute.' }),
  publicLimiter:  make({ windowMs: 60000,  max: 20,   message: 'Too many requests. Wait 1 minute.' }),
  authedLimiter:  make({ windowMs: 60000,  max: 60,   message: 'Rate limit reached. Slow down.',         keyFn: r => r.user?.sub || r.ip || 'unknown' }),
  contactLimiter: make({ windowMs: 300000, max: 3,    message: 'Too many form submissions. Wait 5 minutes.' }),
  aiLimiter:      make({ windowMs: 60000,  max: 10,   message: 'AI chat limit reached. Wait 1 minute.',   keyFn: r => r.user?.sub || r.ip || 'unknown' }),
  globalLimiter:  make({ windowMs: 900000, max: 5000, message: 'Too many requests. Try again later.' }),
};
