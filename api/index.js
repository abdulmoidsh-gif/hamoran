'use strict';
/**
 * api/index.js — Vercel serverless entry point.
 * Delegates to the full Express app in server/index.js.
 *
 * Previously this file contained a placeholder stub with hardcoded credentials
 * at the wrong route (/api/login instead of /api/auth/login). That caused
 * login failures when Vercel's file-based routing served this handler.
 */
module.exports = require('../server/index');
