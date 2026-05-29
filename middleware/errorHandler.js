'use strict';
/**
 * hamoran-secure/middleware/errorHandler.js
 * Centralised error handling.
 *
 * All errors flow through here.
 * - Detailed info logged server-side only.
 * - Generic messages sent to client.
 * - No stack traces, file paths, or DB errors exposed.
 */

/**
 * notFound
 * 404 handler — placed before the error handler in middleware chain.
 */
function notFound(req, res, next) {
  const err = new Error(`Not found: ${req.method} ${req.path}`);
  err.statusCode = 404;
  err.isOperational = true;
  next(err);
}

/**
 * errorHandler
 * Global error handler — must be last middleware registered.
 */
function errorHandler(err, req, res, next) { // eslint-disable-line no-unused-vars
  // Log full error server-side
  const logEntry = {
    timestamp: new Date().toISOString(),
    method:    req.method,
    path:      req.path,
    ip:        req.ip,
    status:    err.statusCode || 500,
    message:   err.message,
    // Only include stack in development
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }),
  };
  console.error('[ERROR]', JSON.stringify(logEntry));

  // Never expose internal details to client
  const statusCode = err.statusCode || err.status || 500;
  const isOperational = err.isOperational === true;

  // Operational errors (known, expected) — safe to show message
  if (isOperational && statusCode < 500) {
    return res.status(statusCode).json({
      error:   err.name || 'Request Error',
      message: err.message,
      ...(err.errors && { errors: err.errors }), // validation errors
    });
  }

  // Unhandled / server errors — generic message only
  return res.status(statusCode).json({
    error:   'Internal Server Error',
    message: 'Something went wrong. Please try again later.',
  });
}

/**
 * createError(message, statusCode, errors?)
 * Helper to create operational errors.
 */
function createError(message, statusCode = 400, errors = null) {
  const err = new Error(message);
  err.statusCode = statusCode;
  err.isOperational = true;
  if (errors) err.errors = errors;
  return err;
}

module.exports = { notFound, errorHandler, createError };
