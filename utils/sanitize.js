'use strict';
/**
 * hamoran-secure/utils/sanitize.js
 * Server-side HTML sanitization and output escaping.
 * Used for any value that reaches the database or a template.
 */

/**
 * escapeHtml(str)
 * Escapes HTML special characters to prevent XSS.
 * Use on ALL values rendered in HTML templates.
 */
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#x27;')
    .replace(/\//g, '&#x2F;');
}

/**
 * stripHtml(str)
 * Removes all HTML tags from a string.
 * Use when HTML must be completely disallowed.
 */
function stripHtml(str) {
  if (!str) return '';
  return String(str).replace(/<[^>]*>/g, '').trim();
}

/**
 * sanitizeText(str, maxLen)
 * Strips HTML and trims to maxLen — for plain text fields.
 */
function sanitizeText(str, maxLen = 2000) {
  return stripHtml(str).substring(0, maxLen).trim();
}

/**
 * sanitizeEmail(str)
 */
function sanitizeEmail(str) {
  return String(str || '').toLowerCase().trim().substring(0, 254);
}

/**
 * sanitizePhone(str)
 */
function sanitizePhone(str) {
  return String(str || '').replace(/[^\d\s\+\-\(\)]/g, '').substring(0, 20).trim();
}

/**
 * detectInjection(text)
 * Checks for prompt injection patterns.
 * Returns true if suspicious content found.
 */
const INJECTION_PATTERNS = [
  /ignore\s+(previous|above|all)\s+instructions?/i,
  /system\s*:/i,
  /assistant\s*:/i,
  /\[INST\]/i,
  /<<SYS>>/i,
  /you\s+are\s+now/i,
  /forget\s+(everything|all|previous)/i,
  /new\s+instructions?\s*:/i,
  /override\s+(your|all)\s+(instructions?|rules?|constraints?)/i,
  /act\s+as\s+(?:a\s+)?(?:different|new|unrestricted|free)/i,
  /jailbreak/i,
  /DAN\s+mode/i,
  /<\s*script/i,
  /javascript\s*:/i,
  /on\w+\s*=/i,
];

function detectInjection(text) {
  return INJECTION_PATTERNS.some(p => p.test(String(text)));
}

/**
 * sanitizeChatInput(text)
 * Full sanitization pipeline for AI chat inputs.
 */
function sanitizeChatInput(text) {
  const cleaned = stripHtml(text).substring(0, 500).trim();
  return cleaned;
}

/**
 * sanitizeForStorage(obj)
 * Sanitizes a plain object's string values for safe storage.
 */
function sanitizeForStorage(obj, fieldMaxLengths = {}) {
  const out = {};
  for (const [key, val] of Object.entries(obj)) {
    if (typeof val === 'string') {
      const maxLen = fieldMaxLengths[key] || 1000;
      out[key] = sanitizeText(val, maxLen);
    } else if (typeof val === 'number' || typeof val === 'boolean') {
      out[key] = val;
    } else if (Array.isArray(val)) {
      out[key] = val.map(v => (typeof v === 'string' ? sanitizeText(v, 200) : v));
    } else {
      out[key] = val;
    }
  }
  return out;
}

module.exports = {
  escapeHtml,
  stripHtml,
  sanitizeText,
  sanitizeEmail,
  sanitizePhone,
  detectInjection,
  sanitizeChatInput,
  sanitizeForStorage,
};
