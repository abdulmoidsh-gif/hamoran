'use strict';
/**
 * hamoran-secure/utils/store.js
 * Simple JSON file-backed data store.
 * In production, replace with a real database (PostgreSQL, MongoDB).
 * All data is sanitized before storage.
 */
const fs   = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { sanitizeForStorage } = require('./sanitize');

const DATA_DIR = path.join(__dirname, '../data');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function filePath(collection) {
  // Whitelist valid collection names to prevent path traversal
  const allowed = new Set(['leads', 'contacts', 'aichats', 'team', 'testimonials', 'blogposts', 'settings']);
  if (!allowed.has(collection)) throw new Error(`Unknown collection: ${collection}`);
  return path.join(DATA_DIR, `${collection}.json`);
}

function readCollection(collection) {
  const fp = filePath(collection);
  try {
    if (!fs.existsSync(fp)) return [];
    const raw = fs.readFileSync(fp, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeCollection(collection, data) {
  const fp = filePath(collection);
  if (!Array.isArray(data)) throw new Error('Data must be an array');
  fs.writeFileSync(fp, JSON.stringify(data, null, 2), 'utf8');
}

function readObject(key) {
  const allowed = new Set(['pricing', 'seo', 'site-settings']);
  if (!allowed.has(key)) throw new Error(`Unknown object key: ${key}`);
  const fp = path.join(DATA_DIR, `${key}.json`);
  try {
    if (!fs.existsSync(fp)) return null;
    return JSON.parse(fs.readFileSync(fp, 'utf8'));
  } catch {
    return null;
  }
}

function writeObject(key, obj) {
  const allowed = new Set(['pricing', 'seo', 'site-settings']);
  if (!allowed.has(key)) throw new Error(`Unknown object key: ${key}`);
  const fp = path.join(DATA_DIR, `${key}.json`);
  fs.writeFileSync(fp, JSON.stringify(obj, null, 2), 'utf8');
}

// ── Collection CRUD ────────────────────────────────────────
const Store = {
  getAll(collection) {
    return readCollection(collection);
  },

  getById(collection, id) {
    return readCollection(collection).find(item => item.id === id) || null;
  },

  create(collection, data, fieldMaxLengths = {}) {
    const items = readCollection(collection);
    const sanitized = sanitizeForStorage(data, fieldMaxLengths);
    const item = {
      ...sanitized,
      id: uuidv4(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    items.unshift(item); // newest first
    writeCollection(collection, items);
    return item;
  },

  update(collection, id, data, fieldMaxLengths = {}) {
    const items = readCollection(collection);
    const idx = items.findIndex(item => item.id === id);
    if (idx === -1) return null;
    const sanitized = sanitizeForStorage(data, fieldMaxLengths);
    items[idx] = { ...items[idx], ...sanitized, updatedAt: new Date().toISOString() };
    writeCollection(collection, items);
    return items[idx];
  },

  delete(collection, id) {
    const items = readCollection(collection);
    const idx = items.findIndex(item => item.id === id);
    if (idx === -1) return false;
    items.splice(idx, 1);
    writeCollection(collection, items);
    return true;
  },

  count(collection) {
    return readCollection(collection).length;
  },

  // Object storage (single config documents)
  getObject: readObject,
  setObject: writeObject,
};

module.exports = Store;
