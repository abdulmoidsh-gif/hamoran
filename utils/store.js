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

const DATA_DIR  = path.join(__dirname, '../data');
const WRITE_DIR = process.env.VERCEL ? '/tmp/hamoran-data' : DATA_DIR;

// Ensure write directory exists
if (!fs.existsSync(WRITE_DIR)) fs.mkdirSync(WRITE_DIR, { recursive: true });

const ALLOWED_COLLECTIONS = new Set(['leads', 'contacts', 'aichats', 'team', 'testimonials', 'blogposts', 'settings']);
const ALLOWED_OBJECTS     = new Set(['pricing', 'seo', 'site-settings']);

function readFilePath(name) {
  return path.join(DATA_DIR, `${name}.json`);
}

function writeFilePath(name) {
  return path.join(WRITE_DIR, `${name}.json`);
}

function readCollection(collection) {
  if (!ALLOWED_COLLECTIONS.has(collection)) throw new Error(`Unknown collection: ${collection}`);
  // Read from write dir first (mutated data), fall back to static data dir
  const paths = [writeFilePath(collection), readFilePath(collection)];
  for (const fp of paths) {
    try {
      if (!fs.existsSync(fp)) continue;
      const parsed = JSON.parse(fs.readFileSync(fp, 'utf8'));
      return Array.isArray(parsed) ? parsed : [];
    } catch { continue; }
  }
  return [];
}

function writeCollection(collection, data) {
  if (!ALLOWED_COLLECTIONS.has(collection)) throw new Error(`Unknown collection: ${collection}`);
  if (!Array.isArray(data)) throw new Error('Data must be an array');
  fs.writeFileSync(writeFilePath(collection), JSON.stringify(data, null, 2), 'utf8');
}

function readObject(key) {
  if (!ALLOWED_OBJECTS.has(key)) throw new Error(`Unknown object key: ${key}`);
  const paths = [writeFilePath(key), readFilePath(key)];
  for (const fp of paths) {
    try {
      if (!fs.existsSync(fp)) continue;
      return JSON.parse(fs.readFileSync(fp, 'utf8'));
    } catch { continue; }
  }
  return null;
}

function writeObject(key, obj) {
  if (!ALLOWED_OBJECTS.has(key)) throw new Error(`Unknown object key: ${key}`);
  fs.writeFileSync(writeFilePath(key), JSON.stringify(obj, null, 2), 'utf8');
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
