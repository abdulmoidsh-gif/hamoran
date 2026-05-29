#!/usr/bin/env node
'use strict';
/**
 * hamoran-secure/scripts/setup.js
 * One-time setup: generates bcrypt hash for admin password.
 * Run: node scripts/setup.js
 */
const crypto  = require('crypto');
const bcrypt  = require('bcryptjs');
const readline = require('readline');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

function ask(q) {
  return new Promise(resolve => rl.question(q, resolve));
}

async function main() {
  console.log('\n═══════════════════════════════════════════');
  console.log('  HAMORAN — Secure Admin Setup');
  console.log('═══════════════════════════════════════════\n');

  const password = await ask('Enter new admin password (min 12 chars): ');
  if (password.length < 12) {
    console.error('Password must be at least 12 characters.');
    process.exit(1);
  }

  console.log('\nHashing password with bcrypt (cost factor 12)...');
  const hash = await bcrypt.hash(password, 12);

  const jwtAccess  = crypto.randomBytes(64).toString('hex');
  const jwtRefresh = crypto.randomBytes(64).toString('hex');
  const csrfSecret = crypto.randomBytes(32).toString('hex');

  console.log('\n══════════════════════════════════════════════════════');
  console.log('  Copy these values into your .env file:');
  console.log('══════════════════════════════════════════════════════');
  console.log(`\nADMIN_PASSWORD_HASH=${hash}`);
  console.log(`JWT_ACCESS_SECRET=${jwtAccess}`);
  console.log(`JWT_REFRESH_SECRET=${jwtRefresh}`);
  console.log(`CSRF_SECRET=${csrfSecret}`);
  console.log('\n⚠  NEVER share these values or commit .env to git.\n');

  rl.close();
}

main().catch(err => { console.error(err); process.exit(1); });
