'use strict';
/**
 * hamoran-secure/routes/contact.js
 * Contact form submission endpoint.
 *
 * POST /api/contact
 * - Server-side Zod validation
 * - Honeypot bot detection
 * - HTML sanitization
 * - Stores lead in JSON store
 * - Returns WhatsApp redirect URL (phone/email never exposed client-side)
 */
const express = require('express');
const router  = express.Router();
const Store   = require('../utils/store');
const { validate, ContactSchema } = require('../utils/validators');
const { sanitizeText, sanitizeEmail, sanitizePhone } = require('../utils/sanitize');
const { contactLimiter, publicLimiter } = require('../middleware/rateLimiter');

// WhatsApp number from environment — never hardcoded in frontend
const WA_NUMBER = process.env.WA_NUMBER;

// ── POST /api/contact ─────────────────────────────────────
router.post('/', contactLimiter, async (req, res, next) => {
  try {
    // 1. Honeypot check — bots fill the 'website' field, humans don't see it
    if (req.body.website && req.body.website.length > 0) {
      // Silently succeed to not tip off bots
      return res.status(200).json({ message: 'Message received. Thank you!' });
    }

    // 2. Server-side schema validation
    const { success, data, errors } = validate(ContactSchema, {
      ...req.body,
      terms: String(req.body.terms), // normalize
    });

    if (!success) {
      return res.status(400).json({
        error: 'Validation failed',
        errors,
      });
    }

    // 3. Additional sanitization (defence in depth)
    const fullName = sanitizeText(`${data.fname} ${data.lname || ''}`.trim(), 100);
    const email    = sanitizeEmail(data.email);
    const phone    = sanitizePhone(data.phone || '');
    const service  = sanitizeText(data.service, 100);
    const message  = sanitizeText(data.message || '', 2000);

    // 4. Store lead
    const lead = Store.create('leads', {
      name:    fullName,
      email,
      phone,
      service,
      message,
      status:  'new',
      date:    new Date().toLocaleDateString('en-GB'),
      source:  'contact_form',
      ip:      req.ip, // stored server-side only, never returned to client
    }, {
      name: 100, email: 254, phone: 20, service: 100, message: 2000,
    });

    // Also store in contacts collection
    Store.create('contacts', {
      name: fullName, email, message, date: new Date().toLocaleDateString('en-GB'),
    }, { name: 100, message: 2000 });

    // 5. Build WhatsApp URL server-side — number never exposed in frontend JS
    const waMessage = [
      `Hello Hamoran! 👋`,
      ``,
      `My name is ${fullName}.`,
      `I am interested in: ${service}`,
      ``,
      `📧 Email: ${email}`,
      phone ? `📞 Phone: ${phone}` : null,
      ``,
      `💬 Message:`,
      message || 'No additional message.',
      ``,
      `Looking forward to hearing from you!`,
    ].filter(l => l !== null).join('\n');

    const waUrl = `https://wa.me/${WA_NUMBER}?text=${encodeURIComponent(waMessage)}`;

    return res.status(201).json({
      message: 'Enquiry received. Opening WhatsApp to connect you with our team.',
      leadId:  lead.id,
      waUrl,           // Server generates this — WA number stays server-side
    });

  } catch (err) {
    next(err);
  }
});

// ── GET /api/contact/wa-number — INTENTIONALLY NOT EXPOSED ──
// The WA number is only used server-side to generate URLs.
// It is NOT returned via any API endpoint.

module.exports = router;
