'use strict';
/**
 * hamoran-secure/routes/admin.js
 * Admin management API routes.
 * ALL routes require server-side authentication (requireAuth + requireAdmin).
 * No client-side auth check is trusted.
 *
 * Endpoints:
 *   GET    /api/admin/dashboard         — stats overview
 *   GET    /api/admin/leads             — list leads
 *   POST   /api/admin/leads             — create lead manually
 *   PATCH  /api/admin/leads/:id/status  — update lead status
 *   DELETE /api/admin/leads/:id         — delete lead
 *   GET    /api/admin/contacts          — list contact messages
 *   GET    /api/admin/aichats           — list AI chat sessions
 *   GET    /api/admin/team              — list team members
 *   POST   /api/admin/team              — add team member
 *   DELETE /api/admin/team/:id          — remove team member
 *   GET    /api/admin/testimonials       — list testimonials
 *   POST   /api/admin/testimonials       — add testimonial
 *   DELETE /api/admin/testimonials/:id   — delete testimonial
 *   GET    /api/admin/blog              — list blog posts
 *   POST   /api/admin/blog              — create blog post
 *   DELETE /api/admin/blog/:id          — delete blog post
 *   GET    /api/admin/pricing           — get pricing
 *   PUT    /api/admin/pricing           — update pricing
 *   GET    /api/admin/seo               — get SEO settings
 *   PUT    /api/admin/seo               — update SEO settings
 *   POST   /api/admin/credentials       — change admin password (Super Admin only)
 *   GET    /api/admin/export/leads      — CSV export of leads
 */
const express = require('express');
const router  = express.Router();
const bcrypt  = require('bcryptjs');
const Store   = require('../utils/store');
const { validate, LeadSchema, LeadStatusSchema, TeamMemberSchema, TestimonialSchema,
        BlogPostSchema, PricingSchema, SEOSchema, CredentialsSchema } = require('../utils/validators');
const { requireAuth, requireAdmin, requireSuperAdmin } = require('../middleware/auth');
const { authedLimiter } = require('../middleware/rateLimiter');
const { verifyCsrf }    = require('../middleware/csrf');
const { sanitizeText }  = require('../utils/sanitize');

// Apply auth + rate limit to ALL admin routes
router.use(requireAuth, requireAdmin, authedLimiter);

// Apply CSRF verification to all state-changing requests
router.use(verifyCsrf);

// ── DASHBOARD ─────────────────────────────────────────────
router.get('/dashboard', (req, res) => {
  res.json({
    stats: {
      leads:     Store.count('leads'),
      contacts:  Store.count('contacts'),
      aichats:   Store.count('aichats'),
      team:      Store.count('team'),
      blog:      Store.count('blogposts'),
    },
    recentLeads: Store.getAll('leads').slice(0, 5),
  });
});

// ── LEADS ─────────────────────────────────────────────────
router.get('/leads', (req, res) => {
  res.json({ leads: Store.getAll('leads') });
});

router.post('/leads', (req, res, next) => {
  const { success, data, errors } = validate(LeadSchema, req.body);
  if (!success) return res.status(400).json({ error: 'Validation failed', errors });
  const lead = Store.create('leads', { ...data, source: 'manual' });
  res.status(201).json({ lead });
});

router.patch('/leads/:id/status', (req, res, next) => {
  const { id } = req.params;
  if (!id || !/^[0-9a-f-]{36}$/.test(id)) {
    return res.status(400).json({ error: 'Invalid ID' });
  }
  const { success, data, errors } = validate(LeadStatusSchema, req.body);
  if (!success) return res.status(400).json({ error: 'Validation failed', errors });
  const updated = Store.update('leads', id, { status: data.status });
  if (!updated) return res.status(404).json({ error: 'Lead not found' });
  res.json({ lead: updated });
});

router.delete('/leads/:id', (req, res, next) => {
  const { id } = req.params;
  if (!id || !/^[0-9a-f-]{36}$/.test(id)) {
    return res.status(400).json({ error: 'Invalid ID' });
  }
  const deleted = Store.delete('leads', id);
  if (!deleted) return res.status(404).json({ error: 'Lead not found' });
  res.json({ message: 'Lead deleted' });
});

// ── CONTACTS ──────────────────────────────────────────────
router.get('/contacts', (req, res) => {
  res.json({ contacts: Store.getAll('contacts') });
});

// ── AI CHATS ──────────────────────────────────────────────
router.get('/aichats', (req, res) => {
  const chats = Store.getAll('aichats').map(c => ({
    id:           c.id,
    firstMsg:     c.firstMsg,
    topic:        c.topic,
    messageCount: c.messageCount,
    date:         c.date,
    createdAt:    c.createdAt,
    // Note: IP address NOT returned to client — stays server-side
  }));
  res.json({ aichats: chats });
});

// ── TEAM ──────────────────────────────────────────────────
router.get('/team', (req, res) => {
  res.json({ team: Store.getAll('team') });
});

router.post('/team', (req, res, next) => {
  const { success, data, errors } = validate(TeamMemberSchema, req.body);
  if (!success) return res.status(400).json({ error: 'Validation failed', errors });
  // Block duplicate Moid
  const existing = Store.getAll('team');
  const isMoidDuplicate = existing.some(m =>
    m.name?.toLowerCase() === 'moid' ||
    m.email?.toLowerCase() === process.env.ADMIN_EMAIL?.toLowerCase()
  );
  if (data.name.toLowerCase() === 'moid' || data.email.toLowerCase() === process.env.ADMIN_EMAIL?.toLowerCase()) {
    return res.status(409).json({ error: 'The CEO & Super Admin account already exists and cannot be duplicated.' });
  }
  const duplicate = existing.find(m =>
    m.name?.toLowerCase() === data.name.toLowerCase() ||
    m.email?.toLowerCase() === data.email.toLowerCase()
  );
  if (duplicate) return res.status(409).json({ error: `A team member named "${duplicate.name}" already exists.` });
  const member = Store.create('team', data);
  res.status(201).json({ member });
});

router.delete('/team/:id', requireSuperAdmin, (req, res, next) => {
  const { id } = req.params;
  if (!id || !/^[0-9a-f-]{36}$/.test(id)) {
    return res.status(400).json({ error: 'Invalid ID' });
  }
  // Prevent deletion of Moid's team entry
  const member = Store.getById('team', id);
  if (!member) return res.status(404).json({ error: 'Team member not found' });
  if (member.name?.toLowerCase() === 'moid' ||
      member.email?.toLowerCase() === process.env.ADMIN_EMAIL?.toLowerCase()) {
    return res.status(403).json({ error: 'The CEO & Super Admin account cannot be removed.' });
  }
  Store.delete('team', id);
  res.json({ message: 'Team member removed' });
});

// ── TESTIMONIALS ──────────────────────────────────────────
router.get('/testimonials', (req, res) => {
  res.json({ testimonials: Store.getAll('testimonials') });
});

router.post('/testimonials', (req, res, next) => {
  const { success, data, errors } = validate(TestimonialSchema, req.body);
  if (!success) return res.status(400).json({ error: 'Validation failed', errors });
  const t = Store.create('testimonials', data);
  res.status(201).json({ testimonial: t });
});

router.delete('/testimonials/:id', (req, res, next) => {
  const { id } = req.params;
  if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid ID' });
  if (!Store.delete('testimonials', id)) return res.status(404).json({ error: 'Not found' });
  res.json({ message: 'Testimonial removed' });
});

// ── BLOG ──────────────────────────────────────────────────
router.get('/blog', (req, res) => {
  res.json({ posts: Store.getAll('blogposts') });
});

router.post('/blog', (req, res, next) => {
  const { success, data, errors } = validate(BlogPostSchema, req.body);
  if (!success) return res.status(400).json({ error: 'Validation failed', errors });
  const post = Store.create('blogposts', data);
  res.status(201).json({ post });
});

router.delete('/blog/:id', (req, res, next) => {
  const { id } = req.params;
  if (!id || !/^[0-9a-f-]{36}$/.test(id)) return res.status(400).json({ error: 'Invalid ID' });
  if (!Store.delete('blogposts', id)) return res.status(404).json({ error: 'Not found' });
  res.json({ message: 'Post deleted' });
});

// ── PRICING ───────────────────────────────────────────────
router.get('/pricing', (req, res) => {
  const pricing = Store.getObject('pricing') || { web: 150, ai: 100, ads: 100, bundle: 299 };
  res.json({ pricing });
});

router.put('/pricing', (req, res, next) => {
  const { success, data, errors } = validate(PricingSchema, req.body);
  if (!success) return res.status(400).json({ error: 'Validation failed', errors });
  Store.setObject('pricing', data);
  res.json({ message: 'Pricing updated', pricing: data });
});

// ── SEO SETTINGS ──────────────────────────────────────────
router.get('/seo', (req, res) => {
  const seo = Store.getObject('seo') || {};
  res.json({ seo });
});

router.put('/seo', (req, res, next) => {
  const { success, data, errors } = validate(SEOSchema, req.body);
  if (!success) return res.status(400).json({ error: 'Validation failed', errors });
  Store.setObject('seo', data);
  res.json({ message: 'SEO settings updated', seo: data });
});

// ── CREDENTIALS (Super Admin only + re-auth) ──────────────
router.post('/credentials', requireSuperAdmin, async (req, res, next) => {
  try {
    const { success, data, errors } = validate(CredentialsSchema, req.body);
    if (!success) return res.status(400).json({ error: 'Validation failed', errors });

    // Verify current password against stored hash
    const currentHash = process.env.ADMIN_PASSWORD_HASH;
    const isValid = await bcrypt.compare(data.currentPassword, currentHash);
    if (!isValid) {
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }

    // Hash new password
    const newHash = await bcrypt.hash(data.newPassword, 12);

    // In production: write to secure environment / secrets manager
    // For this deployment: output the new hash for manual .env update
    console.info('[ADMIN] Password hash updated — update ADMIN_PASSWORD_HASH in .env:', newHash);

    return res.json({
      message: 'Password hash generated. Update ADMIN_PASSWORD_HASH in your .env file and restart the server.',
      newHash, // Only returned to the Super Admin — update your .env with this
    });
  } catch (err) {
    next(err);
  }
});

// ── CSV EXPORT ────────────────────────────────────────────
router.get('/export/leads', (req, res) => {
  const leads = Store.getAll('leads');
  const header = 'Name,Email,Phone,Service,Status,Date\n';
  const rows = leads.map(l =>
    `"${(l.name||'').replace(/"/g,'""')}","${(l.email||'').replace(/"/g,'""')}","${(l.phone||'').replace(/"/g,'""')}","${(l.service||'').replace(/"/g,'""')}","${l.status||''}","${l.date||''}"`
  ).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="hamoran-leads.csv"');
  res.send(header + rows);
});

module.exports = router;
