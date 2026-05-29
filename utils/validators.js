'use strict';
/**
 * hamoran-secure/utils/validators.js
 * Zod schemas for every API endpoint.
 * All inputs validated server-side before any processing.
 */
const { z } = require('zod');

// ── Shared field definitions ────────────────────────────────
const safeString = (max = 200) =>
  z.string()
    .max(max, `Maximum ${max} characters`)
    .regex(/^[^<>{}]*$/, { message: 'Invalid characters detected' })
    .refine(
      val => !/javascript\s*:/i.test(val) && !/on\w+\s*=/i.test(val) && !/data\s*:/i.test(val),
      { message: 'Invalid content detected' }
    )
    .trim();

const emailField = z
  .string()
  .email('Invalid email address')
  .max(254, 'Email too long')
  .toLowerCase()
  .trim();

const phoneField = z
  .string()
  .max(20, 'Phone number too long')
  .regex(/^[\d\s\+\-\(\)]+$/, 'Invalid phone number')
  .optional()
  .or(z.literal(''));

// ── Auth schemas ────────────────────────────────────────────
const LoginSchema = z.object({
  email: emailField,
  password: z
    .string()
    .min(1, 'Password required')
    .max(128, 'Password too long'),
});

const RefreshSchema = z.object({
  // refresh token comes from HttpOnly cookie — not from body
  // This schema validates any body params that might be sent
});

// ── Contact form schema ─────────────────────────────────────
const ContactSchema = z.object({
  fname: safeString(50).min(1, 'First name required'),
  lname: safeString(50).optional().or(z.literal('')),
  email: emailField,
  phone: phoneField,
  service: z.enum([
    'Website Development',
    'AI Chat System',
    'Paid Advertising',
    'Full Bundle',
    'Not sure yet',
  ], { errorMap: () => ({ message: 'Invalid service selection' }) }),
  message: safeString(2000).optional().or(z.literal('')),
  // honeypot — must be empty
  website: z.string().max(0, 'Bot detected').optional(),
  // terms acceptance
  terms: z.literal('true').or(z.literal(true)).refine(v => !!v, 'You must accept the terms'),
});

// ── Admin: Lead management ──────────────────────────────────
const LeadSchema = z.object({
  name: safeString(100).min(1, 'Name required'),
  email: emailField,
  phone: phoneField,
  service: safeString(100).optional(),
  message: safeString(2000).optional(),
  status: z.enum(['new', 'active', 'pending', 'closed']).default('new'),
});

const LeadStatusSchema = z.object({
  status: z.enum(['new', 'active', 'pending', 'closed']),
});

// ── Admin: Team member ──────────────────────────────────────
const TeamMemberSchema = z.object({
  name: safeString(100).min(1, 'Name required'),
  role: safeString(100).min(1, 'Role required'),
  bio: safeString(500).optional(),
  email: emailField,
});

// ── Admin: Testimonial ──────────────────────────────────────
const TestimonialSchema = z.object({
  name: safeString(100).min(1, 'Name required'),
  company: safeString(200).optional(),
  text: safeString(1000).min(10, 'Review must be at least 10 characters'),
  rating: z.number().int().min(1).max(5).default(5),
});

// ── Admin: Blog post ───────────────────────────────────────
const BlogPostSchema = z.object({
  title: safeString(200).min(5, 'Title must be at least 5 characters'),
  content: z.string().min(1, 'Content required').max(50000),
  category: z.enum([
    'AI & Technology',
    'Web Design',
    'Marketing',
    'Case Studies',
    'Business',
  ]),
  status: z.enum(['draft', 'published']).default('draft'),
});

// ── Admin: Portfolio project ────────────────────────────────
const ProjectSchema = z.object({
  name: safeString(100).min(1, 'Project name required'),
  category: z.enum(['gym', 'ecom', 'restaurant', 'fashion', 'ai', 'realestate']),
  description: safeString(1000).optional(),
  tags: z.array(safeString(50)).max(10).optional(),
});

// ── Admin: Pricing update ───────────────────────────────────
const PricingSchema = z.object({
  web:    z.number().int().min(0).max(100000),
  ai:     z.number().int().min(0).max(100000),
  ads:    z.number().int().min(0).max(100000),
  bundle: z.number().int().min(0).max(100000),
});

// ── Admin: SEO settings ────────────────────────────────────
const SEOSchema = z.object({
  title:       safeString(70),
  description: safeString(160),
  keywords:    safeString(500),
  ogTitle:     safeString(70).optional(),
  ogDescription: safeString(200).optional(),
});

// ── Admin: Credentials update ──────────────────────────────
const CredentialsSchema = z.object({
  currentPassword: z.string().min(1, 'Current password required'),
  newPassword: z
    .string()
    .min(12, 'New password must be at least 12 characters')
    .max(128)
    .regex(/[A-Z]/, 'Must contain uppercase letter')
    .regex(/[a-z]/, 'Must contain lowercase letter')
    .regex(/[0-9]/, 'Must contain a number')
    .regex(/[^A-Za-z0-9]/, 'Must contain a special character'),
  confirmPassword: z.string(),
}).refine(d => d.newPassword === d.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword'],
});

/**
 * validate(schema, data)
 * Returns { success, data, errors }
 */
function validate(schema, data) {
  const result = schema.safeParse(data);
  if (result.success) return { success: true, data: result.data };
  // Zod v4: errors are in result.error.issues
  const issues = result.error.issues || JSON.parse(result.error.message || '[]');
  const errors = issues.map(e => ({
    field: Array.isArray(e.path) ? e.path.join('.') : String(e.path || ''),
    message: e.message,
  }));
  return { success: false, errors };
}

module.exports = {
  validate,
  LoginSchema,
  RefreshSchema,
  ContactSchema,
  LeadSchema,
  LeadStatusSchema,
  TeamMemberSchema,
  TestimonialSchema,
  BlogPostSchema,
  ProjectSchema,
  PricingSchema,
  SEOSchema,
  CredentialsSchema,
};
