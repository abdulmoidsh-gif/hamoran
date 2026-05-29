'use strict';
/**
 * hamoran-secure/routes/chat.js
 * AI chat endpoint.
 *
 * POST /api/chat
 * - Server-side prompt injection detection
 * - Input delimiters around user content
 * - Rate limited
 * - Logs chat interactions server-side
 */
const express = require('express');
const router  = express.Router();
const Store   = require('../utils/store');
const { detectInjection, sanitizeChatInput } = require('../utils/sanitize');
const { aiLimiter } = require('../middleware/rateLimiter');

// ── Keyword response map (same as frontend, but server-authoritative) ──
const REPLIES = {
  greet:    "Hi there! 👋 I'm the Hamoran AI assistant. I can help you learn about our services — website development, AI chat systems, and paid advertising. What are you looking for?",
  web:      "Our Website Development service (£150) includes a fully custom-designed, mobile-responsive website with modern UI, SEO optimisation, and contact forms. Want to get started?",
  ai_chat:  "Our AI Chat System (£100/month) is a 24/7 intelligent assistant that handles enquiries, captures leads, and books appointments automatically. Interested in a demo?",
  ads:      "Our Paid Advertising service (£100/month) covers Meta, Google, and TikTok campaigns managed by our experts. We focus on maximising your return on ad spend.",
  bundle:   "The Full Bundle (£299/month) includes everything: website, AI chat system, and paid advertising — our best value option. Shall I connect you with our team?",
  contact:  "You can reach us via the contact form below, or directly on WhatsApp. Our team typically responds within 2 hours during business hours.",
  services: "We offer three core services: Website Development (£150), AI Chat Systems (£100/month), and Paid Advertising (£100/month). All three bundled is just £299/month.",
  team:     "Hamoran's team is led by Moid (CEO), Hanzala (COO), and Arman (CMO). We're a passionate team committed to helping UK businesses grow through technology.",
  general:  "Thanks for reaching out! I can help with questions about our services, pricing, or team. Would you like to know about our website development, AI systems, or paid advertising?",
};

const TOPIC_KEYWORDS = {
  greet:    ['hello','hi','hey','howdy','hiya','good morning','good afternoon'],
  bundle:   ['bundle','package','all three','299','save','everything','full'],
  web:      ['website','web','site','150'],
  ai_chat:  ['ai chat','chatbot','chat system','bot','ai system','automated'],
  ads:      ['ads','advert','marketing','facebook','tiktok','instagram','google','paid'],
  contact:  ['contact','email','phone','call','whatsapp','reach','speak'],
  services: ['service','offer','provide','what do'],
  team:     ['team','ceo','coo','cmo','moid','hanzala','arman','who are'],
};

function matchTopic(text) {
  const lower = text.toLowerCase();
  for (const [topic, keywords] of Object.entries(TOPIC_KEYWORDS)) {
    if (keywords.some(k => lower.includes(k))) return topic;
  }
  return 'general';
}

// ── POST /api/chat ─────────────────────────────────────────
router.post('/', aiLimiter, async (req, res, next) => {
  try {
    // 1. Input validation via schema
    const { z } = require('zod');
    const ChatSchema = z.object({
      message: z.string().min(1, 'Message required').max(500, 'Message too long (max 500 characters)'),
    });
    const validation = ChatSchema.safeParse(req.body);
    if (!validation.success) {
      const issues = validation.error.issues || [];
      return res.status(400).json({
        error: 'Validation failed',
        message: issues[0]?.message || 'Invalid input',
      });
    }
    const rawInput = validation.data.message;

    // 2. Server-side prompt injection detection
    if (detectInjection(rawInput)) {
      // Log attempt server-side
      console.warn('[SECURITY] Prompt injection attempt blocked:', {
        ip: req.ip,
        timestamp: new Date().toISOString(),
        // Note: we log that it happened but NOT the content (could contain malicious payloads)
      });

      return res.status(200).json({
        // Return a normal-looking response so attacker learns nothing
        topic:    'general',
        response: "I can only help with questions about Hamoran's services. How can I assist you today?",
      });
    }

    // 3. Sanitize input (strip HTML, limit length)
    //    [USER_INPUT_START] delimiter makes intent clear in any logging
    const cleanInput = sanitizeChatInput(rawInput);

    // 4. Keyword matching (this is the "LLM" for our purposes — pure lookup, no LLM API)
    const topic    = matchTopic(cleanInput);
    const response = REPLIES[topic] || REPLIES.general;

    // 5. Log chat interaction server-side
    Store.create('aichats', {
      firstMsg:  cleanInput.substring(0, 100), // truncate for storage
      topic,
      messageCount: 1,
      date:      new Date().toLocaleDateString('en-GB'),
      ip:        req.ip, // server-side only
    }, { firstMsg: 100, topic: 50 });

    // 6. Return response
    return res.status(200).json({
      topic,
      response,
      // Quick reply suggestions (safe static strings only)
      quickReplies: getQuickReplies(topic),
    });

  } catch (err) {
    next(err);
  }
});

function getQuickReplies(topic) {
  const map = {
    greet:    ['Tell me about pricing', 'What services do you offer?', 'How do I get started?'],
    web:      ['What\'s included?', 'See portfolio examples', 'Get a quote'],
    ai_chat:  ['How does it work?', 'See pricing', 'Book a call'],
    ads:      ['What platforms?', 'See case studies', 'Get started'],
    bundle:   ['Tell me more', 'Book a call', 'Contact the team'],
    general:  ['Website Development', 'AI Chat System', 'Paid Advertising', 'View pricing'],
  };
  return map[topic] || map.general;
}

module.exports = router;
