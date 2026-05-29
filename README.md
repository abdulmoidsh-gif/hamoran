# Hamoran — Secure Full-Stack Deployment Guide

## Architecture Overview

```
hamoran-secure/
├── server/index.js          ← Express server (entry point)
├── public/
│   ├── index.html           ← Main website (hamoran.html)
│   └── admin.html           ← Admin panel
├── routes/
│   ├── auth.js              ← POST /api/auth/login|refresh|logout, GET /api/auth/me
│   ├── contact.js           ← POST /api/contact (WhatsApp form)
│   ├── chat.js              ← POST /api/chat (AI chat)
│   └── admin.js             ← GET|POST|PATCH|DELETE /api/admin/*
├── middleware/
│   ├── auth.js              ← JWT verification from HttpOnly cookie
│   ├── rateLimiter.js       ← Per-endpoint rate limits with Retry-After
│   ├── csrf.js              ← Double-submit CSRF protection
│   └── errorHandler.js      ← No stack traces to client
├── utils/
│   ├── jwt.js               ← Access (15min) + Refresh (7d) token system
│   ├── validators.js        ← Zod schemas for every endpoint
│   ├── sanitize.js          ← HTML escape + prompt injection detection
│   └── store.js             ← JSON file store (replace with DB in production)
├── data/                    ← Persistent JSON storage (gitignored)
├── .env                     ← Secrets (never commit this)
├── .env.example             ← Template — copy this to .env
└── scripts/setup.js         ← One-time password hash + secret generator
```

---

## Quick Start (Local)

```bash
# 1. Clone / download the hamoran-secure folder
cd hamoran-secure

# 2. Install dependencies
npm install

# 3. Generate secrets and admin password hash
node scripts/setup.js

# 4. Copy .env.example and fill in the values from setup output
cp .env.example .env
# Edit .env — paste the values printed by setup.js

# 5. Start the server
npm start

# 6. Open browser
# Website:     http://localhost:3000
# Admin panel: http://localhost:3000/admin.html
```

---

## Environment Variables (.env)

| Variable | Description | Example |
|---|---|---|
| `NODE_ENV` | `production` or `development` | `production` |
| `PORT` | Server port | `3000` |
| `ADMIN_EMAIL` | Admin login email | `moidabdul959@gmail.com` |
| `ADMIN_PASSWORD_HASH` | bcrypt hash of password | `$2b$12$...` |
| `JWT_ACCESS_SECRET` | 64-byte random hex | `node -e "require('crypto').randomBytes(64).toString('hex')"` |
| `JWT_REFRESH_SECRET` | Different 64-byte random hex | Same command |
| `CSRF_SECRET` | 32-byte random hex | `node -e "require('crypto').randomBytes(32).toString('hex')"` |
| `ALLOWED_ORIGINS` | Comma-separated allowed domains | `https://hamoran.co.uk,https://www.hamoran.co.uk` |
| `WA_NUMBER` | WhatsApp number (no spaces, with country code) | `447404829923` |
| `CONTACT_EMAIL` | Your contact email | `abdulmoidsh@gmail.com` |
| `FORCE_HTTPS` | Redirect HTTP to HTTPS | `true` |
| `REDIS_URL` | Redis for multi-instance rate limiting | `redis://...` (optional) |

---

## Deployment: Railway (Recommended — Easiest)

```bash
# 1. Install Railway CLI
npm install -g @railway/cli

# 2. Login
railway login

# 3. Create project
cd hamoran-secure
railway init

# 4. Set environment variables (Railway dashboard or CLI)
railway variables set NODE_ENV=production
railway variables set ADMIN_EMAIL=moidabdul959@gmail.com
railway variables set ADMIN_PASSWORD_HASH='$2b$12$...'   # from setup.js
railway variables set JWT_ACCESS_SECRET=...
railway variables set JWT_REFRESH_SECRET=...
railway variables set CSRF_SECRET=...
railway variables set ALLOWED_ORIGINS=https://hamoran.co.uk
railway variables set WA_NUMBER=447404829923
railway variables set CONTACT_EMAIL=abdulmoidsh@gmail.com
railway variables set FORCE_HTTPS=true

# 5. Deploy
railway up

# 6. Add custom domain in Railway dashboard
# Railway → Settings → Domains → Add Custom Domain → hamoran.co.uk
```

---

## Deployment: Render

1. Push `hamoran-secure/` to a GitHub repo
2. Create new **Web Service** on [render.com](https://render.com)
3. Connect your GitHub repo
4. Settings:
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Node version**: 18+
5. Add all environment variables in the Render dashboard
6. Add your domain in **Settings → Custom Domains**

---

## Deployment: VPS (Ubuntu/Debian)

```bash
# 1. SSH into your server
ssh user@your-server-ip

# 2. Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# 3. Install PM2 (process manager)
sudo npm install -g pm2

# 4. Upload your hamoran-secure folder (rsync or git)
rsync -av hamoran-secure/ user@your-server:/var/www/hamoran/

# 5. Install dependencies
cd /var/www/hamoran && npm install --production

# 6. Create .env with your secrets
nano .env  # paste all variables

# 7. Start with PM2
pm2 start server/index.js --name hamoran
pm2 startup  # auto-start on reboot
pm2 save

# 8. Install Nginx as reverse proxy
sudo apt install -y nginx certbot python3-certbot-nginx

# 9. Nginx config: /etc/nginx/sites-available/hamoran
cat > /etc/nginx/sites-available/hamoran << 'NGINX'
server {
    listen 80;
    server_name hamoran.co.uk www.hamoran.co.uk;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINX

sudo ln -s /etc/nginx/sites-available/hamoran /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# 10. Get SSL certificate (HTTPS)
sudo certbot --nginx -d hamoran.co.uk -d www.hamoran.co.uk

# 11. Set FORCE_HTTPS=true in .env and restart
pm2 restart hamoran
```

---

## API Endpoints Reference

### Public (rate limited: 20/min/IP)
| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Server health check |
| GET | `/api/csrf-token` | Get CSRF token |

### Auth (rate limited: 5/min/IP)
| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/login` | Login → sets HttpOnly JWT cookies |
| POST | `/api/auth/refresh` | Refresh access token |
| POST | `/api/auth/logout` | Logout + revoke refresh token |
| GET | `/api/auth/me` | Get current user info |

### Contact & Chat (public, rate limited)
| Method | Path | Description |
|---|---|---|
| POST | `/api/contact` | Submit contact form (3/5min/IP) |
| POST | `/api/chat` | AI chat message (10/min) |

### Admin (requires auth cookie, rate limited: 60/min)
| Method | Path | Description |
|---|---|---|
| GET | `/api/admin/dashboard` | Stats + recent leads |
| GET/POST | `/api/admin/leads` | List / create leads |
| PATCH | `/api/admin/leads/:id/status` | Update lead status |
| DELETE | `/api/admin/leads/:id` | Delete lead |
| GET | `/api/admin/contacts` | Contact messages |
| GET | `/api/admin/aichats` | AI chat sessions |
| GET/POST/DELETE | `/api/admin/team` | Team management |
| GET/POST/DELETE | `/api/admin/testimonials` | Testimonials |
| GET/POST/DELETE | `/api/admin/blog` | Blog posts |
| GET/PUT | `/api/admin/pricing` | Pricing config |
| GET/PUT | `/api/admin/seo` | SEO settings |
| POST | `/api/admin/credentials` | Change password (Super Admin only) |
| GET | `/api/admin/export/leads` | Download leads CSV |

---

## Changing the Admin Password

```bash
# On the server
cd /var/www/hamoran
node scripts/setup.js

# Copy the ADMIN_PASSWORD_HASH= line into your .env
# Then restart:
pm2 restart hamoran
```

---

## Security Architecture

- **Authentication**: bcrypt (cost 12) password hash. JWT access tokens (15-min) + refresh tokens (7-day). Server-side refresh token revocation. HttpOnly, Secure, SameSite=Strict cookies.
- **Rate Limiting**: Auth 5/min, public 20/min, authed 60/min, contact 3/5min, AI 10/min. HTTP 429 + Retry-After.
- **CSRF**: Double-submit cookie pattern. HMAC-SHA256 signed tokens. Constant-time comparison.
- **Input Validation**: Zod schemas on every endpoint. All text fields max-length enforced. HTML stripped before storage.
- **Prompt Injection**: 12 regex patterns detected server-side. Cannot be bypassed with client JS disabled.
- **Security Headers**: CSP, HSTS, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy, Permissions-Policy — all real HTTP headers via Helmet.
- **Error Handling**: No stack traces, file paths, or internal details exposed to client. All errors logged server-side only.
- **Super Admin**: Moid's account protected at API level — cannot be deleted via `/api/admin/team/:id`.

---

## Production Checklist

- [ ] Run `node scripts/setup.js` and update `.env`
- [ ] Set `NODE_ENV=production` in `.env`
- [ ] Set `FORCE_HTTPS=true` in `.env`
- [ ] Set `ALLOWED_ORIGINS` to your actual domain(s)
- [ ] Configure TLS/HTTPS at reverse proxy level
- [ ] Set up Redis and add `REDIS_URL` for multi-instance deployments
- [ ] Replace `data/*.json` store with PostgreSQL or MongoDB
- [ ] Configure automated backups for `data/` directory
- [ ] Set up monitoring (uptime checks on `/api/health`)
- [ ] Add HSTS preload via [hstspreload.org](https://hstspreload.org)
