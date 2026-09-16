'use strict';

/**
 * Cyberlab — Audit Orchestrator backend
 * =====================================
 * Passive external-posture audit of a single target, plus an optional Gemini
 * layer that turns the raw findings into a client-facing narrative.
 *
 * Everything here is NON-INTRUSIVE: HTTP GET on the target + a handful of
 * well-known paths, one TLS handshake, and DNS lookups over DoH. No fuzzing,
 * no injection, no auth bypass.
 *
 * An OPT-IN active phase (`{ target, active: true }`) adds two light,
 * non-destructive probes on top of that: a CORS reflection check and an
 * unfiltered-input-reflection check (a benign marker in a query param,
 * checked for verbatim echo — never framed as "XSS confirmed", only as
 * "unfiltered reflection"). It never touches SQLi, JWT or access control —
 * those stay a manual checklist on the frontend. Gated by its own tighter
 * rate limit and the same SSRF guard as the passive phase.
 *
 *   POST /api/audit        { target, active? }        -> start a job
 *   GET  /api/audit/:jobId                            -> poll job status
 *   GET  /health
 *
 * The detection is 100% deterministic (this file). Gemini only rewrites the
 * result for a non-technical reader and is fed ONLY the findings we computed —
 * it never sees the target and is instructed never to invent anything.
 */

const express = require('express');
const net = require('net');
const tls = require('tls');
const dns = require('dns').promises;
const rateLimit = require('express-rate-limit');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '16kb' }));

// --- config --------------------------------------------------------------

const PORT = Number(process.env.PORT || 4003);
const INTERNAL_API_TOKEN = process.env.INTERNAL_API_TOKEN;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-2.0-flash';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS ||
  'https://cyberlab-audit-proxy.axelginepro.workers.dev')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

// Service-to-service call into the dns_analyzer container (same
// docker-compose project, same default network — reachable by service name,
// no Cloudflare Worker hop needed). dns_analyzer enforces its own
// x-internal-token check regardless of network path, so this must be its
// INTERNAL_API_TOKEN value, not ours.
const DNS_ANALYZER_BASE_URL =
  process.env.DNS_ANALYZER_BASE_URL || 'http://dns-analyzer:4002';
const DNS_ANALYZER_INTERNAL_TOKEN = process.env.DNS_ANALYZER_INTERNAL_TOKEN || '';

if (!INTERNAL_API_TOKEN) {
  console.error(
    'FATAL: INTERNAL_API_TOKEN is not set. Refusing to start with an open /api surface.',
  );
  process.exit(1);
}
if (!GEMINI_API_KEY) {
  console.warn(
    'WARN: GEMINI_API_KEY not set — audits will return deterministic findings only (no AI narrative).',
  );
}
if (!DNS_ANALYZER_INTERNAL_TOKEN) {
  console.warn(
    'WARN: DNS_ANALYZER_INTERNAL_TOKEN not set — the active phase will skip subdomain discovery.',
  );
}

// UA de navigateur réel : les protections anti-bot (Akamai, DataDome,
// Cloudflare) renvoient un 403/challenge aux UA « bot », ce qui ferait croire
// à tort que tous les en-têtes sont absents.
const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

// --- CORS + auth + rate limit -----------------------------------------------

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Vary', 'Origin');
  }
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  res.header('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    ai: GEMINI_API_KEY ? GEMINI_MODEL : 'disabled',
    activeJobs: Object.keys(jobs).length,
  });
});

app.use('/api', (req, res, next) => {
  if (req.headers['x-internal-token'] !== INTERNAL_API_TOKEN) {
    return res.status(401).json({ success: false, error: 'unauthorized' });
  }
  next();
});

// Only job *creation* is rate-limited here — job *polling* (GET
// /api/audit/:jobId) must not be, or it defeats itself: the frontend polls
// every 3s, and an active-phase audit (subdomain discovery can take up to
// ~100s) generates ~20+ polls on its own within any 60s window, well past
// a 12/min cap meant to stop someone from spamming new audit jobs, not from
// checking on the one they already started.
const createAuditLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 12,
  standardHeaders: true,
  legacyHeaders: false,
});

// Polling itself is a cheap in-memory read (no outbound requests), but still
// capped generously against outright abuse — well above the ~20 polls/min a
// legitimate active-phase audit generates.
const pollAuditLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
});

// --- active-phase rate limit ----------------------------------------------
// The active phase sends a handful of extra requests to the target itself
// (CORS probe + up to 6 reflection probes) on top of the passive scan — kept
// rarer than plain passive audits, independent of the general /api limiter.

const activeLog = new Map(); // ip -> timestamps[]
const ACTIVE_WINDOW_MS = 10 * 60 * 1000;
const ACTIVE_MAX = 3;

function activeRateLimited(ip) {
  const now = Date.now();
  const hits = (activeLog.get(ip) || []).filter(
    (t) => now - t < ACTIVE_WINDOW_MS,
  );
  if (hits.length >= ACTIVE_MAX) {
    activeLog.set(ip, hits);
    return true;
  }
  hits.push(now);
  activeLog.set(ip, hits);
  return false;
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, hits] of activeLog) {
    const kept = hits.filter((t) => now - t < ACTIVE_WINDOW_MS);
    if (kept.length === 0) activeLog.delete(ip);
    else activeLog.set(ip, kept);
  }
}, 600000);

// --- job store ------------------------------------------------------------
// One audit fans out ~25 requests + a Gemini call — well within Cloudflare's
// limits, but a job queue keeps the proxy request short and predictable.

const jobs = {};
const MAX_CONCURRENT_JOBS = 3;

setInterval(() => {
  const now = Date.now();
  for (const id in jobs) {
    if (now - jobs[id].startedAt > 3600000) delete jobs[id];
  }
}, 600000);

// --- validation ---------------------------------------------------------

const HOSTNAME_RE =
  /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

function normalizeTarget(raw) {
  let value = (raw || '').trim();
  if (!value) return { error: 'target requis' };
  if (value.length > 253 + 16) return { error: 'target trop long' };
  if (!/^https?:\/\//i.test(value)) value = 'https://' + value;
  let u;
  try {
    u = new URL(value);
  } catch {
    return { error: 'URL invalide' };
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    return { error: 'seuls http:// et https:// sont acceptés' };
  }
  const host = u.hostname;
  if (net.isIP(host) === 0 && !HOSTNAME_RE.test(host)) {
    return { error: 'nom d’hôte invalide' };
  }
  return { url: u, host };
}

function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    return false;
  }
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
  if (/^fe[89ab]/.test(lower)) return true;
  if (lower.startsWith('::ffff:')) return isPrivateAddress(lower.slice(7));
  return false;
}

// --- routes ------------------------------------------------------------

app.post('/api/audit', createAuditLimiter, (req, res) => {
  const parsed = normalizeTarget(req.body && req.body.target);
  if (parsed.error) {
    return res.status(400).json({ success: false, error: parsed.error });
  }
  const activePhase = req.body && req.body.active === true;
  if (activePhase && activeRateLimited(req.ip)) {
    return res.status(429).json({
      success: false,
      error: 'trop de tests actifs récents, réessayez dans quelques minutes',
    });
  }

  const pendingCount = Object.values(jobs).filter(
    (j) => j.status === 'pending',
  ).length;
  if (pendingCount >= MAX_CONCURRENT_JOBS) {
    return res
      .status(429)
      .json({ success: false, error: 'trop d’audits en cours, réessayez' });
  }

  const jobId = `${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
  jobs[jobId] = { status: 'pending', startedAt: Date.now() };
  res.json({ success: true, job_id: jobId });

  runAudit(parsed.url, parsed.host, jobId, activePhase).catch((err) => {
    jobs[jobId] = {
      status: 'error',
      error: String((err && err.message) || err),
      startedAt: jobs[jobId] ? jobs[jobId].startedAt : Date.now(),
    };
  });
});

app.get('/api/audit/:jobId', pollAuditLimiter, (req, res) => {
  const job = jobs[req.params.jobId];
  if (!job) {
    return res
      .status(404)
      .json({ success: false, error: 'job introuvable ou expiré' });
  }
  res.json({ success: true, ...job });
});

// --- audit runner -----------------------------------------------------

async function runAudit(url, host, jobId, activePhase) {
  const startedAt = jobs[jobId].startedAt;

  // SSRF guard: resolve the target and refuse anything internal.
  let addresses = [];
  try {
    const looked = await dns.lookup(host, { all: true });
    addresses = [...new Set(looked.map((a) => a.address))];
  } catch {
    // maybe an IP literal, maybe unresolvable — handled below
  }
  if (net.isIP(host) !== 0) addresses = [host];
  if (addresses.length === 0) {
    jobs[jobId] = {
      status: 'error',
      error: 'le domaine ne résout pas',
      startedAt,
    };
    return;
  }
  if (addresses.some(isPrivateAddress)) {
    jobs[jobId] = {
      status: 'error',
      error: 'cible interne/privée refusée',
      startedAt,
    };
    return;
  }

  const [http, tlsInfo, dnsInfo, exposure] = await Promise.all([
    withTimeout(inspectHttp(url), 20000, { error: 'timeout HTTP' }),
    withTimeout(inspectTls(host), 12000, { error: 'timeout TLS' }),
    withTimeout(inspectDns(host), 15000, { error: 'timeout DNS' }),
    withTimeout(inspectExposure(url), 30000, { error: 'timeout exposition' }),
  ]);

  const headerFindings = gradeHeaders(http);
  const passiveFindings = [
    ...headerFindings,
    ...gradeTls(tlsInfo),
    ...gradeDns(dnsInfo),
    ...gradeExposure(exposure),
  ];

  // Phase active (opt-in) : CORS + réflexion d'entrée + découverte de
  // sous-domaines, greffées sur la même cible que le scan passif. Findings
  // pliées dans le même score/grade final ; `activeChecks` dit au
  // frontend/PDF quels axes actifs ont réellement tourné (le sous-domaine
  // n'y figure pas si DNS_ANALYZER_INTERNAL_TOKEN n'est pas configuré —
  // mieux vaut l'omettre honnêtement que prétendre l'avoir fait).
  let activeChecks = [];
  let activeFindings = [];
  if (activePhase) {
    // Sublist3r fait de l'OSINT sur un nom de domaine, pas sur une IP — et on
    // énumère l'apex (comme inspectDns) pour couvrir tous les sous-domaines,
    // pas seulement ceux du sous-domaine éventuellement saisi par l'utilisateur.
    const apexDomain =
      net.isIP(host) === 0
        ? host.replace(/\.$/, '').split('.').slice(-2).join('.')
        : null;
    const subdomainsEnabled = !!DNS_ANALYZER_INTERNAL_TOKEN && !!apexDomain;
    const [corsFindings, reflectionFindings, subdomainFindings] =
      await Promise.all([
        withTimeout(inspectCors(url), 12000, []),
        withTimeout(inspectReflection(url), 20000, []),
        subdomainsEnabled
          ? withTimeout(
              inspectSubdomains(apexDomain),
              SUBDOMAIN_TIMEOUT_MS + 5000,
              [],
            )
          : Promise.resolve([]),
      ]);
    activeFindings = [
      ...corsFindings,
      ...reflectionFindings,
      ...subdomainFindings,
    ];
    activeChecks = subdomainsEnabled
      ? ['cors', 'reflection', 'subdomains']
      : ['cors', 'reflection'];
  }

  const findings = [...passiveFindings, ...activeFindings];

  // Note en-têtes seule, calculée exactement comme l'outil « HTTP Security
  // Headers » (mêmes pénalités, mêmes seuils) : garantit que les deux
  // affichent la même lettre pour un même site. Null si non mesurable
  // (cible injoignable ou bloquée par une protection anti-bot).
  const headersMeasurable = !headerFindings.some(
    (x) => x.id === 'headers-blocked' || x.id === 'http-unreachable',
  );
  const headersGrade = headersMeasurable
    ? headersOnlyGrade(headerFindings)
    : { grade: null, value: null };

  const score = scoreFindings(findings);
  // Audit partiel : si les en-têtes n'ont pas pu être lus, la note globale ne
  // reflète que TLS/DNS/exposition — on le dit au lieu d'afficher un faux « A ».
  score.partial = !headersMeasurable;
  const finalUrl = (http && http.finalUrl) || url.toString();

  const report = {
    target: url.toString(),
    finalUrl,
    domain: host,
    scannedAt: new Date().toISOString(),
    score,
    findings,
    activeChecks,
    sections: {
      headers: http && http.error ? { error: http.error } : {
        status: http.status,
        redirectChain: http.redirectChain,
        httpsUpgrade: http.httpsUpgrade,
        headers: http.headers,
        setCookie: http.setCookie,
        grade: headersGrade.grade,
        gradeValue: headersGrade.value,
      },
      tls: tlsInfo,
      dns: dnsInfo,
      exposure: exposure && exposure.error
        ? exposure
        : { probed: exposure.probed, catchAll: !!exposure.catchAll },
    },
  };

  report.ai = await buildAiNarrative(report);

  jobs[jobId] = { status: 'done', data: report, startedAt };
}

function withTimeout(promise, ms, fallback) {
  return Promise.race([
    promise.catch((e) => ({ error: String((e && e.message) || e) })),
    new Promise((resolve) => setTimeout(() => resolve(fallback), ms)),
  ]);
}

// --- HTTP inspection --------------------------------------------------

const FETCH_TIMEOUT = 12000;

async function fetchOnce(target, redirect) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT);
  try {
    return await fetch(target, {
      method: 'GET',
      redirect,
      signal: controller.signal,
      headers: {
        'User-Agent': USER_AGENT,
        Accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

async function inspectHttp(url) {
  const chain = [];
  let current = url.toString();
  let res = null;
  for (let i = 0; i < 10; i++) {
    res = await fetchOnce(current, 'manual');
    const loc = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && loc) {
      const next = new URL(loc, current).toString();
      chain.push(`${current} -> ${next} (${res.status})`);
      const check = normalizeTarget(next);
      if (check.error) break;
      current = check.url.toString();
      continue;
    }
    break;
  }

  const headers = {};
  const setCookie =
    typeof res.headers.getSetCookie === 'function'
      ? res.headers.getSetCookie()
      : [];
  for (const [name, value] of res.headers) {
    if (name.toLowerCase() === 'set-cookie') {
      if (setCookie.length === 0) setCookie.push(value);
      continue;
    }
    headers[name.toLowerCase()] = value;
  }

  // Does plain http:// force an upgrade to https://?
  let httpsUpgrade = null;
  try {
    const httpUrl = new URL(url.toString());
    httpUrl.protocol = 'http:';
    const probe = await fetchOnce(httpUrl.toString(), 'manual');
    const loc = probe.headers.get('location') || '';
    httpsUpgrade =
      probe.status >= 300 &&
      probe.status < 400 &&
      /^https:\/\//i.test(new URL(loc, httpUrl).toString());
  } catch {
    httpsUpgrade = null;
  }

  // Protection anti-bot : un 401/403/429/503 (souvent AkamaiGHost, DataDome,
  // cloudflare) sur la page d'accueil renvoie une page de challenge sans les
  // en-têtes réels. On le signale au lieu de conclure « tout est absent ».
  const srv = (headers['server'] || '').toLowerCase();
  const blocked =
    [401, 403, 429, 503].includes(res.status) &&
    (/akamai|datadome|cloudflare|imperva|incapsula|sucuri/.test(srv) ||
      Number(headers['content-length'] || 0) < 2048);

  return {
    finalUrl: current,
    status: res.status,
    redirectChain: chain,
    httpsUpgrade,
    headers,
    setCookie,
    blocked,
    blockedBy: blocked ? headers['server'] || `HTTP ${res.status}` : null,
  };
}

// --- TLS inspection --------------------------------------------------

function inspectTls(host) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host,
        port: 443,
        servername: host,
        rejectUnauthorized: false,
        timeout: 10000,
      },
      () => {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const authorized = socket.authorized;
        const authorizationError = socket.authorizationError
          ? String(socket.authorizationError)
          : null;
        let expiresInDays = null;
        if (cert && cert.valid_to) {
          expiresInDays = Math.round(
            (new Date(cert.valid_to).getTime() - Date.now()) / 86400000,
          );
        }
        const names = [];
        if (cert && cert.subjectaltname) {
          for (const part of cert.subjectaltname.split(',')) {
            const m = part.trim().match(/^DNS:(.+)$/i);
            if (m) names.push(m[1].toLowerCase());
          }
        }
        socket.end();
        resolve({
          protocol,
          authorized,
          authorizationError,
          expiresInDays,
          validFrom: cert && cert.valid_from ? cert.valid_from : null,
          validTo: cert && cert.valid_to ? cert.valid_to : null,
          issuer:
            cert && cert.issuer && cert.issuer.O
              ? cert.issuer.O
              : cert && cert.issuer && cert.issuer.CN
                ? cert.issuer.CN
                : null,
          subjectCn: cert && cert.subject ? cert.subject.CN || null : null,
          altNames: names,
          keyBits: cert && cert.bits ? cert.bits : null,
          curve:
            cert && (cert.asn1Curve || cert.nistCurve)
              ? cert.asn1Curve || cert.nistCurve
              : null,
        });
      },
    );
    socket.on('error', (err) => resolve({ error: String(err.message || err) }));
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ error: 'timeout TLS' });
    });
  });
}

// --- DNS inspection (DoH, no binary) --------------------------------

async function doh(name, type) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);
  try {
    const r = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(
        name,
      )}&type=${encodeURIComponent(type)}`,
      { headers: { accept: 'application/dns-json' }, signal: controller.signal },
    );
    const j = await r.json();
    return Array.isArray(j.Answer) ? j.Answer : [];
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

const txt = (a) =>
  a
    .filter((x) => x.type === 16)
    .map((x) => String(x.data).replace(/^"|"$/g, '').replace(/"\s+"/g, ''));

async function inspectDns(host) {
  const domain = host.replace(/\.$/, '').split('.').slice(-2).join('.');
  const [root, dmarc, dnssecDs, caa, mx, ns] = await Promise.all([
    doh(domain, 'TXT'),
    doh(`_dmarc.${domain}`, 'TXT'),
    doh(domain, 'DS'),
    doh(domain, 'CAA'),
    doh(domain, 'MX'),
    doh(domain, 'NS'),
  ]);

  const spf = txt(root).find((r) => r.toLowerCase().startsWith('v=spf1')) || null;
  const dmarcRec =
    txt(dmarc).find((r) => r.toLowerCase().startsWith('v=dmarc1')) || null;

  return {
    domain,
    spf,
    dmarc: dmarcRec,
    dnssec: dnssecDs.some((x) => x.type === 43),
    caa: caa.filter((x) => x.type === 257).map((x) => String(x.data)),
    mxCount: mx.filter((x) => x.type === 15).length,
    ns: ns.filter((x) => x.type === 2).map((x) => String(x.data).replace(/\.$/, '')),
  };
}

// --- exposed paths ---------------------------------------------------

// `sig` is a content signature the real file must match. A 200 alone means
// nothing: SPA / catch-all hosts (Cloudflare Pages, Netlify…) serve index.html
// for every unknown path. So a hit requires: 200 + body is NOT HTML + body
// differs from the "random path" baseline + matches `sig` when given.
//
// The extra entries below (config.json, web.config, settings.py,
// docker-compose.yml, id_rsa, error.log, access.log) are pulled from
// content_discovery_screen.dart's "Fichiers de configuration" / "Fichiers
// sensibles" / "Sauvegardes et logs" wordlists. Its "Répertoires communs"
// category (/admin, /login, /api…) is deliberately NOT reused here: those
// are normal app routes whose mere presence isn't a finding under this
// tool's evidence-based model — only a matching `sig` earns a report.
const EXPOSED_PATHS = [
  { path: '/.git/config', sev: 'crit', sig: /\[core\]/ },
  { path: '/.git/HEAD', sev: 'crit', sig: /^(ref:\s|[0-9a-f]{40})/ },
  { path: '/.env', sev: 'crit', sig: /^[A-Z][A-Z0-9_]{2,}\s*=/m },
  { path: '/.env.local', sev: 'crit', sig: /^[A-Z][A-Z0-9_]{2,}\s*=/m },
  { path: '/.svn/entries', sev: 'high', sig: /^(\d+\s|<\?xml|svn:)/ },
  { path: '/.DS_Store', sev: 'low', sig: /Bud1|\x00\x00\x00\x01/ },
  { path: '/.htaccess', sev: 'medium', sig: /rewrite|<ifmodule|deny\s|require\s|authtype/i },
  { path: '/config.php.bak', sev: 'high', sig: /<\?php|\$[a-z_]+\s*=/i },
  { path: '/wp-config.php.bak', sev: 'crit', sig: /<\?php|DB_(NAME|PASSWORD|USER)/ },
  { path: '/backup.zip', sev: 'high', sig: /^PK\x03\x04/ },
  { path: '/backup.sql', sev: 'high', sig: /(CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL|PostgreSQL database dump)/i },
  { path: '/database.sql', sev: 'high', sig: /(CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL|PostgreSQL database dump)/i },
  { path: '/dump.sql', sev: 'high', sig: /(CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL|PostgreSQL database dump)/i },
  { path: '/phpinfo.php', sev: 'medium', sig: /PHP Version|phpinfo\(\)/ },
  { path: '/server-status', sev: 'medium', sig: /Apache Server Status/ },
  { path: '/config.json', sev: 'high', sig: /"(secret|password|api[_-]?key|token|database|db_(host|user|pass|name))"\s*:/i },
  { path: '/web.config', sev: 'high', sig: /<configuration/i },
  { path: '/settings.py', sev: 'crit', sig: /SECRET_KEY\s*=|DATABASES\s*=\s*\{|DEBUG\s*=\s*True/ },
  { path: '/docker-compose.yml', sev: 'high', sig: /^\s*(version:|services:)/m },
  { path: '/id_rsa', sev: 'crit', sig: /-----BEGIN (RSA |OPENSSH |EC |DSA |)PRIVATE KEY-----/ },
  { path: '/error.log', sev: 'low', sig: /^\[?\d{4}-\d{2}-\d{2}|^\d{1,3}(\.\d{1,3}){3} - -/m },
  { path: '/access.log', sev: 'low', sig: /^\d{1,3}(\.\d{1,3}){3} - -|^\[?\d{4}-\d{2}-\d{2}/m },
  { path: '/.well-known/security.txt', sev: 'good', sig: /contact:/i },
  { path: '/robots.txt', sev: 'info', sig: /user-agent:/i },
  { path: '/sitemap.xml', sev: 'info', sig: /<urlset|<sitemapindex/i },
];

const HTML_RE = /^\s*(<!doctype\s+html|<html[\s>]|<\?xml[^>]*>\s*<!doctype\s+html)/i;

// 3 workers + a jittered delay before each request, instead of 6 firing
// back-to-back: a burst of 25 rapid GETs to known-vulnerable paths
// (/.git/config, /wp-config.php.bak, /.env…) is exactly the fingerprint bot
// managers (Akamai, Cloudflare) key on — this trips their IP reputation and
// gets the *next* audit challenged too, on totally unrelated targets. Spread
// out, it still finishes well inside the exposure check's own 30s budget.
const EXPOSURE_CONCURRENCY = 3;
const EXPOSURE_DELAY_MIN_MS = 150;
const EXPOSURE_DELAY_MAX_MS = 450;

function exposureJitterDelay() {
  const span = EXPOSURE_DELAY_MAX_MS - EXPOSURE_DELAY_MIN_MS;
  return EXPOSURE_DELAY_MIN_MS + Math.floor(Math.random() * span);
}

async function inspectExposure(url) {
  const origin = new URL(url.toString()).origin;

  // Baseline: a path that cannot exist. If it 200s, the host has a catch-all
  // and raw status codes are meaningless for the real probes below.
  let baselineBody = '';
  let baselineStatus = 0;
  try {
    const b = await fetchOnce(
      `${origin}/cyberlab-audit-${Math.random().toString(36).slice(2)}-probe`,
      'manual',
    );
    baselineStatus = b.status;
    baselineBody = (await b.text()).slice(0, 2048);
  } catch {
    /* offline baseline is fine */
  }

  const probed = [];
  let cursor = 0;
  async function worker() {
    while (cursor < EXPOSED_PATHS.length) {
      const item = EXPOSED_PATHS[cursor++];
      await new Promise((resolve) =>
        setTimeout(resolve, exposureJitterDelay()),
      );
      try {
        const res = await fetchOnce(origin + item.path, 'manual');
        const body = res.status === 200 ? (await res.text()).slice(0, 4096) : '';
        const looksHtml = HTML_RE.test(body);
        const sameAsBaseline =
          res.status === baselineStatus &&
          body.slice(0, 2048) === baselineBody;
        const confirmed =
          res.status === 200 &&
          !looksHtml &&
          !sameAsBaseline &&
          (item.sig ? item.sig.test(body) : body.trim().length > 0);
        probed.push({
          path: item.path,
          status: res.status,
          sev: item.sev,
          flagged: confirmed && item.sev !== 'info' && item.sev !== 'good',
          confirmed,
        });
      } catch {
        probed.push({ path: item.path, status: 0, sev: item.sev, flagged: false });
      }
    }
  }
  await Promise.all(Array.from({ length: EXPOSURE_CONCURRENCY }, worker));
  probed.sort((a, b) => a.path.localeCompare(b.path));
  return { probed, catchAll: baselineStatus === 200 };
}

// --- active phase: CORS reflection ------------------------------------

// One GET with a bogus but well-formed Origin header. Non-destructive: reads
// the response, sends no state-changing request, no auth. If the target
// echoes the origin back (instead of validating against a whitelist), that's
// a real, evidence-backed finding — not a heuristic guess.
const CORS_PROBE_ORIGIN = 'https://cyberlab-cors-probe.invalid';

async function fetchWithOrigin(target, origin, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(target, {
      method: 'GET',
      redirect: 'manual',
      signal: controller.signal,
      headers: {
        'User-Agent': USER_AGENT,
        Origin: origin,
        Accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

async function inspectCors(url) {
  try {
    const res = await fetchWithOrigin(url.toString(), CORS_PROBE_ORIGIN, 10000);
    const acao = res.headers.get('access-control-allow-origin');
    if (!acao) return [];
    const acac =
      (res.headers.get('access-control-allow-credentials') || '').toLowerCase() ===
      'true';
    if (acao === CORS_PROBE_ORIGIN && acac) {
      return [
        f(
          'cors-reflect-credentials',
          'cors',
          'crit',
          'CORS reflète une origine arbitraire avec credentials',
          "Access-Control-Allow-Origin reflète l'Origin envoyé sans liste blanche, ET Access-Control-Allow-Credentials: true — un site tiers malveillant peut lire les réponses authentifiées de la cible pour un utilisateur connecté (vol de session, de données de compte).",
          [
            `Origin envoyé : ${CORS_PROBE_ORIGIN}`,
            `access-control-allow-origin: ${acao}`,
            'access-control-allow-credentials: true',
          ],
          "Restreindre Access-Control-Allow-Origin à une liste blanche explicite de domaines de confiance ; ne jamais combiner reflet d'Origin et Allow-Credentials.",
        ),
      ];
    }
    if (acao === CORS_PROBE_ORIGIN) {
      return [
        f(
          'cors-reflect-origin',
          'cors',
          'medium',
          "CORS reflète n'importe quelle origine",
          `Access-Control-Allow-Origin reflète tout Origin envoyé (testé avec ${CORS_PROBE_ORIGIN}), sans validation contre une liste blanche.`,
          [`Origin envoyé : ${CORS_PROBE_ORIGIN}`, `access-control-allow-origin: ${acao}`],
          "Valider l'Origin contre une liste blanche de domaines de confiance avant de le refléter.",
        ),
      ];
    }
    if (acao === '*') {
      return [
        f(
          'cors-wildcard',
          'cors',
          'low',
          'CORS ouvert à tous (wildcard)',
          "Access-Control-Allow-Origin: * autorise tout site tiers à lire les réponses non authentifiées de cet endpoint. Sans impact si l'endpoint ne sert pas de données sensibles ni de cookies.",
          ['access-control-allow-origin: *'],
          "Restreindre aux domaines qui en ont réellement besoin si l'endpoint sert des données sensibles.",
        ),
      ];
    }
    return [];
  } catch {
    return [];
  }
}

// --- active phase: unfiltered-input reflection -------------------------

// Appends a benign, inert marker to a handful of common query-param names and
// checks whether it comes back verbatim (unescaped) in an HTML response. This
// is NOT payload injection or exploitation — no script tag, no event handler,
// nothing that executes. It only proves output-encoding is missing, which is
// reported honestly as "réflexion non filtrée", never as a confirmed XSS.
const REFLECTION_PARAMS = ['q', 'search', 'query', 'name', 'id', 's'];
const REFLECTION_MARKER = 'cyb3rl4b-audit-probe-<>"\'';

async function inspectReflection(url) {
  for (const param of REFLECTION_PARAMS) {
    try {
      const probeUrl = new URL(url.toString());
      probeUrl.searchParams.set(param, REFLECTION_MARKER);
      const res = await fetchOnce(probeUrl.toString(), 'manual');
      if (res.status < 200 || res.status >= 400) continue;
      const ct = (res.headers.get('content-type') || '').toLowerCase();
      if (!ct.includes('html')) continue;
      const body = await res.text();
      if (body.includes(REFLECTION_MARKER)) {
        return [
          f(
            `reflection-${param}`,
            'reflection',
            'medium',
            `Réflexion non filtrée du paramètre "${param}"`,
            `La valeur envoyée dans le paramètre "${param}" (incluant des caractères spéciaux HTML) est renvoyée telle quelle dans la page, sans encodage de sortie. Ceci ne prouve pas une XSS exploitable — aucun script n'a été injecté ni exécuté — mais l'absence d'échappement en sortie est un point d'entrée à tester manuellement.`,
            [`GET ?${param}=${REFLECTION_MARKER} -> le marqueur apparaît non encodé dans le HTML`],
            "Encoder toute donnée utilisateur en sortie HTML (échappement contextuel) et poser une CSP restrictive en défense en profondeur.",
          ),
        ];
      }
    } catch {
      // paramètre non supporté / timeout — on continue avec le suivant
    }
  }
  return [];
}

// --- active phase: subdomain discovery ----------------------------------

// Delegates to the dns_analyzer service (Sublist3r passive OSINT + optional
// HTTP probe on the merged host list) instead of reimplementing recon here —
// it already runs in prod as the DNS Analyzer tool's own subdomain feature.
// Passive-only (bruteforce: false): a full brute-force run is the heaviest
// mode dns_analyzer offers and isn't needed for a report-scoped audit; this
// keeps footprint and latency modest while still surfacing real results.
const SUBDOMAIN_TIMEOUT_MS = 100000;
const SUBDOMAIN_POLL_MS = 2500;
const STALE_HOST_RE =
  /^(dev|staging|stage|test|uat|preprod|pre-prod|qa|demo|internal|admin|old|backup|beta|sandbox|vpn)\./i;

async function fetchDnsAnalyzer(path, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(`${DNS_ANALYZER_BASE_URL}${path}`, {
      ...options,
      signal: controller.signal,
      headers: {
        'x-internal-token': DNS_ANALYZER_INTERNAL_TOKEN,
        ...(options && options.headers),
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

async function inspectSubdomains(domain) {
  if (!DNS_ANALYZER_INTERNAL_TOKEN) return [];
  try {
    const startRes = await fetchDnsAnalyzer(
      '/api/subdomains/start',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, bruteforce: false, probe: true }),
      },
      10000,
    );
    if (!startRes.ok) return [];
    const started = await startRes.json();
    if (!started.success || !started.job_id) return [];

    const deadline = Date.now() + SUBDOMAIN_TIMEOUT_MS;
    while (Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, SUBDOMAIN_POLL_MS));
      const statusRes = await fetchDnsAnalyzer(
        `/api/subdomains/status/${started.job_id}`,
        {},
        10000,
      );
      if (!statusRes.ok) continue;
      const body = await statusRes.json();
      if (body.status === 'done') return gradeSubdomains(body.data);
      if (body.status === 'error') return [];
    }
    // Notre délai a expiré ; le job dns_analyzer continue en arrière-plan
    // (il a son propre timeout de 20 min) mais ne fera pas partie de ce
    // rapport-ci.
    return [];
  } catch {
    return [];
  }
}

function gradeSubdomains(data) {
  if (!data || !Array.isArray(data.subdomains)) return [];
  const total = data.count || data.subdomains.length;
  if (total === 0) {
    return [
      f(
        'subdomains-none',
        'subdomains',
        'info',
        'Aucun sous-domaine découvert (recon passive)',
        "Recherche OSINT passive (Sublist3r : certificats TLS, moteurs de recherche) : aucun résultat.",
        ['sources : Sublist3r (OSINT passif)'],
        'Aucune action.',
        { optional: true },
      ),
    ];
  }

  const out = [];
  const results = Array.isArray(data.results) ? data.results : [];
  const alive = results.filter((r) => r && r.http);
  out.push(
    f(
      'subdomains-found',
      'subdomains',
      'info',
      `${total} sous-domaine(s) découvert(s) (recon passive)`,
      `${alive.length} en ligne sur ${total} trouvés via OSINT passif (certificats TLS, moteurs de recherche).`,
      data.subdomains.slice(0, 20),
      'Vérifier que chaque sous-domaine exposé est intentionnel et à jour.',
      { optional: true },
    ),
  );

  const stale = alive.filter(
    (r) => STALE_HOST_RE.test(r.host) && r.http.status < 400,
  );
  if (stale.length > 0) {
    out.push(
      f(
        'subdomains-stale-exposed',
        'subdomains',
        'medium',
        `${stale.length} sous-domaine(s) de pré-production potentiellement exposé(s)`,
        "Ces sous-domaines (nom évoquant dev/staging/test/admin/interne) répondent publiquement — souvent moins durcis que la production et parfois oubliés après un déploiement.",
        stale
          .slice(0, 10)
          .map(
            (r) =>
              `${r.host} -> HTTP ${r.http.status}${r.http.title ? ' · ' + r.http.title : ''}`,
          ),
        "Restreindre l'accès (VPN, liste blanche d'IP, authentification) ou dépublier si obsolète.",
      ),
    );
  }

  return out;
}

// --- grading: HTTP headers -----------------------------------------

// `opts.penalty` : points retirés de la note en-têtes (barème identique à
// security_headers_screen.dart). `opts.optional` : montré mais hors note.
function f(id, category, severity, title, summary, evidence, recommendation, opts) {
  return {
    id,
    category,
    severity,
    title,
    summary,
    evidence: Array.isArray(evidence) ? evidence : [evidence],
    recommendation,
    penalty: opts && typeof opts.penalty === 'number' ? opts.penalty : undefined,
    optional: !!(opts && opts.optional),
  };
}

// Barème 100 % aligné sur l'outil dédié « HTTP Security Headers »
// (security_headers_screen.dart) : mêmes en-têtes de référence, mêmes
// sévérités, mêmes pénalités, mêmes seuils de note. Les deux ne peuvent donc
// plus se contredire. Tout le reste (redirection http→https, unsafe-inline,
// bannière serveur, cookies) est « facultatif », montré mais hors note.
function gradeHeaders(http) {
  if (!http || http.error) {
    return [
      f(
        'http-unreachable',
        'headers',
        'high',
        'Réponse HTTP non analysable',
        http && http.error ? http.error : 'aucune réponse',
        [String((http && http.error) || 'timeout')],
        'Vérifier que le site répond en HTTP(S) depuis Internet.',
        { penalty: 40 },
      ),
    ];
  }
  if (http.blocked) {
    return [
      f(
        'headers-blocked',
        'headers',
        'info',
        'Analyse des en-têtes bloquée par une protection anti-bot',
        `La cible a renvoyé une page de challenge (${http.blockedBy}) au lieu de la vraie réponse. Les en-têtes de sécurité n'ont pas pu être lus — utilise l'outil HTTP Security Headers depuis un navigateur, ou analyse depuis une IP autorisée.`,
        [`HTTP ${http.status} · server: ${http.blockedBy}`],
        "Relancer l'analyse via l'outil dédié (navigateur) ou en liste blanche.",
        { optional: true },
      ),
    ];
  }
  const h = http.headers || {};
  const out = [];

  // HSTS — absent : -25 (critique) ; < 6 mois : -8 (moyen).
  const hsts = h['strict-transport-security'];
  if (!hsts) {
    out.push(
      f(
        'hsts-missing',
        'headers',
        'crit',
        'HSTS absent',
        "Sans Strict-Transport-Security, un attaquant en position d'intercepteur peut forcer la première connexion en HTTP clair (SSL stripping).",
        ['strict-transport-security: (absent)'],
        'Ajouter Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
        { penalty: 25 },
      ),
    );
  } else {
    const maxAge = Number((hsts.match(/max-age=(\d+)/i) || [])[1] || 0);
    if (maxAge < 15552000) {
      out.push(
        f(
          'hsts-short',
          'headers',
          'medium',
          'HSTS avec durée trop courte',
          `max-age=${maxAge} (< 6 mois) : la protection expire vite si l'utilisateur ne revient pas.`,
          [`strict-transport-security: ${hsts}`],
          'Porter max-age à 63072000 (2 ans).',
          { penalty: 8 },
        ),
      );
    }
  }

  // CSP — absente : -15 (élevé) ; `*`/pas de baseline script : -10 (élevé) ;
  // unsafe-inline en contexte script : montré mais hors note.
  const csp = h['content-security-policy'];
  if (!csp) {
    out.push(
      f(
        'csp-missing',
        'headers',
        'crit',
        'Content-Security-Policy absente',
        "Aucune politique CSP : une injection de code s'exécute sans restriction dans le navigateur.",
        ['content-security-policy: (absent)'],
        "Poser Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; upgrade-insecure-requests",
        { penalty: 15 },
      ),
    );
  } else {
    const directives = {};
    for (const part of csp.split(';')) {
      const t = part.trim();
      if (!t) continue;
      const m = t.match(/^(\S+)\s*(.*)$/);
      if (m) directives[m[1].toLowerCase()] = (m[2] || '').toLowerCase();
    }
    const scriptCtx = directives['script-src'] ?? directives['default-src'] ?? '';
    const noBaseline =
      !('default-src' in directives) && !('script-src' in directives);
    const scriptWildcard = /(^|\s)\*(\s|$)/.test(scriptCtx);
    const scriptUnsafe =
      scriptCtx.includes("'unsafe-inline'") ||
      /(^|[\s'])unsafe-eval'/.test(scriptCtx.replace(/wasm-unsafe-eval/g, ''));
    if (noBaseline || scriptWildcard) {
      out.push(
        f(
          'csp-open-script',
          'headers',
          'high',
          'CSP sans restriction sur les scripts',
          noBaseline
            ? "Ni default-src ni script-src : aucune restriction sur le chargement des scripts."
            : "`*` dans le contexte script : n'importe quel domaine peut injecter du JavaScript.",
          [`content-security-policy: ${csp.slice(0, 300)}`],
          "Définir script-src 'self' (+ nonces/hash pour l'inline) et un default-src 'self' de repli.",
          { penalty: 10 },
        ),
      );
    } else if (scriptUnsafe) {
      out.push(
        f(
          'csp-script-unsafe',
          'headers',
          'info',
          "CSP : 'unsafe-inline' / 'unsafe-eval' dans le contexte script",
          "Un script injecté peut s'exécuter malgré la CSP. Réduit sa valeur, mais reste un durcissement facultatif (hors note).",
          [`content-security-policy: ${csp.slice(0, 300)}`],
          'Remplacer par des nonces (par requête) ou des hash SHA-256 des scripts inline légitimes.',
          { optional: true },
        ),
      );
    }
  }

  // X-Frame-Options (ou CSP frame-ancestors) — absent : -15 (élevé).
  if (!h['x-frame-options'] && !(csp && /frame-ancestors/i.test(csp))) {
    out.push(
      f(
        'clickjacking',
        'headers',
        'high',
        'Protection anti-clickjacking absente',
        "Ni X-Frame-Options ni frame-ancestors : la page peut être chargée dans une iframe pour du clickjacking.",
        ['x-frame-options: (absent)', 'csp frame-ancestors: (absent)'],
        'Poser X-Frame-Options: DENY (et frame-ancestors \'none\' dans la CSP).',
        { penalty: 15 },
      ),
    );
  }

  // X-Content-Type-Options — absent : -15 (moyen).
  if ((h['x-content-type-options'] || '').toLowerCase() !== 'nosniff') {
    out.push(
      f(
        'nosniff-missing',
        'headers',
        'medium',
        'X-Content-Type-Options absent',
        "Sans nosniff, le navigateur peut deviner le type d'un fichier et exécuter comme script une ressource servie en text/plain.",
        [`x-content-type-options: ${h['x-content-type-options'] || '(absent)'}`],
        'Poser X-Content-Type-Options: nosniff.',
        { penalty: 15 },
      ),
    );
  }

  // Referrer-Policy — absente : -7 (moyen, demi-cran).
  if (!h['referrer-policy']) {
    out.push(
      f(
        'referrer-policy-missing',
        'headers',
        'medium',
        'Referrer-Policy absente',
        "L'URL complète (chemins, tokens en query string) fuit vers les sites tiers et les CDN.",
        ['referrer-policy: (absent)'],
        'Poser Referrer-Policy: strict-origin-when-cross-origin.',
        { penalty: 7 },
      ),
    );
  }

  // Permissions-Policy — absente : -7 (moyen, demi-cran).
  if (!h['permissions-policy']) {
    out.push(
      f(
        'permissions-policy-missing',
        'headers',
        'medium',
        'Permissions-Policy absente',
        "Aucune restriction déclarée sur les API du navigateur (caméra, micro, géolocalisation…).",
        ['permissions-policy: (absent)'],
        'Poser Permissions-Policy: camera=(), microphone=(), geolocation=(), browsing-topics=().',
        { penalty: 7 },
      ),
    );
  }

  // --- Durcissements facultatifs (montrés, hors note) ------------------
  if (http.httpsUpgrade === false) {
    out.push(
      f(
        'https-no-redirect',
        'headers',
        'info',
        'HTTP ne redirige pas vers HTTPS',
        "Un visiteur qui tape l'URL sans https:// reste en clair pour la première requête. Sans effet sur la note.",
        ['http:// -> pas de redirection vers https://'],
        'Ajouter une redirection 301 permanente du port 80 vers HTTPS.',
        { optional: true },
      ),
    );
  }

  const discloser = [];
  if (h['server'] && /\d/.test(h['server'])) discloser.push(`server: ${h['server']}`);
  if (h['x-powered-by']) discloser.push(`x-powered-by: ${h['x-powered-by']}`);
  if (discloser.length) {
    out.push(
      f(
        'version-disclosure',
        'headers',
        'info',
        'Divulgation de versions logicielles',
        "Les en-têtes révèlent la pile technique et sa version. Sans effet sur la note.",
        discloser,
        'Masquer/normaliser les en-têtes Server et supprimer X-Powered-By.',
        { optional: true },
      ),
    );
  }

  // Un seul constat cookies agrégé, facultatif (comme l'outil dédié) — les
  // cookies tiers (Akamai bm_*, Cloudflare __cf*) polluent sinon la liste.
  const badCookies = [];
  for (const cookie of http.setCookie || []) {
    const flags = [];
    if (!/;\s*secure/i.test(cookie)) flags.push('Secure');
    if (!/;\s*httponly/i.test(cookie)) flags.push('HttpOnly');
    if (!/;\s*samesite=/i.test(cookie)) flags.push('SameSite');
    if (flags.length) {
      const name = (cookie.split('=')[0] || 'cookie').trim();
      badCookies.push(`${name} (manque ${flags.join(', ')})`);
    }
  }
  if (badCookies.length) {
    out.push(
      f(
        'cookie-flags',
        'headers',
        'info',
        `${badCookies.length} cookie(s) sans tous les attributs de sécurité`,
        "Un cookie de session sans Secure/HttpOnly/SameSite est exposé au vol et au CSRF. À vérifier au cas par cas (les cookies non sensibles sont parfois volontairement lisibles). Sans effet sur la note.",
        badCookies.slice(0, 8),
        'Ajouter Secure, HttpOnly et SameSite=Lax aux cookies applicatifs.',
        { optional: true },
      ),
    );
  }

  return out;
}

// --- grading: TLS ---------------------------------------------------

function gradeTls(tlsInfo) {
  if (!tlsInfo || tlsInfo.error) {
    return [
      f(
        'tls-unreachable',
        'tls',
        'medium',
        'Handshake TLS impossible',
        tlsInfo && tlsInfo.error ? tlsInfo.error : 'pas de réponse sur le port 443',
        [String((tlsInfo && tlsInfo.error) || 'timeout')],
        'Vérifier que le port 443 est ouvert et sert un certificat valide.',
      ),
    ];
  }
  const out = [];
  const proto = tlsInfo.protocol || '';
  if (/TLSv1(\.0|\.1)?$/.test(proto) || proto === 'TLSv1' || proto === 'TLSv1.1') {
    out.push(
      f(
        'tls-legacy-protocol',
        'tls',
        'high',
        `Protocole TLS obsolète (${proto})`,
        'TLS 1.0/1.1 sont dépréciés et vulnérables à plusieurs attaques.',
        [`Protocole négocié : ${proto}`],
        'Désactiver TLS 1.0/1.1, n’accepter que TLS 1.2 et 1.3.',
      ),
    );
  }
  if (tlsInfo.expiresInDays !== null && tlsInfo.expiresInDays < 0) {
    out.push(
      f(
        'tls-cert-expired',
        'tls',
        'crit',
        'Certificat TLS expiré',
        `Le certificat a expiré il y a ${Math.abs(tlsInfo.expiresInDays)} jour(s).`,
        [`valid_to: ${tlsInfo.validTo}`],
        'Renouveler le certificat immédiatement et automatiser le renouvellement (ACME).',
      ),
    );
  } else if (tlsInfo.expiresInDays !== null && tlsInfo.expiresInDays < 15) {
    out.push(
      f(
        'tls-cert-expiring',
        'tls',
        'high',
        'Certificat TLS proche de l’expiration',
        `Expire dans ${tlsInfo.expiresInDays} jour(s).`,
        [`valid_to: ${tlsInfo.validTo}`],
        'Renouveler le certificat et mettre en place le renouvellement automatique.',
      ),
    );
  } else if (tlsInfo.expiresInDays !== null && tlsInfo.expiresInDays < 30) {
    out.push(
      f(
        'tls-cert-soon',
        'tls',
        'medium',
        'Certificat TLS à renouveler bientôt',
        `Expire dans ${tlsInfo.expiresInDays} jour(s).`,
        [`valid_to: ${tlsInfo.validTo}`],
        'Planifier le renouvellement.',
      ),
    );
  }
  if (!tlsInfo.authorized && tlsInfo.authorizationError) {
    const errStr = String(tlsInfo.authorizationError);
    const isName = /HOSTNAME|ALTNAME/i.test(errStr);
    out.push(
      f(
        'tls-chain-invalid',
        'tls',
        isName ? 'high' : 'high',
        isName
          ? 'Certificat TLS ne couvre pas le domaine'
          : 'Chaîne de certification TLS invalide',
        errStr,
        [`authorizationError: ${errStr}`],
        isName
          ? 'Émettre un certificat couvrant exactement ce nom d’hôte.'
          : 'Corriger la chaîne (certificats intermédiaires manquants ou autorité inconnue).',
      ),
    );
  }
  // Le seuil 2048 ne vaut que pour RSA. Une clé EC (courbe présente) de 256
  // bits ≈ RSA 3072 — on ne signale que EC < 256 ou RSA < 2048.
  const weakKey = tlsInfo.curve
    ? tlsInfo.keyBits && tlsInfo.keyBits < 256
    : tlsInfo.keyBits && tlsInfo.keyBits < 2048;
  if (weakKey) {
    out.push(
      f(
        'tls-weak-key',
        'tls',
        'high',
        'Clé de certificat trop faible',
        `Clé de ${tlsInfo.keyBits} bits${tlsInfo.curve ? ` (${tlsInfo.curve})` : ''}, en dessous du minimum recommandé.`,
        [`keyBits: ${tlsInfo.keyBits}`, `curve: ${tlsInfo.curve || 'RSA'}`],
        'Réémettre le certificat avec une clé RSA 2048+ ou ECDSA P-256.',
      ),
    );
  }
  return out;
}

// --- grading: DNS -------------------------------------------------

function gradeDns(dnsInfo) {
  if (!dnsInfo || dnsInfo.error) {
    return [
      f(
        'dns-error',
        'dns',
        'low',
        'Analyse DNS incomplète',
        dnsInfo && dnsInfo.error ? dnsInfo.error : 'résolution DoH indisponible',
        [String((dnsInfo && dnsInfo.error) || 'timeout')],
        'Relancer l’audit ; vérifier la connectivité DNS.',
      ),
    ];
  }
  const out = [];

  if (!dnsInfo.spf) {
    out.push(
      f(
        'spf-missing',
        'dns',
        'medium',
        'SPF absent',
        "Sans SPF, n'importe quel serveur peut envoyer du mail au nom du domaine.",
        ['TXT v=spf1 : (absent)'],
        'Publier un enregistrement SPF se terminant par -all.',
      ),
    );
  } else {
    const q = (dnsInfo.spf.match(/([-~?+])all\b/) || [])[1];
    if (q === '~' || q === '?') {
      out.push(
        f(
          'spf-soft',
          'dns',
          'low',
          'SPF non strict',
          `Terminaison ${q}all : les mails usurpés sont généralement acceptés puis marqués.`,
          [dnsInfo.spf],
          'Passer à -all une fois les émetteurs légitimes recensés.',
        ),
      );
    } else if (q === '+') {
      out.push(
        f(
          'spf-permit-all',
          'dns',
          'high',
          'SPF +all (dangereux)',
          '+all autorise explicitement tout le monde à émettre pour le domaine.',
          [dnsInfo.spf],
          'Remplacer +all par -all.',
        ),
      );
    }
  }

  if (!dnsInfo.dmarc) {
    out.push(
      f(
        'dmarc-missing',
        'dns',
        'medium',
        'DMARC absent',
        "Sans DMARC, SPF et DKIM ne protègent pas l'adresse « From: » affichée à l'utilisateur.",
        ['TXT _dmarc : (absent)'],
        'Publier _dmarc avec au minimum p=quarantine et une adresse rua=.',
      ),
    );
  } else {
    const p = (dnsInfo.dmarc.match(/\bp=([a-z]+)/i) || [])[1] || 'none';
    if (p === 'none') {
      out.push(
        f(
          'dmarc-none',
          'dns',
          'low',
          'DMARC en observation seule (p=none)',
          'Aucun blocage des mails usurpés, surveillance uniquement.',
          [dnsInfo.dmarc],
          'Après une période d’observation, passer à p=quarantine puis p=reject.',
        ),
      );
    }
  }

  if (!dnsInfo.dnssec) {
    out.push(
      f(
        'dnssec-off',
        'dns',
        'low',
        'DNSSEC non activé',
        'La zone n’est pas signée : pas de protection contre les réponses DNS falsifiées.',
        ['DS : (absent)'],
        'Activer DNSSEC chez l’hébergeur DNS et publier le DS chez le registrar.',
      ),
    );
  }

  if (!dnsInfo.caa || dnsInfo.caa.length === 0) {
    out.push(
      f(
        'caa-missing',
        'dns',
        'low',
        'Enregistrement CAA absent',
        "N'importe quelle autorité de certification peut émettre un certificat pour ce domaine.",
        ['CAA : (absent)'],
        'Publier un enregistrement CAA limitant les autorités autorisées.',
      ),
    );
  }

  return out;
}

// --- grading: exposure -------------------------------------------

function gradeExposure(exposure) {
  if (!exposure || exposure.error) {
    return [
      f(
        'exposure-error',
        'exposure',
        'low',
        'Sonde des fichiers exposés incomplète',
        exposure && exposure.error ? exposure.error : 'timeout',
        [String((exposure && exposure.error) || 'timeout')],
        'Relancer l’audit.',
      ),
    ];
  }
  const out = [];
  for (const p of exposure.probed || []) {
    if (!p.flagged) continue;
    if (p.sev === 'good' || p.sev === 'info') continue;
    out.push(
      f(
        `exposed${p.path.replace(/[^a-z0-9]+/gi, '-')}`,
        'exposure',
        p.sev,
        `Fichier/chemin sensible accessible : ${p.path}`,
        `${p.path} répond en HTTP ${p.status} avec un contenu correspondant au fichier attendu — données internes potentiellement exposées.`,
        [`GET ${p.path} -> ${p.status}, contenu confirmé (pas la page de repli du site)`],
        `Bloquer l'accès public à ${p.path} (règle serveur, .gitignore de déploiement, retrait du fichier).`,
      ),
    );
  }
  const hasSecTxt = (exposure.probed || []).some(
    (p) => p.path === '/.well-known/security.txt' && p.confirmed,
  );
  if (!hasSecTxt) {
    out.push(
      f(
        'securitytxt-missing',
        'exposure',
        'info',
        'security.txt absent',
        'Aucun point de contact sécurité déclaré (/.well-known/security.txt).',
        ['GET /.well-known/security.txt -> absent'],
        'Publier un fichier /.well-known/security.txt (RFC 9116).',
      ),
    );
  }
  if (exposure.catchAll) {
    out.push(
      f(
        'exposure-catchall',
        'exposure',
        'info',
        'Hébergement avec page de repli (SPA)',
        "Le site renvoie une page par défaut pour toute URL inconnue : la sonde de fichiers exposés ne se fie qu'au contenu réel, pas au code HTTP.",
        ['GET /<chemin-aléatoire> -> 200'],
        'Aucune action — contexte pour interpréter la section.',
      ),
    );
  }
  return out;
}

// --- scoring ----------------------------------------------------
// Échelle et seuils identiques à security_headers_screen.dart.

const WEIGHT = { crit: 25, high: 15, medium: 8, low: 3, info: 0, ok: 0, good: 0 };

function penaltyOf(finding) {
  if (finding.optional) return 0;
  if (typeof finding.penalty === 'number') return finding.penalty;
  return WEIGHT[finding.severity] || 0;
}

function gradeFromValue(value) {
  if (value >= 100) return 'A+';
  if (value >= 85) return 'A';
  if (value >= 70) return 'B';
  if (value >= 55) return 'C';
  if (value >= 40) return 'D';
  if (value >= 20) return 'E';
  return 'F';
}

function scoreFindings(findings) {
  const counts = { crit: 0, high: 0, medium: 0, low: 0, info: 0 };
  let penalty = 0;
  for (const finding of findings) {
    if (counts[finding.severity] !== undefined) counts[finding.severity] += 1;
    penalty += penaltyOf(finding);
  }
  const value = Math.max(0, 100 - penalty);
  return { grade: gradeFromValue(value), value, counts };
}

// Note « en-têtes seule », strictement comme l'outil dédié.
function headersOnlyGrade(headerFindings) {
  let penalty = 0;
  for (const finding of headerFindings) penalty += penaltyOf(finding);
  const value = Math.max(0, Math.min(100, 100 - penalty));
  return { grade: gradeFromValue(value), value };
}

// --- Gemini narrative -----------------------------------------

const AI_SCHEMA = {
  type: 'object',
  properties: {
    executiveSummary: { type: 'string' },
    businessRisks: { type: 'array', items: { type: 'string' } },
    remediationPlan: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          priority: { type: 'integer' },
          action: { type: 'string' },
          effort: { type: 'string', enum: ['faible', 'moyen', 'élevé'] },
          rationale: { type: 'string' },
        },
        required: ['priority', 'action', 'effort', 'rationale'],
      },
    },
  },
  required: ['executiveSummary', 'businessRisks', 'remediationPlan'],
};

const AI_SYSTEM = `Tu es un consultant senior en cybersécurité qui restitue un audit à un dirigeant NON technique.
On te fournit UNIQUEMENT les résultats factuels d'un scan passif externe (en-têtes HTTP, TLS, DNS, fichiers exposés).
Règles absolues :
- N'invente JAMAIS de vulnérabilité, de CVE, de faille applicative (XSS, SQLi...) ou de donnée absente du JSON fourni.
- Ne parle que de ce qui est dans les findings. Si un domaine n'a aucun finding, dis qu'il est correct.
- Langage clair, orienté impact métier (confiance client, conformité RGPD, risque d'usurpation, interruption de service).
- Le plan de remédiation est priorisé (1 = le plus urgent), avec un effort réaliste.
- Réponds en français.`;

async function buildAiNarrative(report) {
  if (!GEMINI_API_KEY) {
    return { available: false, reason: 'GEMINI_API_KEY non configuré' };
  }
  const compact = {
    domain: report.domain,
    score: report.score,
    findings: report.findings.map((x) => ({
      severity: x.severity,
      category: x.category,
      title: x.title,
      summary: x.summary,
      recommendation: x.recommendation,
    })),
  };
  const body = {
    systemInstruction: { parts: [{ text: AI_SYSTEM }] },
    contents: [
      {
        role: 'user',
        parts: [
          {
            text:
              'Voici les résultats de l’audit passif au format JSON. Produis la synthèse client.\n\n' +
              JSON.stringify(compact, null, 2),
          },
        ],
      },
    ],
    generationConfig: {
      temperature: 0.3,
      responseMimeType: 'application/json',
      responseSchema: AI_SCHEMA,
    },
  };
  // Gemini renvoie fréquemment 429 (quota) ou 5xx (« model overloaded »)
  // de façon transitoire : on retente jusqu'à 3 fois avec un backoff.
  const TRANSIENT = new Set([429, 500, 502, 503, 504]);
  let lastFail = { available: false, reason: 'Gemini injoignable' };
  for (let attempt = 0; attempt < 3; attempt += 1) {
    if (attempt > 0) {
      await new Promise((res) => setTimeout(res, 1500 * attempt));
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 25000);
    try {
      const r = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(
          GEMINI_MODEL,
        )}:generateContent?key=${GEMINI_API_KEY}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          signal: controller.signal,
        },
      );
      if (!r.ok) {
        const detail = await r.text();
        lastFail = {
          available: false,
          reason: `Gemini HTTP ${r.status}`,
          detail: detail.slice(0, 300),
        };
        if (TRANSIENT.has(r.status)) continue;
        return lastFail;
      }
      const j = await r.json();
      const text =
        j &&
        j.candidates &&
        j.candidates[0] &&
        j.candidates[0].content &&
        j.candidates[0].content.parts &&
        j.candidates[0].content.parts[0] &&
        j.candidates[0].content.parts[0].text;
      if (!text) {
        lastFail = { available: false, reason: 'réponse Gemini vide' };
        continue;
      }
      const parsed = JSON.parse(text);
      return {
        available: true,
        model: GEMINI_MODEL,
        executiveSummary: parsed.executiveSummary,
        businessRisks: parsed.businessRisks || [],
        remediationPlan: parsed.remediationPlan || [],
      };
    } catch (err) {
      lastFail = {
        available: false,
        reason:
          err && err.name === 'AbortError'
            ? 'délai Gemini dépassé'
            : String((err && err.message) || err),
      };
    } finally {
      clearTimeout(timer);
    }
  }
  return lastFail;
}

// --- start ----------------------------------------------------

app.listen(PORT, '0.0.0.0', () => {
  console.log(
    `Audit Orchestrator backend on :${PORT} (AI: ${GEMINI_API_KEY ? GEMINI_MODEL : 'disabled'})`,
  );
});
