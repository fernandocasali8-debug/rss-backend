// Backend bÃ¡sico Node.js/Express para gerenciar feeds RSS

require('dotenv').config();

const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { v4: uuidv4 } = require('uuid');
const Parser = require('rss-parser');
const { JSDOM } = require('jsdom');
const { Readability } = require('@mozilla/readability');
const cheerio = require('cheerio');
const http = require('http');
const https = require('https');
const { URL } = require('url');
const iconv = require('iconv-lite');
const nodemailer = require('nodemailer');

const app = express();
const port = 4000;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
const IS_SECURE_FRONTEND = FRONTEND_URL.startsWith('https://');
const MP_ACCESS_TOKEN = process.env.MP_ACCESS_TOKEN || '';
const MP_PUBLIC_KEY = process.env.MP_PUBLIC_KEY || '';
const NITTER_BASE = process.env.NITTER_BASE || 'https://nitter.net';
const NITTER_FALLBACKS = (process.env.NITTER_FALLBACKS || '')
  .split(',')
  .map(item => item.trim())
  .filter(Boolean);

const normalizeRedirectPath = (value) => {
  if (typeof value !== 'string') return '/app';
  if (!value.startsWith('/') || value.startsWith('//')) return '/app';
  return value;
};

const appendQueryParam = (path, key, value) => {
  const separator = path.includes('?') ? '&' : '?';
  return `${path}${separator}${key}=${encodeURIComponent(value)}`;
};
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || `http://localhost:${port}/auth/google/callback`;
const GOOGLE_SHEETS_CLIENT_ID = process.env.GOOGLE_SHEETS_CLIENT_ID || GOOGLE_CLIENT_ID;
const GOOGLE_SHEETS_CLIENT_SECRET = process.env.GOOGLE_SHEETS_CLIENT_SECRET || GOOGLE_CLIENT_SECRET;
const GOOGLE_SHEETS_REDIRECT_URL = process.env.GOOGLE_SHEETS_REDIRECT_URL || `http://localhost:${port}/google/sheets/callback`;
const GOOGLE_DRIVE_CLIENT_ID = process.env.GOOGLE_DRIVE_CLIENT_ID || GOOGLE_CLIENT_ID;
const GOOGLE_DRIVE_CLIENT_SECRET = process.env.GOOGLE_DRIVE_CLIENT_SECRET || GOOGLE_CLIENT_SECRET;
const GOOGLE_DRIVE_REDIRECT_URL = process.env.GOOGLE_DRIVE_REDIRECT_URL || `http://localhost:${port}/google/drive/callback`;
const SESSION_SECRET = process.env.SESSION_SECRET || 'rss-session-secret';
const REMEMBER_MAX_AGE = 1000 * 60 * 60 * 24 * 30;
const KALSHI_BASE_URL = process.env.KALSHI_BASE_URL || 'https://api.elections.kalshi.com/trade-api/v2';
const KALSHI_API_KEY = process.env.KALSHI_API_KEY || '';

app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));
app.set('trust proxy', 1);
app.use(bodyParser.json());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: IS_SECURE_FRONTEND ? 'none' : 'lax',
    secure: IS_SECURE_FRONTEND
  }
}));
app.use(passport.initialize());
app.use(passport.session());

const googleAuthEnabled = Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

if (googleAuthEnabled) {
  passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: GOOGLE_CALLBACK_URL
  }, (_accessToken, _refreshToken, profile, done) => {
    const email = profile.emails && profile.emails[0] ? profile.emails[0].value : '';
    const photo = profile.photos && profile.photos[0] ? profile.photos[0].value : '';
    const user = {
      id: profile.id,
      name: profile.displayName || '',
      email,
      photo
    };
    done(null, user);
  }));
} else {
  console.warn('[auth] Google OAuth is not configured (missing client id/secret).');
}

app.get('/auth/google', (req, res, next) => {
  if (!googleAuthEnabled) {
    return res.status(500).json({ error: 'Google OAuth nao configurado.' });
  }
  if (req.session) {
    req.session.remember = req.query.remember === '1';
    req.session.oauthRedirect = normalizeRedirectPath(req.query.redirect || '/app');
  }
  return passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
});

app.get('/auth/google/callback', (req, res, next) => {
  if (!googleAuthEnabled) {
    return res.status(500).json({ error: 'Google OAuth nao configurado.' });
  }
  const redirectPath = normalizeRedirectPath(req.session?.oauthRedirect || '/app');
  return passport.authenticate('google', {
    failureRedirect: `${FRONTEND_URL}${appendQueryParam(redirectPath, 'auth', 'fail')}`
  })(req, res, () => {
    if (req.session) {
      if (req.session.remember) {
        req.session.cookie.maxAge = REMEMBER_MAX_AGE;
      } else {
        req.session.cookie.expires = false;
        req.session.cookie.maxAge = null;
      }
      delete req.session.oauthRedirect;
    }
    res.redirect(`${FRONTEND_URL}${appendQueryParam(redirectPath, 'auth', 'ok')}`);
  });
});

app.get('/auth/me', (req, res) => {
  if (!req.user) {
    return res.json({ user: null });
  }
  const email = String(req.user.email || '').toLowerCase();
  let meta = users.find(user => user.email === email);
  const now = new Date().toISOString();
  if (!meta) {
    meta = {
      id: uuidv4(),
      name: req.user.name || '',
      email,
      role: 'viewer',
      plan: 'starter',
      active: true,
      approved: false,
      approvedAt: null,
      authProvider: 'google',
      authId: req.user.id || '',
      lastLoginAt: now,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    users.push(meta);
    saveUsers(users);
  } else {
    let changed = false;
    if (req.user.name && meta.name !== req.user.name) {
      meta.name = req.user.name;
      changed = true;
    }
    if (meta.authProvider !== 'google') {
      meta.authProvider = 'google';
      changed = true;
    }
    if (meta.approved === undefined) {
      meta.approved = meta.role === 'admin';
      meta.approvedAt = meta.approved ? now : null;
      changed = true;
    }
    if (req.user.id && meta.authId !== req.user.id) {
      meta.authId = req.user.id;
      changed = true;
    }
    const previousLoginAt = meta.lastLoginAt ? Date.parse(meta.lastLoginAt) : 0;
    const shouldUpdateLoginAt = !Number.isFinite(previousLoginAt)
      || (Date.now() - previousLoginAt) > 5 * 60 * 1000;
    if (shouldUpdateLoginAt) {
      meta.lastLoginAt = now;
      changed = true;
    }
    if (changed) {
      meta.updatedAt = now;
      saveUsers(users);
    }
  }
  const trialEndsAt = meta.trialEndsAt ? Date.parse(meta.trialEndsAt) : null;
  const trialExpired = trialEndsAt ? Date.now() > trialEndsAt : false;
  const safeMeta = {
    role: meta.role || 'viewer',
    plan: meta.plan || 'starter',
    active: meta.active !== false,
    approved: meta.approved === true,
    approvedAt: meta.approvedAt || null,
    trialStartedAt: meta.trialStartedAt || null,
    trialEndsAt: meta.trialEndsAt || null,
    trialExpired,
    billingModalSeenAt: meta.billingModalSeenAt || null
  };
  return res.json({ user: { ...req.user, ...safeMeta } });
});

app.post('/auth/logout', (req, res) => {
  if (typeof req.logout === 'function') {
    req.logout((err) => {
      if (err) {
        return res.status(500).json({ error: 'Falha ao sair.' });
      }
      if (req.session) {
        req.session.destroy(() => res.json({ ok: true }));
      } else {
        res.json({ ok: true });
      }
    });
    return;
  }
  if (req.session) {
    req.session.destroy(() => res.json({ ok: true }));
    return;
  }
  res.json({ ok: true });
});

const isPublicRoute = (req) => {
  if (req.path.startsWith('/auth/')) return true;
  if (req.path === '/auth/google') return true;
  if (req.path === '/auth/me') return true;
  if (req.path.startsWith('/billing')) return true;
  if (req.method === 'GET') {
    if (req.path.startsWith('/public/')) return true;
    if (req.path === '/rss') return true;
    if (req.path === '/x/rss') return true;
    if (req.path.startsWith('/rss/generated/')) return true;
    if (req.path.startsWith('/site/')) return true;
    if (req.path === '/polymarket/events') return true;
  }
  return false;
};

app.use((req, res, next) => {
  if (isPublicRoute(req)) return next();
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  return res.status(401).json({ error: 'Nao autorizado.' });
});

app.use((req, res, next) => {
  if (isPublicRoute(req)) return next();
  const email = String(req.user?.email || '').toLowerCase();
  if (!email) return res.status(401).json({ error: 'Nao autorizado.' });
  const meta = users.find(user => user.email === email);
  if (!meta) return res.status(401).json({ error: 'Nao autorizado.' });
  if (meta.role === 'admin') return next();
  if (meta.approved === true) return next();
  return res.status(403).json({ error: 'Aguardando liberacao do administrador.' });
});


const { loadSheetsConfig, saveSheetsConfig } = require('./sheetsStorage');
let sheetsConfig = loadSheetsConfig();
const {
  createOAuthClient,
  getAuthUrl,
  exchangeCode,
  createSheetsClient,
  appendRows
} = require('./googleSheets');
const { loadDriveConfig, saveDriveConfig } = require('./driveStorage');
let driveConfig = loadDriveConfig();
const {
  createOAuthClient: createDriveOAuthClient,
  getAuthUrl: getDriveAuthUrl,
  exchangeCode: exchangeDriveCode,
  createDriveClient,
  createFolder: createDriveFolder,
  uploadTextFile: uploadDriveTextFile,
  createDocsClient,
  createDocument,
  insertDocumentText
} = require('./googleDrive');

const getSheetsUser = (req) => {
  const email = req?.user?.email || '';
  return email ? String(email) : '';
};

const getSheetsConfigForUser = (email) => {
  if (!email) return null;
  return sheetsConfig.users[email] || null;
};

const setSheetsConfigForUser = (email, next) => {
  if (!email) return;
  sheetsConfig.users[email] = { ...(sheetsConfig.users[email] || {}), ...next };
  saveSheetsConfig(sheetsConfig);
};

const clearSheetsConfigForUser = (email) => {
  if (!email) return;
  if (sheetsConfig.users[email]) {
    delete sheetsConfig.users[email];
    saveSheetsConfig(sheetsConfig);
  }
};

const sheetsOAuthEnabled = Boolean(GOOGLE_SHEETS_CLIENT_ID && GOOGLE_SHEETS_CLIENT_SECRET);

const buildSheetsOAuthClient = () => createOAuthClient(
  GOOGLE_SHEETS_CLIENT_ID,
  GOOGLE_SHEETS_CLIENT_SECRET,
  GOOGLE_SHEETS_REDIRECT_URL
);

app.get('/google/sheets/connect', (req, res) => {
  if (!sheetsOAuthEnabled) {
    return res.status(500).json({ error: 'Google Sheets OAuth nao configurado.' });
  }
  const email = getSheetsUser(req);
  if (!email) {
    return res.status(400).json({ error: 'Usuario sem email.' });
  }
  const oauthClient = buildSheetsOAuthClient();
  const state = Buffer.from(JSON.stringify({ email, ts: Date.now() })).toString('base64url');
  if (req.session) {
    req.session.sheetsState = state;
  }
  const url = getAuthUrl(oauthClient, state);
  res.redirect(url);
});

app.get('/google/sheets/callback', async (req, res) => {
  if (!sheetsOAuthEnabled) {
    return res.status(500).json({ error: 'Google Sheets OAuth nao configurado.' });
  }
  const email = getSheetsUser(req);
  if (!email) {
    return res.redirect(`${FRONTEND_URL}/app?sheets=fail`);
  }
  const code = String(req.query.code || '');
  if (!code) {
    return res.redirect(`${FRONTEND_URL}/app?sheets=fail`);
  }
  if (req.session?.sheetsState && req.query.state && req.session.sheetsState !== req.query.state) {
    return res.redirect(`${FRONTEND_URL}/app?sheets=fail`);
  }
  try {
    const oauthClient = buildSheetsOAuthClient();
    const tokens = await exchangeCode(oauthClient, code);
    const existing = getSheetsConfigForUser(email) || {};
    const mergedTokens = { ...(existing.tokens || {}), ...tokens };
    setSheetsConfigForUser(email, { tokens: mergedTokens });
    res.redirect(`${FRONTEND_URL}/app?sheets=ok`);
  } catch (err) {
    res.redirect(`${FRONTEND_URL}/app?sheets=fail`);
  }
});

app.get('/google/sheets/status', (req, res) => {
  const email = getSheetsUser(req);
  if (!email) {
    return res.json({ connected: false, spreadsheetId: '' });
  }
  const config = getSheetsConfigForUser(email);
  res.json({
    connected: Boolean(config?.tokens),
    spreadsheetId: config?.spreadsheetId || ''
  });
});

app.post('/google/sheets/disconnect', (req, res) => {
  const email = getSheetsUser(req);
  if (!email) {
    return res.status(400).json({ error: 'Usuario sem email.' });
  }
  clearSheetsConfigForUser(email);
  res.json({ ok: true });
});

app.post('/google/sheets/spreadsheet', async (req, res) => {
  const email = getSheetsUser(req);
  if (!email) {
    return res.status(400).json({ error: 'Usuario sem email.' });
  }
  const spreadsheetId = String(req.body.spreadsheetId || '').trim();
  if (!spreadsheetId) {
    return res.status(400).json({ error: 'Informe o ID da planilha.' });
  }
  const config = getSheetsConfigForUser(email);
  if (!config?.tokens) {
    return res.status(400).json({ error: 'Google Sheets nao conectado.' });
  }
  try {
    const oauthClient = buildSheetsOAuthClient();
    const sheets = createSheetsClient(oauthClient, config.tokens);
    await sheets.spreadsheets.get({ spreadsheetId });
    setSheetsConfigForUser(email, { spreadsheetId });
    res.json({ ok: true, spreadsheetId });
  } catch (err) {
    res.status(400).json({ error: 'Planilha invalida ou sem permissao.' });
  }
});

app.post('/google/sheets/export/queue', async (req, res) => {
  const email = getSheetsUser(req);
  if (!email) {
    return res.status(400).json({ error: 'Usuario sem email.' });
  }
  const config = getSheetsConfigForUser(email);
  if (!config?.tokens || !config?.spreadsheetId) {
    return res.status(400).json({ error: 'Configure o Google Sheets antes de exportar.' });
  }
  try {
    const oauthClient = buildSheetsOAuthClient();
    const sheets = createSheetsClient(oauthClient, config.tokens);
    const header = [
      'Exportado em',
      'Influenciador',
      'Status',
      'Titulo',
      'Fonte',
      'Data noticia',
      'Score',
      'Score IA',
      'Publicado em',
      'Link',
      'Item ID'
    ];
    const rows = [];
    const influencerList = Array.isArray(influencers) ? influencers : [];
    Object.entries(influencerQueues || {}).forEach(([influencerId, items]) => {
      const name = influencerList.find(item => item.id === influencerId)?.name || influencerId;
      (Array.isArray(items) ? items : []).forEach((item) => {
        rows.push([
          new Date().toISOString(),
          name,
          item.status || 'pending',
          item.title || '',
          item.feedName || '',
          item.pubDate || '',
          item.score ?? '',
          item.aiScore ?? '',
          item.publishedAt || '',
          item.link || '',
          item.id || ''
        ]);
      });
    });
    await appendRows(sheets, config.spreadsheetId, 'Fila', header, rows);
    res.json({ ok: true, rows: rows.length });
  } catch (err) {
    res.status(500).json({ error: 'Falha ao exportar fila.' });
  }
});

app.post('/google/sheets/export/metrics', async (req, res) => {
  const email = getSheetsUser(req);
  if (!email) {
    return res.status(400).json({ error: 'Usuario sem email.' });
  }
  const config = getSheetsConfigForUser(email);
  if (!config?.tokens || !config?.spreadsheetId) {
    return res.status(400).json({ error: 'Configure o Google Sheets antes de exportar.' });
  }
  try {
    const payload = await buildDashboardMetrics(req.body?.period || '24h');
    const oauthClient = buildSheetsOAuthClient();
    const sheets = createSheetsClient(oauthClient, config.tokens);
    const header = [
      'Exportado em',
      'Periodo',
      'Noticias no periodo',
      'Feeds total',
      'Feeds na timeline',
      'Alertas',
      'Temas ativos',
      'Salvos',
      'Eventos',
      'Erros',
      'Warnings',
      'Influenciadores',
      'Fila total',
      'Fila aprovadas',
      'Fila pendentes',
      'Fila descartadas',
      'Publicados',
      'IA reescritas',
      'IA hashtags'
    ];
    const row = [
      new Date().toISOString(),
      String(req.body?.period || '24h'),
      payload.activity?.newsLastRange || 0,
      payload.totals?.feedsTotal || 0,
      payload.totals?.feedsOnTimeline || 0,
      payload.totals?.watchAlertsLastRange || 0,
      payload.totals?.watchTopicsCount || 0,
      payload.totals?.savedCount || 0,
      payload.totals?.eventsLastRange || 0,
      payload.totals?.errorsLastRange || 0,
      payload.totals?.warningLastRange || 0,
      payload.influencers?.total || 0,
      payload.influencers?.queueTotal || 0,
      payload.influencers?.queueApproved || 0,
      payload.influencers?.queuePending || 0,
      payload.influencers?.queueDiscarded || 0,
      payload.influencers?.published || 0,
      payload.ai?.rewrites || 0,
      payload.ai?.hashtags || 0
    ];
    await appendRows(sheets, config.spreadsheetId, 'Metricas', header, [row]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Falha ao exportar metricas.' });
  }
});

app.post('/google/sheets/export/saved', async (req, res) => {
  const email = getSheetsUser(req);
  if (!email) {
    return res.status(400).json({ error: 'Usuario sem email.' });
  }
  const config = getSheetsConfigForUser(email);
  if (!config?.tokens || !config?.spreadsheetId) {
    return res.status(400).json({ error: 'Configure o Google Sheets antes de exportar.' });
  }
  try {
    const oauthClient = buildSheetsOAuthClient();
    const sheets = createSheetsClient(oauthClient, config.tokens);
    const header = [
      'Exportado em',
      'Origem',
      'Titulo',
      'Fonte',
      'Data',
      'Link',
      'Item ID'
    ];
    const rows = (Array.isArray(savedItems) ? savedItems : []).map((item) => ([
      new Date().toISOString(),
      item.source || 'timeline',
      item.title || '',
      item.feedName || '',
      item.pubDate || item.isoDate || '',
      item.link || '',
      item.id || ''
    ]));
    await appendRows(sheets, config.spreadsheetId, 'Salvos', header, rows);
    res.json({ ok: true, rows: rows.length });
  } catch (err) {
    res.status(500).json({ error: 'Falha ao exportar salvos.' });
  }
});

const getDriveUser = (req) => {
  const email = req?.user?.email || '';
  return email ? String(email) : '';
};

const getDriveConfigForUser = (email) => {
  if (!email) return null;
  return driveConfig.users[email] || null;
};

const setDriveConfigForUser = (email, next) => {
  if (!email) return;
  driveConfig.users[email] = { ...(driveConfig.users[email] || {}), ...next };
  saveDriveConfig(driveConfig);
};

const clearDriveConfigForUser = (email) => {
  if (!email) return;
  if (driveConfig.users[email]) {
    delete driveConfig.users[email];
    saveDriveConfig(driveConfig);
  }
};

const driveOAuthEnabled = Boolean(GOOGLE_DRIVE_CLIENT_ID && GOOGLE_DRIVE_CLIENT_SECRET);

const buildDriveOAuthClient = () => createDriveOAuthClient(
  GOOGLE_DRIVE_CLIENT_ID,
  GOOGLE_DRIVE_CLIENT_SECRET,
  GOOGLE_DRIVE_REDIRECT_URL
);

const getDriveClientForUser = (email) => {
  const config = getDriveConfigForUser(email);
  if (!config?.tokens) return null;
  const oauthClient = buildDriveOAuthClient();
  return createDriveClient(oauthClient, config.tokens);
};

const getDriveDocsClientForUser = (email) => {
  const config = getDriveConfigForUser(email);
  if (!config?.tokens) return null;
  const oauthClient = buildDriveOAuthClient();
  return createDocsClient(oauthClient, config.tokens);
};

const formatDriveError = (err) => {
  const message = String(err?.message || err || '').trim();
  if (!message) return 'Falha ao executar acao no Drive.';
  if (message.includes('drive.googleapis.com') || message.includes('Drive API has not been used')) {
    return 'Google Drive API desativada. Ative no Google Cloud Console e tente novamente.';
  }
  if (message.toLowerCase().includes('insufficientpermissions')) {
    return 'Permissao insuficiente no Google Drive. Reconecte a conta.';
  }
  if (message.toLowerCase().includes('invalid_grant')) {
    return 'Conexao expirada. Desconecte e conecte o Google Drive novamente.';
  }
  return message;
};

const buildBriefingText = async () => {
  const aggregated = await buildAggregatedItems();
  const items = buildSummaryItems(
    aggregated,
    summaryConfig.maxItems || 10,
    summaryConfig.lookbackHours || 24
  );
  const trendsItems = await fetchTrendsItems(trendsConfig);
  const lines = [];
  lines.push(`Resumo diario - ${getDailyKey(new Date())}`);
  lines.push('');
  lines.push('Top noticias');
  if (!items.length) {
    lines.push('Sem itens no periodo.');
  } else {
    items.forEach((item, idx) => {
      const title = item.title || '';
      const source = item.feedName ? ` (${item.feedName})` : '';
      lines.push(`${idx + 1}. ${title}${source}`);
      if (item.link) lines.push(`   ${item.link}`);
    });
  }
  lines.push('');
  lines.push('Tendencias');
  if (!trendsItems.length) {
    lines.push('Sem tendencias no momento.');
  } else {
    trendsItems.slice(0, 12).forEach((trend, idx) => {
      const traffic = trend.traffic ? ` - ${trend.traffic}` : '';
      lines.push(`${idx + 1}. ${trend.title || ''}${traffic}`);
      if (trend.link) lines.push(`   ${trend.link}`);
    });
  }
  return lines.join('\n');
};

app.get('/google/drive/connect', (req, res) => {
  if (!driveOAuthEnabled) {
    return res.status(500).json({ error: 'Google Drive OAuth nao configurado.' });
  }
  const email = getDriveUser(req);
  if (!email) {
    return res.status(400).json({ error: 'Usuario sem email.' });
  }
  const oauthClient = buildDriveOAuthClient();
  const state = Buffer.from(JSON.stringify({ email, ts: Date.now() })).toString('base64url');
  if (req.session) {
    req.session.driveState = state;
  }
  const url = getDriveAuthUrl(oauthClient, state);
  res.redirect(url);
});

app.get('/google/drive/callback', async (req, res) => {
  if (!driveOAuthEnabled) {
    return res.status(500).json({ error: 'Google Drive OAuth nao configurado.' });
  }
  const email = getDriveUser(req);
  if (!email) {
    return res.redirect(`${FRONTEND_URL}/app?drive=fail`);
  }
  const code = String(req.query.code || '');
  if (!code) {
    return res.redirect(`${FRONTEND_URL}/app?drive=fail`);
  }
  if (req.session?.driveState && req.query.state && req.session.driveState !== req.query.state) {
    return res.redirect(`${FRONTEND_URL}/app?drive=fail`);
  }
  try {
    const oauthClient = buildDriveOAuthClient();
    const tokens = await exchangeDriveCode(oauthClient, code);
    const existing = getDriveConfigForUser(email) || {};
    const mergedTokens = { ...(existing.tokens || {}), ...tokens };
    setDriveConfigForUser(email, { tokens: mergedTokens });
    res.redirect(`${FRONTEND_URL}/app?drive=ok`);
  } catch (err) {
    res.redirect(`${FRONTEND_URL}/app?drive=fail`);
  }
});

app.get('/google/drive/status', (req, res) => {
  const email = getDriveUser(req);
  if (!email) {
    return res.json({ connected: false, rootFolderId: '', clients: [] });
  }
  const config = getDriveConfigForUser(email);
  res.json({
    connected: Boolean(config?.tokens),
    rootFolderId: config?.rootFolderId || '',
    clients: Array.isArray(config?.clients) ? config.clients : [],
    lastExportAt: config?.lastExportAt || '',
    lastBackupAt: config?.lastBackupAt || ''
  });
});

app.post('/google/drive/disconnect', (req, res) => {
  const email = getDriveUser(req);
  if (!email) {
    return res.status(400).json({ error: 'Usuario sem email.' });
  }
  clearDriveConfigForUser(email);
  res.json({ ok: true });
});

app.post('/google/drive/root', async (req, res) => {
  const email = getDriveUser(req);
  if (!email) {
    return res.status(400).json({ error: 'Usuario sem email.' });
  }
  const drive = getDriveClientForUser(email);
  if (!drive) {
    return res.status(400).json({ error: 'Google Drive nao conectado.' });
  }
  try {
    const folder = await createDriveFolder(drive, 'Leitor RSS');
    setDriveConfigForUser(email, { rootFolderId: folder.id });
    res.json({ ok: true, folder });
  } catch (err) {
    res.status(500).json({ error: formatDriveError(err) });
  }
});

app.post('/google/drive/clients', async (req, res) => {
  const email = getDriveUser(req);
  if (!email) {
    return res.status(400).json({ error: 'Usuario sem email.' });
  }
  const config = getDriveConfigForUser(email);
  const drive = getDriveClientForUser(email);
  if (!drive || !config?.rootFolderId) {
    return res.status(400).json({ error: 'Conecte o Drive e crie a pasta principal.' });
  }
  const name = String(req.body?.name || '').trim();
  if (!name) {
    return res.status(400).json({ error: 'Nome do cliente e obrigatorio.' });
  }
  try {
    const folder = await createDriveFolder(drive, name, config.rootFolderId);
    const nextClient = { id: uuidv4(), name, folderId: folder.id };
    const nextClients = [...(config.clients || []), nextClient];
    setDriveConfigForUser(email, { clients: nextClients });
    res.json({ ok: true, client: nextClient });
  } catch (err) {
    res.status(500).json({ error: formatDriveError(err) });
  }
});

app.delete('/google/drive/clients/:id', (req, res) => {
  const email = getDriveUser(req);
  if (!email) {
    return res.status(400).json({ error: 'Usuario sem email.' });
  }
  const config = getDriveConfigForUser(email) || {};
  const nextClients = (config.clients || []).filter(client => client.id !== req.params.id);
  setDriveConfigForUser(email, { clients: nextClients });
  res.json({ ok: true });
});

app.post('/google/drive/export/rss', async (req, res) => {
  const email = getDriveUser(req);
  if (!email) {
    return res.status(400).json({ error: 'Usuario sem email.' });
  }
  const config = getDriveConfigForUser(email);
  const drive = getDriveClientForUser(email);
  if (!drive) {
    return res.status(400).json({ error: 'Google Drive nao conectado.' });
  }
  const clientId = String(req.body?.clientId || '').trim();
  const client = (config?.clients || []).find(item => item.id === clientId);
  const parentId = client?.folderId || config?.rootFolderId || '';
  if (!parentId) {
    return res.status(400).json({ error: 'Defina a pasta principal do Drive.' });
  }
  try {
    const list = generatedRssIndex.map(entry => ({
      ...entry,
      feedUrl: `/rss/generated/${entry.id}`
    }));
    const payload = {
      generatedAt: new Date().toISOString(),
      items: list
    };
    const name = `rss-gerados-${getDailyKey(new Date())}.json`;
    const file = await uploadDriveTextFile(drive, name, JSON.stringify(payload, null, 2), parentId);
    setDriveConfigForUser(email, { lastExportAt: new Date().toISOString() });
    res.json({ ok: true, file });
  } catch (err) {
    res.status(500).json({ error: formatDriveError(err) });
  }
});

app.post('/google/drive/export/trends', async (req, res) => {
  const email = getDriveUser(req);
  if (!email) {
    return res.status(400).json({ error: 'Usuario sem email.' });
  }
  const config = getDriveConfigForUser(email);
  const drive = getDriveClientForUser(email);
  if (!drive) {
    return res.status(400).json({ error: 'Google Drive nao conectado.' });
  }
  const clientId = String(req.body?.clientId || '').trim();
  const client = (config?.clients || []).find(item => item.id === clientId);
  const parentId = client?.folderId || config?.rootFolderId || '';
  if (!parentId) {
    return res.status(400).json({ error: 'Defina a pasta principal do Drive.' });
  }
  try {
    const items = await fetchTrendsItems(trendsConfig);
    const payload = {
      generatedAt: new Date().toISOString(),
      region: trendsConfig.geo || 'BR',
      items
    };
    const name = `tendencias-${getDailyKey(new Date())}.json`;
    const file = await uploadDriveTextFile(drive, name, JSON.stringify(payload, null, 2), parentId);
    setDriveConfigForUser(email, { lastExportAt: new Date().toISOString() });
    res.json({ ok: true, file });
  } catch (err) {
    res.status(500).json({ error: formatDriveError(err) });
  }
});

app.post('/google/drive/export/briefing', async (req, res) => {
  const email = getDriveUser(req);
  if (!email) {
    return res.status(400).json({ error: 'Usuario sem email.' });
  }
  const config = getDriveConfigForUser(email);
  const drive = getDriveClientForUser(email);
  const docs = getDriveDocsClientForUser(email);
  if (!drive || !docs) {
    return res.status(400).json({ error: 'Google Drive nao conectado.' });
  }
  const clientId = String(req.body?.clientId || '').trim();
  const client = (config?.clients || []).find(item => item.id === clientId);
  const parentId = client?.folderId || config?.rootFolderId || '';
  if (!parentId) {
    return res.status(400).json({ error: 'Defina a pasta principal do Drive.' });
  }
  try {
    const name = `briefing-${getDailyKey(new Date())}`;
    const doc = await createDocument(drive, name, parentId);
    const text = await buildBriefingText();
    await insertDocumentText(docs, doc.id, text);
    setDriveConfigForUser(email, { lastExportAt: new Date().toISOString() });
    res.json({ ok: true, file: doc });
  } catch (err) {
    res.status(500).json({ error: formatDriveError(err) });
  }
});

app.post('/google/drive/backup', async (req, res) => {
  const email = getDriveUser(req);
  if (!email) {
    return res.status(400).json({ error: 'Usuario sem email.' });
  }
  const config = getDriveConfigForUser(email);
  const drive = getDriveClientForUser(email);
  if (!drive) {
    return res.status(400).json({ error: 'Google Drive nao conectado.' });
  }
  const parentId = config?.rootFolderId || '';
  if (!parentId) {
    return res.status(400).json({ error: 'Defina a pasta principal do Drive.' });
  }
  try {
    const backup = {
      generatedAt: new Date().toISOString(),
      feeds,
      influencers,
      tickerConfig,
      displayConfig,
      alerts: alertConfig,
      summary: summaryConfig
    };
    const name = `backup-config-${getDailyKey(new Date())}.json`;
    const file = await uploadDriveTextFile(drive, name, JSON.stringify(backup, null, 2), parentId);
    setDriveConfigForUser(email, { lastBackupAt: new Date().toISOString() });
    res.json({ ok: true, file });
  } catch (err) {
    res.status(500).json({ error: formatDriveError(err) });
  }
});




// PersistÃªncia em arquivo
const { loadFeeds, saveFeeds } = require('./feedsStorage');
const normalizeFeedLanguage = (value) => (value === 'auto' ? 'auto' : 'pt');
const normalizeFeed = (feed) => ({
  id: String(feed.id || uuidv4()),
  name: String(feed.name || '').trim(),
  url: String(feed.url || '').trim(),
  showOnTimeline: feed.showOnTimeline !== false,
  sourceUrl: String(feed.sourceUrl || ''),
  language: normalizeFeedLanguage(feed.language)
});
let feeds = loadFeeds().map(normalizeFeed);

const { loadUsers, saveUsers } = require('./usersStorage');
let users = loadUsers().map((user) => ({
  ...user,
  role: normalizeUserRole(user.role),
  plan: normalizePlan(user.plan),
  active: user.active !== false,
  approved: user.approved === undefined ? true : user.approved === true,
  approvedAt: user.approvedAt || null
}));

const { loadTeams, saveTeams } = require('./teamsStorage');
let teams = loadTeams();

const { loadNotifications, saveNotifications } = require('./notificationsStorage');
let notifications = loadNotifications();

const { loadEmailConfig, saveEmailConfig } = require('./emailStorage');
let emailConfig = loadEmailConfig();

const { loadSaved, saveSaved } = require('./savedStorage');
let savedItems = loadSaved();

const { loadEvents, saveEvents } = require('./eventLogStorage');
let events = loadEvents();
const MAX_EVENTS = 200;

const { loadAutomation, saveAutomation } = require('./automationStorage');
let automationConfig = loadAutomation();

const { loadState, saveState } = require('./automationStateStorage');
let automationState = loadState();
const { TwitterApi } = require('twitter-api-v2');

const { loadAlerts, saveAlerts } = require('./alertStorage');
let alertConfig = loadAlerts();
const { loadAlertState, saveAlertState } = require('./alertStateStorage');
let alertState = loadAlertState();
const MAX_ALERT_IDS = 500;

const { loadSummaryConfig, saveSummaryConfig } = require('./summaryStorage');
let summaryConfig = loadSummaryConfig();
const { loadAiConfig, saveAiConfig } = require('./aiStorage');
let aiConfig = loadAiConfig();
const { loadTelegram, saveTelegram } = require('./telegramStorage');
let telegramConfig = loadTelegram();
const { loadTelegramState, saveTelegramState } = require('./telegramStateStorage');
let telegramState = loadTelegramState();
const { loadTelegramFeeds, saveTelegramFeeds } = require('./telegramFeedsStorage');
let telegramFeedsConfig = loadTelegramFeeds();
const { loadTelegramFeedsState, saveTelegramFeedsState } = require('./telegramFeedsStateStorage');
let telegramFeedsState = loadTelegramFeedsState();
const { loadWhatsApp, saveWhatsApp } = require('./whatsappStorage');
let whatsappConfig = loadWhatsApp();
const { loadWhatsAppState, saveWhatsAppState } = require('./whatsappStateStorage');
let whatsappState = loadWhatsAppState();
const { loadTrends, saveTrends } = require('./trendsStorage');
let trendsConfig = loadTrends();
const { loadYouTube, saveYouTube } = require('./youtubeStorage');
let youtubeConfig = loadYouTube();
const { loadSites, saveSites, defaultSite } = require('./siteStorage');
let siteStore = loadSites();
const { loadSitePosts, saveSitePosts } = require('./sitePostsStorage');
let sitePosts = loadSitePosts();
const { loadWatchTopics, saveWatchTopics } = require('./watchStorage');
let watchTopics = loadWatchTopics();
const { loadWatchAlerts, saveWatchAlerts } = require('./watchAlertsStorage');
let watchAlerts = loadWatchAlerts();
const { loadWatchSettings, saveWatchSettings } = require('./watchSettingsStorage');
let watchSettings = loadWatchSettings();
const MAX_WATCH_ALERTS = 500;
const watchAlertKeys = new Set();
const { loadInfluencers, saveInfluencers } = require('./influencerStorage');
let influencers = loadInfluencers();
const { loadInfluencerQueues, saveInfluencerQueues } = require('./influencerQueueStorage');
let influencerQueues = loadInfluencerQueues();
const DASHBOARD_CACHE_TTL_MS = 60 * 1000;
let dashboardMetricsCache = { updatedAt: 0, data: null, period: null };
const AGGREGATED_CACHE_TTL_MS = 5 * 60 * 1000;
let aggregatedCache = { updatedAt: 0, items: [] };
const PUBLIC_WATCH_TTL_MS = 5 * 60 * 1000;
const publicWatchCache = new Map();
let dashboardRefreshInFlight = false;
const TRENDS_EXPLAIN_CACHE_TTL_MS = 12 * 60 * 60 * 1000;
const trendsExplainCache = new Map();
const dailySummaryStatePath = path.join(__dirname, 'dailySummary.json');
let dailySummaryState = (() => {
  try {
    return JSON.parse(fs.readFileSync(dailySummaryStatePath, 'utf-8'));
  } catch (e) {
    return { lastSummaryDate: null, latest: null };
  }
})();
const { loadCache, saveCache } = require('./rssCacheStorage');
const rssCache = new Map();
const persistedCache = loadCache();
Object.entries(persistedCache).forEach(([key, value]) => {
  if (value && value.rss) {
    rssCache.set(key, value);
  }
});
const RSS_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const RSS_CACHE_MAX = 50;
const WEATHER_CACHE_TTL_MS = 10 * 60 * 1000;
const weatherCache = new Map();

const GENERATED_RSS_DIR = path.join(__dirname, 'generated-rss');
const GENERATED_RSS_INDEX = path.join(GENERATED_RSS_DIR, 'index.json');
const GENERATED_RSS_MAX = 200;
const GENERATED_RSS_TTL_DAYS = 45;
let generatedRssIndex = (() => {
  try {
    fs.mkdirSync(GENERATED_RSS_DIR, { recursive: true });
    return JSON.parse(fs.readFileSync(GENERATED_RSS_INDEX, 'utf-8'));
  } catch (e) {
    return [];
  }
})();

function pruneRssCache() {
  const now = Date.now();
  const entries = Array.from(rssCache.entries())
    .filter(([, value]) => value && value.updatedAt && (now - value.updatedAt) <= RSS_CACHE_TTL_MS)
    .sort((a, b) => (b[1].updatedAt || 0) - (a[1].updatedAt || 0))
    .slice(0, RSS_CACHE_MAX);

  rssCache.clear();
  const nextCache = {};
  for (const [key, value] of entries) {
    rssCache.set(key, value);
    nextCache[key] = value;
  }
  saveCache(nextCache);
}

function saveGeneratedIndex() {
  fs.mkdirSync(GENERATED_RSS_DIR, { recursive: true });
  fs.writeFileSync(GENERATED_RSS_INDEX, JSON.stringify(generatedRssIndex, null, 2), 'utf-8');
}

function removeGeneratedFile(entry) {
  if (!entry || !entry.fileName) return;
  const filePath = path.join(GENERATED_RSS_DIR, entry.fileName);
  if (fs.existsSync(filePath)) {
    try {
      fs.unlinkSync(filePath);
    } catch (e) {
      // ignore
    }
  }
}

function pruneGeneratedRssIndex() {
  const now = Date.now();
  const maxAgeMs = GENERATED_RSS_TTL_DAYS * 24 * 60 * 60 * 1000;
  const validEntries = [];
  for (const entry of generatedRssIndex) {
    if (!entry || !entry.fileName) continue;
    const createdAt = Date.parse(entry.createdAt);
    if (!Number.isNaN(createdAt) && now - createdAt > maxAgeMs) {
      removeGeneratedFile(entry);
      continue;
    }
    const filePath = path.join(GENERATED_RSS_DIR, entry.fileName);
    if (!fs.existsSync(filePath)) {
      continue;
    }
    validEntries.push(entry);
  }
  validEntries.sort((a, b) => {
    const aTime = Date.parse(a.createdAt) || 0;
    const bTime = Date.parse(b.createdAt) || 0;
    return bTime - aTime;
  });
  const kept = validEntries.slice(0, GENERATED_RSS_MAX);
  const removed = validEntries.slice(GENERATED_RSS_MAX);
  removed.forEach(removeGeneratedFile);
  generatedRssIndex = kept;
  saveGeneratedIndex();
}

pruneGeneratedRssIndex();

function normalizeRssSlug(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9\-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60);
}

function buildGeneratedFileName(siteUrl) {
  let host = 'site';
  try {
    host = new URL(siteUrl).hostname.replace(/^www\./, '');
  } catch (e) {
    // ignore
  }
  const slug = normalizeRssSlug(host) || 'site';
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  return `${slug}-${stamp}.xml`;
}

function normalizeAiJson(text) {
  const raw = String(text || '').trim();
  if (!raw) return null;
  const cleaned = raw
    .replace(/^```json/i, '')
    .replace(/^```/i, '')
    .replace(/```$/i, '')
    .trim();
  try {
    return JSON.parse(cleaned);
  } catch (e) {
    return null;
  }
}

async function fetchRobotsTxt(siteUrl) {
  try {
    const url = new URL(siteUrl);
    const robotsUrl = `${url.origin}/robots.txt`;
    const text = await fetchHtml(robotsUrl);
    return text || '';
  } catch (e) {
    return '';
  }
}

function isRobotsAllowed(robotsText, targetUrl) {
  if (!robotsText) return true;
  let path = '/';
  try {
    path = new URL(targetUrl).pathname || '/';
  } catch (e) {
    return true;
  }
  const lines = robotsText.split(/\r?\n/);
  let applies = false;
  let disallows = [];
  for (const raw of lines) {
    const line = raw.split('#')[0].trim();
    if (!line) continue;
    const [key, value] = line.split(':').map(part => part.trim());
    if (!key || value == null) continue;
    if (key.toLowerCase() === 'user-agent') {
      applies = value === '*' ? true : false;
      if (!applies) disallows = [];
    }
    if (applies && key.toLowerCase() === 'disallow') {
      disallows.push(value);
    }
  }
  return !disallows.some(rule => rule && path.startsWith(rule));
}

function normalizeAiCandidate(item, baseUrl) {
  if (!item || !item.link || !item.title) return null;
  let link = String(item.link || '').trim();
  if (!link) return null;
  try {
    link = new URL(link, baseUrl).toString();
  } catch (e) {
    return null;
  }
  const title = String(item.title || '').replace(/\s+/g, ' ').trim();
  if (!title) return null;
  const description = String(item.description || item.summary || '').trim();
  const author = String(item.author || '').trim();
  const image = String(item.image || '').trim();
  const date = String(item.date || item.pubDate || '').trim();
  return { title, link, description, author, image, date };
}

function buildRssItemsXml(items, fallbackDate) {
  const now = fallbackDate || new Date().toUTCString();
  return items.map((item) => {
    const date = item.date || now;
    const imageTag = item.image
      ? `<enclosure url="${item.image}" type="image/jpeg" />`
      : '';
    const authorTag = item.author ? `<author>${cdata(item.author)}</author>` : '';
    const desc = item.description || item.title;
    return [
      '<item>',
      `<title>${cdata(item.title)}</title>`,
      `<link>${item.link}</link>`,
      `<guid isPermaLink="true">${item.link}</guid>`,
      `<pubDate>${date}</pubDate>`,
      `<description>${cdata(desc)}</description>`,
      authorTag,
      imageTag,
      '</item>'
    ].join('');
  }).join('');
}

async function generateSmartRss(targetUrl, options = {}) {
  const html = await fetchHtml(targetUrl);
  const baseUrl = new URL(targetUrl).toString();
  const dom = new JSDOM(html, { url: baseUrl });
  const reader = new Readability(dom.window.document);
  const article = reader.parse();
  const $ = cheerio.load(html);

  const siteTitle =
    $('meta[property="og:site_name"]').attr('content') ||
    $('title').first().text().trim() ||
    new URL(targetUrl).hostname;
  const description =
    $('meta[name="description"]').attr('content') ||
    article?.excerpt ||
    `Noticias recentes de ${siteTitle}`;
  const ogImage = $('meta[property="og:image"]').attr('content') || '';

  const candidates = extractCandidates($, baseUrl);
  const maxItems = options.maxItems
    ? Math.min(40, Math.max(5, Number(options.maxItems)))
    : candidates.length > 60
      ? 30
      : candidates.length > 30
        ? 25
        : 20;

  let items = candidates.slice(0, maxItems).map(item => ({
    title: item.title,
    link: item.link,
    description: item.title,
    image: ogImage || '',
    date: new Date().toUTCString()
  }));

  if (options.useAi && canUseAiProvider(aiConfig)) {
    const prompt = [
      'Voce recebe uma pagina HTML e uma lista de links candidatos.',
      'Extraia uma lista de itens de RSS com title, link, date, author, description, image.',
      'Responda SOMENTE com JSON valido neste formato: { "items": [ { "title": "", "link": "", "date": "", "author": "", "description": "", "image": "" } ] }',
      'Use apenas links da lista de candidatos quando possivel.',
      'Se faltar data, deixe string vazia.',
      `Base URL: ${baseUrl}`,
      `Candidatos: ${JSON.stringify(candidates.slice(0, 30))}`,
      `HTML (primeiros 8000 chars): ${html.slice(0, 8000)}`
    ].join('\n');

    try {
      let aiText = '';
      if (aiConfig.provider === 'openai') {
        aiText = await runPromptWithOpenAi(prompt, aiConfig.openai);
      } else if (aiConfig.provider === 'gemini') {
        aiText = await runPromptWithGemini(prompt, aiConfig.gemini);
      } else if (aiConfig.provider === 'copilot') {
        aiText = await runPromptWithCopilot(prompt, aiConfig.copilot);
      }
      const parsed = normalizeAiJson(aiText);
      const aiItems = Array.isArray(parsed?.items) ? parsed.items : [];
      const normalized = aiItems
        .map(item => normalizeAiCandidate(item, baseUrl))
        .filter(Boolean)
        .slice(0, maxItems);
      if (normalized.length) {
        items = normalized.map(item => ({
          title: item.title,
          link: item.link,
          description: item.description || item.title,
          author: item.author,
          image: item.image || ogImage,
          date: item.date || new Date().toUTCString()
        }));
      }
    } catch (e) {
      // ignore, fallback to deterministic items
    }
  }

  const itemXml = buildRssItemsXml(items, new Date().toUTCString());
  const channelLink = new URL(targetUrl).origin;
  return {
    rss: [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<rss version="2.0">',
      '<channel>',
      `<title>${cdata(siteTitle)}</title>`,
      `<link>${channelLink}</link>`,
      `<description>${cdata(description)}</description>`,
      itemXml,
      '</channel>',
      '</rss>'
    ].join(''),
    itemsCount: items.length,
    title: siteTitle
  };
}
function logEvent(event) {
  const entry = {
    id: uuidv4(),
    level: event.level || 'info',
    source: event.source || 'system',
    message: event.message || '',
    detail: event.detail || '',
    timestamp: new Date().toISOString()
  };
  events = [entry, ...events].slice(0, MAX_EVENTS);
  saveEvents(events);
  return entry;
}

function hasTwitterCredentials(config) {
  const cred = config.credentials || {};
  return !!(cred.apiKey && cred.apiSecret && cred.accessToken && cred.accessSecret);
}

function createTwitterClient(config) {
  return new TwitterApi({
    appKey: config.credentials.apiKey,
    appSecret: config.credentials.apiSecret,
    accessToken: config.credentials.accessToken,
    accessSecret: config.credentials.accessSecret
  });
}

function withinQuietHours(quietHours, now) {
  if (!quietHours || !quietHours.enabled) return false;
  const [startH, startM] = quietHours.start.split(':').map(Number);
  const [endH, endM] = quietHours.end.split(':').map(Number);
  const start = new Date(now);
  start.setHours(startH, startM, 0, 0);
  const end = new Date(now);
  end.setHours(endH, endM, 0, 0);
  if (start <= end) {
    return now >= start && now <= end;
  }
  return now >= start || now <= end;
}

function matchRules(item, rules) {
  const title = (item.title || '').toLowerCase();
  const snippet = (item.contentSnippet || '').toLowerCase();
  const text = `${title} ${snippet}`.trim();
  if (rules.onlyWithLink && !item.link) return false;
  if (rules.requireWords && rules.requireWords.length) {
    const ok = rules.requireWords.every(word => text.includes(word.toLowerCase()));
    if (!ok) return false;
  }
  if (rules.blockWords && rules.blockWords.length) {
    const blocked = rules.blockWords.some(word => text.includes(word.toLowerCase()));
    if (blocked) return false;
  }
  return true;
}

const INFLUENCER_PRESETS = [
  {
    key: 'direita',
    name: 'Direita padrao',
    description: 'Seguranca, economia, valores tradicionais.',
    topics: ['economia', 'seguranca', 'politica', 'valores'],
    diversity: 20
  },
  {
    key: 'esquerda',
    name: 'Esquerda padrao',
    description: 'Direitos sociais, cultura e politicas publicas.',
    topics: ['direitos', 'cultura', 'educacao', 'saude'],
    diversity: 35
  },
  {
    key: 'centro',
    name: 'Centro moderado',
    description: 'Governanca, dados e impacto social.',
    topics: ['governanca', 'economia', 'dados', 'gestao'],
    diversity: 55
  }
];

function normalizeList(value) {
  if (Array.isArray(value)) {
    return value.map(item => String(item || '').trim()).filter(Boolean);
  }
  if (typeof value === 'string') {
    return value.split(',').map(item => item.trim()).filter(Boolean);
  }
  return [];
}

function clampNumber(value, min, max, fallback) {
  const num = Number(value);
  if (Number.isNaN(num)) return fallback;
  return Math.min(Math.max(num, min), max);
}

function sanitizeInfluencerPayload(payload, base = {}) {
  const next = payload || {};
  return {
    id: base.id || next.id,
    name: String(next.name || base.name || '').trim(),
    description: String(next.description || base.description || '').trim(),
    topics: normalizeList(next.topics ?? base.topics ?? []),
    requireWords: normalizeList(next.requireWords ?? base.requireWords ?? []),
    blockWords: normalizeList(next.blockWords ?? base.blockWords ?? []),
    feedIds: normalizeList(next.feedIds ?? base.feedIds ?? []),
    blockedFeedIds: normalizeList(next.blockedFeedIds ?? base.blockedFeedIds ?? []),
    onlyWithLink: typeof next.onlyWithLink === 'boolean' ? next.onlyWithLink : (base.onlyWithLink ?? true),
    diversity: clampNumber(next.diversity ?? base.diversity, 0, 100, 30),
    alignment: clampNumber(next.alignment ?? base.alignment, 0, 100, 70),
    maxItems: clampNumber(next.maxItems ?? base.maxItems, 5, 200, 40),
    lookbackHours: clampNumber(next.lookbackHours ?? base.lookbackHours, 6, 168, 48),
    language: String(next.language ?? base.language ?? '').trim(),
    region: String(next.region ?? base.region ?? '').trim(),
    useAi: typeof next.useAi === 'boolean' ? next.useAi : (base.useAi ?? true),
    axes: {
      economic: clampNumber(next.axes?.economic ?? base.axes?.economic, 0, 100, 50),
      social: clampNumber(next.axes?.social ?? base.axes?.social, 0, 100, 50),
      institutional: clampNumber(next.axes?.institutional ?? base.axes?.institutional, 0, 100, 50)
    }
  };
}

function matchesInfluencerTopics(item, topics) {
  if (!topics || !topics.length) return true;
  const text = `${item.title || ''} ${item.contentSnippet || ''}`.toLowerCase();
  const tags = Array.isArray(item.tags) ? item.tags.map(tag => String(tag).toLowerCase()) : [];
  return topics.some(topic => {
    const key = String(topic).toLowerCase();
    if (!key) return false;
    if (tags.some(tag => tag.includes(key))) return true;
    return text.includes(key);
  });
}

const PORTUGUESE_HINTS = [
  ' de ', ' da ', ' do ', ' que ', ' para ', ' com ', ' nao ', ' nao', ' sao ', ' uma ', ' por ', ' em ', ' dos '
];

function detectLanguage(text) {
  const value = ` ${String(text || '').toLowerCase()} `;
  const ptHits = PORTUGUESE_HINTS.reduce((acc, hint) => (value.includes(hint) ? acc + 1 : acc), 0);
  if (ptHits >= 2) return 'pt';
  return 'en';
}

function matchesInfluencerLanguage(item, language) {
  if (!language) return true;
  const lang = String(language).toLowerCase();
  if (lang !== 'pt' && lang !== 'en') return true;
  const text = `${item.title || ''} ${item.contentSnippet || ''}`;
  return detectLanguage(text) === lang;
}

function matchesInfluencerRegion(item, region) {
  if (!region) return true;
  const code = String(region).toLowerCase();
  if (!item.feedUrl) return false;
  try {
    const host = new URL(item.feedUrl).hostname.toLowerCase();
    return host.endsWith(`.${code}`);
  } catch (err) {
    return false;
  }
}

function scoreInfluencerItem(item, topics) {
  const text = `${item.title || ''} ${item.contentSnippet || ''}`.toLowerCase();
  const topicHits = (topics || []).reduce((acc, topic) => {
    const key = String(topic).toLowerCase();
    if (!key) return acc;
    return acc + (text.includes(key) ? 1 : 0);
  }, 0);
  return 50 + topicHits * 8 + (item.tags ? Math.min(item.tags.length, 4) * 3 : 0);
}

function buildInfluencerScorePrompt(influencer, item) {
  const topics = (influencer.topics || []).join(', ') || 'N/A';
  const requireWords = (influencer.requireWords || []).join(', ') || 'N/A';
  const blockWords = (influencer.blockWords || []).join(', ') || 'N/A';
  const axes = influencer.axes || {};
  return [
    'Voce avalia alinhamento editorial de noticias para um perfil.',
    'Considere temas, palavras-chave e eixo ideologico.',
    'Retorne apenas um numero de 0 a 100.',
    '',
    `Perfil: ${influencer.name || 'N/A'}`,
    `Descricao: ${influencer.description || 'N/A'}`,
    `Temas: ${topics}`,
    `Palavras obrigatorias: ${requireWords}`,
    `Palavras bloqueadas: ${blockWords}`,
    `Eixo economico (0-100): ${axes.economic ?? 50}`,
    `Eixo social (0-100): ${axes.social ?? 50}`,
    `Eixo institucional (0-100): ${axes.institutional ?? 50}`,
    '',
    `Manchete: ${normalizeAiInput(item.title) || 'N/A'}`,
    `Trecho: ${normalizeAiInput(item.contentSnippet) || 'N/A'}`
  ].join('\n');
}

function parseAiScore(text) {
  const match = String(text || '').match(/-?\d+(\.\d+)?/);
  if (!match) return null;
  const value = Number(match[0]);
  if (Number.isNaN(value)) return null;
  return Math.min(Math.max(value, 0), 100);
}

async function scoreInfluencerWithOpenAi(item, influencer, config) {
  if (!config || !config.apiKey) {
    throw new Error('Chave da OpenAI ausente.');
  }
  const prompt = buildInfluencerScorePrompt(influencer, item);
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.apiKey}`
    },
    body: JSON.stringify({
      model: config.model || 'gpt-4o-mini',
      temperature: 0.2,
      max_tokens: 30,
      messages: [
        { role: 'system', content: 'Voce avalia alinhamento editorial.' },
        { role: 'user', content: prompt }
      ]
    })
  });
  const data = await res.json();
  if (!res.ok) {
    const message = data?.error?.message || 'Falha ao avaliar alinhamento.';
    throw new Error(message);
  }
  return parseAiScore(data?.choices?.[0]?.message?.content || '');
}

async function scoreInfluencerWithGemini(item, influencer, config) {
  if (!config || !config.apiKey) {
    throw new Error('Chave do Gemini ausente.');
  }
  const model = config.model || 'gemini-1.5-flash';
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${config.apiKey}`;
  const prompt = buildInfluencerScorePrompt(influencer, item);
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ role: 'user', parts: [{ text: prompt }] }]
    })
  });
  const data = await res.json();
  if (!res.ok) {
    const message = data?.error?.message || 'Falha ao avaliar alinhamento.';
    throw new Error(message);
  }
  return parseAiScore(data?.candidates?.[0]?.content?.parts?.[0]?.text || '');
}

async function scoreInfluencerWithCopilot(item, influencer, config) {
  if (!config || !config.apiKey || !config.baseUrl) {
    throw new Error('Copilot sem chave ou endpoint.');
  }
  const baseUrl = config.baseUrl.replace(/\/+$/, '');
  const prompt = buildInfluencerScorePrompt(influencer, item);
  const res = await fetch(`${baseUrl}/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.apiKey}`
    },
    body: JSON.stringify({
      model: config.model || 'gpt-4o-mini',
      temperature: 0.2,
      max_tokens: 30,
      messages: [
        { role: 'system', content: 'Voce avalia alinhamento editorial.' },
        { role: 'user', content: prompt }
      ]
    })
  });
  const data = await res.json();
  if (!res.ok) {
    const message = data?.error?.message || 'Falha ao avaliar alinhamento.';
    throw new Error(message);
  }
  return parseAiScore(data?.choices?.[0]?.message?.content || '');
}

async function scoreInfluencerWithAi(item, influencer) {
  if (!canUseAiProvider(aiConfig)) return null;
  if (aiConfig.provider === 'openai') {
    return scoreInfluencerWithOpenAi(item, influencer, aiConfig.openai);
  }
  if (aiConfig.provider === 'gemini') {
    return scoreInfluencerWithGemini(item, influencer, aiConfig.gemini);
  }
  if (aiConfig.provider === 'copilot') {
    return scoreInfluencerWithCopilot(item, influencer, aiConfig.copilot);
  }
  return null;
}

function hasTelegramCredentials(config) {
  return !!(config && config.botToken && config.chatId);
}

function hasWhatsAppCredentials(config) {
  return !!(config && config.accessToken && config.phoneNumberId && config.recipientNumber && config.templateName);
}

function renderWhatsAppParams(item) {
  const safeTitle = (item.title || '').replace(/\s+/g, ' ').trim();
  const safeLink = item.link || '';
  const safeSource = item.feedName || '';
  return [safeTitle, safeLink, safeSource];
}

async function sendWhatsAppTemplate(config, params) {
  const url = `https://graph.facebook.com/v18.0/${config.phoneNumberId}/messages`;
  const payload = {
    messaging_product: 'whatsapp',
    to: config.recipientNumber,
    type: 'template',
    template: {
      name: config.templateName,
      language: { code: config.templateLanguage || 'pt_BR' },
      components: [
        {
          type: 'body',
          parameters: params.map(value => ({ type: 'text', text: String(value || '').slice(0, 1024) }))
        }
      ]
    }
  };
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.accessToken}`
    },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`WhatsApp erro ${res.status}: ${detail}`);
  }
  return res.json();
}

function getWhatsAppCandidate(items) {
  if (!whatsappConfig.enabled) return null;
  if (!hasWhatsAppCredentials(whatsappConfig)) return null;
  const rules = whatsappConfig.rules || {};
  if (!whatsappState.dailyDate || whatsappState.dailyDate !== getDailyKey(new Date())) {
    whatsappState.dailyDate = getDailyKey(new Date());
    whatsappState.dailyCount = 0;
  }
  if (whatsappState.dailyCount >= (rules.maxPerDay || 10)) return null;
  if (whatsappState.lastSentAt) {
    const elapsed = (Date.now() - new Date(whatsappState.lastSentAt).getTime()) / 60000;
    if (elapsed < (rules.minIntervalMinutes || 60)) return null;
  }
  let filtered = items;
  if (rules.feedIds && rules.feedIds.length) {
    const allowedUrls = feeds.filter(f => rules.feedIds.includes(f.id)).map(f => f.url);
    const allowed = new Set(allowedUrls);
    filtered = filtered.filter(item => allowed.has(item.feedUrl));
  }
  filtered = filtered.filter(item => matchRules(item, rules));
  const postedSet = new Set(whatsappState.postedIds || []);
  const candidate = filtered.find(item => {
    const id = item.link || item.guid || item.title;
    return id && !postedSet.has(id);
  });
  return candidate || null;
}

async function runWhatsAppAutomation() {
  try {
    const items = await buildAggregatedItems();
    const candidate = getWhatsAppCandidate(items);
    if (!candidate) return;
    const params = renderWhatsAppParams(candidate);
    await sendWhatsAppTemplate(whatsappConfig, params);
    const postedId = candidate.link || candidate.guid || candidate.title;
    whatsappState.lastSentAt = new Date().toISOString();
    whatsappState.dailyCount = (whatsappState.dailyCount || 0) + 1;
    whatsappState.postedIds = [postedId, ...(whatsappState.postedIds || [])].slice(0, 500);
    saveWhatsAppState(whatsappState);
    logEvent({
      level: 'info',
      source: 'whatsapp',
      message: 'Noticia enviada no WhatsApp.',
      detail: candidate.title || ''
    });
  } catch (err) {
    logEvent({
      level: 'error',
      source: 'whatsapp',
      message: 'Falha ao enviar no WhatsApp.',
      detail: err.message || String(err)
    });
  }
}

function renderTelegramTemplate(template, item) {
  const safeTitle = (item.title || '').replace(/\s+/g, ' ').trim();
  const safeLink = item.link || '';
  const safeSource = item.feedName || '';
  return template
    .replace('{title}', safeTitle)
    .replace('{link}', safeLink)
    .replace('{source}', safeSource)
    .trim();
}

async function sendTelegramMessage(config, text) {
  const url = `https://api.telegram.org/bot${config.botToken}/sendMessage`;
  const payload = {
    chat_id: config.chatId,
    text,
    disable_web_page_preview: false
  };
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`Telegram erro ${res.status}: ${detail}`);
  }
  return res.json();
}

function getTelegramCandidate(items) {
  if (!telegramConfig.enabled) return null;
  if (!hasTelegramCredentials(telegramConfig)) return null;
  const rules = telegramConfig.rules || {};
  if (!telegramState.dailyDate || telegramState.dailyDate !== getDailyKey(new Date())) {
    telegramState.dailyDate = getDailyKey(new Date());
    telegramState.dailyCount = 0;
  }
  if (telegramState.dailyCount >= (rules.maxPerDay || 20)) return null;
  if (telegramState.lastSentAt) {
    const elapsed = (Date.now() - new Date(telegramState.lastSentAt).getTime()) / 60000;
    if (elapsed < (rules.minIntervalMinutes || 10)) return null;
  }
  let filtered = items;
  if (rules.feedIds && rules.feedIds.length) {
    const allowedUrls = feeds.filter(f => rules.feedIds.includes(f.id)).map(f => f.url);
    const allowed = new Set(allowedUrls);
    filtered = filtered.filter(item => allowed.has(item.feedUrl));
  }
  filtered = filtered.filter(item => matchRules(item, rules));
  const postedSet = new Set(telegramState.postedIds || []);
  const candidate = filtered.find(item => {
    const id = item.link || item.guid || item.title;
    return id && !postedSet.has(id);
  });
  return candidate || null;
}

async function runTelegramAutomation() {
  try {
    const items = await buildAggregatedItems();
    const candidate = getTelegramCandidate(items);
    if (!candidate) return;
    const message = renderTelegramTemplate(telegramConfig.template || '{title}\n{link}', candidate);
    if (!message) return;
    await sendTelegramMessage(telegramConfig, message);
    const postedId = candidate.link || candidate.guid || candidate.title;
    telegramState.lastSentAt = new Date().toISOString();
    telegramState.dailyCount = (telegramState.dailyCount || 0) + 1;
    telegramState.postedIds = [postedId, ...(telegramState.postedIds || [])].slice(0, 500);
    saveTelegramState(telegramState);
    logEvent({
      level: 'info',
      source: 'telegram',
      message: 'Noticia enviada no Telegram.',
      detail: candidate.title || ''
    });
  } catch (err) {
    logEvent({
      level: 'error',
      source: 'telegram',
      message: 'Falha ao enviar no Telegram.',
      detail: err.message || String(err)
    });
  }
}

function renderTemplate(template, item) {
  const safeTitle = (item.title || '').replace(/\s+/g, ' ').trim();
  const safeLink = item.link || '';
  let text = template.replace('{title}', safeTitle).replace('{link}', safeLink).trim();
  if (text.length <= 280) return text;
  const reserved = safeLink ? (safeLink.length + 1) : 0;
  const maxTitle = Math.max(0, 280 - reserved - 1);
  const trimmedTitle = safeTitle.length > maxTitle ? `${safeTitle.slice(0, Math.max(0, maxTitle - 1))}â€¦` : safeTitle;
  text = template.replace('{title}', trimmedTitle).replace('{link}', safeLink).trim();
  return text.length > 280 ? text.slice(0, 277) + 'â€¦' : text;
}

function getDailyKey(date) {
  return date.toISOString().slice(0, 10);
}


const TRANSLATION_CACHE_MAX = 2000;
const translationCache = new Map();
const polymarketTranslationCache = new Map();
const polymarketQueryCache = new Map();

function shouldTranslateFeed(feed) {
  return !!feed && feed.language === 'auto';
}

function getTranslationCacheKey(feed, item) {
  const key = item.link || item.guid || item.id || item.title || '';
  if (!key) return '';
  return `${feed.id}:${key}`;
}

function setTranslationCache(key, value) {
  translationCache.set(key, value);
  if (translationCache.size > TRANSLATION_CACHE_MAX) {
    const firstKey = translationCache.keys().next().value;
    if (firstKey) translationCache.delete(firstKey);
  }
}

async function translateWithAi(title, snippet) {
  const prompt = [
    'Detecte o idioma do texto abaixo.',
    'Se nao for portugues, traduza para pt-BR.',
    'Responda apenas em JSON valido com as chaves:',
    'detectedLanguage, isPortuguese, title, snippet.',
    'Se ja estiver em portugues, mantenha o texto original.',
    `Titulo: "${title}"`,
    `Resumo: "${snippet}"`
  ].join('\n');

  let aiText = '';
  if (aiConfig.provider === 'openai') {
    aiText = await runPromptWithOpenAi(prompt, aiConfig.openai);
  } else if (aiConfig.provider === 'gemini') {
    aiText = await runPromptWithGemini(prompt, aiConfig.gemini);
  } else if (aiConfig.provider === 'copilot') {
    aiText = await runPromptWithCopilot(prompt, aiConfig.copilot);
  }
  const parsed = normalizeAiJson(aiText);
  if (!parsed) return null;
  return {
    detectedLanguage: String(parsed.detectedLanguage || '').trim(),
    isPortuguese: parsed.isPortuguese === true,
    title: parsed.title,
    snippet: parsed.snippet
  };
}

async function translateItemIfNeeded(item, feed) {
  if (!shouldTranslateFeed(feed)) return item;
  if (!aiConfig.enabled || !canUseAiProvider(aiConfig)) return item;
  if (item.originalTitle || item.originalSnippet) return item;

  const title = stripHtml(item.title || '');
  const snippet = stripHtml(item.contentSnippet || '');
  const baseText = `${title} ${snippet}`.trim();
  if (!baseText) return item;

  const cacheKey = getTranslationCacheKey(feed, item);
  if (cacheKey && translationCache.has(cacheKey)) {
    return { ...item, ...translationCache.get(cacheKey) };
  }

  try {
    const translated = await translateWithAi(title, snippet);
    if (!translated) return item;

    const detectedLanguage = String(translated.detectedLanguage || '').toLowerCase();
    const isPortuguese = translated.isPortuguese === true || detectedLanguage.startsWith('pt');
    const translatedTitle = translated.title ? String(translated.title) : title;
    const translatedSnippet = translated.snippet ? String(translated.snippet) : snippet;

    if (isPortuguese) {
      const output = { title, contentSnippet: snippet, detectedLanguage };
      if (cacheKey) setTranslationCache(cacheKey, output);
      return { ...item, ...output };
    }

    const output = {
      originalTitle: title,
      originalSnippet: snippet,
      title: translatedTitle,
      contentSnippet: translatedSnippet,
      detectedLanguage,
      translated: true
    };
    if (cacheKey) setTranslationCache(cacheKey, output);
    return { ...item, ...output };
  } catch (err) {
    logEvent({
      level: 'error',
      source: 'ai',
      message: 'Falha ao traduzir feed.',
      detail: `${feed.name || 'Feed'} | ${err.message || err}`
    });
    return item;
  }
}

async function buildAggregatedItems() {
  const parser = new Parser();
  let aggregated = [];
  for (const feed of feeds.filter(f => f.showOnTimeline)) {
    try {
      const parsed = await parseFeedWithEncoding(feed.url, parser);
      let feedItems = parsed.items.map(item => ({
        ...item,
        title: stripHtml(item.title),
        contentSnippet: stripHtml(item.contentSnippet),
        feedName: stripHtml(feed.name),
        feedUrl: feed.url,
        tags: []
      }));
      if (shouldTranslateFeed(feed)) {
        const tasks = feedItems.map(item => async () => translateItemIfNeeded(item, feed));
        feedItems = await runWithLimit(tasks, 3);
      }
      aggregated = aggregated.concat(feedItems);
    } catch (e) {
      // ignore
    }
  }
  try {
    const telegramItems = await fetchTelegramFeedItems(telegramFeedsConfig, telegramFeedsState);
    if (telegramItems.length) {
      aggregated = aggregated.concat(telegramItems.map(item => ({ ...item, tags: [] })));
    }
  } catch (e) {
    // ignore
  }
  aggregated.sort((a, b) => {
    const dateA = new Date(a.pubDate || a.isoDate || 0);
    const dateB = new Date(b.pubDate || b.isoDate || 0);
    return dateB - dateA;
  });
  const computed = aggregated.map(item => ({
    ...item,
    tags: computeTags(item)
  }));
  updateAggregatedCache(computed);
  return computed;
}

async function buildInfluencerQueue(influencer, useAi) {
  const aggregated = await buildAggregatedItems();
  const now = Date.now();
  const cutoff = now - (influencer.lookbackHours || 48) * 60 * 60 * 1000;
  let items = aggregated.filter(item => {
    const date = new Date(item.pubDate || item.isoDate || 0);
    return date.getTime() >= cutoff;
  });

  if (influencer.feedIds && influencer.feedIds.length) {
    const allowedUrls = new Set(
      feeds.filter(feed => influencer.feedIds.includes(feed.id)).map(feed => feed.url)
    );
    items = items.filter(item => allowedUrls.has(item.feedUrl));
  }

  if (influencer.blockedFeedIds && influencer.blockedFeedIds.length) {
    const blockedUrls = new Set(
      feeds.filter(feed => influencer.blockedFeedIds.includes(feed.id)).map(feed => feed.url)
    );
    items = items.filter(item => !blockedUrls.has(item.feedUrl));
  }

  items = items.filter(item => matchRules(item, {
    requireWords: influencer.requireWords || [],
    blockWords: influencer.blockWords || [],
    onlyWithLink: influencer.onlyWithLink !== false
  }));

  items = items.filter(item => matchesInfluencerTopics(item, influencer.topics || []));
  items = items.filter(item => matchesInfluencerLanguage(item, influencer.language));
  items = items.filter(item => matchesInfluencerRegion(item, influencer.region));

  const seen = new Set();
  let ranked = items.map(item => ({
    ...item,
    score: scoreInfluencerItem(item, influencer.topics || [])
  }))
    .sort((a, b) => b.score - a.score || new Date(b.pubDate || b.isoDate || 0) - new Date(a.pubDate || a.isoDate || 0))
    .filter(item => {
      const key = normalizeTitle(item.title) || item.link || item.guid || item.title;
      if (!key || seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .slice(0, influencer.maxItems || 40);

  if (useAi && canUseAiProvider(aiConfig)) {
    const limit = Math.min(15, ranked.length);
    for (let i = 0; i < limit; i += 1) {
      try {
        const aiScore = await scoreInfluencerWithAi(ranked[i], influencer);
        if (aiScore !== null && aiScore !== undefined) {
          ranked[i] = {
            ...ranked[i],
            aiScore,
            score: Math.round((ranked[i].score * 0.4) + (aiScore * 0.6))
          };
        }
      } catch (err) {
        // ignore
      }
    }
    ranked = ranked
      .slice()
      .sort((a, b) => b.score - a.score || new Date(b.pubDate || b.isoDate || 0) - new Date(a.pubDate || a.isoDate || 0));
  }

  return ranked.map(item => ({
    id: uuidv4(),
    title: item.title || '',
    contentSnippet: item.contentSnippet || '',
    link: item.link || '',
    feedName: item.feedName || '',
    feedUrl: item.feedUrl || '',
    pubDate: item.pubDate || item.isoDate || null,
    score: item.score || 0,
    aiScore: item.aiScore ?? null,
    status: 'recommended',
    createdAt: new Date().toISOString()
  }));
}

function buildSummaryItems(aggregated, maxItems, lookbackHours) {
  const cutoff = Date.now() - (lookbackHours * 60 * 60 * 1000);
  const seen = new Set();
  const result = [];
  for (const item of aggregated) {
    const date = new Date(item.pubDate || item.isoDate || 0);
    if (date.getTime() < cutoff) continue;
    const key = normalizeTitle(item.title) || item.link || item.guid || item.title;
    if (!key || seen.has(key)) continue;
    seen.add(key);
    result.push({
      title: item.title,
      link: item.link,
      feedName: item.feedName,
      pubDate: item.pubDate,
      isoDate: item.isoDate
    });
    if (result.length >= maxItems) break;
  }
  return result;
}


function normalizeEmails(list) {
  return (Array.isArray(list) ? list : [])
    .map(item => String(item || '').trim())
    .filter(Boolean);
}

function buildTransporter(config) {
  const smtp = config.smtp || {};
  return nodemailer.createTransport({
    host: smtp.host,
    port: Number(smtp.port || 587),
    secure: !!smtp.secure,
    auth: smtp.user ? { user: smtp.user, pass: smtp.pass } : undefined
  });
}

async function sendEmail(config, payload) {
  if (!config.enabled) return false;
  const recipients = normalizeEmails(payload.to);
  if (!recipients.length) return false;
  const transporter = buildTransporter(config);
  const from = config.from || config.smtp?.user || 'no-reply@rss.local';
  await transporter.sendMail({
    from,
    to: recipients.join(','),
    subject: payload.subject,
    text: payload.text
  });
  return true;
}

function buildSummaryEmail(summary) {
  const lines = [];
  lines.push(`Resumo diario - ${summary.date}`);
  lines.push('');
  summary.items.forEach((item, idx) => {
    lines.push(`${idx + 1}. ${item.title || ''}`);
    if (item.feedName) lines.push(`   Fonte: ${item.feedName}`);
    if (item.link) lines.push(`   Link: ${item.link}`);
    lines.push('');
  });
  return lines.join('\n');
}

function buildAlertEmail(items) {
  const lines = [];
  lines.push('Alerta critico detectado');
  lines.push('');
  items.forEach((item, idx) => {
    lines.push(`${idx + 1}. ${item.title || ''}`);
    if (item.feedName) lines.push(`   Fonte: ${item.feedName}`);
    if (item.link) lines.push(`   Link: ${item.link}`);
    lines.push('');
  });
  return lines.join('\n');
}

function matchCritical(item, keywords) {
  if (!keywords || !keywords.length) return true;
  const title = (item.title || '').toLowerCase();
  const snippet = (item.contentSnippet || '').toLowerCase();
  const text = `${title} ${snippet}`.trim();
  return keywords.some(word => text.includes(String(word).toLowerCase()));
}

function shouldRunSummary(now, config, state) {
  if (!config.enabled) return false;
  const [hour, minute] = (config.time || '08:00').split(':').map(Number);
  const scheduled = new Date(now);
  scheduled.setHours(hour, minute, 0, 0);
  const todayKey = getDailyKey(now);
  if (state.lastSummaryDate === todayKey) return false;
  return now >= scheduled;
}

async function runDailySummary() {
  const now = new Date();
  if (!shouldRunSummary(now, summaryConfig, dailySummaryState)) return;
  const aggregated = await buildAggregatedItems();
  const items = buildSummaryItems(
    aggregated,
    summaryConfig.maxItems || 10,
    summaryConfig.lookbackHours || 24
  );
  const summary = {
    date: getDailyKey(now),
    generatedAt: now.toISOString(),
    items
  };
  dailySummaryState.lastSummaryDate = summary.date;
  dailySummaryState.latest = summary;
  fs.writeFileSync(dailySummaryStatePath, JSON.stringify(dailySummaryState, null, 2), 'utf-8');
  logEvent({
    level: 'info',
    source: 'summary',
    message: 'Resumo diÃ¡rio gerado.',
    detail: `Itens: ${items.length}`
  });
}


function matchAlert(item, rules) {
  if (!rules.keywords || !rules.keywords.length) return false;
  const title = (item.title || '').toLowerCase();
  const snippet = (item.contentSnippet || '').toLowerCase();
  const text = rules.matchTitleOnly ? title : `${title} ${snippet}`.trim();
  if (rules.matchAll) {
    return rules.keywords.every(word => text.includes(word.toLowerCase()));
  }
  return rules.keywords.some(word => text.includes(word.toLowerCase()));
}

async function runAlerts() {
  if (!alertConfig.enabled) return;
  const aggregated = await buildAggregatedItems();

  let items = aggregated;
  if (alertConfig.feedIds && alertConfig.feedIds.length) {
    const allowedUrls = new Set(
      feeds.filter(f => alertConfig.feedIds.includes(f.id)).map(f => f.url)
    );
    items = items.filter(item => allowedUrls.has(item.feedUrl));
  }

  const alertedSet = new Set(alertState.alertedIds || []);
  const matches = items.filter(item => {
    const id = item.link || item.guid || item.title;
    if (!id || alertedSet.has(id)) return false;
    return matchAlert(item, alertConfig);
  });

  if (!matches.length) return;

  const toLog = matches.slice(0, 5);
  toLog.forEach(item => {
    logEvent({
      level: 'info',
      source: 'alert',
      message: 'Alerta por palavra-chave.',
      detail: `${item.feedName} | ${item.title}`
    });
  });

  if (emailConfig.alerts?.enabled) {
    const recipients = normalizeEmails(emailConfig.alerts.recipients || []);
    const criticalKeywords = normalizeEmails(emailConfig.alerts.criticalKeywords || []);
    const alertItems = matches.filter(item => matchCritical(item, criticalKeywords));
    if (recipients.length && alertItems.length) {
      try {
        await sendEmail(emailConfig, {
          to: recipients,
          subject: 'Alerta critico - RSS',
          text: buildAlertEmail(alertItems.slice(0, 10))
        });
      } catch (err) {
        logEvent({
          level: 'error',
          source: 'email',
          message: 'Falha ao enviar alertas por email.',
          detail: err.message || ''
        });
      }
    }
  }

  const newIds = matches.map(item => item.link || item.guid || item.title).filter(Boolean);
  alertState.alertedIds = [...newIds, ...(alertState.alertedIds || [])].slice(0, MAX_ALERT_IDS);
  saveAlertState(alertState);
}

function getAutomationEligibility() {
  if (!automationConfig.rules.enabled) {
    return { ok: false, reason: 'AutomaÃ§Ã£o desativada.' };
  }
  if (!hasTwitterCredentials(automationConfig)) {
    return { ok: false, reason: 'Credenciais incompletas.' };
  }
  const now = new Date();
  if (withinQuietHours(automationConfig.rules.quietHours, now)) {
    return { ok: false, reason: 'Dentro do horÃ¡rio silencioso.' };
  }

  if (!automationState.dailyDate || automationState.dailyDate !== getDailyKey(now)) {
    automationState.dailyDate = getDailyKey(now);
    automationState.dailyCount = 0;
  }

  if (automationState.dailyCount >= automationConfig.rules.maxPerDay) {
    return { ok: false, reason: 'Limite diÃ¡rio atingido.' };
  }

  if (automationState.lastPostedAt) {
    const elapsed = (now.getTime() - new Date(automationState.lastPostedAt).getTime()) / 60000;
    if (elapsed < automationConfig.rules.minIntervalMinutes) {
      return { ok: false, reason: 'Aguardando intervalo mÃ­nimo.' };
    }
  }

  return { ok: true, reason: '' };
}

async function getAutomationCandidate() {
  const eligibility = getAutomationEligibility();
  if (!eligibility.ok) return { candidate: null, reason: eligibility.reason };

  const aggregated = await buildAggregatedItems();

  let items = aggregated;
  if (automationConfig.rules.feedIds && automationConfig.rules.feedIds.length) {
    const allowedUrls = new Set(
      feeds.filter(f => automationConfig.rules.feedIds.includes(f.id)).map(f => f.url)
    );
    items = items.filter(item => allowedUrls.has(item.feedUrl));
  }

  items = items.filter(item => matchRules(item, automationConfig.rules));
  const postedSet = new Set(automationState.postedIds || []);
  const candidate = items.find(item => {
    const id = item.link || item.guid || item.title;
    return id && !postedSet.has(id);
  });

  if (!candidate) {
    return { candidate: null, reason: 'Nenhum item novo eleg?vel.' };
  }

  return { candidate, reason: '' };
}

async function tryPostAutomation() {
  const { candidate } = await getAutomationCandidate();
  if (!candidate) return;

  const now = new Date();
  const client = createTwitterClient(automationConfig);

  const tweetText = renderTemplate(automationConfig.rules.template, candidate);
  await client.v2.tweet(tweetText);

  const postedId = candidate.link || candidate.guid || candidate.title;
  automationState.lastPostedAt = now.toISOString();
  automationState.dailyCount += 1;
  automationState.postedIds = [postedId, ...(automationState.postedIds || [])].slice(0, 500);
  saveState(automationState);
  logEvent({
    level: 'info',
    source: 'automation',
    message: 'Post publicado no X/Twitter.',
    detail: `${candidate.feedName} | ${candidate.title}`
  });
}

function fetchHtml(targetUrl, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    if (redirectCount > 5) {
      return reject(new Error('Muitos redirecionamentos.'));
    }
    let urlObj;
    try {
      urlObj = new URL(targetUrl);
    } catch (err) {
      return reject(new Error('URL invÃ¡lida.'));
    }
    const lib = urlObj.protocol === 'https:' ? https : http;
    const req = lib.get(
      urlObj,
      {
        headers: {
          'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
          'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
          'Accept': 'text/html,application/xhtml+xml'
        },
        timeout: 10000
      },
      (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          const nextUrl = new URL(res.headers.location, urlObj).toString();
          res.resume();
          return resolve(fetchHtml(nextUrl, redirectCount + 1));
        }
        if (res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          return reject(new Error('Falha ao carregar pÃ¡gina.'));
        }
        let data = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => resolve(data));
      }
    );
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy(new Error('Timeout ao carregar pÃ¡gina.'));
    });
  });
}

function fetchBuffer(targetUrl, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    if (redirectCount > 5) {
      return reject(new Error('Muitos redirecionamentos.'));
    }
    let urlObj;
    try {
      urlObj = new URL(targetUrl);
    } catch (err) {
      return reject(new Error('URL invÃ¡lida.'));
    }
    const lib = urlObj.protocol === 'https:' ? https : http;
    const req = lib.get(
      urlObj,
      {
        headers: {
          'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
          'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
          'Accept': 'application/rss+xml,application/xml,text/xml;q=0.9,*/*;q=0.8'
        },
        timeout: 10000
      },
      (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          const nextUrl = new URL(res.headers.location, urlObj).toString();
          res.resume();
          return resolve(fetchBuffer(nextUrl, redirectCount + 1));
        }
        if (res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          return reject(new Error('Falha ao carregar feed.'));
        }
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const buffer = Buffer.concat(chunks);
          const contentType = res.headers['content-type'] || '';
          resolve({ buffer, contentType });
        });
      }
    );
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy(new Error('Timeout ao carregar feed.'));
    });
  });
}

function detectCharset(contentType, buffer) {
  const match = /charset=([^;]+)/i.exec(contentType || '');
  if (match) {
    return match[1].trim().toLowerCase();
  }
  const head = buffer.slice(0, 2000).toString('ascii');
  const xmlMatch = /encoding=["']([^"']+)["']/i.exec(head);
  if (xmlMatch) {
    return xmlMatch[1].trim().toLowerCase();
  }
  return 'utf-8';
}

async function parseFeedWithEncoding(url, parser) {
  const { buffer, contentType } = await fetchBuffer(url);
  const charset = detectCharset(contentType, buffer);
  const decoded = iconv.decode(buffer, charset);
  return parser.parseString(decoded);
}

async function checkFeedStatus(url) {
  const parser = new Parser();
  try {
    const feed = await parseFeedWithEncoding(url, parser);
    const count = Array.isArray(feed.items) ? feed.items.length : 0;
    if (count > 0) {
      return { status: 'green', message: 'OK', count };
    }
    return { status: 'yellow', message: 'Sem itens recentes.', count };
  } catch (err) {
    return { status: 'red', message: err.message || 'Falha ao carregar.', count: 0 };
  }
}

async function runWithLimit(tasks, limit) {
  const results = [];
  let index = 0;
  const workers = new Array(Math.min(limit, tasks.length)).fill(null).map(async () => {
    while (index < tasks.length) {
      const current = index;
      index += 1;
      results[current] = await tasks[current]();
    }
  });
  await Promise.all(workers);
  return results;
}

function fetchJson(targetUrl) {
  return new Promise((resolve, reject) => {
    let urlObj;
    try {
      urlObj = new URL(targetUrl);
    } catch (err) {
      return reject(new Error('URL invalida.'));
    }
    const lib = urlObj.protocol === 'https:' ? https : http;
    const req = lib.get(
      urlObj,
      {
        headers: {
          'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
          'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
          'Accept': 'application/json'
        },
        timeout: 10000
      },
      (res) => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          return reject(new Error('Falha ao carregar JSON.'));
        }
        let data = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (err) {
            reject(err);
          }
        });
      }
    );
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy(new Error('Timeout ao carregar JSON.'));
    });
  });
}

function weatherCodeToText(code) {
  const map = {
    0: 'CÃ©u limpo',
    1: 'PredomÃ­nio de sol',
    2: 'Parcialmente nublado',
    3: 'Nublado',
    45: 'Neblina',
    48: 'Nevoeiro',
    51: 'Chuvisco leve',
    53: 'Chuvisco moderado',
    55: 'Chuvisco intenso',
    61: 'Chuva fraca',
    63: 'Chuva moderada',
    65: 'Chuva forte',
    71: 'Neve fraca',
    73: 'Neve moderada',
    75: 'Neve forte',
    80: 'Pancadas leves',
    81: 'Pancadas moderadas',
    82: 'Pancadas fortes',
    95: 'Tempestade',
    96: 'Tempestade com granizo',
    99: 'Tempestade intensa'
  };
  return map[code] || 'Tempo instÃ¡vel';
}

async function getWeatherForCity(city) {
  const geoUrl = `https://geocoding-api.open-meteo.com/v1/search?name=${encodeURIComponent(city)}&count=1&language=pt&format=json`;
  const geo = await fetchJson(geoUrl);
  if (!geo || !geo.results || !geo.results.length) {
    throw new Error('Cidade nÃ£o encontrada.');
  }
  const location = geo.results[0];
  const weatherUrl = `https://api.open-meteo.com/v1/forecast?latitude=${location.latitude}&longitude=${location.longitude}&current_weather=true&daily=temperature_2m_max,temperature_2m_min&timezone=America/Sao_Paulo`;
  const weather = await fetchJson(weatherUrl);
  const current = weather.current_weather || {};
  const daily = weather.daily || {};
  const tempMax = Array.isArray(daily.temperature_2m_max) ? daily.temperature_2m_max[0] : null;
  const tempMin = Array.isArray(daily.temperature_2m_min) ? daily.temperature_2m_min[0] : null;
  return {
    city: location.name,
    region: location.admin1 || '',
    temp: current.temperature,
    wind: current.windspeed,
    code: current.weathercode,
    description: weatherCodeToText(current.weathercode),
    tempMax,
    tempMin,
    updatedAt: current.time
  };
}
function cdata(text) {
  const safe = String(text || '').replace(/]]>/g, ']]]]><![CDATA[>');
  return `<![CDATA[${safe}]]>`;
}

function decodeEntities(text) {
  if (!text) return '';
  const map = {
    '&amp;': '&',
    '&lt;': '<',
    '&gt;': '>',
    '&quot;': '"',
    '&#39;': "'",
    '&nbsp;': ' '
  };
  return text
    .replace(/&(amp|lt|gt|quot|#39|nbsp);/g, (m) => map[m] || m)
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&#([0-9]+);/g, (_, num) => String.fromCharCode(parseInt(num, 10)));
}

function stripHtml(text) {
  if (!text) return '';
  const withoutTags = String(text).replace(/<[^>]*>/g, ' ');
  return decodeEntities(withoutTags).replace(/\s+/g, ' ').trim();
}

function normalizeTitle(text) {
  return stripHtml(text)
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s]/gu, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function getWatchItemKey(item) {
  return item.link || item.guid || item.id || `${item.title || ''}-${item.pubDate || item.isoDate || ''}`;
}

function buildWatchAlertKey(topicId, item) {
  return `${topicId}:${getWatchItemKey(item)}`;
}

function normalizeWatchKeywords(list) {
  if (!Array.isArray(list)) return [];
  return list.map(word => String(word || '').trim()).filter(Boolean);
}

function normalizeWatchSettings(payload) {
  const next = payload || {};
  return {
    recencyWeight: clampNumber(next.recencyWeight, 0, 100, 70),
    viewMode: ['list', 'grid', 'compact'].includes(next.viewMode) ? next.viewMode : 'list',
    timeRange: ['24h', '7d', 'all'].includes(next.timeRange) ? next.timeRange : '24h',
    sortMode: ['recent', 'relevant'].includes(next.sortMode) ? next.sortMode : 'recent',
    topicFilter: typeof next.topicFilter === 'string' ? next.topicFilter : 'all',
    newOnly: !!next.newOnly
  };
}

function getWatchSettingsForUser(userId) {
  if (userId && watchSettings.users && watchSettings.users[userId]) {
    return { ...watchSettings.default, ...watchSettings.users[userId] };
  }
  return watchSettings.default || watchSettings;
}

function setWatchSettingsForUser(userId, payload) {
  if (userId) {
    watchSettings.users = watchSettings.users || {};
    watchSettings.users[userId] = { ...watchSettings.users[userId], ...payload };
  } else {
    watchSettings.default = { ...watchSettings.default, ...payload };
  }
  saveWatchSettings(watchSettings);
}

function matchesWatchTopic(item, topic) {
  if (!topic || topic.enabled === false) return false;
  const keywords = normalizeWatchKeywords(topic.keywords);
  if (!keywords.length) return false;
  const text = `${stripHtml(item.title || '')} ${stripHtml(item.contentSnippet || '')} ${stripHtml(item.feedName || '')}`.toLowerCase();
  if (topic.matchMode === 'all') {
    return keywords.every(word => text.includes(word.toLowerCase()));
  }
  return keywords.some(word => text.includes(word.toLowerCase()));
}

function initWatchAlertKeys() {
  watchAlertKeys.clear();
  let changed = false;
  watchAlerts = (watchAlerts || []).map(alert => {
    if (!alert) return alert;
    if (!alert.key && alert.item && alert.topicId) {
      alert.key = buildWatchAlertKey(alert.topicId, alert.item);
      changed = true;
    }
    if (alert.key) {
      watchAlertKeys.add(alert.key);
    }
    return alert;
  }).filter(Boolean);
  if (changed) {
    saveWatchAlerts(watchAlerts);
  }
}

function updateWatchAlerts(items) {
  if (!Array.isArray(items) || !watchTopics.length) return 0;
  const nextAlerts = [];
  for (const item of items) {
    for (const topic of watchTopics) {
      if (!matchesWatchTopic(item, topic)) continue;
      const key = buildWatchAlertKey(topic.id, item);
      if (watchAlertKeys.has(key)) continue;
      const alert = {
        id: uuidv4(),
        key,
        topicId: topic.id,
        topicName: topic.name,
        matchedAt: new Date().toISOString(),
        item: {
          title: item.title || '',
          link: item.link || '',
          feedName: item.feedName || '',
          contentSnippet: item.contentSnippet || '',
          pubDate: item.pubDate || '',
          isoDate: item.isoDate || ''
        }
      };
      watchAlertKeys.add(key);
      nextAlerts.push(alert);
    }
  }
  if (!nextAlerts.length) return 0;
  watchAlerts = [...nextAlerts, ...watchAlerts].slice(0, MAX_WATCH_ALERTS);
  saveWatchAlerts(watchAlerts);
  return nextAlerts.length;
}

function computeTags(item) {
  if (!tagConfig.enabled || !tagConfig.rules || !tagConfig.rules.length) return [];
  const title = (item.title || '').toLowerCase();
  const snippet = (item.contentSnippet || '').toLowerCase();
  const text = `${title} ${snippet}`.trim();
  return tagConfig.rules
    .filter(rule => rule.name && Array.isArray(rule.keywords) && rule.keywords.length)
    .filter(rule => {
      if (rule.matchAll) {
        return rule.keywords.every(word => text.includes(String(word).toLowerCase()));
      }
      return rule.keywords.some(word => text.includes(String(word).toLowerCase()));
    })
    .map(rule => rule.name);
}

function updateAggregatedCache(items) {
  aggregatedCache = {
    updatedAt: Date.now(),
    items
  };
  dashboardMetricsCache = { updatedAt: 0, data: null, period: null };
}

function getAggregatedCache() {
  if (!aggregatedCache.items || aggregatedCache.items.length === 0) return { items: [], stale: true };
  const age = Date.now() - aggregatedCache.updatedAt;
  return {
    items: aggregatedCache.items,
    stale: age > AGGREGATED_CACHE_TTL_MS,
    age
  };
}

function scheduleDashboardRefresh() {
  if (dashboardRefreshInFlight) return;
  dashboardRefreshInFlight = true;
  buildAggregatedItems()
    .catch(() => {
      // ignore
    })
    .finally(() => {
      dashboardRefreshInFlight = false;
    });
}

initWatchAlertKeys();

function normalizeSlug(value) {
  return String(value || '')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\- ]/g, '')
    .replace(/\s+/g, '-')
    .replace(/\-+/g, '-')
    .replace(/^\-+|\-+$/g, '');
}

function normalizeSiteInput(input, fallback) {
  const base = fallback || defaultSite;
  const next = input || {};
  const slug = normalizeSlug(next.slug || base.slug || 'site');
  return {
    slug: slug || base.slug,
    title: String(next.title || base.title || '').trim(),
    subtitle: String(next.subtitle || base.subtitle || '').trim(),
    primaryColor: String(next.primaryColor || base.primaryColor || '#0f172a'),
    accentColor: String(next.accentColor || base.accentColor || '#f97316'),
    backgroundColor: String(next.backgroundColor || base.backgroundColor || '#f5f1ea'),
    surfaceColor: String(next.surfaceColor || base.surfaceColor || '#ffffff'),
    textColor: String(next.textColor || base.textColor || '#1f2937'),
    themeMode: next.themeMode === 'light' ? 'light' : 'dark',
    fontFamily: String(next.fontFamily || base.fontFamily || '"Segoe UI", "Helvetica Neue", Arial, sans-serif'),
    automationEnabled: typeof next.automationEnabled === 'boolean' ? next.automationEnabled : (base.automationEnabled ?? true),
    showTicker: !!next.showTicker,
    maxItems: Number.isFinite(Number(next.maxItems)) ? Math.max(10, Math.min(300, Number(next.maxItems))) : base.maxItems || 80,
    menuLinks: Array.isArray(next.menuLinks)
      ? next.menuLinks
          .filter(link => link && link.label && link.url)
          .map(link => ({ label: String(link.label).trim(), url: String(link.url).trim() }))
      : base.menuLinks || [],
    tags: Array.isArray(next.tags) ? next.tags.map(tag => String(tag).trim()).filter(Boolean) : base.tags || [],
    rules: {
      feedIds: Array.isArray(next.rules?.feedIds) ? next.rules.feedIds : base.rules?.feedIds || [],
      requireWords: Array.isArray(next.rules?.requireWords) ? next.rules.requireWords : base.rules?.requireWords || [],
      blockWords: Array.isArray(next.rules?.blockWords) ? next.rules.blockWords : base.rules?.blockWords || [],
      onlyWithLink: typeof next.rules?.onlyWithLink === 'boolean' ? next.rules.onlyWithLink : base.rules?.onlyWithLink ?? true
    }
  };
}

const trendsCache = { updatedAt: 0, items: [] };
const POLYMARKET_CACHE_TTL_MS = 5 * 60 * 1000;
const polymarketCache = new Map();
const POLYMARKET_DEFAULT_KEYWORDS = [
  'politica',
  'politico',
  'governo',
  'governador',
  'presidente',
  'ministerio',
  'congresso',
  'senado',
  'camara',
  'suprema',
  'tribunal',
  'justica',
  'eleicao',
  'eleicoes',
  'votacao',
  'voto',
  'campanha',
  'parlamento',
  'partido',
  'corrupcao',
  'impeachment',
  'protesto',
  'manifestacao',
  'geopolitica',
  'guerra',
  'conflito',
  'sanction',
  'sancao',
  'diplomacia',
  'tratado',
  'acordo',
  'economia',
  'inflacao',
  'juros',
  'taxa',
  'dolar',
  'pib',
  'recessao',
  'banco central',
  'commodity',
  'energia',
  'petroleo',
  'election',
  'government',
  'congress',
  'senate',
  'president',
  'prime minister',
  'parliament',
  'policy',
  'war',
  'conflict',
  'sanctions',
  'treaty',
  'inflation',
  'interest rate',
  'central bank'
];
const POLYMARKET_CATEGORY_FILTERS = {
  politics: [
    'politics',
    'political',
    'government',
    'president',
    'prime minister',
    'prime-minister',
    'minister',
    'ministers',
    'congress',
    'senate',
    'senator',
    'senators',
    'parliament',
    'parliamentary',
    'election',
    'elections',
    'electoral',
    'primary',
    'primaries',
    'vote',
    'voter',
    'voters',
    'campaign',
    'candidate',
    'candidates',
    'party',
    'policy',
    'impeachment',
    'ministry',
    'cabinet',
    'supreme court',
    'tribunal',
    'court',
    'justice',
    'governor',
    'mayor',
    'administration',
    'democrat',
    'democrats',
    'republican',
    'republicans',
    'labour',
    'labor',
    'tory',
    'conservative',
    'liberal',
    'justica',
    'governo',
    'presidente',
    'eleicao',
    'eleicoes',
    'congresso',
    'senado',
    'camara',
    'partido',
    'politica',
    'governador',
    'prefeito',
    'ministro',
    'ministra',
    'presidencial',
    'candidato',
    'candidatos',
    'campanha',
    'votacao',
    'voto',
    'oposicao',
    'situacao'
  ]
};
const POLYMARKET_CATEGORIES = [
  {
    id: 'eleicoes',
    label: 'Eleicoes',
    keywords: ['eleicao', 'eleicoes', 'election', 'vote', 'votacao', 'ballot', 'turno', 'campaign', 'candidato']
  },
  {
    id: 'politica',
    label: 'Politica',
    keywords: ['governo', 'presidente', 'congresso', 'senado', 'camara', 'parlamento', 'partido', 'policy', 'cabinet']
  },
  {
    id: 'geopolitica',
    label: 'Geopolitica',
    keywords: ['guerra', 'conflito', 'sanction', 'sancao', 'diplomacia', 'tratado', 'acordo', 'treaty', 'border']
  },
  {
    id: 'economia',
    label: 'Economia',
    keywords: ['economia', 'inflacao', 'juros', 'taxa', 'dolar', 'pib', 'recessao', 'central bank', 'interest']
  },
  {
    id: 'justica',
    label: 'Justica',
    keywords: ['tribunal', 'suprema', 'justica', 'court', 'law', 'legal', 'impeachment', 'corrupcao']
  }
];

function getTrendsLocale(geo) {
  const upper = String(geo || 'BR').toUpperCase();
  if (upper === 'BR') {
    return { hl: 'pt-BR', ceid: 'BR:pt-419', gl: 'BR' };
  }
  return { hl: 'en-US', ceid: `${upper}:en`, gl: upper };
}

function getTrendsUrl(config) {
  const locale = getTrendsLocale(config.geo || 'BR');
  return `https://news.google.com/rss?hl=${encodeURIComponent(locale.hl)}&gl=${encodeURIComponent(locale.gl)}&ceid=${encodeURIComponent(locale.ceid)}`;
}

function normalizeAiTextResponse(text) {
  const raw = String(text || '').trim();
  if (!raw) return '';
  let cleaned = raw.replace(/^\"|\"$/g, '').trim();
  cleaned = cleaned.replace(/^```[\s\S]*?\n/, '').replace(/```$/, '').trim();
  return cleaned;
}

async function translatePolymarketQuery(query) {
  const raw = String(query || '').trim();
  if (!raw) return '';
  if (polymarketQueryCache.has(raw)) return polymarketQueryCache.get(raw);
  if (!aiConfig.enabled || !canUseAiProvider(aiConfig)) return raw;
  const prompt = [
    'Traduza o texto para ingles.',
    'Responda apenas com a traducao, sem explicacoes.',
    `Texto: "${raw}"`
  ].join('\n');
  let aiText = '';
  if (aiConfig.provider === 'openai') {
    aiText = await runPromptWithOpenAi(prompt, aiConfig.openai);
  } else if (aiConfig.provider === 'gemini') {
    aiText = await runPromptWithGemini(prompt, aiConfig.gemini);
  } else if (aiConfig.provider === 'copilot') {
    aiText = await runPromptWithCopilot(prompt, aiConfig.copilot);
  }
  const translated = normalizeAiTextResponse(aiText) || raw;
  polymarketQueryCache.set(raw, translated);
  if (polymarketQueryCache.size > 500) {
    const firstKey = polymarketQueryCache.keys().next().value;
    if (firstKey) polymarketQueryCache.delete(firstKey);
  }
  return translated;
}

async function translatePolymarketTitle(title) {
  const raw = String(title || '').trim();
  if (!raw) return raw;
  if (polymarketTranslationCache.has(raw)) return polymarketTranslationCache.get(raw);
  if (!aiConfig.enabled || !canUseAiProvider(aiConfig)) return raw;
  const prompt = [
    'Traduza o texto para pt-BR.',
    'Responda apenas com a traducao, sem explicacoes.',
    `Texto: "${raw}"`
  ].join('\n');
  let aiText = '';
  if (aiConfig.provider === 'openai') {
    aiText = await runPromptWithOpenAi(prompt, aiConfig.openai);
  } else if (aiConfig.provider === 'gemini') {
    aiText = await runPromptWithGemini(prompt, aiConfig.gemini);
  } else if (aiConfig.provider === 'copilot') {
    aiText = await runPromptWithCopilot(prompt, aiConfig.copilot);
  }
  const translated = normalizeAiTextResponse(aiText) || raw;
  polymarketTranslationCache.set(raw, translated);
  if (polymarketTranslationCache.size > 3000) {
    const firstKey = polymarketTranslationCache.keys().next().value;
    if (firstKey) polymarketTranslationCache.delete(firstKey);
  }
  return translated;
}

function normalizePolymarketText(value) {
  const raw = stripHtml(String(value || '').toLowerCase());
  return raw.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

function parseJsonArray(value) {
  if (Array.isArray(value)) return value;
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return [];
    try {
      const parsed = JSON.parse(trimmed);
      return Array.isArray(parsed) ? parsed : [];
    } catch (err) {
      return [];
    }
  }
  return [];
}

function isWorldEventTitle(value) {
  const text = normalizePolymarketText(value);
  if (!text) return false;
  return text.includes('world') || text.includes('global') || text.includes('international');
}

function hasKeywordMatch(text, keywords) {
  if (!keywords.length) return true;
  return keywords.some((keyword) => text.includes(keyword));
}

function detectPolymarketCategory(text) {
  for (const category of POLYMARKET_CATEGORIES) {
    if (category.keywords.some((keyword) => text.includes(keyword))) {
      return category;
    }
  }
  return { id: 'outros', label: 'Outros' };
}

function parsePolymarketProbability(value) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(String(value).replace('%', '').trim());
  if (!Number.isFinite(number)) return null;
  const percent = number <= 1 ? number * 100 : number;
  return Math.round(percent * 10) / 10;
}

function normalizePolymarketItem(item) {
  const title = String(item.question || item.title || item.name || '').trim();
  const slug = String(item.slug || '').trim();
  const outcomes = parseJsonArray(item.outcomes);
  const prices = parseJsonArray(item.outcomePrices).length
    ? parseJsonArray(item.outcomePrices)
    : parseJsonArray(item.prices);
  const events = parseJsonArray(item.events);
  const seriesTitles = [];
  let eventTitle = '';
  events.forEach((event) => {
    if (!eventTitle && event.title) {
      eventTitle = String(event.title || '').trim();
    }
    const seriesList = Array.isArray(event.series) ? event.series : [];
    seriesList.forEach((series) => {
      if (series && series.title) {
        seriesTitles.push(String(series.title).trim());
      }
    });
  });
  const seriesTitle = seriesTitles[0] || '';
  const yesIndex = outcomes.findIndex((outcome) => {
    const value = String(outcome || '').toLowerCase();
    return value === 'yes' || value === 'sim';
  });
  const yesRaw = yesIndex >= 0 ? prices[yesIndex] : item.yesPrice || item.probability || item.probabilityYes;
  const probability = parsePolymarketProbability(yesRaw);
  const textForCategory = normalizePolymarketText(`${title} ${item.category || ''} ${(item.tags || []).join(' ')}`);
  const category = detectPolymarketCategory(textForCategory);
  return {
    id: String(item.id || item.marketId || item.conditionId || slug || title),
    title,
    source: 'Polymarket',
    slug,
    url: String(item.url || (slug ? `https://polymarket.com/market/${slug}` : '')),
    volume: item.volume || item.volume24h || item.volume24hr || item.totalVolume || item.volumeUsd || '',
    liquidity: item.liquidity || item.liquidityNum || item.liquidityUsd || '',
    probability,
    updatedAt: item.updatedAt || item.updatedTime || item.lastUpdated || '',
    endDate: item.endDate || item.endDateIso || item.expirationTime || item.closeTime || '',
    seriesTitle,
    eventTitle,
    categoryId: category.id,
    categoryLabel: category.label
  };
}

function buildPolymarketSearchText(item) {
  return normalizePolymarketText([
    item.title,
    item.originalTitle,
    item.seriesTitle,
    item.eventTitle
  ].filter(Boolean).join(' '));
}

function normalizeKalshiItem(item) {
  const title = String(item.title || item.market_title || item.question || '').trim();
  const ticker = String(item.ticker || item.market_ticker || '').trim();
  const url = ticker ? `https://kalshi.com/markets/${ticker}` : '';
  const volume = item.volume || item.volume_24h || item.volume24h || item.volume_7d || item.volume_30d || '';
  const liquidity = item.liquidity || item.open_interest || item.openInterest || '';
  const yesBid = Number(item.yes_bid || item.yesBid || item.yes_bid_cents || item.yes_bid_price || item.yes_bid_value);
  const yesAsk = Number(item.yes_ask || item.yesAsk || item.yes_ask_cents || item.yes_ask_price || item.yes_ask_value);
  const yesMid = Number.isFinite(yesBid) && Number.isFinite(yesAsk)
    ? (yesBid + yesAsk) / 2
    : Number.isFinite(yesBid)
      ? yesBid
      : Number.isFinite(yesAsk)
        ? yesAsk
        : null;
  const probability = Number.isFinite(yesMid) ? Math.round(yesMid * 10) / 10 : null;
  return {
    id: String(item.id || ticker || title),
    title,
    source: 'Kalshi',
    slug: ticker,
    url,
    volume,
    liquidity,
    probability,
    updatedAt: item.updated_at || item.updatedAt || '',
    endDate: item.close_time || item.closeTime || item.expiry_time || item.expirationTime || '',
    seriesTitle: item.event_title || item.eventTitle || '',
    eventTitle: item.event_ticker || item.eventTicker || '',
    categoryId: 'politics',
    categoryLabel: 'Politics'
  };
}

function buildKalshiSearchText(item) {
  return normalizePolymarketText([
    item.title,
    item.seriesTitle,
    item.eventTitle
  ].filter(Boolean).join(' '));
}

async function fetchKalshiEvents(limit, category) {
  const safeLimit = Math.max(1, Math.min(Number(limit) || 60, 500));
  const headers = {
    Accept: 'application/json',
    'User-Agent': 'rss-backend/1.0'
  };
  if (KALSHI_API_KEY) {
    headers.Authorization = `Bearer ${KALSHI_API_KEY}`;
  }
  const url = new URL(`${KALSHI_BASE_URL}/markets`);
  url.searchParams.set('limit', String(safeLimit));
  url.searchParams.set('status', 'open');
  const response = await fetch(url.toString(), { headers });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Kalshi ${response.status}: ${text.slice(0, 120)}`);
  }
  const rawText = await response.text();
  let data;
  try {
    data = JSON.parse(rawText);
  } catch (err) {
    throw new Error('Kalshi resposta invalida.');
  }
  const rawItems = Array.isArray(data)
    ? data
    : Array.isArray(data?.markets)
      ? data.markets
      : Array.isArray(data?.data)
        ? data.data
        : Array.isArray(data?.data?.markets)
          ? data.data.markets
          : [];
  let items = rawItems
    .map(normalizeKalshiItem)
    .filter(item => item.title && item.url);
  if (String(category || '').toLowerCase() === 'politics') {
    items = items.filter(item => hasKeywordMatch(buildKalshiSearchText(item), POLYMARKET_CATEGORY_FILTERS.politics));
  }
  return items;
}

async function fetchPolymarketEvents(limit, query, lang, category) {
  const safeLimit = Math.max(1, Math.min(Number(limit) || 60, 500));
  const wantsPortuguese = String(lang || '').toLowerCase().startsWith('pt');
  const translatedQuery = wantsPortuguese ? await translatePolymarketQuery(query) : String(query || '');
  const categoryKey = String(category || '').toLowerCase();
  const categoryKeywords = POLYMARKET_CATEGORY_FILTERS[categoryKey] || [];
  const extraKeywords = String(translatedQuery || '')
    .split(',')
    .map(word => word.trim().toLowerCase())
    .filter(Boolean);
  const keywords = categoryKeywords.length
    ? Array.from(new Set([...categoryKeywords, ...extraKeywords]))
    : Array.from(new Set([...POLYMARKET_DEFAULT_KEYWORDS, ...extraKeywords]));
  const cacheKey = `${safeLimit}:${wantsPortuguese ? 'pt' : 'en'}:${categoryKey}:${keywords.join('|')}`;
  const cached = polymarketCache.get(cacheKey);
  const now = Date.now();
  if (cached && (now - cached.updatedAt) < POLYMARKET_CACHE_TTL_MS) {
    return cached;
  }
  const url = new URL('https://gamma-api.polymarket.com/markets');
  url.searchParams.set('active', 'true');
  url.searchParams.set('closed', 'false');
  url.searchParams.set('archived', 'false');
  url.searchParams.set('limit', String(safeLimit));
  url.searchParams.set('offset', '0');
  url.searchParams.set('sort', 'volume');
  const response = await fetch(url.toString(), {
    headers: {
      Accept: 'application/json',
      'User-Agent': 'rss-backend/1.0'
    }
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Polymarket ${response.status}: ${text.slice(0, 120)}`);
  }
  const rawText = await response.text();
  let data;
  try {
    data = JSON.parse(rawText);
  } catch (err) {
    throw new Error('Polymarket resposta invalida.');
  }
  const rawItems = Array.isArray(data)
    ? data
    : Array.isArray(data?.data)
      ? data.data
      : Array.isArray(data?.markets)
        ? data.markets
        : [];
  let items = rawItems
    .filter(item => item && (item.active !== false) && !item.closed && !item.archived)
    .map(normalizePolymarketItem)
    .filter(item => item.title && item.url)
    .filter(item => hasKeywordMatch(buildPolymarketSearchText(item), keywords));
  if (wantsPortuguese) {
    const translatedItems = [];
    for (const item of items) {
      const translatedTitle = await translatePolymarketTitle(item.title);
      translatedItems.push({
        ...item,
        originalTitle: item.title,
        title: translatedTitle || item.title
      });
    }
    items = translatedItems;
  }
  const topics = items.reduce((acc, item) => {
    const topic = item.seriesTitle || item.eventTitle;
    if (!topic) return acc;
    const key = String(topic).trim();
    if (!key) return acc;
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  const topicList = Object.entries(topics)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 12)
    .map(([label, count]) => ({ id: label.toLowerCase().replace(/\s+/g, '-'), label, count }));
  const worldTopics = items.reduce((acc, item) => {
    const title = item.eventTitle || item.seriesTitle || '';
    if (!isWorldEventTitle(title)) return acc;
    const label = String(title).trim();
    if (!label) return acc;
    acc[label] = (acc[label] || 0) + 1;
    return acc;
  }, {});
  const worldTopicList = Object.entries(worldTopics)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([label, count]) => ({ id: label.toLowerCase().replace(/\s+/g, '-'), label, count }));
  const payload = { items, topics: topicList, worldTopics: worldTopicList, updatedAt: now };
  polymarketCache.set(cacheKey, payload);
  return payload;
}

function normalizeYoutubeConfig(next) {
  const safeOptions = new Set(['none', 'moderate', 'strict']);
  const maxResults = Number.isFinite(Number(next.maxResults))
    ? Math.max(1, Math.min(25, Number(next.maxResults)))
    : 6;
  const region = String(next.region || 'BR').toUpperCase();
  return {
    enabled: !!next.enabled,
    apiKey: String(next.apiKey || '').trim(),
    maxResults,
    region,
    safeSearch: safeOptions.has(next.safeSearch) ? next.safeSearch : 'moderate'
  };
}

function normalizeTelegramFeeds(next) {
  const feeds = Array.isArray(next.feeds)
    ? next.feeds.map(feed => ({
        id: String(feed.id || uuidv4()),
        name: String(feed.name || '').trim() || 'Telegram',
        chatId: String(feed.chatId || '').trim(),
        showOnTimeline: typeof feed.showOnTimeline === 'boolean' ? feed.showOnTimeline : true
      }))
        .filter(feed => feed.chatId)
    : [];
  return {
    enabled: !!next.enabled,
    botToken: String(next.botToken || '').trim(),
    feeds
  };
}

async function fetchTelegramFeedItems(config, state) {
  if (!config.enabled || !config.botToken || !config.feeds.length) return [];
  const botToken = config.botToken;
  const chatMap = new Map(config.feeds.map(feed => [String(feed.chatId), feed]));
  const offset = state.lastUpdateId ? state.lastUpdateId + 1 : undefined;
  const url = new URL(`https://api.telegram.org/bot${botToken}/getUpdates`);
  if (offset) url.searchParams.set('offset', String(offset));
  url.searchParams.set('timeout', '0');
  const res = await fetch(url.toString());
  const data = await res.json();
  if (!data.ok) {
    throw new Error(data.description || 'Falha ao ler Telegram.');
  }
  let lastUpdateId = state.lastUpdateId || 0;
  const messages = Array.isArray(state.messages) ? state.messages.slice() : [];
  const incoming = [];
  for (const update of data.result || []) {
    if (typeof update.update_id === 'number') {
      lastUpdateId = Math.max(lastUpdateId, update.update_id);
    }
    const msg = update.message || update.channel_post;
    if (!msg || !msg.chat || !msg.chat.id) continue;
    const chatId = String(msg.chat.id);
    const feed = chatMap.get(chatId);
    if (!feed) continue;
    const text = msg.text || msg.caption || '';
    const title = (text.split('\n')[0] || '').trim() || 'Mensagem do Telegram';
    const pubDate = msg.date ? new Date(msg.date * 1000) : new Date();
    const link = msg.chat.username
      ? `https://t.me/${msg.chat.username}/${msg.message_id}`
      : '';
    const entry = {
      id: `tg-${chatId}-${msg.message_id}`,
      title: stripHtml(title),
      link,
      pubDate: pubDate.toUTCString(),
      isoDate: pubDate.toISOString(),
      contentSnippet: stripHtml(text),
      feedName: feed.name,
      feedUrl: `telegram:${chatId}`,
      chatId
    };
    incoming.push(entry);
  }
  if (incoming.length) {
    const merged = [...incoming, ...messages].reduce((acc, item) => {
      if (!acc.seen.has(item.id)) {
        acc.seen.add(item.id);
        acc.items.push(item);
      }
      return acc;
    }, { seen: new Set(), items: [] }).items;
    state.messages = merged.slice(0, 200);
  }
  state.lastUpdateId = lastUpdateId;
  saveTelegramFeedsState(state);
  const allowed = new Set(config.feeds.filter(f => f.showOnTimeline).map(f => String(f.chatId)));
  return (state.messages || []).filter(item => allowed.has(String(item.chatId)));
}

function parseIsoDuration(value) {
  if (!value) return 0;
  const match = String(value).match(/PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?/);
  if (!match) return 0;
  const hours = Number(match[1] || 0);
  const minutes = Number(match[2] || 0);
  const seconds = Number(match[3] || 0);
  return (hours * 3600) + (minutes * 60) + seconds;
}

async function fetchTrendsItems(config) {
  if (!config.enabled) return [];
  const ttl = (Number(config.refreshMinutes) || 10) * 60 * 1000;
  const now = Date.now();
  if (trendsCache.items.length && (now - trendsCache.updatedAt) < ttl) {
    return trendsCache.items.slice(0, config.maxItems || 10);
  }
  const parser = new Parser({
    customFields: {
      item: ['ht:approx_traffic']
    }
  });
  const url = getTrendsUrl(config);
  const feed = await parseFeedWithEncoding(url, parser);
  const items = (feed.items || []).map(item => ({
    title: stripHtml(item.title),
    traffic: item['ht:approx_traffic'] || '',
    link: item.link || '',
    pubDate: item.pubDate || '',
    isoDate: item.isoDate || ''
  }));
  trendsCache.updatedAt = now;
  trendsCache.items = items;
  return items.slice(0, config.maxItems || 10);
}

function filterSiteItems(items, site) {
  let filtered = items;
  const rules = site.rules || {};
  if (rules.feedIds && rules.feedIds.length) {
    const allowedUrls = feeds
      .filter(feed => rules.feedIds.includes(feed.id))
      .map(feed => feed.url);
    const allowed = new Set(allowedUrls);
    filtered = filtered.filter(item => allowed.has(item.feedUrl));
  }
  filtered = filtered.filter(item => matchRules(item, rules));
  if (site.tags && site.tags.length) {
    filtered = filtered.filter(item => (item.tags || []).some(tag => site.tags.includes(tag)));
  }
  return filtered;
}

function getSitePostsForSlug(slug) {
  return (sitePosts.posts || []).filter(post => post.slug === slug);
}

function saveSitePost(post) {
  sitePosts.posts = [post, ...(sitePosts.posts || [])].slice(0, 500);
  saveSitePosts(sitePosts);
  return post;
}

function getSiteItemTime(item) {
  const raw = item.sortDate || item.isoDate || item.pubDate || item.createdAt;
  if (!raw) return 0;
  const d = new Date(raw);
  return Number.isNaN(d.getTime()) ? 0 : d.getTime();
}

function normalizeAiInput(text) {
  return stripHtml(text || '').replace(/\s+/g, ' ').trim();
}

function buildAiPrompts(item, maxChars, mode) {
  const title = normalizeAiInput(item.title);
  const snippet = normalizeAiInput(item.contentSnippet);
  const feedName = normalizeAiInput(item.feedName);
  const link = String(item.link || '').trim();
  const limit = Math.max(200, Math.min(1200, Number(maxChars) || 600));
  const twitterLimit = Math.min(280, limit);
  const systemPrompt = [
    'Voce e um redator jornalistico.',
    'Use apenas as informacoes fornecidas pela manchete e trecho.',
    'Nao invente fatos, numeros ou nomes.',
    'Se nao houver dados suficientes, responda exatamente com SEM_DADOS.'
  ].join(' ');
  let style = [
    `Escreva um texto jornalistico curto (2 a 4 frases), em pt-BR,`,
    `com no maximo ${limit} caracteres.`,
    'Sem listas, sem markdown, sem titulo extra.'
  ].join(' ');
  if (mode === 'twitter') {
    style = [
      `Escreva um texto curto para X/Twitter (2 a 3 frases), em pt-BR,`,
      'com tom informativo.',
      `Use no maximo ${twitterLimit} caracteres.`,
      'Sem listas, sem markdown, sem emojis excessivos.',
      'Se fizer sentido, inclua o link ao final.'
    ].join(' ');
  } else if (mode === 'twitter_short') {
    style = [
      `Escreva um texto curto para X/Twitter (1 a 2 frases), em pt-BR,`,
      'com tom direto.',
      `Use no maximo ${Math.min(200, twitterLimit)} caracteres.`,
      'Sem listas, sem markdown, sem emojis.'
    ].join(' ');
  } else if (mode === 'twitter_cta') {
    style = [
      `Escreva um texto curto para X/Twitter (2 a 3 frases), em pt-BR,`,
      'com tom informativo e uma chamada final.',
      `Use no maximo ${twitterLimit} caracteres.`,
      'Sem listas, sem markdown, sem emojis excessivos.',
      'Inclua uma chamada final do tipo "Leia mais" ou "Saiba mais".',
      'Inclua o link ao final, se possivel.'
    ].join(' ');
  } else if (mode === 'twitter_nolink') {
    style = [
      `Escreva um texto curto para X/Twitter (2 a 3 frases), em pt-BR,`,
      'com tom informativo.',
      `Use no maximo ${twitterLimit} caracteres.`,
      'Sem listas, sem markdown, sem emojis.',
      'Nao inclua o link no texto.'
    ].join(' ');
  }
  const userPrompt = [
    `Manchete: ${title || 'N/A'}`,
    `Trecho: ${snippet || 'N/A'}`,
    `Fonte: ${feedName || 'N/A'}`,
    `Link: ${link || 'N/A'}`,
    '',
    style
  ].join('\n');
  const outputLimit = mode && mode.startsWith('twitter') ? twitterLimit : limit;
  return { systemPrompt, userPrompt, limit: outputLimit };
}

async function rewriteWithOpenAi(item, config, mode) {
  if (!config || !config.apiKey) {
    throw new Error('Chave da OpenAI ausente.');
  }
  const title = normalizeAiInput(item.title);
  const snippet = normalizeAiInput(item.contentSnippet);
  if (!title && !snippet) {
    throw new Error('Dados insuficientes para reescrita.');
  }

  const { systemPrompt, userPrompt, limit } = buildAiPrompts(item, config.maxChars, mode);

  const payload = {
    model: config.model || 'gpt-4o-mini',
    temperature: Number.isFinite(Number(config.temperature)) ? Number(config.temperature) : 0.4,
    max_tokens: 300,
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt }
    ]
  };

  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.apiKey}`
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`OpenAI erro ${response.status}: ${errText}`);
  }
  const data = await response.json();
  const content = data && data.choices && data.choices[0] && data.choices[0].message
    ? String(data.choices[0].message.content || '').trim()
    : '';

  if (!content || content === 'SEM_DADOS') {
    throw new Error('Sem dados suficientes para reescrita.');
  }

  let cleaned = content.replace(/\s+/g, ' ').trim();
  if (cleaned.length > limit) {
    cleaned = cleaned.slice(0, limit).trim();
  }
  return cleaned;
}

async function rewriteWithGemini(item, config, maxChars, mode) {
  if (!config || !config.apiKey) {
    throw new Error('Chave do Gemini ausente.');
  }
  const title = normalizeAiInput(item.title);
  const snippet = normalizeAiInput(item.contentSnippet);
  if (!title && !snippet) {
    throw new Error('Dados insuficientes para reescrita.');
  }
  const { userPrompt, limit } = buildAiPrompts(item, maxChars, mode);

  const model = config.model || 'gemini-1.5-flash';
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${config.apiKey}`;
  const payload = {
    contents: [
      { role: 'user', parts: [{ text: userPrompt }] }
    ],
    generationConfig: {
      temperature: 0.4,
      maxOutputTokens: 512
    }
  };
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Gemini erro ${response.status}: ${errText}`);
  }
  const data = await response.json();
  const content = data?.candidates?.[0]?.content?.parts?.[0]?.text
    ? String(data.candidates[0].content.parts[0].text).trim()
    : '';
  if (!content || content === 'SEM_DADOS') {
    throw new Error('Sem dados suficientes para reescrita.');
  }
  let cleaned = content.replace(/\s+/g, ' ').trim();
  if (cleaned.length > limit) {
    cleaned = cleaned.slice(0, limit).trim();
  }
  return cleaned;
}

async function rewriteWithCopilot(item, config, maxChars, mode) {
  if (!config || !config.apiKey || !config.baseUrl) {
    throw new Error('Copilot sem chave ou endpoint.');
  }
  const title = normalizeAiInput(item.title);
  const snippet = normalizeAiInput(item.contentSnippet);
  if (!title && !snippet) {
    throw new Error('Dados insuficientes para reescrita.');
  }
  const { systemPrompt, userPrompt, limit } = buildAiPrompts(item, maxChars, mode);

  const baseUrl = config.baseUrl.replace(/\/+$/, '');
  const response = await fetch(`${baseUrl}/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.apiKey}`
    },
    body: JSON.stringify({
      model: config.model || 'gpt-4o-mini',
      temperature: 0.4,
      max_tokens: 300,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt }
      ]
    })
  });
  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Copilot erro ${response.status}: ${errText}`);
  }
  const data = await response.json();
  const content = data?.choices?.[0]?.message?.content
    ? String(data.choices[0].message.content).trim()
    : '';
  if (!content || content === 'SEM_DADOS') {
    throw new Error('Sem dados suficientes para reescrita.');
  }
  let cleaned = content.replace(/\s+/g, ' ').trim();
  if (cleaned.length > limit) {
    cleaned = cleaned.slice(0, limit).trim();
  }
  return cleaned;
}

function sanitizeHashtag(tag) {
  if (!tag) return '';
  return String(tag)
    .replace(/#/g, '')
    .replace(/\s+/g, '')
    .replace(/[^\p{L}\p{N}_]/gu, '')
    .trim();
}

function parseHashtagResponse(raw, maxTags) {
  const limit = Math.min(5, Math.max(1, Number(maxTags) || 3));
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed.map(sanitizeHashtag).filter(Boolean).slice(0, limit);
    }
  } catch (e) {
    // ignore
  }
  const matches = String(raw).match(/#[\p{L}\p{N}_]+/gu);
  if (matches && matches.length) {
    return matches.map(sanitizeHashtag).filter(Boolean).slice(0, limit);
  }
  return String(raw)
    .split(/[,;\n]+/)
    .map(sanitizeHashtag)
    .filter(Boolean)
    .slice(0, limit);
}

function buildHashtagPrompt(text, maxTags) {
  const limit = Math.min(5, Math.max(1, Number(maxTags) || 3));
  return [
    `Gere ${limit} hashtags em portugues do Brasil, curtas e relevantes.`,
    'Evite hashtags genÃ©ricas. Use termos especificos do tema.',
    'Responda apenas com um JSON array de strings.',
    `Texto: """${text}"""`
  ].join('\n');
}

async function generateHashtagsWithOpenAi(text, config, maxTags) {
  if (!config || !config.apiKey) {
    throw new Error('Chave da OpenAI ausente.');
  }
  const prompt = buildHashtagPrompt(text, maxTags);
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.apiKey}`
    },
    body: JSON.stringify({
      model: config.model || 'gpt-4o-mini',
      temperature: 0.2,
      max_tokens: 120,
      messages: [
        { role: 'system', content: 'Voce gera hashtags para redes sociais.' },
        { role: 'user', content: prompt }
      ]
    })
  });
  const data = await res.json();
  if (!res.ok) {
    const message = data?.error?.message || 'Falha ao gerar hashtags.';
    throw new Error(message);
  }
  const raw = data?.choices?.[0]?.message?.content || '';
  return parseHashtagResponse(raw, maxTags);
}

async function generateHashtagsWithGemini(text, config, maxTags) {
  if (!config || !config.apiKey) {
    throw new Error('Chave do Gemini ausente.');
  }
  const model = config.model || 'gemini-1.5-flash';
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${config.apiKey}`;
  const prompt = buildHashtagPrompt(text, maxTags);
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ role: 'user', parts: [{ text: prompt }] }]
    })
  });
  const data = await res.json();
  if (!res.ok) {
    const message = data?.error?.message || 'Falha ao gerar hashtags.';
    throw new Error(message);
  }
  const raw = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
  return parseHashtagResponse(raw, maxTags);
}

async function generateHashtagsWithCopilot(text, config, maxTags) {
  if (!config || !config.apiKey || !config.baseUrl) {
    throw new Error('Copilot sem chave ou endpoint.');
  }
  const prompt = buildHashtagPrompt(text, maxTags);
  const baseUrl = config.baseUrl.replace(/\/+$/, '');
  const res = await fetch(`${baseUrl}/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.apiKey}`
    },
    body: JSON.stringify({
      model: config.model || 'gpt-4o-mini',
      temperature: 0.2,
      max_tokens: 120,
      messages: [
        { role: 'system', content: 'Voce gera hashtags para redes sociais.' },
        { role: 'user', content: prompt }
      ]
    })
  });
  const data = await res.json();
  if (!res.ok) {
    const message = data?.error?.message || 'Falha ao gerar hashtags.';
    throw new Error(message);
  }
  const raw = data?.choices?.[0]?.message?.content || '';
  return parseHashtagResponse(raw, maxTags);
}

function canUseAiProvider(config) {
  if (!config?.enabled) return false;
  if (config.provider === 'openai') return !!config.openai?.apiKey;
  if (config.provider === 'gemini') return !!config.gemini?.apiKey;
  if (config.provider === 'copilot') return !!(config.copilot?.apiKey && config.copilot?.baseUrl);
  return false;
}

function getTrendExplanationFromCache(title) {
  const key = normalizeTitle(title || '');
  if (!key) return null;
  const cached = trendsExplainCache.get(key);
  if (!cached) return null;
  if ((Date.now() - cached.updatedAt) > TRENDS_EXPLAIN_CACHE_TTL_MS) {
    trendsExplainCache.delete(key);
    return null;
  }
  return cached.text;
}

function setTrendExplanationCache(title, text) {
  const key = normalizeTitle(title || '');
  if (!key || !text) return;
  trendsExplainCache.set(key, { text, updatedAt: Date.now() });
}

function buildTrendExplainPrompt(title) {
  return [
    'Explique em 1 ou 2 frases, em portugues do Brasil, o que significa este termo em tendencia.',
    'Se for um assunto amplo, resuma o contexto mais provavel e atual.',
    'Evite inventar fatos especificos ou datas. Seja objetivo.',
    `Termo: "${title}"`
  ].join('\n');
}

function normalizeExplanation(text) {
  if (!text) return '';
  let cleaned = String(text).replace(/\s+/g, ' ').trim();
  if (cleaned.length > 220) {
    cleaned = `${cleaned.slice(0, 217)}...`;
  }
  return cleaned;
}

async function generateTrendExplanationWithOpenAi(title, config) {
  const prompt = buildTrendExplainPrompt(title);
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.apiKey}`
    },
    body: JSON.stringify({
      model: config.model || 'gpt-4o-mini',
      temperature: 0.3,
      max_tokens: 180,
      messages: [
        { role: 'system', content: 'Voce explica termos de noticias.' },
        { role: 'user', content: prompt }
      ]
    })
  });
  const data = await res.json();
  if (!res.ok) {
    const message = data?.error?.message || 'Falha ao gerar explicacao.';
    throw new Error(message);
  }
  return normalizeExplanation(data?.choices?.[0]?.message?.content || '');
}

async function generateTrendExplanationWithGemini(title, config) {
  const model = config.model || 'gemini-1.5-flash';
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${config.apiKey}`;
  const prompt = buildTrendExplainPrompt(title);
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ role: 'user', parts: [{ text: prompt }] }]
    })
  });
  const data = await res.json();
  if (!res.ok) {
    const message = data?.error?.message || 'Falha ao gerar explicacao.';
    throw new Error(message);
  }
  return normalizeExplanation(data?.candidates?.[0]?.content?.parts?.[0]?.text || '');
}

async function generateTrendExplanationWithCopilot(title, config) {
  const prompt = buildTrendExplainPrompt(title);
  const baseUrl = config.baseUrl.replace(/\/+$/, '');
  const res = await fetch(`${baseUrl}/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.apiKey}`
    },
    body: JSON.stringify({
      model: config.model || 'gpt-4o-mini',
      temperature: 0.3,
      max_tokens: 180,
      messages: [
        { role: 'system', content: 'Voce explica termos de noticias.' },
        { role: 'user', content: prompt }
      ]
    })
  });
  const data = await res.json();
  if (!res.ok) {
    const message = data?.error?.message || 'Falha ao gerar explicacao.';
    throw new Error(message);
  }
  return normalizeExplanation(data?.choices?.[0]?.message?.content || '');
}

async function runPromptWithOpenAi(prompt, config) {
  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.apiKey}`
    },
    body: JSON.stringify({
      model: config.model || 'gpt-4o-mini',
      temperature: 0.2,
      max_tokens: 600,
      messages: [
        { role: 'system', content: 'Responda apenas com JSON valido.' },
        { role: 'user', content: prompt }
      ]
    })
  });
  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`OpenAI erro ${response.status}: ${errText}`);
  }
  const data = await response.json();
  return data?.choices?.[0]?.message?.content ? String(data.choices[0].message.content).trim() : '';
}

async function runPromptWithGemini(prompt, config) {
  const model = config.model || 'gemini-1.5-flash';
  const url =
    `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${config.apiKey}`;
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: {
        temperature: 0.2,
        maxOutputTokens: 900
      }
    })
  });
  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Gemini erro ${response.status}: ${errText}`);
  }
  const data = await response.json();
  return data?.candidates?.[0]?.content?.parts?.[0]?.text
    ? String(data.candidates[0].content.parts[0].text).trim()
    : '';
}

async function runPromptWithCopilot(prompt, config) {
  const baseUrl = config.baseUrl.replace(/\/+$/, '');
  const response = await fetch(`${baseUrl}/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.apiKey}`
    },
    body: JSON.stringify({
      model: config.model || 'gpt-4o-mini',
      temperature: 0.2,
      max_tokens: 600,
      messages: [
        { role: 'system', content: 'Responda apenas com JSON valido.' },
        { role: 'user', content: prompt }
      ]
    })
  });
  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Copilot erro ${response.status}: ${errText}`);
  }
  const data = await response.json();
  return data?.choices?.[0]?.message?.content
    ? String(data.choices[0].message.content).trim()
    : '';
}

function extractCandidates($, baseUrl) {
  const candidates = [];
  const selectors = [
    'article a',
    'h1 a',
    'h2 a',
    'h3 a',
    'a'
  ];
  const seen = new Set();
  for (const selector of selectors) {
    $(selector).each((_, el) => {
      const href = $(el).attr('href');
      if (!href || href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:')) {
        return;
      }
      let abs;
      try {
        abs = new URL(href, baseUrl).toString();
      } catch (err) {
        return;
      }
      if (seen.has(abs)) return;
      const text = $(el).text().replace(/\s+/g, ' ').trim();
      if (text.length < 8) return;
      seen.add(abs);
      candidates.push({ link: abs, title: text });
    });
    if (candidates.length >= 25) break;
  }
  return candidates;
}

async function generateRssFromSite(targetUrl) {
  const html = await fetchHtml(targetUrl);
  const $ = cheerio.load(html);
  const urlObj = new URL(targetUrl);
  const channelTitle =
    $('meta[property="og:site_name"]').attr('content') ||
    $('title').first().text().trim() ||
    urlObj.hostname;
  const description =
    $('meta[name="description"]').attr('content') ||
    `NotÃ­cias recentes de ${urlObj.hostname}`;

  const items = extractCandidates($, urlObj.toString())
    .slice(0, 20)
    .map((item) => ({
      title: item.title,
      link: item.link
    }));

  const now = new Date().toUTCString();
  const itemXml = items
    .map((item) => {
      return [
        '<item>',
        `<title>${cdata(item.title)}</title>`,
        `<link>${item.link}</link>`,
        `<guid isPermaLink="true">${item.link}</guid>`,
        `<pubDate>${now}</pubDate>`,
        `<description>${cdata(item.title)}</description>`,
        '</item>'
      ].join('');
    })
    .join('');

  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<rss version="2.0">',
    '<channel>',
    `<title>${cdata(channelTitle)}</title>`,
    `<link>${urlObj.origin}</link>`,
    `<description>${cdata(description)}</description>`,
    itemXml,
    '</channel>',
    '</rss>'
  ].join('');
}

const normalizeXHandle = (input) => {
  let value = String(input || '').trim();
  if (!value) return '';
  if (value.startsWith('@')) {
    value = value.slice(1);
  }
  if (value.startsWith('http://') || value.startsWith('https://')) {
    try {
      const url = new URL(value);
      const parts = url.pathname.split('/').filter(Boolean);
      if (parts.length) {
        value = parts[0];
      }
    } catch (err) {
      return '';
    }
  }
  if (value.includes('/')) {
    value = value.split('/')[0];
  }
  value = value.replace(/^@/, '').trim();
  if (!/^[A-Za-z0-9_]{1,15}$/.test(value)) return '';
  return value;
};

const buildXFeedUrl = (baseUrl, handle) => {
  const base = String(baseUrl || '').replace(/\/$/, '');
  return `${base}/${handle}/rss`;
};

const fetchRssBody = async (url) => {
  const response = await fetch(url, {
    headers: {
      'User-Agent': 'rss-backend/1.0',
      'Accept': 'application/rss+xml,application/xml,text/xml;q=0.9,*/*;q=0.8'
    }
  });
  const body = await response.text();
  if (!response.ok || !body || !body.includes('<rss')) return null;
  return body;
};

const fetchRssViaJina = async (url) => {
  const target = url.replace(/^https?:\/\//, '');
  const proxyUrl = `https://r.jina.ai/http://${target}`;
  return fetchRssBody(proxyUrl);
};

const buildTwtrssUrl = (handle) => (
  `https://twitrss.me/twitter_user_to_rss/?user=${encodeURIComponent(handle)}`
);

const bodyIndicatesNotFound = (body) => {
  if (!body) return false;
  const needle = String(body).toLowerCase();
  return (
    needle.includes('not found')
    || needle.includes('user not found')
    || needle.includes('does not exist')
    || needle.includes('non e stato trovato nulla')
    || needle.includes('non è stato trovato nulla')
  );
};

app.get('/x/rss', async (req, res) => {
  const raw = String(req.query.user || req.query.url || '').trim();
  const handle = normalizeXHandle(raw);
  if (!handle) {
    return res.status(400).json({ error: 'Informe um @usuario ou URL do perfil.' });
  }
  let lastBody = '';
  const candidates = [NITTER_BASE, ...NITTER_FALLBACKS].filter(Boolean);
  for (const base of candidates) {
    const feedUrl = buildXFeedUrl(base, handle);
    try {
      const response = await fetch(feedUrl, {
        headers: {
          'User-Agent': 'rss-backend/1.0',
          'Accept': 'application/rss+xml,application/xml,text/xml;q=0.9,*/*;q=0.8'
        }
      });
      const body = await response.text();
      lastBody = body || '';
      if (!response.ok) {
        if (bodyIndicatesNotFound(lastBody)) {
          return res.status(404).json({ error: 'Conta nao encontrada ou protegida no X.' });
        }
        continue;
      }
      if (body && body.includes('<rss')) {
        res.set('Content-Type', 'application/rss+xml; charset=utf-8');
        res.set('X-Source-Url', feedUrl);
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
        res.set('Surrogate-Control', 'no-store');
        res.set('ETag', Date.now().toString());
        return res.status(200).send(body);
      }
      if (bodyIndicatesNotFound(lastBody)) {
        return res.status(404).json({ error: 'Conta nao encontrada ou protegida no X.' });
      }
      const proxied = await fetchRssViaJina(feedUrl);
      if (proxied) {
        res.set('Content-Type', 'application/rss+xml; charset=utf-8');
        res.set('X-Source-Url', feedUrl);
        res.set('X-Proxy-Url', `https://r.jina.ai/http/${feedUrl.replace(/^https?:\/\//, '')}`);
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
        res.set('Surrogate-Control', 'no-store');
        res.set('ETag', Date.now().toString());
        return res.status(200).send(proxied);
      }
    } catch (err) {
      // try next base
    }
  }
  const twtrssUrl = buildTwtrssUrl(handle);
  try {
    const body = await fetchRssBody(twtrssUrl);
    if (body) {
      res.set('Content-Type', 'application/rss+xml; charset=utf-8');
      res.set('X-Source-Url', twtrssUrl);
      res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.set('Pragma', 'no-cache');
      res.set('Expires', '0');
      res.set('Surrogate-Control', 'no-store');
      res.set('ETag', Date.now().toString());
      return res.status(200).send(body);
    }
  } catch (err) {
    // ignore
  }
  if (bodyIndicatesNotFound(lastBody)) {
    return res.status(404).json({ error: 'Conta nao encontrada ou protegida no X.' });
  }
  return res.status(502).json({ error: 'Falha ao gerar RSS do X.' });
});

// Listar todos os feeds
app.get('/feeds', (req, res) => {
  res.json(feeds);
});

// Verificar status de feeds
app.post('/feeds/status', async (req, res) => {
  const urls = Array.isArray(req.body?.urls) ? req.body.urls : [];
  if (!urls.length) {
    return res.json({ ok: true, items: [] });
  }
  const uniqueUrls = Array.from(new Set(urls.map(url => String(url).trim()).filter(Boolean))).slice(0, 60);
  const tasks = uniqueUrls.map(url => async () => ({
    url,
    ...(await checkFeedStatus(url))
  }));
  const items = await runWithLimit(tasks, 5);
  res.json({ ok: true, items });
});

// Adicionar novo feed
app.post('/feeds', (req, res) => {
  const { name, url, showOnTimeline, sourceUrl, language } = req.body;
  if (!name || !url) {
    return res.status(400).json({ error: 'Nome e URL sÃ£o obrigatÃ³rios.' });
  }
  const newFeed = { id: uuidv4(), name, url, showOnTimeline: !!showOnTimeline, sourceUrl: sourceUrl || '', language: normalizeFeedLanguage(language) };
  feeds.push(newFeed);
  saveFeeds(feeds);
  res.status(201).json(newFeed);
});

// Remover feed
app.delete('/feeds/:id', (req, res) => {
  const { id } = req.params;
  feeds = feeds.filter(feed => feed.id !== id);
  saveFeeds(feeds);
  res.status(204).send();
});

// Editar feed
app.put('/feeds/:id', (req, res) => {
  const { id } = req.params;
  const { name, url, showOnTimeline, sourceUrl, language } = req.body;
  const feed = feeds.find(f => f.id === id);
  if (!feed) return res.status(404).json({ error: 'Feed nÃ£o encontrado.' });
  if (name !== undefined) feed.name = name;
  if (url !== undefined) feed.url = url;
  if (showOnTimeline !== undefined) feed.showOnTimeline = !!showOnTimeline;
  if (sourceUrl !== undefined) feed.sourceUrl = sourceUrl;
  if (language !== undefined) feed.language = normalizeFeedLanguage(language);
  saveFeeds(feeds);
  res.json(feed);
});

function normalizeUserRole(role) {
  const value = String(role || '').toLowerCase();
  if (value === 'admin' || value === 'editor' || value === 'viewer') return value;
  return 'viewer';
}

function normalizePlan(plan) {
  const value = String(plan || '').toLowerCase();
  if (value === 'starter' || value === 'pro' || value === 'business' || value === 'enterprise') {
    return value;
  }
  return 'starter';
}

const planRank = (plan) => {
  switch (normalizePlan(plan)) {
    case 'enterprise':
      return 4;
    case 'business':
      return 3;
    case 'pro':
      return 2;
    case 'starter':
    default:
      return 1;
  }
};

const ensureUserPlanAtLeast = (email, minimumPlan) => {
  const normalizedEmail = String(email || '').trim().toLowerCase();
  if (!normalizedEmail) return;
  const targetRank = planRank(minimumPlan);
  const existing = users.find(user => user.email === normalizedEmail);
  if (existing) {
    if (planRank(existing.plan) < targetRank) {
      existing.plan = normalizePlan(minimumPlan);
      existing.updatedAt = new Date().toISOString();
      saveUsers(users);
    }
    return;
  }
  const now = new Date().toISOString();
  const created = {
    id: uuidv4(),
    name: normalizedEmail.split('@')[0],
    email: normalizedEmail,
    role: 'viewer',
    plan: normalizePlan(minimumPlan),
    active: true,
    createdAt: now,
    updatedAt: now
  };
  users = [created, ...users];
  saveUsers(users);
};

const createNotification = (payload) => {
  const now = new Date().toISOString();
  const item = {
    id: uuidv4(),
    type: payload.type || 'task',
    email: String(payload.email || '').toLowerCase(),
    title: String(payload.title || '').trim(),
    message: String(payload.message || '').trim(),
    meta: payload.meta || {},
    read: false,
    createdAt: now
  };
  notifications = [item, ...notifications];
  saveNotifications(notifications);
  sendTaskEvent(item.email, { type: 'notification', notification: item });
  return item;
};

const markNotificationsRead = (email, ids) => {
  const idSet = new Set(ids);
  let changed = false;
  notifications = notifications.map((item) => {
    if (item.email === email && idSet.has(item.id)) {
      if (!item.read) {
        changed = true;
      }
      return { ...item, read: true };
    }
    return item;
  });
  if (changed) {
    saveNotifications(notifications);
  }
};

const taskStreams = new Map();
const sendTaskEvent = (email, payload) => {
  const normalized = String(email || '').toLowerCase();
  if (!normalized) return;
  const streams = taskStreams.get(normalized);
  if (!streams || streams.size === 0) return;
  const data = JSON.stringify(payload);
  streams.forEach((res) => {
    res.write(`event: task\n`);
    res.write(`data: ${data}\n\n`);
  });
};

const normalizeUserPayload = (payload, current = {}) => {
  const next = { ...current };
  if (payload.name !== undefined) {
    next.name = String(payload.name || '').trim();
  }
  if (payload.email !== undefined) {
    next.email = String(payload.email || '').trim().toLowerCase();
  }
  if (payload.role !== undefined) {
    next.role = normalizeUserRole(payload.role);
  }
  if (payload.plan !== undefined) {
    next.plan = normalizePlan(payload.plan);
  }
  if (payload.active !== undefined) {
    next.active = payload.active !== false;
  }
  if (payload.approved !== undefined) {
    next.approved = payload.approved === true;
    if (next.approved && !next.approvedAt) {
      next.approvedAt = new Date().toISOString();
    }
    if (!next.approved) {
      next.approvedAt = null;
    }
  }
  return next;
};

const isAdminRequest = (req) => {
  const email = String(req.user?.email || '').toLowerCase();
  if (!email) return false;
  const meta = users.find(user => user.email === email);
  return meta?.role === 'admin';
};

const requireAdmin = (req, res) => {
  if (!isAdminRequest(req)) {
    res.status(403).json({ error: 'Acesso restrito ao administrador.' });
    return false;
  }
  return true;
};

// Usuarios admin
app.get('/admin/users', (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.json(users);
});

app.post('/admin/users', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const payload = req.body || {};
  const name = String(payload.name || '').trim();
  const email = String(payload.email || '').trim().toLowerCase();
  if (!name || !email) {
    return res.status(400).json({ error: 'Nome e email sao obrigatorios.' });
  }
  if (users.some(user => user.email === email)) {
    return res.status(409).json({ error: 'Email ja cadastrado.' });
  }
  const now = new Date().toISOString();
  const user = normalizeUserPayload(payload, {
    id: uuidv4(),
    name,
    email,
    role: normalizeUserRole(payload.role),
    plan: normalizePlan(payload.plan),
    active: payload.active !== false,
    approved: payload.approved === undefined ? true : payload.approved === true,
    approvedAt: payload.approved === false ? null : new Date().toISOString(),
    createdAt: now,
    updatedAt: now
  });
  users = [user, ...users];
  saveUsers(users);
  res.status(201).json(user);
});

app.put('/admin/users/:id', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const { id } = req.params;
  const existing = users.find(user => user.id === id);
  if (!existing) {
    return res.status(404).json({ error: 'Usuario nao encontrado.' });
  }
  const next = normalizeUserPayload(req.body || {}, existing);
  if (!next.name || !next.email) {
    return res.status(400).json({ error: 'Nome e email sao obrigatorios.' });
  }
  if (users.some(user => user.email === next.email && user.id !== id)) {
    return res.status(409).json({ error: 'Email ja cadastrado.' });
  }
  next.updatedAt = new Date().toISOString();
  users = users.map(user => (user.id === id ? next : user));
  saveUsers(users);
  res.json(next);
});

app.delete('/admin/users/:id', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const { id } = req.params;
  const exists = users.some(user => user.id === id);
  if (!exists) {
    return res.status(404).json({ error: 'Usuario nao encontrado.' });
  }
  users = users.filter(user => user.id !== id);
  saveUsers(users);
  res.status(204).send();
});

const normalizeTeamRole = (role) => {
  const value = String(role || '').toLowerCase();
  if (value === 'admin' || value === 'editor' || value === 'viewer') return value;
  return 'viewer';
};

const normalizeTeamList = (input) => {
  if (Array.isArray(input)) {
    return input.map(item => String(item || '').trim()).filter(Boolean);
  }
  if (typeof input === 'string') {
    return input.split(',').map(item => item.trim()).filter(Boolean);
  }
  return [];
};

const findTeamById = (id) => teams.find(team => team.id === id);
const canAccessTeam = (req, team) => {
  if (!team) return false;
  if (isAdminRequest(req)) return true;
  const email = String(req.user?.email || '').toLowerCase();
  if (!email) return false;
  if (team.ownerEmail && team.ownerEmail === email) return true;
  return (team.members || []).some(member => member.email === email);
};

const canManageTeam = (req, team) => {
  if (!team) return false;
  if (isAdminRequest(req)) return true;
  const email = String(req.user?.email || '').toLowerCase();
  if (!email) return false;
  if (team.ownerEmail && team.ownerEmail === email) return true;
  const member = (team.members || []).find(item => item.email === email);
  return member?.role === 'admin';
};

// Times
app.get('/teams', (req, res) => {
  if (isAdminRequest(req)) {
    return res.json(teams);
  }
  const email = String(req.user?.email || '').toLowerCase();
  const scoped = teams.filter(team => (
    team.ownerEmail === email
    || (team.members || []).some(member => member.email === email)
  ));
  return res.json(scoped);
});

app.post('/teams', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const payload = req.body || {};
  const name = String(payload.name || '').trim();
  if (!name) {
    return res.status(400).json({ error: 'Nome do time e obrigatorio.' });
  }
  const now = new Date().toISOString();
  const team = {
    id: uuidv4(),
    name,
    description: String(payload.description || '').trim(),
    ownerEmail: String(payload.ownerEmail || '').trim().toLowerCase(),
    members: [],
    feedIds: Array.isArray(payload.feedIds) ? payload.feedIds : [],
    alerts: {
      recipients: normalizeTeamList(payload.alerts?.recipients),
      criticalKeywords: normalizeTeamList(payload.alerts?.criticalKeywords)
    },
    tasks: [],
    createdAt: now,
    updatedAt: now
  };
  teams = [team, ...teams];
  saveTeams(teams);
  res.status(201).json(team);
});

app.put('/teams/:id', (req, res) => {
  const { id } = req.params;
  const team = findTeamById(id);
  if (!team) {
    return res.status(404).json({ error: 'Time nao encontrado.' });
  }
  if (!canAccessTeam(req, team)) {
    return res.status(403).json({ error: 'Sem permissao para este time.' });
  }
  const payload = req.body || {};
  if (payload.name !== undefined) team.name = String(payload.name || '').trim();
  if (payload.description !== undefined) team.description = String(payload.description || '').trim();
  if (payload.ownerEmail !== undefined) {
    team.ownerEmail = String(payload.ownerEmail || '').trim().toLowerCase();
  }
  if (payload.feedIds !== undefined && Array.isArray(payload.feedIds)) {
    team.feedIds = payload.feedIds;
  }
  if (payload.alerts) {
    team.alerts = {
      recipients: normalizeTeamList(payload.alerts.recipients),
      criticalKeywords: normalizeTeamList(payload.alerts.criticalKeywords)
    };
  }
  team.updatedAt = new Date().toISOString();
  saveTeams(teams);
  res.json(team);
});

app.delete('/teams/:id', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const { id } = req.params;
  const exists = teams.some(team => team.id === id);
  if (!exists) {
    return res.status(404).json({ error: 'Time nao encontrado.' });
  }
  teams = teams.filter(team => team.id !== id);
  saveTeams(teams);
  res.status(204).send();
});

app.get('/teams/:id/members', (req, res) => {
  const team = findTeamById(req.params.id);
  if (!team) {
    return res.status(404).json({ error: 'Time nao encontrado.' });
  }
  if (!canAccessTeam(req, team)) {
    return res.status(403).json({ error: 'Sem permissao para este time.' });
  }
  res.json(team.members || []);
});

app.post('/teams/:id/members', (req, res) => {
  const team = findTeamById(req.params.id);
  if (!team) {
    return res.status(404).json({ error: 'Time nao encontrado.' });
  }
  if (!canManageTeam(req, team)) {
    return res.status(403).json({ error: 'Somente admin do time pode adicionar membros.' });
  }
  const payload = req.body || {};
  const name = String(payload.name || '').trim();
  const email = String(payload.email || '').trim().toLowerCase();
  if (!name || !email) {
    return res.status(400).json({ error: 'Nome e email sao obrigatorios.' });
  }
  if ((team.members || []).some(member => member.email === email)) {
    return res.status(409).json({ error: 'Email ja cadastrado no time.' });
  }
  const requesterEmail = String(req.user?.email || '').toLowerCase();
  const requesterMeta = users.find(user => user.email === requesterEmail);
  if (isAdminRequest(req) || planRank(requesterMeta?.plan) >= planRank('business')) {
    ensureUserPlanAtLeast(email, 'business');
  }
  const now = new Date().toISOString();
  const member = {
    id: uuidv4(),
    name,
    email,
    role: normalizeTeamRole(payload.role),
    active: payload.active !== false,
    createdAt: now,
    updatedAt: now
  };
  team.members = [member, ...(team.members || [])];
  team.updatedAt = now;
  saveTeams(teams);
  res.status(201).json(member);
});

app.put('/teams/:id/members/:memberId', (req, res) => {
  const { id, memberId } = req.params;
  const team = findTeamById(id);
  if (!team) {
    return res.status(404).json({ error: 'Time nao encontrado.' });
  }
  if (!canManageTeam(req, team)) {
    return res.status(403).json({ error: 'Somente admin do time pode editar membros.' });
  }
  const member = (team.members || []).find(item => item.id === memberId);
  if (!member) {
    return res.status(404).json({ error: 'Membro nao encontrado.' });
  }
  const payload = req.body || {};
  if (payload.name !== undefined) member.name = String(payload.name || '').trim();
  if (payload.email !== undefined) member.email = String(payload.email || '').trim().toLowerCase();
  if (payload.role !== undefined) member.role = normalizeTeamRole(payload.role);
  if (payload.active !== undefined) member.active = payload.active !== false;
  if ((team.members || []).some(item => item.email === member.email && item.id !== member.id)) {
    return res.status(409).json({ error: 'Email ja cadastrado no time.' });
  }
  member.updatedAt = new Date().toISOString();
  team.updatedAt = member.updatedAt;
  saveTeams(teams);
  res.json(member);
});

app.delete('/teams/:id/members/:memberId', (req, res) => {
  const { id, memberId } = req.params;
  const team = findTeamById(id);
  if (!team) {
    return res.status(404).json({ error: 'Time nao encontrado.' });
  }
  if (!canManageTeam(req, team)) {
    return res.status(403).json({ error: 'Somente admin do time pode remover membros.' });
  }
  const exists = (team.members || []).some(item => item.id === memberId);
  if (!exists) {
    return res.status(404).json({ error: 'Membro nao encontrado.' });
  }
  team.members = (team.members || []).filter(item => item.id !== memberId);
  team.updatedAt = new Date().toISOString();
  saveTeams(teams);
  res.status(204).send();
});

app.get('/teams/:id/feeds', (req, res) => {
  const team = findTeamById(req.params.id);
  if (!team) {
    return res.status(404).json({ error: 'Time nao encontrado.' });
  }
  if (!canAccessTeam(req, team)) {
    return res.status(403).json({ error: 'Sem permissao para este time.' });
  }
  res.json({ feedIds: team.feedIds || [] });
});

app.put('/teams/:id/feeds', (req, res) => {
  const team = findTeamById(req.params.id);
  if (!team) {
    return res.status(404).json({ error: 'Time nao encontrado.' });
  }
  if (!canAccessTeam(req, team)) {
    return res.status(403).json({ error: 'Sem permissao para este time.' });
  }
  const payload = req.body || {};
  team.feedIds = Array.isArray(payload.feedIds) ? payload.feedIds : [];
  team.updatedAt = new Date().toISOString();
  saveTeams(teams);
  res.json({ feedIds: team.feedIds });
});

app.get('/teams/:id/alerts', (req, res) => {
  const team = findTeamById(req.params.id);
  if (!team) {
    return res.status(404).json({ error: 'Time nao encontrado.' });
  }
  if (!canAccessTeam(req, team)) {
    return res.status(403).json({ error: 'Sem permissao para este time.' });
  }
  res.json(team.alerts || { recipients: [], criticalKeywords: [] });
});

app.put('/teams/:id/alerts', (req, res) => {
  const team = findTeamById(req.params.id);
  if (!team) {
    return res.status(404).json({ error: 'Time nao encontrado.' });
  }
  if (!canAccessTeam(req, team)) {
    return res.status(403).json({ error: 'Sem permissao para este time.' });
  }
  const payload = req.body || {};
  team.alerts = {
    recipients: normalizeTeamList(payload.recipients),
    criticalKeywords: normalizeTeamList(payload.criticalKeywords)
  };
  team.updatedAt = new Date().toISOString();
  saveTeams(teams);
  res.json(team.alerts);
});

app.get('/teams/:id/tasks', (req, res) => {
  const team = findTeamById(req.params.id);
  if (!team) {
    return res.status(404).json({ error: 'Time nao encontrado.' });
  }
  if (!canAccessTeam(req, team)) {
    return res.status(403).json({ error: 'Sem permissao para este time.' });
  }
  team.tasks = Array.isArray(team.tasks) ? team.tasks : [];
  res.json(team.tasks);
});

app.post('/teams/:id/tasks', (req, res) => {
  const team = findTeamById(req.params.id);
  if (!team) {
    return res.status(404).json({ error: 'Time nao encontrado.' });
  }
  if (!canManageTeam(req, team)) {
    return res.status(403).json({ error: 'Somente admin do time pode criar tarefas.' });
  }
  const payload = req.body || {};
  const title = String(payload.title || '').trim();
  const assigneeEmail = String(payload.assigneeEmail || '').trim().toLowerCase();
  if (!title || !assigneeEmail) {
    return res.status(400).json({ error: 'Titulo e responsavel sao obrigatorios.' });
  }
  const now = new Date().toISOString();
  const task = {
    id: uuidv4(),
    title,
    description: String(payload.description || '').trim(),
    assigneeEmail,
    assigneeName: String(payload.assigneeName || '').trim(),
    priority: String(payload.priority || 'media').toLowerCase(),
    dueDate: payload.dueDate ? String(payload.dueDate) : '',
    status: 'pendente',
    createdBy: String(req.user?.email || '').toLowerCase(),
    comments: [],
    createdAt: now,
    updatedAt: now
  };
  team.tasks = Array.isArray(team.tasks) ? team.tasks : [];
  team.tasks = [task, ...team.tasks];
  team.updatedAt = now;
  saveTeams(teams);
  sendTaskEvent(assigneeEmail, {
    type: 'task-created',
    task,
    teamId: team.id,
    teamName: team.name
  });
  createNotification({
    type: 'task',
    email: assigneeEmail,
    title: 'Nova tarefa atribuida',
    message: title,
    meta: {
      teamId: team.id,
      teamName: team.name,
      taskId: task.id
    }
  });
  res.status(201).json(task);
});

app.put('/teams/:id/tasks/:taskId', (req, res) => {
  const { id, taskId } = req.params;
  const team = findTeamById(id);
  if (!team) {
    return res.status(404).json({ error: 'Time nao encontrado.' });
  }
  if (!canAccessTeam(req, team)) {
    return res.status(403).json({ error: 'Sem permissao para este time.' });
  }
  team.tasks = Array.isArray(team.tasks) ? team.tasks : [];
  const task = team.tasks.find(item => item.id === taskId);
  if (!task) {
    return res.status(404).json({ error: 'Tarefa nao encontrada.' });
  }
  const email = String(req.user?.email || '').toLowerCase();
  const isManager = canManageTeam(req, team);
  if (!isManager && task.assigneeEmail !== email) {
    return res.status(403).json({ error: 'Sem permissao para editar esta tarefa.' });
  }
  const payload = req.body || {};
  const previousAssignee = task.assigneeEmail;
  if (isManager) {
    if (payload.title !== undefined) task.title = String(payload.title || '').trim();
    if (payload.description !== undefined) task.description = String(payload.description || '').trim();
    if (payload.assigneeEmail !== undefined) {
      task.assigneeEmail = String(payload.assigneeEmail || '').trim().toLowerCase();
    }
    if (payload.assigneeName !== undefined) task.assigneeName = String(payload.assigneeName || '').trim();
    if (payload.priority !== undefined) task.priority = String(payload.priority || '').toLowerCase();
    if (payload.dueDate !== undefined) task.dueDate = String(payload.dueDate || '');
  }
  if (payload.status !== undefined) {
    task.status = String(payload.status || '').toLowerCase();
  }
  task.updatedAt = new Date().toISOString();
  team.updatedAt = task.updatedAt;
  saveTeams(teams);
  if (isManager && payload.assigneeEmail && task.assigneeEmail && task.assigneeEmail !== previousAssignee) {
    createNotification({
      type: 'task',
      email: task.assigneeEmail,
      title: 'Tarefa atribuida',
      message: task.title,
      meta: {
        teamId: team.id,
        teamName: team.name,
        taskId: task.id
      }
    });
    sendTaskEvent(task.assigneeEmail, {
      type: 'task-assigned',
      task,
      teamId: team.id,
      teamName: team.name
    });
    if (previousAssignee) {
      sendTaskEvent(previousAssignee, {
        type: 'task-removed',
        taskId: task.id,
        teamId: team.id
      });
    }
  }
  if (!isManager && payload.status !== undefined) {
    sendTaskEvent(task.assigneeEmail, {
      type: 'task-updated',
      task,
      teamId: team.id,
      teamName: team.name
    });
  }
  res.json(task);
});

app.delete('/teams/:id/tasks/:taskId', (req, res) => {
  const { id, taskId } = req.params;
  const team = findTeamById(id);
  if (!team) {
    return res.status(404).json({ error: 'Time nao encontrado.' });
  }
  if (!canManageTeam(req, team)) {
    return res.status(403).json({ error: 'Somente admin do time pode remover tarefas.' });
  }
  team.tasks = Array.isArray(team.tasks) ? team.tasks : [];
  const task = team.tasks.find(item => item.id === taskId);
  if (!task) {
    return res.status(404).json({ error: 'Tarefa nao encontrada.' });
  }
  team.tasks = team.tasks.filter(item => item.id !== taskId);
  team.updatedAt = new Date().toISOString();
  saveTeams(teams);
  sendTaskEvent(task.assigneeEmail, {
    type: 'task-deleted',
    taskId,
    teamId: team.id
  });
  res.status(204).send();
});

app.post('/teams/:id/tasks/:taskId/comments', (req, res) => {
  const { id, taskId } = req.params;
  const team = findTeamById(id);
  if (!team) {
    return res.status(404).json({ error: 'Time nao encontrado.' });
  }
  if (!canAccessTeam(req, team)) {
    return res.status(403).json({ error: 'Sem permissao para este time.' });
  }
  team.tasks = Array.isArray(team.tasks) ? team.tasks : [];
  const task = team.tasks.find(item => item.id === taskId);
  if (!task) {
    return res.status(404).json({ error: 'Tarefa nao encontrada.' });
  }
  const message = String(req.body?.message || '').trim();
  if (!message) {
    return res.status(400).json({ error: 'Comentario obrigatorio.' });
  }
  const now = new Date().toISOString();
  const comment = {
    id: uuidv4(),
    message,
    authorEmail: String(req.user?.email || '').toLowerCase(),
    authorName: String(req.user?.name || ''),
    createdAt: now
  };
  task.comments = Array.isArray(task.comments) ? task.comments : [];
  task.comments = [...task.comments, comment];
  task.updatedAt = now;
  team.updatedAt = now;
  saveTeams(teams);
  res.status(201).json(comment);
});

app.get('/tasks/my', (req, res) => {
  const email = String(req.user?.email || '').toLowerCase();
  if (!email) {
    return res.json([]);
  }
  const result = [];
  teams.forEach((team) => {
    const tasks = Array.isArray(team.tasks) ? team.tasks : [];
    tasks.forEach((task) => {
      if (task.assigneeEmail === email) {
        result.push({
          ...task,
          teamId: team.id,
          teamName: team.name
        });
      }
    });
  });
  res.json(result);
});

app.get('/stream/tasks', (req, res) => {
  const email = String(req.user?.email || '').toLowerCase();
  if (!email) {
    return res.status(401).end();
  }
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive'
  });
  res.write('\n');
  const set = taskStreams.get(email) || new Set();
  set.add(res);
  taskStreams.set(email, set);
  const heartbeat = setInterval(() => {
    res.write(':keepalive\n\n');
  }, 25000);
  req.on('close', () => {
    clearInterval(heartbeat);
    set.delete(res);
    if (set.size === 0) {
      taskStreams.delete(email);
    }
  });
});

app.get('/notifications/my', (req, res) => {
  const email = String(req.user?.email || '').toLowerCase();
  if (!email) return res.json([]);
  const items = notifications.filter(item => item.email === email && !item.read);
  res.json(items.slice(0, 50));
});

app.put('/notifications/read', (req, res) => {
  const email = String(req.user?.email || '').toLowerCase();
  if (!email) return res.json({ ok: true });
  const ids = Array.isArray(req.body?.ids) ? req.body.ids : [];
  markNotificationsRead(email, ids);
  res.json({ ok: true });
});

// Configuracao de automacao
app.get('/automation', (req, res) => {
  res.json(automationConfig);
});

app.put('/automation', (req, res) => {
  const next = req.body || {};
  automationConfig = {
    credentials: {
      apiKey: next.credentials?.apiKey || '',
      apiSecret: next.credentials?.apiSecret || '',
      accessToken: next.credentials?.accessToken || '',
      accessSecret: next.credentials?.accessSecret || ''
    },
    rules: {
      enabled: !!next.rules?.enabled,
      feedIds: Array.isArray(next.rules?.feedIds) ? next.rules.feedIds : [],
      requireWords: Array.isArray(next.rules?.requireWords) ? next.rules.requireWords : [],
      blockWords: Array.isArray(next.rules?.blockWords) ? next.rules.blockWords : [],
      onlyWithLink: next.rules?.onlyWithLink !== undefined ? !!next.rules.onlyWithLink : true,
      maxPerDay: Number.isFinite(next.rules?.maxPerDay) ? next.rules.maxPerDay : 5,
      minIntervalMinutes: Number.isFinite(next.rules?.minIntervalMinutes) ? next.rules.minIntervalMinutes : 30,
      quietHours: {
        enabled: !!next.rules?.quietHours?.enabled,
        start: next.rules?.quietHours?.start || '22:00',
        end: next.rules?.quietHours?.end || '07:00'
      },
      template: next.rules?.template || '{title} {link}'
    }
  };
  saveAutomation(automationConfig);
  res.json({ ok: true });
});

// Configuracao de resumo diario

app.get('/summary/config', (req, res) => {
  res.json(summaryConfig);
});

app.get('/email/config', (req, res) => {
  res.json(emailConfig);
});

app.put('/email/config', (req, res) => {
  const payload = req.body || {};
  const smtp = payload.smtp || {};
  const summary = payload.summary || {};
  const alerts = payload.alerts || {};
  const normalizeList = (input) => {
    if (Array.isArray(input)) {
      return input.map(item => String(item || '').trim()).filter(Boolean);
    }
    if (typeof input === 'string') {
      return input.split(',').map(item => item.trim()).filter(Boolean);
    }
    return [];
  };
  emailConfig = {
    ...emailConfig,
    enabled: payload.enabled === true,
    from: String(payload.from || emailConfig.from || ''),
    smtp: {
      host: String(smtp.host || emailConfig.smtp.host || ''),
      port: Number(smtp.port || emailConfig.smtp.port || 587),
      secure: smtp.secure === true,
      user: String(smtp.user || emailConfig.smtp.user || ''),
      pass: String(smtp.pass || emailConfig.smtp.pass || '')
    },
    summary: {
      enabled: summary.enabled === true,
      recipients: normalizeList(summary.recipients)
    },
    alerts: {
      enabled: alerts.enabled === true,
      recipients: normalizeList(alerts.recipients),
      criticalKeywords: normalizeList(alerts.criticalKeywords)
    }
  };
  saveEmailConfig(emailConfig);
  res.json(emailConfig);
});

app.post('/email/test', async (req, res) => {
  try {
    if (!emailConfig.enabled) {
      return res.status(400).json({ error: 'Email desativado.' });
    }
    const to = String(req.body?.to || '').trim();
    const recipients = to ? [to] : normalizeEmails(emailConfig.summary?.recipients || emailConfig.alerts?.recipients || []);
    if (!recipients.length) {
      return res.status(400).json({ error: 'Informe um destinatario para teste.' });
    }
    await sendEmail(emailConfig, {
      to: recipients,
      subject: 'Teste de email - Leitor RSS',
      text: 'Este e um email de teste do Leitor RSS.'
    });
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Falha ao enviar teste.' });
  }
});



app.put('/summary/config', (req, res) => {
  const next = req.body || {};
  summaryConfig = {
    enabled: !!next.enabled,
    time: String(next.time || '08:00'),
    maxItems: Number.isFinite(Number(next.maxItems))
      ? Math.max(1, Math.min(50, Number(next.maxItems)))
      : 10,
    lookbackHours: Number.isFinite(Number(next.lookbackHours))
      ? Math.max(1, Math.min(168, Number(next.lookbackHours)))
      : 24
  };
  saveSummaryConfig(summaryConfig);
  res.json({ ok: true });
});

app.get('/summary/preview', async (req, res) => {
  try {
    const aggregated = await buildAggregatedItems();
    const items = buildSummaryItems(
      aggregated,
      summaryConfig.maxItems || 10,
      summaryConfig.lookbackHours || 24
    );
    res.json({ ok: true, items });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message || 'Falha ao gerar preview.' });
  }
});

app.get('/summary/latest', (req, res) => {
  if (!dailySummaryState.latest) {
    return res.json(null);
  }
  res.json(dailySummaryState.latest);
});

// Configuracao de IA
app.get('/ai/config', (req, res) => {
  res.json(aiConfig);
});

app.put('/ai/config', (req, res) => {
  const next = req.body || {};
  aiConfig = {
    enabled: !!next.enabled,
    provider: ['openai', 'gemini', 'copilot'].includes(next.provider) ? next.provider : 'openai',
    openai: {
      apiKey: String(next.openai?.apiKey || '').trim(),
      model: String(next.openai?.model || 'gpt-4o-mini').trim(),
      temperature: Number.isFinite(Number(next.openai?.temperature)) ? Number(next.openai.temperature) : 0.4,
      maxChars: Number.isFinite(Number(next.openai?.maxChars))
        ? Math.max(200, Math.min(1200, Number(next.openai.maxChars)))
        : 600
    },
    gemini: {
      apiKey: String(next.gemini?.apiKey || '').trim(),
      model: String(next.gemini?.model || 'gemini-1.5-flash').trim()
    },
    copilot: {
      apiKey: String(next.copilot?.apiKey || '').trim(),
      baseUrl: String(next.copilot?.baseUrl || '').trim(),
      model: String(next.copilot?.model || 'gpt-4o-mini').trim()
    },
    images: {
      enabled: !!next.images?.enabled,
      provider: next.images?.provider === 'unsplash' ? 'unsplash' : 'unsplash',
      unsplash: {
        accessKey: String(next.images?.unsplash?.accessKey || '').trim(),
        perPage: Number.isFinite(Number(next.images?.unsplash?.perPage))
          ? Math.max(1, Math.min(10, Number(next.images.unsplash.perPage)))
          : 6,
        orientation: ['landscape', 'portrait', 'squarish'].includes(next.images?.unsplash?.orientation)
          ? next.images.unsplash.orientation
          : 'landscape'
      }
    }
  };
  saveAiConfig(aiConfig);
  res.json({ ok: true });
});

  app.post('/ai/rewrite', async (req, res) => {
  if (!aiConfig.enabled) {
    return res.status(400).json({ ok: false, message: 'IA desativada.' });
  }
  if (aiConfig.provider === 'openai' && !aiConfig.openai?.apiKey) {
    return res.status(400).json({ ok: false, message: 'IA desativada ou chave ausente.' });
  }
  if (aiConfig.provider === 'gemini' && !aiConfig.gemini?.apiKey) {
    return res.status(400).json({ ok: false, message: 'Chave do Gemini ausente.' });
  }
  if (aiConfig.provider === 'copilot' && (!aiConfig.copilot?.apiKey || !aiConfig.copilot?.baseUrl)) {
    return res.status(400).json({ ok: false, message: 'Copilot sem chave ou endpoint.' });
  }
  try {
    const item = req.body || {};
    const mode = item.mode === 'twitter' ? 'twitter' : 'default';
    let text = '';
    if (aiConfig.provider === 'openai') {
      text = await rewriteWithOpenAi(item, aiConfig.openai, mode);
    } else if (aiConfig.provider === 'gemini') {
      text = await rewriteWithGemini(item, aiConfig.gemini, aiConfig.openai?.maxChars || 600, mode);
    } else {
      text = await rewriteWithCopilot(item, aiConfig.copilot, aiConfig.openai?.maxChars || 600, mode);
    }
    logEvent({
      level: 'info',
      source: 'ai',
      message: 'Reescrita gerada.',
      detail: `${item.feedName || 'Item'} | ${item.title || item.link || ''}`.trim()
    });
    res.json({ ok: true, text });
  } catch (err) {
    const detail = err.message || String(err);
    const quotaHint = detail.includes('insufficient_quota')
      || detail.includes('You exceeded your current quota')
      || detail.includes('quota');
    logEvent({
      level: 'error',
      source: 'ai',
      message: 'Falha ao reescrever com IA.',
      detail
    });
    if (quotaHint) {
      return res.status(429).json({
        ok: false,
        message: 'Sem saldo na OpenAI. Verifique o billing da conta.'
      });
    }
    res.status(500).json({ ok: false, message: detail || 'Falha ao gerar texto.' });
  }
});

app.post('/ai/hashtags', async (req, res) => {
  if (!aiConfig.enabled) {
    return res.status(400).json({ ok: false, message: 'IA desativada.' });
  }
  if (aiConfig.provider === 'openai' && !aiConfig.openai?.apiKey) {
    return res.status(400).json({ ok: false, message: 'IA desativada ou chave ausente.' });
  }
  if (aiConfig.provider === 'gemini' && !aiConfig.gemini?.apiKey) {
    return res.status(400).json({ ok: false, message: 'Chave do Gemini ausente.' });
  }
  if (aiConfig.provider === 'copilot' && (!aiConfig.copilot?.apiKey || !aiConfig.copilot?.baseUrl)) {
    return res.status(400).json({ ok: false, message: 'Copilot sem chave ou endpoint.' });
  }
  const text = String(req.body?.text || '').trim();
  const maxTags = Math.min(5, Math.max(1, Number(req.body?.maxTags) || 3));
  if (!text) {
    return res.status(400).json({ ok: false, message: 'Texto ausente.' });
  }
  try {
    let tags = [];
    if (aiConfig.provider === 'openai') {
      tags = await generateHashtagsWithOpenAi(text, aiConfig.openai, maxTags);
    } else if (aiConfig.provider === 'gemini') {
      tags = await generateHashtagsWithGemini(text, aiConfig.gemini, maxTags);
    } else {
      tags = await generateHashtagsWithCopilot(text, aiConfig.copilot, maxTags);
    }
    logEvent({
      level: 'info',
      source: 'ai',
      message: 'Hashtags geradas.',
      detail: `Tags: ${tags.length}`
    });
    res.json({ ok: true, tags });
  } catch (err) {
    res.status(400).json({ ok: false, message: err.message || 'Falha ao gerar hashtags.' });
  }
});

app.get('/images/search', async (req, res) => {
  const query = String(req.query.query || '').trim();
  if (!aiConfig.images?.enabled) {
    return res.status(400).json({ ok: false, message: 'Busca de imagens desativada.' });
  }
  if (aiConfig.images.provider !== 'unsplash') {
    return res.status(400).json({ ok: false, message: 'Provedor de imagens nao configurado.' });
  }
  if (!aiConfig.images.unsplash?.accessKey) {
    return res.status(400).json({ ok: false, message: 'Chave do Unsplash ausente.' });
  }
  if (!query) {
    return res.status(400).json({ ok: false, message: 'Informe um termo de busca.' });
  }
  try {
    const perPage = aiConfig.images.unsplash.perPage || 6;
    const orientation = aiConfig.images.unsplash.orientation || 'landscape';
    const url = new URL('https://api.unsplash.com/search/photos');
    url.searchParams.set('query', query);
    url.searchParams.set('per_page', String(perPage));
    url.searchParams.set('orientation', orientation);
    url.searchParams.set('content_filter', 'high');
    const response = await fetch(url.toString(), {
      headers: {
        Authorization: `Client-ID ${aiConfig.images.unsplash.accessKey}`
      }
    });
    const data = await response.json();
    if (!response.ok) {
      const message = data?.errors?.[0] || data?.message || 'Falha ao buscar imagens.';
      return res.status(400).json({ ok: false, message });
    }
    const items = Array.isArray(data.results)
      ? data.results.map((item) => ({
        id: item.id,
        alt: item.alt_description || item.description || 'Imagem',
        photographer: item.user?.name || '',
        photographerUrl: item.user?.links?.html || '',
        pageUrl: item.links?.html || '',
        thumbUrl: item.urls?.small || item.urls?.thumb || '',
        regularUrl: item.urls?.regular || '',
        fullUrl: item.urls?.full || ''
      }))
      : [];
    res.json({ ok: true, items });
  } catch (err) {
    res.status(500).json({ ok: false, message: 'Falha ao buscar imagens.' });
  }
});

app.post('/automation/test', async (req, res) => {
  if (!hasTwitterCredentials(automationConfig)) {
    return res.status(400).json({ error: 'Credenciais incompletas.' });
  }
  try {
    const client = createTwitterClient(automationConfig);
    const stamp = new Date().toISOString();
    const text = `Teste de automaÃ§Ã£o RSS (${stamp})`;
    await client.v2.tweet(text.length > 280 ? text.slice(0, 277) + 'â€¦' : text);
    logEvent({
      level: 'info',
      source: 'automation',
      message: 'Post de teste publicado no X/Twitter.'
    });
    res.json({ ok: true });
  } catch (err) {
    logEvent({
      level: 'error',
      source: 'automation',
      message: 'Falha ao publicar post de teste.',
      detail: err.message || String(err)
    });
    res.status(500).json({ error: 'Falha ao publicar teste.' });
  }
});

app.post('/automation/post', async (req, res) => {
  if (!hasTwitterCredentials(automationConfig)) {
    return res.status(400).json({ ok: false, message: 'Credenciais incompletas.' });
  }
  const eligibility = getAutomationEligibility();
  if (!eligibility.ok) {
    return res.status(400).json({ ok: false, message: eligibility.reason });
  }
  const payload = req.body || {};
  const text = String(payload.text || '').trim();
  if (!text) {
    return res.status(400).json({ ok: false, message: 'Texto vazio.' });
  }
  try {
    const client = createTwitterClient(automationConfig);
    const trimmed = text.length > 280 ? text.slice(0, 277) + 'â€¦' : text;
    await client.v2.tweet(trimmed);
    const now = new Date();
    const postedId = payload.id || payload.link || payload.guid || payload.title;
    automationState.lastPostedAt = now.toISOString();
    automationState.dailyCount = (automationState.dailyCount || 0) + 1;
    if (postedId) {
      automationState.postedIds = [postedId, ...(automationState.postedIds || [])].slice(0, 500);
    }
    saveState(automationState);
    logEvent({
      level: 'info',
      source: 'automation',
      message: 'Post manual publicado no X/Twitter.',
      detail: `${payload.feedName || 'Manual'} | ${payload.title || trimmed.slice(0, 80)}`
    });
    res.json({ ok: true });
  } catch (err) {
    logEvent({
      level: 'error',
      source: 'automation',
      message: 'Falha ao publicar post manual.',
      detail: err.message || String(err)
    });
    res.status(500).json({ ok: false, message: err.message || 'Falha ao publicar.' });
  }
});

app.get('/automation/preview', async (req, res) => {
  try {
    const { candidate, reason } = await getAutomationCandidate();
    if (!candidate) {
      return res.json({ ok: false, reason });
    }
    res.json({ ok: true, candidate });
  } catch (err) {
    res.status(500).json({ ok: false, reason: 'Falha ao gerar preview.' });
  }
});

app.get('/telegram', (req, res) => {
  res.json(telegramConfig);
});

app.put('/telegram', (req, res) => {
  const next = req.body || {};
  telegramConfig = {
    enabled: !!next.enabled,
    botToken: next.botToken || '',
    chatId: next.chatId || '',
    template: next.template || '{title}\n{link}',
    rules: {
      feedIds: Array.isArray(next.rules?.feedIds) ? next.rules.feedIds : [],
      requireWords: Array.isArray(next.rules?.requireWords) ? next.rules.requireWords : [],
      blockWords: Array.isArray(next.rules?.blockWords) ? next.rules.blockWords : [],
      onlyWithLink: typeof next.rules?.onlyWithLink === 'boolean' ? next.rules.onlyWithLink : true,
      maxPerDay: Number.isFinite(Number(next.rules?.maxPerDay)) ? Number(next.rules.maxPerDay) : 20,
      minIntervalMinutes: Number.isFinite(Number(next.rules?.minIntervalMinutes)) ? Number(next.rules.minIntervalMinutes) : 10
    }
  };
  saveTelegram(telegramConfig);
  res.json(telegramConfig);
});

app.post('/telegram/test', async (req, res) => {
  if (!hasTelegramCredentials(telegramConfig)) {
    res.status(400).json({ ok: false, message: 'Credenciais incompletas.' });
    return;
  }
  try {
    await sendTelegramMessage(telegramConfig, 'Teste de envio do Leitor de RSS.');
    logEvent({ level: 'info', source: 'telegram', message: 'Teste enviado no Telegram.' });
    res.json({ ok: true });
  } catch (err) {
    logEvent({ level: 'error', source: 'telegram', message: 'Falha ao testar Telegram.', detail: err.message || String(err) });
    res.status(500).json({ ok: false, message: 'Falha ao enviar teste.' });
  }
});

app.get('/telegram/preview', async (req, res) => {
  try {
    const items = await buildAggregatedItems();
    const candidate = getTelegramCandidate(items);
    if (!candidate) {
      res.json({ ok: true, candidate: null });
      return;
    }
    res.json({
      ok: true,
      candidate: {
        title: candidate.title,
        link: candidate.link,
        feedName: candidate.feedName,
        pubDate: candidate.pubDate,
        isoDate: candidate.isoDate
      }
    });
  } catch (err) {
    res.status(500).json({ ok: false, message: 'Falha ao gerar preview.' });
  }
});

app.get('/whatsapp', (req, res) => {
  res.json(whatsappConfig);
});

app.put('/whatsapp', (req, res) => {
  const next = req.body || {};
  whatsappConfig = {
    enabled: !!next.enabled,
    accessToken: next.accessToken || '',
    phoneNumberId: next.phoneNumberId || '',
    wabaId: next.wabaId || '',
    recipientNumber: next.recipientNumber || '',
    templateName: next.templateName || '',
    templateLanguage: next.templateLanguage || 'pt_BR',
    rules: {
      feedIds: Array.isArray(next.rules?.feedIds) ? next.rules.feedIds : [],
      requireWords: Array.isArray(next.rules?.requireWords) ? next.rules.requireWords : [],
      blockWords: Array.isArray(next.rules?.blockWords) ? next.rules.blockWords : [],
      onlyWithLink: typeof next.rules?.onlyWithLink === 'boolean' ? next.rules.onlyWithLink : true,
      maxPerDay: Number.isFinite(Number(next.rules?.maxPerDay)) ? Number(next.rules.maxPerDay) : 10,
      minIntervalMinutes: Number.isFinite(Number(next.rules?.minIntervalMinutes)) ? Number(next.rules.minIntervalMinutes) : 60
    }
  };
  saveWhatsApp(whatsappConfig);
  res.json(whatsappConfig);
});

app.post('/whatsapp/test', async (req, res) => {
  if (!hasWhatsAppCredentials(whatsappConfig)) {
    res.status(400).json({ ok: false, message: 'Credenciais incompletas.' });
    return;
  }
  try {
    await sendWhatsAppTemplate(whatsappConfig, ['Teste de envio', 'https://example.com', 'Leitor de RSS']);
    logEvent({ level: 'info', source: 'whatsapp', message: 'Teste enviado no WhatsApp.' });
    res.json({ ok: true });
  } catch (err) {
    logEvent({ level: 'error', source: 'whatsapp', message: 'Falha ao testar WhatsApp.', detail: err.message || String(err) });
    res.status(500).json({ ok: false, message: 'Falha ao enviar teste.' });
  }
});

app.get('/whatsapp/preview', async (req, res) => {
  try {
    const items = await buildAggregatedItems();
    const candidate = getWhatsAppCandidate(items);
    if (!candidate) {
      res.json({ ok: true, candidate: null });
      return;
    }
    res.json({
      ok: true,
      candidate: {
        title: candidate.title,
        link: candidate.link,
        feedName: candidate.feedName,
        pubDate: candidate.pubDate,
        isoDate: candidate.isoDate
      }
    });
  } catch (err) {
    res.status(500).json({ ok: false, message: 'Falha ao gerar preview.' });
  }
});

app.get('/trends/config', (req, res) => {
  res.json(trendsConfig);
});

app.put('/trends/config', (req, res) => {
  const next = req.body || {};
  trendsConfig = {
    enabled: !!next.enabled,
    geo: next.geo || 'BR',
    maxItems: Number.isFinite(Number(next.maxItems)) ? Math.max(1, Math.min(50, Number(next.maxItems))) : 10,
    refreshMinutes: Number.isFinite(Number(next.refreshMinutes)) ? Math.max(5, Math.min(120, Number(next.refreshMinutes))) : 10
  };
  saveTrends(trendsConfig);
  res.json(trendsConfig);
});

app.get('/trends', async (req, res) => {
  try {
    const items = await fetchTrendsItems(trendsConfig);
    const explainRequested = ['1', 'true', 'sim'].includes(String(req.query.explain || '').toLowerCase());
    if (!explainRequested || !canUseAiProvider(aiConfig)) {
      return res.json({ ok: true, items });
    }
    const enriched = await Promise.all(items.map(async (item) => {
      const cached = getTrendExplanationFromCache(item.title);
      if (cached) {
        return { ...item, explanation: cached };
      }
      try {
        let explanation = '';
        if (aiConfig.provider === 'openai') {
          explanation = await generateTrendExplanationWithOpenAi(item.title, aiConfig.openai);
        } else if (aiConfig.provider === 'gemini') {
          explanation = await generateTrendExplanationWithGemini(item.title, aiConfig.gemini);
        } else {
          explanation = await generateTrendExplanationWithCopilot(item.title, aiConfig.copilot);
        }
        if (explanation) {
          setTrendExplanationCache(item.title, explanation);
        }
        return { ...item, explanation };
      } catch (err) {
        return { ...item };
      }
    }));
    res.json({ ok: true, items: enriched });
  } catch (err) {
    logEvent({
      level: 'error',
      source: 'trends',
      message: 'Falha ao carregar trends.',
      detail: err.message || String(err)
    });
    res.status(500).json({ ok: false, message: 'Falha ao carregar trends.' });
  }
});

app.get('/polymarket/events', async (req, res) => {
  const limit = Number(req.query.limit) || 40;
  const query = String(req.query.q || '').trim();
  const lang = String(req.query.lang || '').trim();
  const category = String(req.query.category || '').trim();
  try {
    const payload = await fetchPolymarketEvents(limit, query, lang, category);
    let kalshiItems = [];
    try {
      kalshiItems = await fetchKalshiEvents(limit, category);
    } catch (err) {
      logEvent({
        level: 'warning',
        source: 'kalshi',
        message: 'Falha ao carregar Kalshi.',
        detail: err.message || String(err)
      });
    }
    const mergedItems = [...payload.items, ...kalshiItems];
    const sortedItems = mergedItems.sort((a, b) => {
      const volumeA = Number(a.volume || 0);
      const volumeB = Number(b.volume || 0);
      return volumeB - volumeA;
    });
    res.json({
      items: sortedItems || [],
      topics: payload.topics || [],
      worldTopics: payload.worldTopics || [],
      updatedAt: payload.updatedAt ? new Date(payload.updatedAt).toISOString() : new Date().toISOString()
    });
  } catch (err) {
    logEvent({
      level: 'error',
      source: 'polymarket',
      message: 'Falha ao carregar Polymarket.',
      detail: err.message || String(err)
    });
    res.status(500).json({ error: 'Falha ao carregar Polymarket.' });
  }
});

app.get('/telegram/feeds', (req, res) => {
  res.json(telegramFeedsConfig);
});

app.put('/telegram/feeds', (req, res) => {
  telegramFeedsConfig = normalizeTelegramFeeds(req.body || {});
  saveTelegramFeeds(telegramFeedsConfig);
  res.json(telegramFeedsConfig);
});

app.get('/youtube/config', (req, res) => {
  res.json(youtubeConfig);
});

app.put('/youtube/config', (req, res) => {
  youtubeConfig = normalizeYoutubeConfig(req.body || {});
  saveYouTube(youtubeConfig);
  res.json(youtubeConfig);
});

app.get('/youtube/search', async (req, res) => {
  const query = String(req.query.query || '').trim();
  if (!query) {
    res.status(400).json({ ok: false, message: 'Consulta vazia.' });
    return;
  }
  if (!youtubeConfig.enabled) {
    res.status(400).json({ ok: false, message: 'YouTube desativado.' });
    return;
  }
  if (!youtubeConfig.apiKey) {
    res.status(400).json({ ok: false, message: 'Chave da API do YouTube ausente.' });
    return;
  }
  try {
    const params = new URLSearchParams({
      part: 'snippet',
      type: 'video',
      maxResults: String(youtubeConfig.maxResults || 6),
      q: query,
      key: youtubeConfig.apiKey,
      safeSearch: youtubeConfig.safeSearch || 'moderate',
      regionCode: youtubeConfig.region || 'BR',
      relevanceLanguage: youtubeConfig.region === 'BR' ? 'pt' : 'en'
    });
    const url = `https://www.googleapis.com/youtube/v3/search?${params.toString()}`;
    const response = await fetch(url);
    const data = await response.json();
    if (!response.ok || data.error) {
      const message = data?.error?.message || 'Falha ao buscar videos.';
      throw new Error(message);
    }
    const items = (data.items || []).map(item => {
      const snippet = item.snippet || {};
      const videoId = item.id?.videoId || '';
      const thumb = snippet.thumbnails?.medium || snippet.thumbnails?.default || {};
      return {
        id: videoId,
        title: snippet.title || '',
        description: snippet.description || '',
        channelTitle: snippet.channelTitle || '',
        publishedAt: snippet.publishedAt || '',
        thumbnail: thumb.url || '',
        link: videoId ? `https://www.youtube.com/watch?v=${videoId}` : ''
      };
    }).filter(item => item.id);

    if (!items.length) {
      res.json({ ok: true, items: [] });
      return;
    }

    const ids = items.map(item => item.id).join(',');
    const detailParams = new URLSearchParams({
      part: 'contentDetails',
      id: ids,
      key: youtubeConfig.apiKey
    });
    const detailUrl = `https://www.googleapis.com/youtube/v3/videos?${detailParams.toString()}`;
    const detailRes = await fetch(detailUrl);
    const detailData = await detailRes.json();
    if (detailRes.ok && !detailData.error) {
      const durationMap = new Map();
      (detailData.items || []).forEach(entry => {
        durationMap.set(entry.id, parseIsoDuration(entry.contentDetails?.duration));
      });
      items.forEach(item => {
        item.durationSec = durationMap.get(item.id) || 0;
      });
    }
    res.json({ ok: true, items });
  } catch (err) {
    logEvent({
      level: 'error',
      source: 'youtube',
      message: 'Falha ao buscar videos.',
      detail: err.message || String(err)
    });
    res.status(500).json({ ok: false, message: 'Falha ao buscar videos.' });
  }
});

app.get('/site/config', (req, res) => {
  const site = siteStore.sites && siteStore.sites.length ? siteStore.sites[0] : defaultSite;
  res.json(site);
});

app.put('/site/config', (req, res) => {
  const next = normalizeSiteInput(req.body, siteStore.sites && siteStore.sites[0]);
  if (!siteStore.sites || !siteStore.sites.length) {
    siteStore = { sites: [next] };
  } else {
    siteStore.sites[0] = next;
  }
  saveSites(siteStore);
  res.json(next);
});

app.get('/site/:slug', (req, res) => {
  const slug = normalizeSlug(req.params.slug);
  const site = (siteStore.sites || []).find(entry => entry.slug === slug);
  if (!site) {
    res.status(404).json({ ok: false, message: 'Site nÃ†o encontrado.' });
    return;
  }
  res.json(site);
});

app.post('/site/:slug/posts', (req, res) => {
  const slug = normalizeSlug(req.params.slug);
  const site = (siteStore.sites || []).find(entry => entry.slug === slug);
  if (!site) {
    res.status(404).json({ ok: false, message: 'Site n?o encontrado.' });
    return;
  }
  const payload = req.body || {};
  const title = stripHtml(payload.title || '');
  const contentSnippet = stripHtml(payload.contentSnippet || '');
  const link = String(payload.link || '').trim();
  const feedName = stripHtml(payload.feedName || 'Manual');
  const tags = Array.isArray(payload.tags)
    ? payload.tags.map(tag => String(tag).trim()).filter(Boolean)
    : [];
  if (!title && !link) {
    res.status(400).json({ ok: false, message: 'Dados insuficientes.' });
    return;
  }
  const existing = getSitePostsForSlug(slug).find(post => (
    (link && post.link === link) || (title && post.title === title)
  ));
  if (existing) {
    res.json({ ok: true, post: existing });
    return;
  }
  const post = {
    id: uuidv4(),
    slug,
    title,
    contentSnippet,
    link,
    feedName,
    pubDate: payload.pubDate || null,
    isoDate: payload.isoDate || null,
    tags,
    createdAt: new Date().toISOString()
  };
  saveSitePost(post);
  logEvent({
    level: 'info',
    source: 'site',
    message: 'Post publicado no mini site.',
    detail: `${post.title || post.link} | ${slug}`
  });
  res.json({ ok: true, post });
});

app.get('/site/:slug/posts', (req, res) => {
  const slug = normalizeSlug(req.params.slug);
  const site = (siteStore.sites || []).find(entry => entry.slug === slug);
  if (!site) {
    res.status(404).json({ ok: false, message: 'Site n?o encontrado.' });
    return;
  }
  const posts = getSitePostsForSlug(slug)
    .slice()
    .sort((a, b) => getSiteItemTime(b) - getSiteItemTime(a))
    .map(post => ({
      id: post.id,
      title: post.title,
      link: post.link,
      feedName: post.feedName,
      createdAt: post.createdAt,
      pubDate: post.pubDate,
      isoDate: post.isoDate,
      tags: post.tags || []
    }));
  res.json({ ok: true, posts });
});


app.get('/site/:slug/items', async (req, res) => {
  const slug = normalizeSlug(req.params.slug);
  const site = (siteStore.sites || []).find(entry => entry.slug === slug);
  if (!site) {
    res.status(404).json({ ok: false, message: 'Site n?o encontrado.' });
    return;
  }
  try {
    const manualPosts = getSitePostsForSlug(slug).map(post => ({
      title: post.title,
      contentSnippet: post.contentSnippet,
      link: post.link,
      feedName: post.feedName,
      pubDate: post.pubDate,
      isoDate: post.isoDate || post.createdAt,
      tags: post.tags || [],
      createdAt: post.createdAt,
      sortDate: post.createdAt
    }));

    let autoItems = [];
    if (site.automationEnabled !== false) {
      const aggregated = await buildAggregatedItems();
      const filtered = filterSiteItems(aggregated, site);
      autoItems = filtered.map(item => ({
        title: item.title,
        contentSnippet: item.contentSnippet,
        link: item.link,
        feedName: item.feedName,
        pubDate: item.pubDate,
        isoDate: item.isoDate,
        tags: item.tags || [],
        sortDate: item.isoDate || item.pubDate
      }));
    }

    const combined = [...manualPosts, ...autoItems];
    const unique = new Map();
    combined.forEach(item => {
      const key = item.link || item.title;
      if (!key || unique.has(key)) return;
      unique.set(key, item);
    });

    const items = Array.from(unique.values())
      .sort((a, b) => getSiteItemTime(b) - getSiteItemTime(a))
      .slice(0, site.maxItems || 80);

    res.json({ ok: true, items });
  } catch (err) {
    res.status(500).json({ ok: false, message: 'Falha ao carregar items.' });
  }
});

// Influencers: perfis e filas
app.get('/influencers', (req, res) => {
  res.json(influencers);
});

app.get('/influencers/presets', (req, res) => {
  res.json(INFLUENCER_PRESETS);
});

app.post('/influencers', (req, res) => {
  const payload = req.body || {};
  const draft = sanitizeInfluencerPayload(payload);
  if (!draft.name) {
    return res.status(400).json({ ok: false, message: 'Nome obrigatorio.' });
  }
  const created = {
    ...draft,
    id: uuidv4(),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  influencers = [created, ...influencers];
  saveInfluencers(influencers);
  res.status(201).json(created);
});

app.put('/influencers/:id', (req, res) => {
  const { id } = req.params;
  const existing = influencers.find(item => item.id === id);
  if (!existing) {
    return res.status(404).json({ ok: false, message: 'Perfil nao encontrado.' });
  }
  const updated = {
    ...existing,
    ...sanitizeInfluencerPayload(req.body, existing),
    updatedAt: new Date().toISOString()
  };
  influencers = influencers.map(item => (item.id === id ? updated : item));
  saveInfluencers(influencers);
  res.json(updated);
});

app.delete('/influencers/:id', (req, res) => {
  const { id } = req.params;
  const before = influencers.length;
  influencers = influencers.filter(item => item.id !== id);
  if (influencers.length !== before) {
    saveInfluencers(influencers);
  }
  if (influencerQueues && influencerQueues[id]) {
    delete influencerQueues[id];
    saveInfluencerQueues(influencerQueues);
  }
  res.status(204).send();
});

app.get('/influencers/:id/queue', (req, res) => {
  const { id } = req.params;
  const queue = influencerQueues?.[id] || [];
  res.json(queue);
});

app.post('/influencers/:id/queue/generate', async (req, res) => {
  const { id } = req.params;
  const influencer = influencers.find(item => item.id === id);
  if (!influencer) {
    return res.status(404).json({ ok: false, message: 'Perfil nao encontrado.' });
  }
  const useAi = typeof req.body?.useAi === 'boolean' ? req.body.useAi : (influencer.useAi !== false);
  try {
    const queue = await buildInfluencerQueue(influencer, useAi);
    influencerQueues = {
      ...influencerQueues,
      [id]: queue
    };
    saveInfluencerQueues(influencerQueues);
    res.json({ ok: true, items: queue });
  } catch (err) {
    res.status(500).json({ ok: false, message: 'Falha ao gerar fila.' });
  }
});

app.post('/influencers/:id/queue/:itemId/status', (req, res) => {
  const { id, itemId } = req.params;
  const status = String(req.body?.status || '').trim();
  const allowed = new Set(['recommended', 'pending', 'approved', 'discarded']);
  if (!allowed.has(status)) {
    return res.status(400).json({ ok: false, message: 'Status invalido.' });
  }
  const queue = influencerQueues?.[id] || [];
  const updated = queue.map(item => (
    item.id === itemId ? { ...item, status, updatedAt: new Date().toISOString() } : item
  ));
  influencerQueues = {
    ...influencerQueues,
    [id]: updated
  };
  saveInfluencerQueues(influencerQueues);
  res.json({ ok: true });
});

app.post('/influencers/:id/queue/:itemId/publish', async (req, res) => {
  const { id, itemId } = req.params;
  const influencer = influencers.find(item => item.id === id);
  if (!influencer) {
    return res.status(404).json({ ok: false, message: 'Perfil nao encontrado.' });
  }
  const queue = influencerQueues?.[id] || [];
  const item = queue.find(entry => entry.id === itemId);
  if (!item) {
    return res.status(404).json({ ok: false, message: 'Item nao encontrado.' });
  }

  const channels = req.body?.channels || {};
  const autoApprove = req.body?.autoApprove === true;
  const results = { twitter: false, telegram: false, whatsapp: false };
  let summary = '';

  if (influencer.useAi !== false && canUseAiProvider(aiConfig)) {
    try {
      if (aiConfig.provider === 'openai') {
        summary = await rewriteWithOpenAi(item, aiConfig.openai, 'twitter');
      } else if (aiConfig.provider === 'gemini') {
        summary = await rewriteWithGemini(item, aiConfig.gemini, aiConfig.openai?.maxChars || 600, 'twitter');
      } else if (aiConfig.provider === 'copilot') {
        summary = await rewriteWithCopilot(item, aiConfig.copilot, aiConfig.openai?.maxChars || 600, 'twitter');
      }
    } catch (err) {
      summary = '';
    }
  }

  const fallbackText = renderTemplate('{title} {link}', item);
  const tweetText = summary || fallbackText;

  if (channels.twitter) {
    try {
      if (!hasTwitterCredentials(automationConfig)) {
        throw new Error('Credenciais do Twitter ausentes.');
      }
      const client = createTwitterClient(automationConfig);
      await client.v2.tweet(tweetText);
      results.twitter = true;
    } catch (err) {
      logEvent({
        level: 'error',
        source: 'influencer',
        message: 'Falha ao publicar no Twitter.',
        detail: err.message || String(err)
      });
    }
  }

  if (channels.telegram) {
    try {
      if (!hasTelegramCredentials(telegramConfig)) {
        throw new Error('Credenciais do Telegram ausentes.');
      }
      const message = summary
        ? `${summary}\n${item.link || ''}`.trim()
        : renderTelegramTemplate(telegramConfig.template || '{title}\n{link}', item);
      await sendTelegramMessage(telegramConfig, message);
      results.telegram = true;
    } catch (err) {
      logEvent({
        level: 'error',
        source: 'influencer',
        message: 'Falha ao publicar no Telegram.',
        detail: err.message || String(err)
      });
    }
  }

  if (channels.whatsapp) {
    try {
      if (!hasWhatsAppCredentials(whatsappConfig)) {
        throw new Error('Credenciais do WhatsApp ausentes.');
      }
      const params = renderWhatsAppParams(item);
      await sendWhatsAppTemplate(whatsappConfig, params);
      results.whatsapp = true;
    } catch (err) {
      logEvent({
        level: 'error',
        source: 'influencer',
        message: 'Falha ao publicar no WhatsApp.',
        detail: err.message || String(err)
      });
    }
  }

  const publishedChannels = Object.entries(results)
    .filter(([, ok]) => ok)
    .map(([key]) => key);

  const updatedQueue = queue.map(entry => {
    if (entry.id !== itemId) return entry;
    return {
      ...entry,
      status: autoApprove ? 'approved' : entry.status,
      publishedAt: publishedChannels.length ? new Date().toISOString() : entry.publishedAt || null,
      publishedChannels: publishedChannels.length ? publishedChannels : (entry.publishedChannels || [])
    };
  });
  influencerQueues = {
    ...influencerQueues,
    [id]: updatedQueue
  };
  saveInfluencerQueues(influencerQueues);

  if (publishedChannels.length) {
    logEvent({
      level: 'info',
      source: 'influencer',
      message: 'Item publicado pelo influencer.',
      detail: `${item.feedName || 'Feed'} | ${item.title || item.link} | ${publishedChannels.join(', ')}`
    });
  }

  res.json({ ok: true, results, item: updatedQueue.find(entry => entry.id === itemId) });
});

app.get('/tags', (req, res) => {
  res.json(tagConfig);
});

app.put('/tags', (req, res) => {
  const next = req.body || {};
  tagConfig = {
    enabled: !!next.enabled,
    rules: Array.isArray(next.rules) ? next.rules : []
  };
  saveTags(tagConfig);
  res.json({ ok: true });
});

// PrevisÃ£o do tempo
app.get('/weather', async (req, res) => {
  const citiesParam = req.query.cities || '';
  const cities = String(citiesParam)
    .split(',')
    .map((c) => c.trim())
    .filter(Boolean)
    .slice(0, 12);
  if (!cities.length) {
    return res.json([]);
  }
  const cacheKey = cities.join('|').toLowerCase();
  const cached = weatherCache.get(cacheKey);
  if (cached && (Date.now() - cached.updatedAt) < WEATHER_CACHE_TTL_MS) {
    return res.json(cached.data);
  }
  const results = [];
  for (const city of cities) {
    try {
      const data = await getWeatherForCity(city);
      results.push(data);
    } catch (err) {
      logEvent({
        level: 'warning',
        source: 'weather',
        message: 'Falha ao buscar previsÃ£o do tempo.',
        detail: `${city} | ${err.message || err}`
      });
    }
  }
  weatherCache.set(cacheKey, { data: results, updatedAt: Date.now() });
  res.json(results);
});

// Listar eventos
app.get('/events', (req, res) => {
  const limit = Number.parseInt(req.query.limit || '50', 10);
  const safeLimit = Number.isNaN(limit) ? 50 : Math.min(Math.max(limit, 1), 200);
  res.json(events.slice(0, safeLimit));
});

app.get('/public/watch', async (req, res) => {
  try {
    const email = String(req.query.email || '').trim().toLowerCase();
    const topics = watchTopics.filter(topic => topic.enabled !== false);
    if (!topics.length) {
      return res.json({ ok: true, email, items: [], topics: [] });
    }
    const cacheKey = email || 'public';
    const cached = publicWatchCache.get(cacheKey);
    if (cached && (Date.now() - cached.updatedAt) < PUBLIC_WATCH_TTL_MS) {
      return res.json(cached.data);
    }
    const aggregated = await buildAggregatedItems();
    const items = [];
    const seen = new Set();
    for (const item of aggregated) {
      for (const topic of topics) {
        if (!matchesWatchTopic(item, topic)) continue;
        const key = item.link || item.guid || item.title;
        if (!key || seen.has(key)) continue;
        seen.add(key);
        items.push({
          title: item.title || '',
          contentSnippet: item.contentSnippet || '',
          link: item.link || '',
          feedName: item.feedName || '',
          pubDate: item.pubDate || '',
          isoDate: item.isoDate || '',
          topicId: topic.id,
          topicName: topic.name
        });
      }
      if (items.length >= 120) break;
    }
    const payload = {
      ok: true,
      email,
      topics: topics.map(topic => ({ id: topic.id, name: topic.name })),
      items
    };
    publicWatchCache.set(cacheKey, { updatedAt: Date.now(), data: payload });
    res.json(payload);
  } catch (err) {
    res.status(500).json({ ok: false, message: 'Falha ao carregar acompanhamentos.' });
  }
});

// Gerar RSS a partir de uma pÃ¡gina
const BILLING_PLANS = [
  {
    id: 'starter',
    name: 'Starter',
    price: 39,
    description: 'Para uso individual e acompanhamento essencial.',
    features: ['Linha do tempo', 'Salvos', '10 fontes monitoradas'],
    highlight: false
  },
  {
    id: 'pro',
    name: 'Pro',
    price: 99,
    description: 'Para quem precisa de mais sinais e organizacao.',
    features: ['Resumo diario', 'Tendencias', 'Acompanhamentos', '50 fontes monitoradas'],
    highlight: true
  },
  {
    id: 'business',
    name: 'Business',
    price: 249,
    description: 'Para equipes com fluxo editorial estruturado.',
    features: ['Times', 'Repositorio', 'Automacoes', '200 fontes monitoradas'],
    highlight: false
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    price: 499,
    description: 'Para operacoes criticas com volume elevado.',
    features: ['Tudo do Business', 'SLA dedicado', 'Suporte prioritario'],
    highlight: false
  }
];

app.get('/billing/config', (req, res) => {
  res.json({ publicKey: MP_PUBLIC_KEY || '' });
});

app.get('/billing/plans', (req, res) => {
  res.json({ currency: 'BRL', plans: BILLING_PLANS });
});

app.post('/billing/checkout', async (req, res) => {
  try {
    const { planId, email } = req.body || {};
    const plan = BILLING_PLANS.find((item) => item.id === planId);
    if (!plan) {
      return res.status(400).json({ ok: false, message: 'Plano invalido.' });
    }
    if (!MP_ACCESS_TOKEN) {
      return res.status(500).json({ ok: false, message: 'Gateway nao configurado.' });
    }

    const payload = {
      items: [
        {
          title: `Plano ${plan.name} - Radar de Noticias`,
          quantity: 1,
          currency_id: 'BRL',
          unit_price: plan.price
        }
      ],
      metadata: {
        planId: plan.id
      },
      external_reference: `plan_${plan.id}_${Date.now()}`,
      auto_return: 'approved',
      back_urls: {
        success: `${FRONTEND_URL}/beta?checkout=success`,
        failure: `${FRONTEND_URL}/beta?checkout=failure`,
        pending: `${FRONTEND_URL}/beta?checkout=pending`
      }
    };

    if (email) {
      payload.payer = { email: String(email) };
    }

    const mpResponse = await fetch('https://api.mercadopago.com/checkout/preferences', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${MP_ACCESS_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    if (!mpResponse.ok) {
      const errBody = await mpResponse.text();
      return res.status(502).json({ ok: false, message: 'Falha ao iniciar pagamento.', detail: errBody });
    }

    const data = await mpResponse.json();
    res.json({ ok: true, preferenceId: data.id });
  } catch (err) {
    res.status(500).json({ ok: false, message: 'Falha ao iniciar pagamento.' });
  }
});

app.post('/billing/payment', async (req, res) => {
  try {
    const { planId, token, payment_method_id, installments, payer } = req.body || {};
    const plan = BILLING_PLANS.find((item) => item.id === planId);
    if (!plan) {
      return res.status(400).json({ ok: false, message: 'Plano invalido.' });
    }
    if (!MP_ACCESS_TOKEN) {
      return res.status(500).json({ ok: false, message: 'Gateway nao configurado.' });
    }
    if (!payment_method_id) {
      return res.status(400).json({ ok: false, message: 'Dados de pagamento incompletos.' });
    }

    const payload = {
      transaction_amount: plan.price,
      payment_method_id,
      installments: Number(installments) || 1,
      description: `Plano ${plan.name} - Radar de Noticias`,
      statement_descriptor: 'RADAR NOTICIAS',
      payer: {
        email: payer?.email || ''
      },
      metadata: {
        planId: plan.id
      }
    };
    if (token) {
      payload.token = token;
    }
    if (payer?.identification?.type && payer?.identification?.number) {
      payload.payer.identification = {
        type: payer.identification.type,
        number: payer.identification.number
      };
    }

    const idempotencyKey = `pay_${plan.id}_${Date.now()}_${Math.random().toString(16).slice(2)}`;
    console.log('MP payment request', { planId: plan.id, payment_method_id, idempotencyKey });
    const mpResponse = await fetch('https://api.mercadopago.com/v1/payments', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${MP_ACCESS_TOKEN}`,
        'X-Idempotency-Key': idempotencyKey,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    const data = await mpResponse.json();
    if (!mpResponse.ok) {
      console.error('MP payment error', {
        status: mpResponse.status,
        statusText: mpResponse.statusText,
        response: data
      });
      return res.status(502).json({
        ok: false,
        message: 'Falha ao processar pagamento.',
        detail: data
      });
    }

    res.json({ ok: true, status: data.status, detail: data });
  } catch (err) {
    res.status(500).json({ ok: false, message: 'Falha ao processar pagamento.' });
  }
});

app.post('/billing/trial/start', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ ok: false, message: 'Nao autorizado.' });
  }
  const email = String(req.user.email || '').toLowerCase();
  const meta = users.find(user => user.email === email);
  if (!meta) {
    return res.status(404).json({ ok: false, message: 'Usuario nao encontrado.' });
  }
  const now = Date.now();
  meta.trialStartedAt = new Date(now).toISOString();
  meta.trialEndsAt = new Date(now + 7 * 24 * 60 * 60 * 1000).toISOString();
  meta.billingModalSeenAt = new Date(now).toISOString();
  meta.updatedAt = new Date().toISOString();
  saveUsers(users);
  return res.json({
    ok: true,
    trialStartedAt: meta.trialStartedAt,
    trialEndsAt: meta.trialEndsAt
  });
});

app.post('/billing/modal/seen', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ ok: false, message: 'Nao autorizado.' });
  }
  const email = String(req.user.email || '').toLowerCase();
  const meta = users.find(user => user.email === email);
  if (!meta) {
    return res.status(404).json({ ok: false, message: 'Usuario nao encontrado.' });
  }
  meta.billingModalSeenAt = new Date().toISOString();
  meta.updatedAt = new Date().toISOString();
  saveUsers(users);
  return res.json({ ok: true });
});
app.get('/rss', async (req, res) => {
  const { url } = req.query;
  if (!url) {
    return res.status(400).json({ error: 'URL Ã© obrigatÃ³ria.' });
  }
  try {
    const rss = await generateRssFromSite(url);
    const entry = { rss, updatedAt: Date.now() };
    rssCache.set(url, entry);
    pruneRssCache();
    res.set('Content-Type', 'application/rss+xml; charset=utf-8');
    res.send(rss);
  } catch (err) {
    const cached = rssCache.get(url);
    if (cached) {
      logEvent({
        level: 'warning',
        source: 'rss',
        message: 'Falha ao gerar RSS. Servindo cache.',
        detail: `${url} | ${err.message || err}`
      });
      res.set('Content-Type', 'application/rss+xml; charset=utf-8');
      res.set('X-Cache', 'stale');
      return res.send(cached.rss);
    }
    logEvent({
      level: 'error',
      source: 'rss',
      message: 'Falha ao gerar RSS a partir do site.',
      detail: `${url} | ${err.message || err}`
    });
    res.status(500).json({ error: 'NÃ£o foi possÃ­vel gerar RSS.' });
  }
  });

app.post('/rss/generate', async (req, res) => {
  const { url, maxItems, useAi, title, language } = req.body || {};
  if (!url) {
    return res.status(400).json({ error: 'URL Ã© obrigatÃ³ria.' });
  }
  try {
    const robots = await fetchRobotsTxt(url);
    if (!isRobotsAllowed(robots, url)) {
      return res.status(403).json({ error: 'Acesso bloqueado pelo robots.txt.' });
    }
    const result = await generateSmartRss(url, {
      maxItems,
      useAi: useAi !== false
    });
    const fileName = buildGeneratedFileName(url);
    const filePath = path.join(GENERATED_RSS_DIR, fileName);
    fs.mkdirSync(GENERATED_RSS_DIR, { recursive: true });
    fs.writeFileSync(filePath, result.rss, 'utf-8');
    const now = new Date().toISOString();
    const entry = {
      id: uuidv4(),
      url,
      title: title || result.title,
      itemsCount: result.itemsCount,
      language: normalizeFeedLanguage(language),
      fileName,
      createdAt: now,
      updatedAt: now
    };
    generatedRssIndex = [entry, ...generatedRssIndex];
    pruneGeneratedRssIndex();
    saveGeneratedIndex();
    res.status(201).json({ ...entry, feedUrl: `/rss/generated/${entry.id}` });
  } catch (err) {
    logEvent({
      level: 'error',
      source: 'rss-generator',
      message: 'Falha ao gerar RSS inteligente.',
      detail: `${url} | ${err.message || err}`
    });
    res.status(500).json({ error: 'NÃ£o foi possÃ­vel gerar RSS.' });
  }
});

app.get('/rss/generated', (req, res) => {
  const limit = Math.max(1, Math.min(200, Number(req.query.limit) || 50));
  const list = generatedRssIndex
    .slice(0, limit)
    .map(entry => ({ ...entry, feedUrl: `/rss/generated/${entry.id}` }));
  res.json(list);
});

app.get('/rss/generated/:id', (req, res) => {
  const { id } = req.params;
  const entry = generatedRssIndex.find(item => item.id === id);
  if (!entry) {
    return res.status(404).json({ error: 'RSS nÃ£o encontrado.' });
  }
  const filePath = path.join(GENERATED_RSS_DIR, entry.fileName);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'Arquivo RSS nÃ£o encontrado.' });
  }
  const xml = fs.readFileSync(filePath, 'utf-8');
  res.set('Content-Type', 'application/rss+xml; charset=utf-8');
  res.send(xml);
});

app.delete('/rss/generated/:id', (req, res) => {
  const { id } = req.params;
  const entry = generatedRssIndex.find(item => item.id === id);
  if (!entry) {
    return res.status(404).json({ error: 'RSS nÃ£o encontrado.' });
  }
  removeGeneratedFile(entry);
  generatedRssIndex = generatedRssIndex.filter(item => item.id !== id);
  saveGeneratedIndex();
  res.status(204).send();
});

  // Listar itens salvos
  app.get('/saved', (req, res) => {
    res.json(savedItems);
  });

// Salvar item
app.post('/saved', (req, res) => {
  const item = req.body || {};
  const id = item.id || item.link || item.guid || item.title;
  if (!id) {
    return res.status(400).json({ error: 'Item invÃ¡lido.' });
  }
  const existing = savedItems.find(saved => saved.id === id);
  if (existing) return res.status(200).json(existing);

  const saved = {
    id,
    title: item.title || '',
    link: item.link || '',
    feedName: item.feedName || '',
    contentSnippet: item.contentSnippet || '',
    pubDate: item.pubDate || '',
    isoDate: item.isoDate || '',
    source: item.source || ''
  };
  savedItems = [saved, ...savedItems];
  saveSaved(savedItems);
  res.status(201).json(saved);
});

// Remover item salvo
app.delete('/saved/:id', (req, res) => {
  const { id } = req.params;
  const before = savedItems.length;
  savedItems = savedItems.filter(item => item.id !== id);
  if (savedItems.length !== before) {
    saveSaved(savedItems);
  }
  res.status(204).send();
});

// Dashboard: metricas gerais

async function buildDashboardMetrics(periodInput) {
  const period = String(periodInput || '24h').toLowerCase();
  if (
    dashboardMetricsCache.data &&
    dashboardMetricsCache.period === period &&
    (Date.now() - dashboardMetricsCache.updatedAt) < DASHBOARD_CACHE_TTL_MS
  ) {
    return dashboardMetricsCache.data;
  }
  const now = Date.now();
  const rangeMs = period === '30d'
    ? 30 * 24 * 60 * 60 * 1000
    : period === '7d'
      ? 7 * 24 * 60 * 60 * 1000
      : 24 * 60 * 60 * 1000;
  const rangeStart = now - rangeMs;
  const last6h = now - (6 * 60 * 60 * 1000);
  const last24h = now - (24 * 60 * 60 * 1000);
  const errorFeeds = new Set();
  const eventsLastRange = events.filter(event => new Date(event.timestamp).getTime() >= rangeStart);
  const errorEvents = eventsLastRange.filter(event => event.message === 'Falha ao ler feed.');
  const errorFeedCounts = {};
  const errorFeedUrls = {};
  const levelCounts = eventsLastRange.reduce((acc, event) => {
    const level = event.level || 'info';
    acc[level] = (acc[level] || 0) + 1;
    return acc;
  }, {});
  for (const event of errorEvents) {
    const detail = String(event.detail || '');
    const parts = detail.split(' | ').map(part => part.trim());
    const feedName = parts[0] || '';
    const url = parts.find(part => part.startsWith('http'));
    const key = url || parts[0] || detail;
    if (key) errorFeeds.add(key);
    if (feedName) {
      errorFeedCounts[feedName] = (errorFeedCounts[feedName] || 0) + 1;
      if (url) {
        errorFeedUrls[feedName] = url;
      }
    }
  }

  const cached = getAggregatedCache();
  let aggregated = cached.items;
  let pending = false;
  if (!aggregated.length) {
    pending = true;
    scheduleDashboardRefresh();
  }
  const limited = aggregated.slice(0, 600);
  const newsLastRange = limited.filter(item => {
    const date = new Date(item.pubDate || item.isoDate || 0).getTime();
    return date >= rangeStart;
  });
  const newsLast6h = limited.filter(item => {
    const date = new Date(item.pubDate || item.isoDate || 0).getTime();
    return date >= last6h;
  });
  const lastItemDate = limited[0]?.pubDate || limited[0]?.isoDate || '';
  const ages = limited
    .map(item => new Date(item.pubDate || item.isoDate || 0).getTime())
    .filter((value) => !Number.isNaN(value))
    .map(value => Math.max(0, now - value));
  const avgAgeMinutes = ages.length
    ? Math.round((ages.reduce((acc, value) => acc + value, 0) / ages.length) / 60000)
    : 0;

  const dayBuckets = [];
  const dayCount = period === '30d' ? 30 : period === '7d' ? 7 : 1;
  for (let i = dayCount - 1; i >= 0; i -= 1) {
    const day = new Date(now - i * 24 * 60 * 60 * 1000);
    day.setHours(0, 0, 0, 0);
    dayBuckets.push({ day, count: 0 });
  }
  for (const item of aggregated) {
    const date = new Date(item.pubDate || item.isoDate || 0);
    if (Number.isNaN(date.getTime())) continue;
    const dayKey = new Date(date);
    dayKey.setHours(0, 0, 0, 0);
    const bucket = dayBuckets.find(entry => entry.day.getTime() === dayKey.getTime());
    if (bucket) bucket.count += 1;
  }

  const feedCounts = {};
  const tagCounts = {};
  for (const item of limited) {
    const name = item.feedName || 'Feed';
    feedCounts[name] = (feedCounts[name] || 0) + 1;
    if (Array.isArray(item.tags)) {
      item.tags.forEach(tag => {
        if (!tag) return;
        tagCounts[tag] = (tagCounts[tag] || 0) + 1;
      });
    }
  }

  const influencerList = Array.isArray(influencers) ? influencers : [];
  const influencerQueuesList = influencerQueues ? Object.values(influencerQueues) : [];
  const influencerQueueItems = influencerQueuesList.flatMap(list => Array.isArray(list) ? list : []);
  const influencerQueueStats = influencerQueueItems.reduce((acc, item) => {
    const status = item.status || 'pending';
    acc.total += 1;
    acc[status] = (acc[status] || 0) + 1;
    if (item.publishedAt) acc.published += 1;
    return acc;
  }, { total: 0, published: 0 });
  const influencerWithAi = influencerList.filter(item => item.useAi !== false).length;
  const watchAlertsLastRange = watchAlerts.filter(alert => {
    const date = new Date(alert.matchedAt || 0).getTime();
    return date >= rangeStart;
  });
  const aiEvents = eventsLastRange.filter(event => event.source === 'ai');
  const aiRewriteCount = aiEvents.filter(event => event.message === 'Reescrita gerada.').length;
  const aiHashtagCount = aiEvents.filter(event => event.message === 'Hashtags geradas.').length;
  const aiErrorsCount = aiEvents.filter(event => event.level === 'error').length;
  const influencerPublishEvents = eventsLastRange.filter(event => (
    event.source === 'influencer' && event.message === 'Item publicado pelo influencer.'
  ));
  const influencerPublishCount = influencerPublishEvents.length;
  const aiChannelCounts = influencerPublishEvents.reduce((acc, event) => {
    const detail = String(event.detail || '');
    const parts = detail.split(' | ').map(part => part.trim());
    const channelsRaw = parts[2] || '';
    channelsRaw.split(',').map(part => part.trim().toLowerCase()).forEach((channel) => {
      if (!channel) return;
      acc[channel] = (acc[channel] || 0) + 1;
    });
    return acc;
  }, {});

  const aiDayBuckets = [];
  const aiDayIndex = {};
  for (let i = dayCount - 1; i >= 0; i -= 1) {
    const day = new Date(now - i * 24 * 60 * 60 * 1000);
    day.setHours(0, 0, 0, 0);
    const key = day.toISOString().slice(0, 10);
    const entry = { date: key, rewrites: 0, hashtags: 0, total: 0 };
    aiDayBuckets.push(entry);
    aiDayIndex[key] = entry;
  }
  aiEvents.forEach((event) => {
    const date = new Date(event.timestamp || 0);
    if (Number.isNaN(date.getTime())) return;
    const key = new Date(date.setHours(0, 0, 0, 0)).toISOString().slice(0, 10);
    const bucket = aiDayIndex[key];
    if (!bucket) return;
    if (event.message === 'Reescrita gerada.') bucket.rewrites += 1;
    if (event.message === 'Hashtags geradas.') bucket.hashtags += 1;
    bucket.total += 1;
  });
  const topFeeds = Object.entries(feedCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([name, count]) => ({ name, count }));
  const topTags = Object.entries(tagCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([name, count]) => ({ name, count }));
  const topFeedErrors = Object.entries(errorFeedCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([name, count]) => ({ name, count }));

  const hourBuckets = [];
  for (let i = 23; i >= 0; i -= 1) {
    const hour = new Date(now - i * 60 * 60 * 1000);
    hour.setMinutes(0, 0, 0);
    hourBuckets.push({ hour, count: 0 });
  }
  for (const item of limited) {
    const date = new Date(item.pubDate || item.isoDate || 0);
    if (Number.isNaN(date.getTime())) continue;
    if (date.getTime() < last24h) continue;
    const hourKey = new Date(date);
    hourKey.setMinutes(0, 0, 0);
    const bucket = hourBuckets.find(entry => entry.hour.getTime() === hourKey.getTime());
    if (bucket) bucket.count += 1;
  }

  const payload = {
    meta: {
      generatedAt: new Date().toISOString(),
      pending,
      stale: (Date.now() - cached.updatedAt) > AGGREGATED_CACHE_TTL_MS,
      cacheAgeMs: Date.now() - cached.updatedAt
    },
    activity: {
      newsLastRange: newsLastRange.length,
      newsLast6h: newsLast6h.length,
      lastItemDate,
      avgAgeMinutes
    },
    totals: {
      feedsTotal: feeds.length,
      feedsOnTimeline: feeds.filter(feed => feed.enabled !== false).length,
      watchAlertsLastRange: watchAlertsLastRange.length,
      watchTopicsCount: watchTopics.length,
      savedCount: savedItems.length,
      eventsLastRange: eventsLastRange.length,
      errorsLastRange: levelCounts.error || 0,
      warningLastRange: levelCounts.warning || 0
    },
    health: {
      feedsWithError: errorFeeds.size,
      feedHealthPercent: feeds.length
        ? Math.max(0, Math.round((1 - (errorFeeds.size / feeds.length)) * 100))
        : 100
    },
    automation: {
      percent: automationConfig?.rules?.enabled ? 100 : 0,
      twitter: automationConfig?.rules?.enabled && !!automationConfig?.credentials?.apiKey,
      telegram: telegramConfig?.enabled,
      whatsapp: whatsappConfig?.enabled
    },
    influencers: {
      total: influencerList.length,
      withAi: influencerWithAi,
      queueTotal: influencerQueueStats.total || 0,
      queueRecommended: influencerQueueStats.recommended || 0,
      queuePending: influencerQueueStats.pending || 0,
      queueApproved: influencerQueueStats.approved || 0,
      queueDiscarded: influencerQueueStats.discarded || 0,
      published: influencerQueueStats.published || 0
    },
    ai: {
      rewrites: aiRewriteCount,
      hashtags: aiHashtagCount,
      errors: aiErrorsCount,
      influencerPublishes: influencerPublishCount,
      channels: {
        twitter: aiChannelCounts.twitter || 0,
        telegram: aiChannelCounts.telegram || 0,
        whatsapp: aiChannelCounts.whatsapp || 0
      }
    },
    charts: {
      newsPerDay: dayBuckets.map(entry => ({
        date: entry.day.toISOString().slice(0, 10),
        count: entry.count
      })),
      topFeeds,
      topTags,
      feedErrors: topFeedErrors.map(feed => ({
        ...feed,
        url: errorFeedUrls[feed.name] || ''
      })),
      aiPerDay: aiDayBuckets,
      newsPerHour: hourBuckets.map(entry => ({
        hour: entry.hour.getHours(),
        label: `${String(entry.hour.getHours()).padStart(2, '0')}:00`,
        count: entry.count
      }))
    }
  };
  dashboardMetricsCache = { updatedAt: Date.now(), data: payload, period };
  return payload;
}


// Dashboard: metricas gerais
app.get('/dashboard/metrics', async (req, res) => {
  try {
    const payload = await buildDashboardMetrics(req.query.period);
    res.json(payload);
  } catch (err) {
    res.status(500).json({ error: 'Falha ao gerar metricas.' });
  }
});

// Acompanhamentos: temas monitorados
app.get('/watch/topics', (req, res) => {
  res.json(watchTopics);
});

app.get('/watch/settings', (req, res) => {
  const userId = req.query.userId || req.headers['x-user-id'];
  res.json(getWatchSettingsForUser(userId));
});

app.put('/watch/settings', (req, res) => {
  const userId = req.query.userId || req.headers['x-user-id'];
  const next = normalizeWatchSettings(req.body || {});
  setWatchSettingsForUser(userId, next);
  res.json(getWatchSettingsForUser(userId));
});

app.post('/watch/topics', (req, res) => {
  const payload = req.body || {};
  const name = String(payload.name || '').trim();
  const keywords = normalizeWatchKeywords(payload.keywords || []);
  const matchMode = payload.matchMode === 'all' ? 'all' : 'any';
  const enabled = payload.enabled !== false;
  if (!name || !keywords.length) {
    return res.status(400).json({ error: 'Nome e palavras sao obrigatorios.' });
  }
  const topic = {
    id: uuidv4(),
    name,
    keywords,
    matchMode,
    enabled,
    createdAt: new Date().toISOString()
  };
  watchTopics = [topic, ...watchTopics];
  saveWatchTopics(watchTopics);
  res.status(201).json(topic);
});

app.put('/watch/topics/:id', (req, res) => {
  const { id } = req.params;
  const payload = req.body || {};
  const existing = watchTopics.find(topic => topic.id === id);
  if (!existing) {
    return res.status(404).json({ error: 'Tema nao encontrado.' });
  }
  const name = String(payload.name || existing.name || '').trim();
  const keywords = normalizeWatchKeywords(payload.keywords || existing.keywords || []);
  const matchMode = payload.matchMode === 'all' ? 'all' : 'any';
  const enabled = typeof payload.enabled === 'boolean' ? payload.enabled : existing.enabled;
  if (!name || !keywords.length) {
    return res.status(400).json({ error: 'Nome e palavras sao obrigatorios.' });
  }
  const updated = { ...existing, name, keywords, matchMode, enabled };
  watchTopics = watchTopics.map(topic => (topic.id === id ? updated : topic));
  saveWatchTopics(watchTopics);
  res.json(updated);
});

app.delete('/watch/topics/:id', (req, res) => {
  const { id } = req.params;
  const before = watchTopics.length;
  watchTopics = watchTopics.filter(topic => topic.id !== id);
  if (watchTopics.length !== before) {
    saveWatchTopics(watchTopics);
  }
  res.status(204).send();
});

// Acompanhamentos: alertas encontrados
app.get('/watch/alerts', (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 200, 1), 500);
  let items = watchAlerts;
  if (req.query.since) {
    const since = new Date(req.query.since);
    if (!Number.isNaN(since.getTime())) {
      items = items.filter(alert => new Date(alert.matchedAt).getTime() > since.getTime());
    }
  }
  res.json(items.slice(0, limit));
});

app.post('/watch/refresh', async (req, res) => {
  try {
    const items = await buildAggregatedItems();
    const added = updateWatchAlerts(items);
    res.json({ ok: true, added });
  } catch (err) {
    res.status(500).json({ error: 'Falha ao atualizar acompanhamentos.' });
  }
});


// Agregar todos os feeds cadastrados
app.get('/aggregate', async (req, res) => {
  const parser = new Parser();
  let aggregated = [];
  for (const feed of feeds.filter(f => f.showOnTimeline)) {
    try {
      const parsed = await parseFeedWithEncoding(feed.url, parser);
      aggregated = aggregated.concat(parsed.items.map(item => ({
        ...item,
        title: stripHtml(item.title),
        contentSnippet: stripHtml(item.contentSnippet),
        feedName: stripHtml(feed.name),
        feedUrl: feed.url
      })));
    } catch (e) {
      logEvent({
        level: 'error',
        source: 'rss',
        message: 'Falha ao ler feed.',
        detail: `${feed.name} | ${feed.url} | ${e.message || e}`
      });
      // Ignora feeds que nÃ£o puderam ser lidos
    }
  }
  // Ordena por data, se disponÃ­vel
  aggregated.sort((a, b) => {
    const dateA = new Date(a.pubDate || a.isoDate || 0);
    const dateB = new Date(b.pubDate || b.isoDate || 0);
    return dateB - dateA;
  });

  // DeduplicaÃ§Ã£o por tÃ­tulo normalizado
  const grouped = [];
  const seen = new Map();
  for (const item of aggregated) {
    const key = normalizeTitle(item.title) || item.link || item.guid || item.title;
    if (!key) {
      grouped.push({ ...item, sources: [] });
      continue;
    }
    if (!seen.has(key)) {
      const entry = { ...item, sources: [] };
      seen.set(key, entry);
      grouped.push(entry);
      continue;
    }
    const existing = seen.get(key);
    existing.sources.push({
      feedName: item.feedName,
      feedUrl: item.feedUrl,
      link: item.link,
      pubDate: item.pubDate,
      isoDate: item.isoDate
    });
    existing.tags = Array.from(new Set([...(existing.tags || []), ...(item.tags || [])]));
  }

  updateWatchAlerts(grouped);
  res.json(grouped);
});

app.listen(port, () => {
  console.log(`Servidor RSS backend rodando em http://localhost:${port}`);
});

setInterval(() => {
  tryPostAutomation().catch((err) => {
    logEvent({
      level: 'error',
      source: 'automation',
      message: 'Falha ao publicar no X/Twitter.',
      detail: err.message || String(err)
    });
  });
}, 60000);

setInterval(() => {
  runTelegramAutomation().catch((err) => {
    logEvent({
      level: 'error',
      source: 'telegram',
      message: 'Falha ao executar Telegram.',
      detail: err.message || String(err)
    });
  });
}, 60000);

setInterval(() => {
  runWhatsAppAutomation().catch((err) => {
    logEvent({
      level: 'error',
      source: 'whatsapp',
      message: 'Falha ao executar WhatsApp.',
      detail: err.message || String(err)
    });
  });
}, 60000);

setInterval(() => {
  runAlerts().catch((err) => {
    logEvent({
      level: 'error',
      source: 'alert',
      message: 'Falha ao executar alertas.',
      detail: err.message || String(err)
    });
  });
}, 60000);

setInterval(() => {
  runDailySummary().catch((err) => {
    logEvent({
      level: 'error',
      source: 'summary',
      message: 'Falha ao gerar resumo diÃ¡rio.',
      detail: err.message || String(err)
    });
  });
}, 60000);
const { loadTags, saveTags } = require('./tagStorage');
let tagConfig = loadTags();



