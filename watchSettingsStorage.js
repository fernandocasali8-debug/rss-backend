const fs = require('fs');
const path = require('path');

let Database;
try {
  Database = require('better-sqlite3');
} catch (err) {
  Database = null;
}

const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'rss.db');
const SETTINGS_FILE = path.join(__dirname, 'watchSettings.json');

const DEFAULT_REPORT = {
  range: '1h',
  maxItems: 5,
  useAi: true,
  aiRewrite: true,
  autoEnabled: false,
  autoIntervalHours: 3,
  activeStart: '08:00',
  activeEnd: '22:00'
};

const DEFAULT_SETTINGS = {
  recencyWeight: 70,
  viewMode: 'list',
  timeRange: '24h',
  sortMode: 'recent',
  topicFilter: 'all',
  newOnly: false,
  report: { ...DEFAULT_REPORT }
};

function normalizeSettings(input) {
  const base = { ...DEFAULT_SETTINGS, ...(input || {}) };
  const report = (base.report && typeof base.report === 'object') ? base.report : {};
  base.report = { ...DEFAULT_REPORT, ...report };
  return base;
}

let dbInstance = null;

function getDb() {
  if (!Database) return null;
  if (dbInstance) return dbInstance;
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    dbInstance = new Database(DB_FILE);
    dbInstance.pragma('journal_mode = WAL');
    dbInstance.exec(`
      CREATE TABLE IF NOT EXISTS watch_settings (
        user_id TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
    `);
    return dbInstance;
  } catch (err) {
    dbInstance = null;
    return null;
  }
}

function readFromDb() {
  const db = getDb();
  if (!db) return null;
  try {
    const rows = db.prepare('SELECT user_id, data FROM watch_settings').all();
    if (!rows.length) return null;
    const settings = { default: normalizeSettings({}), users: {} };
    rows.forEach((row) => {
      if (!row || !row.data) return;
      let parsed = {};
      try {
        parsed = JSON.parse(row.data);
      } catch (err) {
        parsed = {};
      }
      if (row.user_id === 'default') {
        settings.default = normalizeSettings(parsed);
      } else {
        settings.users[row.user_id] = parsed;
      }
    });
    return settings;
  } catch (err) {
    return null;
  }
}

function writeToDb(settings) {
  const db = getDb();
  if (!db) return false;
  try {
    const now = new Date().toISOString();
    const tx = db.transaction(() => {
      db.prepare('DELETE FROM watch_settings').run();
      const insert = db.prepare(
        'INSERT INTO watch_settings (user_id, data, updated_at) VALUES (?, ?, ?)'
      );
      insert.run('default', JSON.stringify(settings.default || {}), now);
      const users = settings.users || {};
      Object.keys(users).forEach((userId) => {
        insert.run(userId, JSON.stringify(users[userId] || {}), now);
      });
    });
    tx();
    return true;
  } catch (err) {
    return false;
  }
}

function migrateFileToDbIfNeeded() {
  const db = getDb();
  if (!db) return;
  try {
    const row = db.prepare('SELECT COUNT(1) as count FROM watch_settings').get();
    if (row && row.count > 0) return;
  } catch (err) {
    return;
  }
  if (!fs.existsSync(SETTINGS_FILE)) return;
  try {
    const data = fs.readFileSync(SETTINGS_FILE, 'utf-8');
    const parsed = JSON.parse(data);
    const settings = parsed && parsed.default
      ? { default: normalizeSettings(parsed.default), users: parsed.users || {} }
      : { default: normalizeSettings(parsed || {}), users: {} };
    writeToDb(settings);
  } catch (err) {
    // ignore
  }
}

function loadWatchSettings() {
  migrateFileToDbIfNeeded();
  const dbSettings = readFromDb();
  if (dbSettings) return dbSettings;
  try {
    const data = fs.readFileSync(SETTINGS_FILE, 'utf-8');
    const parsed = JSON.parse(data);
    if (parsed && parsed.default) {
      return {
        default: normalizeSettings(parsed.default),
        users: parsed.users || {}
      };
    }
    return {
      default: normalizeSettings(parsed || {}),
      users: {}
    };
  } catch (e) {
    return {
      default: normalizeSettings({}),
      users: {}
    };
  }
}

function saveWatchSettings(settings) {
  const payload = {
    default: normalizeSettings(settings.default || settings || {}),
    users: settings.users || {}
  };
  if (writeToDb(payload)) return;
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(payload, null, 2), 'utf-8');
}

module.exports = { loadWatchSettings, saveWatchSettings };
