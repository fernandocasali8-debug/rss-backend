const fs = require('fs');
const path = require('path');

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

function loadWatchSettings() {
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
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2), 'utf-8');
}

module.exports = { loadWatchSettings, saveWatchSettings };
