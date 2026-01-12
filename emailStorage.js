const fs = require('fs');
const path = require('path');

const storagePath = path.join(__dirname, 'emailConfig.json');

const defaultConfig = {
  enabled: false,
  smtp: {
    host: '',
    port: 587,
    secure: false,
    user: '',
    pass: ''
  },
  from: '',
  summary: {
    enabled: false,
    recipients: []
  },
  alerts: {
    enabled: false,
    recipients: [],
    criticalKeywords: []
  }
};

function loadEmailConfig() {
  try {
    const raw = fs.readFileSync(storagePath, 'utf-8');
    const parsed = JSON.parse(raw);
    return {
      ...defaultConfig,
      ...parsed,
      smtp: { ...defaultConfig.smtp, ...(parsed.smtp || {}) },
      summary: { ...defaultConfig.summary, ...(parsed.summary || {}) },
      alerts: { ...defaultConfig.alerts, ...(parsed.alerts || {}) }
    };
  } catch (e) {
    return { ...defaultConfig };
  }
}

function saveEmailConfig(config) {
  fs.writeFileSync(storagePath, JSON.stringify(config, null, 2), 'utf-8');
}

module.exports = {
  loadEmailConfig,
  saveEmailConfig
};
