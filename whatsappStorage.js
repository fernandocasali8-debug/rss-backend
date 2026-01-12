const fs = require('fs');
const path = require('path');

const storagePath = path.join(__dirname, 'whatsapp.json');

const defaultConfig = {
  enabled: false,
  accessToken: '',
  phoneNumberId: '',
  wabaId: '',
  recipientNumber: '',
  templateName: '',
  templateLanguage: 'pt_BR',
  rules: {
    feedIds: [],
    requireWords: [],
    blockWords: [],
    onlyWithLink: true,
    maxPerDay: 10,
    minIntervalMinutes: 60
  }
};

function loadWhatsApp() {
  try {
    const raw = fs.readFileSync(storagePath, 'utf-8');
    const parsed = JSON.parse(raw);
    return { ...defaultConfig, ...parsed, rules: { ...defaultConfig.rules, ...(parsed.rules || {}) } };
  } catch (e) {
    return { ...defaultConfig };
  }
}

function saveWhatsApp(config) {
  fs.writeFileSync(storagePath, JSON.stringify(config, null, 2));
}

module.exports = {
  loadWhatsApp,
  saveWhatsApp,
  defaultConfig
};
