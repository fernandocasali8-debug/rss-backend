const fs = require('fs');
const path = require('path');

const storagePath = path.join(__dirname, 'telegram.json');

const defaultConfig = {
  enabled: false,
  botToken: '',
  chatId: '',
  template: '{title}\n{link}',
  rules: {
    feedIds: [],
    requireWords: [],
    blockWords: [],
    onlyWithLink: true,
    maxPerDay: 20,
    minIntervalMinutes: 10
  }
};

function loadTelegram() {
  try {
    const raw = fs.readFileSync(storagePath, 'utf-8');
    const parsed = JSON.parse(raw);
    return { ...defaultConfig, ...parsed, rules: { ...defaultConfig.rules, ...(parsed.rules || {}) } };
  } catch (e) {
    return { ...defaultConfig };
  }
}

function saveTelegram(config) {
  fs.writeFileSync(storagePath, JSON.stringify(config, null, 2));
}

module.exports = {
  loadTelegram,
  saveTelegram,
  defaultConfig
};
