const fs = require('fs');
const path = require('path');

const storagePath = path.join(__dirname, 'telegramFeeds.json');

const defaultConfig = {
  enabled: false,
  botToken: '',
  feeds: []
};

function loadTelegramFeeds() {
  try {
    const raw = fs.readFileSync(storagePath, 'utf-8');
    const parsed = JSON.parse(raw);
    return { ...defaultConfig, ...parsed };
  } catch (e) {
    return { ...defaultConfig };
  }
}

function saveTelegramFeeds(config) {
  fs.writeFileSync(storagePath, JSON.stringify(config, null, 2));
}

module.exports = {
  loadTelegramFeeds,
  saveTelegramFeeds,
  defaultConfig
};
