const fs = require('fs');
const path = require('path');

const storagePath = path.join(__dirname, 'youtube.json');

const defaultConfig = {
  enabled: false,
  apiKey: '',
  maxResults: 6,
  region: 'BR',
  safeSearch: 'moderate'
};

function loadYouTube() {
  try {
    const raw = fs.readFileSync(storagePath, 'utf-8');
    const parsed = JSON.parse(raw);
    return { ...defaultConfig, ...parsed };
  } catch (e) {
    return { ...defaultConfig };
  }
}

function saveYouTube(config) {
  fs.writeFileSync(storagePath, JSON.stringify(config, null, 2));
}

module.exports = {
  loadYouTube,
  saveYouTube,
  defaultConfig
};
