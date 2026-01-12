const fs = require('fs');
const path = require('path');

const storagePath = path.join(__dirname, 'trends.json');

const defaultConfig = {
  enabled: false,
  geo: 'BR',
  maxItems: 10,
  refreshMinutes: 10
};

function loadTrends() {
  try {
    const raw = fs.readFileSync(storagePath, 'utf-8');
    const parsed = JSON.parse(raw);
    return { ...defaultConfig, ...parsed };
  } catch (e) {
    return { ...defaultConfig };
  }
}

function saveTrends(config) {
  fs.writeFileSync(storagePath, JSON.stringify(config, null, 2));
}

module.exports = {
  loadTrends,
  saveTrends,
  defaultConfig
};
