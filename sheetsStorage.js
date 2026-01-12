const fs = require('fs');
const path = require('path');

const storagePath = path.join(__dirname, 'sheetsConfig.json');

const defaultConfig = {
  users: {}
};

function loadSheetsConfig() {
  try {
    const raw = fs.readFileSync(storagePath, 'utf-8');
    const parsed = JSON.parse(raw);
    return { ...defaultConfig, ...parsed, users: parsed.users || {} };
  } catch (e) {
    return { ...defaultConfig };
  }
}

function saveSheetsConfig(config) {
  fs.writeFileSync(storagePath, JSON.stringify(config, null, 2), 'utf-8');
}

module.exports = {
  loadSheetsConfig,
  saveSheetsConfig
};
