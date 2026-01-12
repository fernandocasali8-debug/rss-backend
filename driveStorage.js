const fs = require('fs');
const path = require('path');

const storagePath = path.join(__dirname, 'driveConfig.json');

const defaultConfig = {
  users: {}
};

function loadDriveConfig() {
  try {
    const raw = fs.readFileSync(storagePath, 'utf-8');
    const parsed = JSON.parse(raw);
    return { ...defaultConfig, ...parsed, users: parsed.users || {} };
  } catch (e) {
    return { ...defaultConfig };
  }
}

function saveDriveConfig(config) {
  fs.writeFileSync(storagePath, JSON.stringify(config, null, 2), 'utf-8');
}

module.exports = {
  loadDriveConfig,
  saveDriveConfig
};
