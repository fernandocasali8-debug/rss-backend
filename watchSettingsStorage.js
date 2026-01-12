const fs = require('fs');
const path = require('path');

const SETTINGS_FILE = path.join(__dirname, 'watchSettings.json');

function loadWatchSettings() {
  try {
    const data = fs.readFileSync(SETTINGS_FILE, 'utf-8');
    const parsed = JSON.parse(data);
    if (parsed && parsed.default) {
      return parsed;
    }
    return {
      default: parsed || {
        recencyWeight: 70,
        viewMode: 'list',
        timeRange: '24h',
        sortMode: 'recent',
        topicFilter: 'all',
        newOnly: false
      },
      users: {}
    };
  } catch (e) {
    return {
      default: {
        recencyWeight: 70,
        viewMode: 'list',
        timeRange: '24h',
        sortMode: 'recent',
        topicFilter: 'all',
        newOnly: false
      },
      users: {}
    };
  }
}

function saveWatchSettings(settings) {
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2), 'utf-8');
}

module.exports = { loadWatchSettings, saveWatchSettings };
