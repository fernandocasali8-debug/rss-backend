const fs = require('fs');
const path = require('path');

const ALERT_FILE = path.join(__dirname, 'alerts.json');

function loadAlerts() {
  try {
    const data = fs.readFileSync(ALERT_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (e) {
    return {
      enabled: false,
      keywords: [],
      matchAll: false,
      matchTitleOnly: false,
      feedIds: []
    };
  }
}

function saveAlerts(data) {
  fs.writeFileSync(ALERT_FILE, JSON.stringify(data, null, 2), 'utf-8');
}

module.exports = { loadAlerts, saveAlerts };
