const fs = require('fs');
const path = require('path');

const ALERTS_FILE = path.join(__dirname, 'watchAlerts.json');

function loadWatchAlerts() {
  try {
    const data = fs.readFileSync(ALERTS_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (e) {
    return [];
  }
}

function saveWatchAlerts(items) {
  fs.writeFileSync(ALERTS_FILE, JSON.stringify(items, null, 2), 'utf-8');
}

module.exports = { loadWatchAlerts, saveWatchAlerts };
