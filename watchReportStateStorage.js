const fs = require('fs');
const path = require('path');

const STORAGE_DIR = process.env.STORAGE_DIR || path.join(__dirname, 'data');
fs.mkdirSync(STORAGE_DIR, { recursive: true });
const STATE_FILE = path.join(STORAGE_DIR, 'watchReportState.json');

function loadWatchReportState() {
  try {
    const raw = fs.readFileSync(STATE_FILE, 'utf-8');
    return JSON.parse(raw);
  } catch (err) {
    return {};
  }
}

function saveWatchReportState(state) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), 'utf-8');
}

module.exports = { loadWatchReportState, saveWatchReportState };

