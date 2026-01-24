const fs = require('fs');
const path = require('path');

const STORAGE_DIR = process.env.STORAGE_DIR || path.join(__dirname, 'data');\nfs.mkdirSync(STORAGE_DIR, { recursive: true });\nconst STATE_FILE = path.join(STORAGE_DIR, 'automationState.json');\n

function loadState() {
  try {
    const data = fs.readFileSync(STATE_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (e) {
    return {
      lastPostedAt: null,
      dailyCount: 0,
      dailyDate: null,
      postedIds: []
    };
  }
}

function saveState(state) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), 'utf-8');
}

module.exports = { loadState, saveState };

