const fs = require('fs');
const path = require('path');

const STATE_FILE = path.join(__dirname, 'automationState.json');

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
