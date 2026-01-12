const fs = require('fs');
const path = require('path');

const STATE_FILE = path.join(__dirname, 'alertState.json');

function loadAlertState() {
  try {
    const data = fs.readFileSync(STATE_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (e) {
    return {
      alertedIds: []
    };
  }
}

function saveAlertState(state) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), 'utf-8');
}

module.exports = { loadAlertState, saveAlertState };
