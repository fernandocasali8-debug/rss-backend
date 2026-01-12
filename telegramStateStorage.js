const fs = require('fs');
const path = require('path');

const storagePath = path.join(__dirname, 'telegramState.json');

function loadTelegramState() {
  try {
    const raw = fs.readFileSync(storagePath, 'utf-8');
    return JSON.parse(raw);
  } catch (e) {
    return { lastSentAt: null, dailyDate: null, dailyCount: 0, postedIds: [] };
  }
}

function saveTelegramState(state) {
  fs.writeFileSync(storagePath, JSON.stringify(state, null, 2));
}

module.exports = {
  loadTelegramState,
  saveTelegramState
};
