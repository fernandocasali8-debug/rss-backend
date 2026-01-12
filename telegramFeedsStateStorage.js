const fs = require('fs');
const path = require('path');

const storagePath = path.join(__dirname, 'telegramFeedsState.json');

const defaultState = {
  lastUpdateId: 0,
  messages: []
};

function loadTelegramFeedsState() {
  try {
    const raw = fs.readFileSync(storagePath, 'utf-8');
    const parsed = JSON.parse(raw);
    return { ...defaultState, ...parsed };
  } catch (e) {
    return { ...defaultState };
  }
}

function saveTelegramFeedsState(state) {
  fs.writeFileSync(storagePath, JSON.stringify(state, null, 2));
}

module.exports = {
  loadTelegramFeedsState,
  saveTelegramFeedsState,
  defaultState
};
