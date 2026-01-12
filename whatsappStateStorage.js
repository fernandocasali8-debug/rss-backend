const fs = require('fs');
const path = require('path');

const storagePath = path.join(__dirname, 'whatsappState.json');

function loadWhatsAppState() {
  try {
    const raw = fs.readFileSync(storagePath, 'utf-8');
    return JSON.parse(raw);
  } catch (e) {
    return { lastSentAt: null, dailyDate: null, dailyCount: 0, postedIds: [] };
  }
}

function saveWhatsAppState(state) {
  fs.writeFileSync(storagePath, JSON.stringify(state, null, 2));
}

module.exports = {
  loadWhatsAppState,
  saveWhatsAppState
};
