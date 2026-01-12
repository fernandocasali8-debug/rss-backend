const fs = require('fs');
const path = require('path');

const EVENTS_FILE = path.join(__dirname, 'events.json');

function loadEvents() {
  try {
    const data = fs.readFileSync(EVENTS_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (e) {
    return [];
  }
}

function saveEvents(events) {
  fs.writeFileSync(EVENTS_FILE, JSON.stringify(events, null, 2), 'utf-8');
}

module.exports = { loadEvents, saveEvents };
