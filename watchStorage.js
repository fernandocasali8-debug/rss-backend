const fs = require('fs');
const path = require('path');

const WATCH_FILE = path.join(__dirname, 'watchTopics.json');

function loadWatchTopics() {
  try {
    const data = fs.readFileSync(WATCH_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (e) {
    return [];
  }
}

function saveWatchTopics(items) {
  fs.writeFileSync(WATCH_FILE, JSON.stringify(items, null, 2), 'utf-8');
}

module.exports = { loadWatchTopics, saveWatchTopics };
