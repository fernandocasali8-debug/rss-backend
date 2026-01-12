const fs = require('fs');
const FEEDS_FILE = './feeds.json';

function loadFeeds() {
  try {
    const data = fs.readFileSync(FEEDS_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (e) {
    return [];
  }
}

function saveFeeds(feeds) {
  fs.writeFileSync(FEEDS_FILE, JSON.stringify(feeds, null, 2), 'utf-8');
}

module.exports = { loadFeeds, saveFeeds };
