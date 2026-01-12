const fs = require('fs');
const path = require('path');

const SAVED_FILE = path.join(__dirname, 'saved.json');

function loadSaved() {
  try {
    const data = fs.readFileSync(SAVED_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (e) {
    return [];
  }
}

function saveSaved(items) {
  fs.writeFileSync(SAVED_FILE, JSON.stringify(items, null, 2), 'utf-8');
}

module.exports = { loadSaved, saveSaved };
