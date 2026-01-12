const fs = require('fs');
const path = require('path');

const CACHE_FILE = path.join(__dirname, 'rssCache.json');

function loadCache() {
  try {
    const data = fs.readFileSync(CACHE_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (e) {
    return {};
  }
}

function saveCache(cache) {
  fs.writeFileSync(CACHE_FILE, JSON.stringify(cache, null, 2), 'utf-8');
}

module.exports = { loadCache, saveCache };
