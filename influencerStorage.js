const fs = require('fs');
const INFLUENCERS_FILE = './influencers.json';

function loadInfluencers() {
  try {
    const data = fs.readFileSync(INFLUENCERS_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (e) {
    return [];
  }
}

function saveInfluencers(influencers) {
  fs.writeFileSync(INFLUENCERS_FILE, JSON.stringify(influencers, null, 2), 'utf-8');
}

module.exports = { loadInfluencers, saveInfluencers };
