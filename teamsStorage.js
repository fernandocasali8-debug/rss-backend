const fs = require('fs');
const path = require('path');

const TEAMS_FILE = path.join(__dirname, 'teams.json');

const loadTeams = () => {
  if (!fs.existsSync(TEAMS_FILE)) return [];
  try {
    const raw = fs.readFileSync(TEAMS_FILE, 'utf-8');
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data : [];
  } catch (err) {
    return [];
  }
};

const saveTeams = (teams) => {
  fs.writeFileSync(TEAMS_FILE, JSON.stringify(teams, null, 2), 'utf-8');
};

module.exports = { loadTeams, saveTeams };
