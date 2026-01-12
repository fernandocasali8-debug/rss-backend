const fs = require('fs');
const path = require('path');

const SUMMARY_FILE = path.join(__dirname, 'summaryConfig.json');

function loadSummaryConfig() {
  try {
    const data = fs.readFileSync(SUMMARY_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (e) {
    return {
      enabled: false,
      time: '08:00',
      maxItems: 10,
      lookbackHours: 24
    };
  }
}

function saveSummaryConfig(data) {
  fs.writeFileSync(SUMMARY_FILE, JSON.stringify(data, null, 2), 'utf-8');
}

module.exports = { loadSummaryConfig, saveSummaryConfig };
