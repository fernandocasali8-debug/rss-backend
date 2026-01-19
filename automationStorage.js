const fs = require('fs');
const path = require('path');

const AUTOMATION_FILE = path.join(__dirname, 'automation.json');

function loadAutomation() {
  try {
    const data = fs.readFileSync(AUTOMATION_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (e) {
    return {
      credentials: {
        apiKey: '',
        apiSecret: '',
        accessToken: '',
        accessSecret: ''
      },
      rules: {
        enabled: false,
        feedIds: [],
        useWatchTopics: false,
        useAiSummary: false,
        aiMode: 'twitter_cta',
        requireWords: [],
        blockWords: [],
        onlyWithLink: true,
        maxPerDay: 5,
        enforceDailyCap16: false,
        minIntervalMinutes: 30,
        quietHours: {
          enabled: false,
          start: '22:00',
          end: '07:00'
        },
        template: '{title} - {source} {date} {time} {link}'
      }
    };
  }
}

function saveAutomation(data) {
  fs.writeFileSync(AUTOMATION_FILE, JSON.stringify(data, null, 2), 'utf-8');
}

module.exports = { loadAutomation, saveAutomation };
