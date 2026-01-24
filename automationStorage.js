const fs = require('fs');
const path = require('path');

const STORAGE_DIR = process.env.STORAGE_DIR || path.join(__dirname, 'data');
fs.mkdirSync(STORAGE_DIR, { recursive: true });
const AUTOMATION_FILE = path.join(STORAGE_DIR, 'automation.json');

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
        maxChars: 4000,
        maxItemsPerPost: 5,
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

