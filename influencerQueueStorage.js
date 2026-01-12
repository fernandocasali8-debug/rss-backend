const fs = require('fs');
const QUEUE_FILE = './influencerQueues.json';

function loadInfluencerQueues() {
  try {
    const data = fs.readFileSync(QUEUE_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (e) {
    return {};
  }
}

function saveInfluencerQueues(queues) {
  fs.writeFileSync(QUEUE_FILE, JSON.stringify(queues, null, 2), 'utf-8');
}

module.exports = { loadInfluencerQueues, saveInfluencerQueues };
