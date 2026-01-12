const fs = require('fs');
const path = require('path');

const NOTIFICATIONS_FILE = path.join(__dirname, 'notifications.json');

const loadNotifications = () => {
  if (!fs.existsSync(NOTIFICATIONS_FILE)) return [];
  try {
    const raw = fs.readFileSync(NOTIFICATIONS_FILE, 'utf-8');
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data : [];
  } catch (err) {
    return [];
  }
};

const saveNotifications = (items) => {
  fs.writeFileSync(NOTIFICATIONS_FILE, JSON.stringify(items, null, 2), 'utf-8');
};

module.exports = { loadNotifications, saveNotifications };
