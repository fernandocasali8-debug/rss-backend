const fs = require('fs');
const path = require('path');

const storagePath = path.join(__dirname, 'sitePosts.json');

function loadSitePosts() {
  try {
    const raw = fs.readFileSync(storagePath, 'utf-8');
    const parsed = JSON.parse(raw);
    return parsed && Array.isArray(parsed.posts) ? parsed : { posts: [] };
  } catch (e) {
    return { posts: [] };
  }
}

function saveSitePosts(data) {
  fs.writeFileSync(storagePath, JSON.stringify(data, null, 2));
}

module.exports = {
  loadSitePosts,
  saveSitePosts
};
