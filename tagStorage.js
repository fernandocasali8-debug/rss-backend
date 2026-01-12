const fs = require('fs');
const path = require('path');

const TAGS_FILE = path.join(__dirname, 'tagConfig.json');

function loadTags() {
  try {
    const data = fs.readFileSync(TAGS_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (e) {
    return {
      enabled: true,
      rules: [
        { name: 'Politica', keywords: ['politica', 'congresso', 'governo', 'eleicao'], matchAll: false },
        { name: 'Economia', keywords: ['economia', 'mercado', 'inflacao', 'juros'], matchAll: false },
        { name: 'Tecnologia', keywords: ['tecnologia', 'software', 'ia', 'inteligencia artificial'], matchAll: false },
        { name: 'Esportes', keywords: ['futebol', 'esporte', 'campeonato', 'gol'], matchAll: false },
        { name: 'Saude', keywords: ['saude', 'medicina', 'hospital', 'vacina'], matchAll: false }
      ]
    };
  }
}

function saveTags(config) {
  fs.writeFileSync(TAGS_FILE, JSON.stringify(config, null, 2), 'utf-8');
}

module.exports = { loadTags, saveTags };
