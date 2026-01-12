const fs = require('fs');
const path = require('path');

const storagePath = path.join(__dirname, 'sites.json');

const defaultSite = {
  slug: 'meu-site',
  title: 'Noticias em destaque',
  subtitle: 'Atualizacoes automaticas do leitor de RSS',
  primaryColor: '#0f172a',
  accentColor: '#f97316',
  backgroundColor: '#f5f1ea',
  surfaceColor: '#ffffff',
  textColor: '#1f2937',
  themeMode: 'dark',
  fontFamily: '"Segoe UI", "Helvetica Neue", Arial, sans-serif',
  automationEnabled: true,
  showTicker: true,
  maxItems: 80,
  menuLinks: [
    { label: 'Inicio', url: '/' }
  ],
  tags: [],
  rules: {
    feedIds: [],
    requireWords: [],
    blockWords: [],
    onlyWithLink: true
  }
};

function loadSites() {
  try {
    const raw = fs.readFileSync(storagePath, 'utf-8');
    const parsed = JSON.parse(raw);
    if (!parsed || !Array.isArray(parsed.sites)) {
      return { sites: [defaultSite] };
    }
    return parsed;
  } catch (e) {
    return { sites: [defaultSite] };
  }
}

function saveSites(data) {
  fs.writeFileSync(storagePath, JSON.stringify(data, null, 2));
}

module.exports = {
  loadSites,
  saveSites,
  defaultSite
};
