const fs = require('fs');
const path = require('path');

const storagePath = path.join(__dirname, 'aiConfig.json');

const defaultConfig = {
  enabled: false,
  provider: 'openai',
  openai: {
    apiKey: '',
    model: 'gpt-4o-mini',
    temperature: 0.4,
    maxChars: 600
  },
  gemini: {
    apiKey: '',
    model: 'gemini-1.5-flash'
  },
  copilot: {
    apiKey: '',
    baseUrl: '',
    model: 'gpt-4o-mini'
  },
  images: {
    enabled: false,
    provider: 'unsplash',
    unsplash: {
      accessKey: '',
      perPage: 6,
      orientation: 'landscape'
    }
  }
};

function loadAiConfig() {
  try {
    const raw = fs.readFileSync(storagePath, 'utf-8');
    const parsed = JSON.parse(raw);
    const merged = { ...defaultConfig, ...parsed };
    if (parsed.apiKey || parsed.model || parsed.temperature || parsed.maxChars) {
      merged.openai = {
        apiKey: parsed.apiKey || merged.openai.apiKey,
        model: parsed.model || merged.openai.model,
        temperature: parsed.temperature ?? merged.openai.temperature,
        maxChars: parsed.maxChars ?? merged.openai.maxChars
      };
    }
    if (parsed.images) {
      merged.images = {
        ...defaultConfig.images,
        ...parsed.images,
        unsplash: {
          ...defaultConfig.images.unsplash,
          ...(parsed.images.unsplash || {})
        }
      };
    }
    return merged;
  } catch (e) {
    return { ...defaultConfig };
  }
}

function saveAiConfig(config) {
  fs.writeFileSync(storagePath, JSON.stringify(config, null, 2));
}

module.exports = {
  loadAiConfig,
  saveAiConfig
};
