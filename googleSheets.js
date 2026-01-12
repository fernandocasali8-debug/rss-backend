const { google } = require('googleapis');

function createOAuthClient(clientId, clientSecret, redirectUrl) {
  return new google.auth.OAuth2(clientId, clientSecret, redirectUrl);
}

function getAuthUrl(oauthClient, state) {
  return oauthClient.generateAuthUrl({
    access_type: 'offline',
    scope: ['https://www.googleapis.com/auth/spreadsheets'],
    prompt: 'consent',
    include_granted_scopes: true,
    state
  });
}

async function exchangeCode(oauthClient, code) {
  const { tokens } = await oauthClient.getToken(code);
  return tokens;
}

function createSheetsClient(oauthClient, tokens) {
  oauthClient.setCredentials(tokens);
  return google.sheets({ version: 'v4', auth: oauthClient });
}

async function ensureSheet(sheets, spreadsheetId, title) {
  const meta = await sheets.spreadsheets.get({ spreadsheetId });
  const exists = (meta.data.sheets || []).some(sheet => sheet.properties?.title === title);
  if (exists) return;
  await sheets.spreadsheets.batchUpdate({
    spreadsheetId,
    requestBody: {
      requests: [{ addSheet: { properties: { title } } }]
    }
  });
}

async function appendRows(sheets, spreadsheetId, title, header, rows) {
  await ensureSheet(sheets, spreadsheetId, title);
  let values = rows;
  const existing = await sheets.spreadsheets.values.get({
    spreadsheetId,
    range: `${title}!A1:Z1`
  });
  const hasHeader = Array.isArray(existing.data.values) && existing.data.values.length > 0;
  if (!hasHeader && header && header.length) {
    values = [header, ...rows];
  }
  await sheets.spreadsheets.values.append({
    spreadsheetId,
    range: `${title}!A1`,
    valueInputOption: 'USER_ENTERED',
    insertDataOption: 'INSERT_ROWS',
    requestBody: { values }
  });
}

module.exports = {
  createOAuthClient,
  getAuthUrl,
  exchangeCode,
  createSheetsClient,
  appendRows
};
