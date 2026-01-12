const { google } = require('googleapis');

function createOAuthClient(clientId, clientSecret, redirectUrl) {
  return new google.auth.OAuth2(clientId, clientSecret, redirectUrl);
}

function getAuthUrl(oauthClient, state) {
  return oauthClient.generateAuthUrl({
    access_type: 'offline',
    scope: [
      'https://www.googleapis.com/auth/drive.file',
      'https://www.googleapis.com/auth/documents'
    ],
    prompt: 'consent',
    include_granted_scopes: true,
    state
  });
}

async function exchangeCode(oauthClient, code) {
  const { tokens } = await oauthClient.getToken(code);
  return tokens;
}

function createDriveClient(oauthClient, tokens) {
  oauthClient.setCredentials(tokens);
  return google.drive({ version: 'v3', auth: oauthClient });
}

function createDocsClient(oauthClient, tokens) {
  oauthClient.setCredentials(tokens);
  return google.docs({ version: 'v1', auth: oauthClient });
}

async function createFolder(drive, name, parentId) {
  const requestBody = {
    name,
    mimeType: 'application/vnd.google-apps.folder'
  };
  if (parentId) {
    requestBody.parents = [parentId];
  }
  const response = await drive.files.create({
    requestBody,
    fields: 'id, name, webViewLink'
  });
  return response.data;
}

async function uploadTextFile(drive, name, content, parentId, mimeType = 'application/json') {
  const requestBody = { name, mimeType };
  if (parentId) {
    requestBody.parents = [parentId];
  }
  const media = { mimeType, body: content };
  const response = await drive.files.create({
    requestBody,
    media,
    fields: 'id, name, webViewLink'
  });
  return response.data;
}

async function createDocument(drive, name, parentId) {
  const requestBody = {
    name,
    mimeType: 'application/vnd.google-apps.document'
  };
  if (parentId) {
    requestBody.parents = [parentId];
  }
  const response = await drive.files.create({
    requestBody,
    fields: 'id, name, webViewLink'
  });
  return response.data;
}

async function insertDocumentText(docs, documentId, text) {
  await docs.documents.batchUpdate({
    documentId,
    requestBody: {
      requests: [
        {
          insertText: {
            location: { index: 1 },
            text
          }
        }
      ]
    }
  });
}

module.exports = {
  createOAuthClient,
  getAuthUrl,
  exchangeCode,
  createDriveClient,
  createFolder,
  uploadTextFile,
  createDocsClient,
  createDocument,
  insertDocumentText
};
