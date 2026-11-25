'use strict';

const COMMAND_FORMAT = 'secure-session-command';
const COMMAND_DOMAIN = 'secure-session-command-v1\0';
const POLL_MS = 8000;
const FALLBACK_MS = 30000;
const SSE_RETRY_MS = 15000;

let meta = null;
let config = null;
let topic = null;
let publicKey = null;
let vaultKey = null;
let attemptId = null;
let pollTimer = null;
let eventSource = null;
let refreshing = false;
let unlocked = false;
let runnerSeen = false;
const seen = new Set();

function status(message, kind = '') {
  const node = document.getElementById('status');
  node.textContent = message;
  node.className = `status ${kind}`.trim();
}

function payloadState(message) {
  document.getElementById('payload-state').textContent = message;
}

function setBusy(busy) {
  document.getElementById('unlock').disabled = busy;
  document.getElementById('password').disabled = busy;
}

async function fetchJson(url) {
  const response = await fetch(url, {
    cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer',
  });
  if (!response.ok) throw new Error(`Request failed (HTTP ${response.status}).`);
  return response.json();
}

function parseLink() {
  const params = new URLSearchParams(location.hash.replace(/^#/, ''));
  const value = params.get('s') || '';
  if (!/^[a-z0-9_-]{8,64}$/.test(value)) {
    throw new Error('This link is incomplete. Open the link from the workflow run summary.');
  }
  const encoded = params.get('k') || '';
  if (!/^[A-Za-z0-9_-]{100,1024}$/.test(encoded)) {
    throw new Error('This link is missing its session key. Open the link from the workflow run summary.');
  }
  const spki = SessionCrypto.fromBase64Url(encoded);
  if (spki.length < 100 || spki.length > 1024) {
    throw new Error('This link has an invalid session key.');
  }
  return { topic: value, publicKey: SessionCrypto.toBase64(spki) };
}

function validateMeta(value) {
  const expected = {
    format: 'secure-session', version: 1, kdf: 'PBKDF2-HMAC-SHA256',
  };
  for (const [key, wanted] of Object.entries(expected)) {
    if (!value || value[key] !== wanted) throw new Error('This page is not configured for this session.');
  }
  if (!Number.isInteger(value.iterations) || value.iterations < 100000 || value.iterations > 10000000) {
    throw new Error('This page has invalid KDF settings.');
  }
  const salt = SessionCrypto.fromBase64(value.salt || '');
  if (salt.length !== 16) throw new Error('This page has invalid session metadata.');
  return value;
}

function validateConfig(value) {
  if (!value || typeof value.relay !== 'string' || !value.relay.startsWith('https://')) {
    throw new Error('This page has invalid relay settings.');
  }
  return { relay: value.relay.replace(/\/+$/, '') };
}

function messagePayload(row) {
  if (!row || typeof row.message !== 'string') return null;
  try {
    const value = JSON.parse(row.message);
    return value && typeof value === 'object' ? value : null;
  } catch {
    return null;
  }
}

async function relayMessages() {
  const response = await fetch(
    `${config.relay}/${encodeURIComponent(topic)}/json?poll=1&since=all`,
    { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' },
  );
  if (response.status === 404) return [];
  if (!response.ok) throw new Error(`Relay request failed (HTTP ${response.status}).`);
  const text = await response.text();
  const rows = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    try {
      const row = JSON.parse(line);
      if (row && row.event === 'message') rows.push(row);
    } catch {
      // Ignore malformed relay lines.
    }
  }
  return rows;
}

async function relayPublish(payload) {
  const response = await fetch(`${config.relay}/${encodeURIComponent(topic)}`, {
    method: 'POST',
    body: JSON.stringify(payload),
    headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
    cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer',
  });
  if (!response.ok) throw new Error(`Relay publish failed (HTTP ${response.status}).`);
}

async function showCommand(clear) {
  const command = SessionCrypto.utf8Decode(clear).trim();
  if (!command) throw new Error('The session command is empty.');
  document.getElementById('command').value = command;
  document.getElementById('command-panel').classList.remove('hidden');
  unlocked = true;
  setBusy(false);
  stopEvents();
  status('Unlocked. Copy the command and run it on the remote machine.', 'success');
  payloadState('Session ready.');
}

async function tryCommand(key, sealed) {
  const clear = await SessionCrypto.openSealed(
    key, sealed, COMMAND_DOMAIN, COMMAND_FORMAT,
  );
  vaultKey = key;
  await showCommand(clear);
  return true;
}

async function handleMessage(message) {
  if (!message || typeof message.t !== 'string') return;
  if (message.t === 'pub' && typeof message.key === 'string') {
    if (message.key !== publicKey) {
      status('Ignoring an unexpected session key from the relay.', 'error');
      return;
    }
    runnerSeen = true;
    if (!unlocked) {
      status('');
      payloadState('Session ready. Enter the passphrase once.');
    }
    return;
  }
  if (message.t === 'status') {
    if (message.state === 'accepted' && message.id === attemptId) {
      status('Passphrase accepted. Starting the session…', 'success');
      payloadState('The runner is starting the session…');
    } else if (message.state === 'rejected' && message.id === attemptId) {
      vaultKey = null;
      attemptId = null;
      setBusy(false);
      status('Incorrect passphrase. Try again.', 'error');
      payloadState('The runner rejected the passphrase.');
    } else if (message.state === 'ready') {
      if (!unlocked) payloadState('Session ready. Waiting for the encrypted command…');
    } else if (message.state === 'timeout') {
      stopEvents();
      setBusy(false);
      status('The session timed out. Start the workflow again.', 'error');
    } else if (message.state === 'locked') {
      stopEvents();
      setBusy(false);
      status('Too many attempts. Start the workflow again.', 'error');
    }
    return;
  }
  if (message.t === 'cmd' && message.cmd && vaultKey && !unlocked) {
    try {
      await tryCommand(vaultKey, message.cmd);
    } catch {
      // The key has not been accepted yet, or the command is not for this link.
    }
  }
}

async function refresh() {
  if (refreshing || !config || !topic) return;
  refreshing = true;
  try {
    const rows = await relayMessages();
    for (const row of rows) {
      const id = row.id;
      if (typeof id !== 'string' || seen.has(id)) continue;
      seen.add(id);
      await handleMessage(messagePayload(row));
    }
  } finally {
    refreshing = false;
  }
}

function startPolling(interval = POLL_MS) {
  stopPolling();
  pollTimer = setInterval(() => {
    refresh().catch(() => {
      // Keep the last visible state; the next poll retries.
    });
  }, interval);
  refresh().catch(() => {});
}

function stopPolling() {
  if (pollTimer !== null) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

function connectEvents() {
  if (eventSource || !config || !topic || unlocked) return;
  if (typeof EventSource !== 'function') {
    startPolling();
    return;
  }
  startPolling(FALLBACK_MS);
  eventSource = new EventSource(
    `${config.relay}/${encodeURIComponent(topic)}/sse?since=all`,
  );
  eventSource.addEventListener('open', () => {
    stopPolling();
  });
  eventSource.addEventListener('message', (event) => {
    let row = null;
    try {
      row = JSON.parse(event.data);
    } catch {
      return;
    }
    if (!row || row.event !== 'message') return;
    const id = row.id;
    if (typeof id !== 'string' || seen.has(id)) return;
    seen.add(id);
    handleMessage(messagePayload(row)).catch(() => {});
  });
  eventSource.addEventListener('error', () => {
    startPolling(SSE_RETRY_MS);
  });
}

function stopEvents() {
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }
  stopPolling();
}

async function unlock(password) {
  if (!publicKey) throw new Error('This link is missing its session key.');
  if (password.length < 16) throw new Error('The passphrase must be at least 16 characters.');
  const key = await SessionCrypto.deriveKey(password, meta.salt, meta.iterations);

  let sawCommand = false;
  const rows = await relayMessages();
  for (const row of rows) {
    const message = messagePayload(row);
    if (message && message.t === 'cmd' && message.cmd) {
      sawCommand = true;
      try {
        await tryCommand(key, message.cmd);
        return;
      } catch {
        // The command is already published, so the session has been unlocked.
      }
    }
  }
  if (sawCommand) throw new Error('Incorrect passphrase for this session.');

  vaultKey = key;
  attemptId = SessionCrypto.randomHex(12);
  const wrapped = await SessionCrypto.rsaEncrypt(publicKey, key);
  await relayPublish({
    t: 'key', v: 1, id: attemptId, key: SessionCrypto.toBase64(wrapped),
  });
  status('Passphrase sent. Waiting for the runner to accept it…');
  payloadState('The runner is checking the passphrase…');
  connectEvents();
}

async function load() {
  setBusy(true);
  try {
    const link = parseLink();
    topic = link.topic;
    publicKey = link.publicKey;
    meta = validateMeta(await fetchJson('vault.json'));
    config = validateConfig(await fetchJson('config.json'));
    await SessionCrypto.validatePublicKey(publicKey);
    payloadState('Connecting to the session…');
    await refresh();
    if (!runnerSeen) payloadState('Waiting for the session to start…');
    connectEvents();
    setBusy(false);
  } catch (error) {
    const message = error.message || 'Could not load this session.';
    setBusy(false);
    status(message, 'error');
    payloadState('This page could not start the session.');
  }
}

document.getElementById('unlock-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const input = document.getElementById('password');
  const password = input.value;
  if (!password) return;
  setBusy(true);
  status('Deriving the session key locally…');
  try {
    await unlock(password);
    input.value = '';
  } catch (error) {
    setBusy(false);
    status(error.message || 'Could not unlock this session.', 'error');
  }
});

document.getElementById('copy').addEventListener('click', async () => {
  const field = document.getElementById('command');
  try {
    await navigator.clipboard.writeText(field.value);
    status('Command copied. Paste it into the remote shell.', 'success');
  } catch {
    field.focus();
    field.select();
    status('Clipboard blocked. The command is selected; copy it manually.');
  }
});

document.getElementById('clear').addEventListener('click', () => {
  document.getElementById('command').value = '';
  document.getElementById('command-panel').classList.add('hidden');
  vaultKey = null;
  attemptId = null;
  unlocked = false;
  stopEvents();
  setBusy(false);
  status('Command cleared from this page.');
  payloadState('Enter the passphrase again to unlock the session.');
});

load();
