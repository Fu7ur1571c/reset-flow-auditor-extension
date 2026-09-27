const STORAGE_KEY = 'reset-url-list';
const RESULTS_KEY = 'reset-audit-results';

const urlInput = document.getElementById('urlInput');
const statusPill = document.getElementById('statusPill');
const targetCount = document.getElementById('targetCount');
const resultsBox = document.getElementById('resultsBox');

const loadBtn = document.getElementById('loadBtn');
const clearBtn = document.getElementById('clearBtn');
const runBtn = document.getElementById('runBtn');

function setStatus(text, tone = 'info') {
  statusPill.textContent = text;
  statusPill.style.borderColor = tone === 'success'
    ? 'rgba(102, 255, 208, 0.35)'
    : tone === 'warn'
      ? 'rgba(255, 175, 95, 0.38)'
      : tone === 'fail'
        ? 'rgba(255, 95, 124, 0.38)'
        : 'rgba(103, 243, 255, 0.4)';
  statusPill.style.color = tone === 'success'
    ? '#b8fce9'
    : tone === 'warn'
      ? '#ffd9a8'
      : tone === 'fail'
        ? '#ffd0d8'
        : '#9be7ff';
}

function appendLog(message, tone = 'info') {
  const line = document.createElement('div');
  line.className = `log-line ${tone}`;
  line.textContent = message;
  resultsBox.prepend(line);
}

function updateTargetCount() {
  const urls = parseInput(urlInput.value);
  targetCount.textContent = String(urls.length);
}

function parseInput(value) {
  return value
    .split(/\n+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function saveUrls() {
  const urls = parseInput(urlInput.value);
  chrome.storage.local.set({ [STORAGE_KEY]: urls });
  updateTargetCount();
}

function loadUrls() {
  chrome.storage.local.get([STORAGE_KEY], ({ [STORAGE_KEY]: urls = [] }) => {
    urlInput.value = (urls || []).join('\n');
    updateTargetCount();
    appendLog(`Loaded ${urls.length} target URLs.`, 'info');
  });
}

function clearUrls() {
  urlInput.value = '';
  chrome.storage.local.set({ [STORAGE_KEY]: [] }, () => {
    updateTargetCount();
    appendLog('Target list cleared.', 'warn');
  });
}

function validateLocalhost(url) {
  try {
    const parsed = new URL(url.startsWith('http') ? url : 'http://' + url);
    const hostname = parsed.hostname;
    return /^(localhost|127\.0\.0\.1|0\.0\.0\.0)$/.test(hostname);
  } catch (e) {
    return false;
  }
}

async function runAudit() {
  let urls = parseInput(urlInput.value);
  if (!urls.length) {
    setStatus('EMPTY', 'warn');
    appendLog('Add at least one localhost URL.', 'warn');
    return;
  }

  // Validate all URLs are localhost
  const invalidUrls = urls.filter(u => !validateLocalhost(u));
  if (invalidUrls.length > 0) {
    setStatus('BLOCKED', 'fail');
    appendLog(`ERROR: Only localhost URLs allowed. Found: ${invalidUrls.slice(0, 2).join(', ')}`, 'fail');
    return;
  }

  // Normalize URLs
  urls = urls.map(u => {
    if (!u.startsWith('http')) return 'http://' + u;
    return u;
  });

  setStatus('RUNNING', 'info');
  chrome.storage.local.set({ [STORAGE_KEY]: urls });
  const allResults = [];

  for (const url of urls) {
    appendLog(`\n>>> Auditing: ${url}`, 'info');
    try {
      const result = await chrome.runtime.sendMessage({
        action: 'exploit',
        target: url
      });

      allResults.push(result);
      chrome.storage.local.set({ [RESULTS_KEY]: allResults });

      // Display results
      const tone = result.status === 'takeover' ? 'success' : result.status === 'error' || result.error ? 'fail' : 'warn';
      appendLog(`Status: ${result.status.toUpperCase()}`, tone);

      if (result.steps && result.steps.length) {
        result.steps.forEach((step) => {
          const stepTone = step.includes('✓') ? 'success' : step.includes('⚠') ? 'warn' : 'info';
          appendLog(`  ${step}`, stepTone);
        });
      }

      if (result.shells && result.shells.length) {
        result.shells.forEach((shell) => {
          appendLog(`  SHELL: ${shell.url} (${shell.method})`, 'success');
        });
      }
    } catch (error) {
      appendLog(`Target error: ${String(error)}`, 'fail');
    }
  }

  setStatus('DONE', 'success');
  appendLog(`\n=== Audit complete for ${urls.length} target(s) ===`, 'success');
}

loadBtn.addEventListener('click', () => {
  loadUrls();
});

clearBtn.addEventListener('click', () => {
  clearUrls();
});

runBtn.addEventListener('click', () => {
  runAudit();
});

urlInput.addEventListener('input', () => {
  updateTargetCount();
});

loadUrls();
