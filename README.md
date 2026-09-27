# Reset Flow Auditor

A consent-based Chrome extension scaffold for authorized reset-flow validation on approved URLs.

What this project includes
- Dark cyber UI and modern extension popup layout
- URL list input with one target per line
- Tab-based verification workflow for each target
- Cookie and User-Agent capture from the page context
- Sequence runner that checks for nonce fields, language metadata, reset triggers, and password-change forms
- Local result logging in extension storage

Important usage guardrails
- Only test environments you own or are explicitly authorized to assess.
- Do not point the auditor at public or third-party sites without written permission.
- This project is intentionally designed as a local audit tool with explicit consent and target validation.

Files
- `manifest.json` — extension manifest
- `popup.html` — popup UI
- `popup.css` — cyber theme styling
- `popup.js` — URL management and execution logic

How to load it in Chrome
1. Open `chrome://extensions`
2. Enable Developer mode
3. Click Load unpacked
4. Select this repository folder
5. Open the extension popup and add one target URL per line
6. Click Run Audit

This repository is intentionally scoped to consent-based internal testing workflows.
