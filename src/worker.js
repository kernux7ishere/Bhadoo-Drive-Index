// Software: Bhadoo Drive Index (Modern ES Module Worker)
// Backends: Google Drive (OAuth / Service Account via ACCOUNTS_JSON) + Cloudflare R2

import { BUNDLED_APP_JS } from './app_bundle.js';

let environment, domain_for_dl, blocked_region, blocked_asn, CDN_VERSION;
let authConfig, uiConfig, player_config, crypto_base_key, hmac_base_key;
let cdn_base, dev_mode, app_js_file, css_file, homepage_js_file;
let homepage, login_html, ENV, DB;
let configReady = false;
let drivesReady = null;
const gds = [];

function envBool(v, def) {
  if (v === undefined || v === null || v === '') return def;
  return String(v).toLowerCase() === 'true';
}

function envInt(v, def) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : def;
}

function envList(v) {
  if (!v) return [];
  const s = String(v).trim();
  if (s.startsWith('[')) return JSON.parse(s);
  return s.split(',').map(x => x.trim()).filter(Boolean);
}

function envJSON(v, def, name) {
  if (!v) return def;
  try {
    return JSON.parse(v);
  } catch (e) {
    throw new Error(`${name} is not valid JSON`);
  }
}

function pickRandom(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

const ACCOUNT_SECRET_CHUNKS = 9; // ACCOUNTS_JSON, ACCOUNTS_JSON_2 ... ACCOUNTS_JSON_9

class Credential {
  constructor(spec, label) {
    this.label = label;
    this.client_id = spec.client_id;
    this.client_secret = spec.client_secret;
    this.refresh_token = spec.refresh_token;
    this.service_account_json = spec.service_account_json;
    this.accessToken = null;
    this.expires = 0;
    this.pending = null;
  }

  async getAccessToken() {
    if (this.accessToken && this.expires > Date.now()) return this.accessToken;
    if (!this.pending) {
      this.pending = this._refresh().finally(() => { this.pending = null; });
    }
    return this.pending;
  }

  async _refresh() {
    let post_data;
    if (this.service_account_json) {
      const assertion = await JSONWebToken.generateGCPToken(this.service_account_json);
      post_data = { grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion };
    } else {
      post_data = {
        client_id: this.client_id,
        client_secret: this.client_secret,
        refresh_token: this.refresh_token,
        grant_type: 'refresh_token',
      };
    }
    const requestOption = {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: enQuery(post_data),
    };
    let response;
    for (let i = 0; i < 3; i++) {
      response = await fetch('https://www.googleapis.com/oauth2/v4/token', requestOption);
      if (response.ok) break;
      if (response.status >= 400 && response.status < 500 && response.status !== 429) break;
      await sleep(800 * (i + 1));
    }
    if (!response.ok) {
      let code = '';
      try { code = (await response.json()).error || ''; } catch (_) {}
      throw new Error(`Token request failed for account "${this.label}" (HTTP ${response.status}${code ? ' ' + code : ''})`);
    }
    const obj = await response.json();
    if (!obj.access_token) throw new Error(`Token response for account "${this.label}" has no access_token`);
    this.accessToken = obj.access_token;
    this.expires = Date.now() + 3300 * 1000;
    return this.accessToken;
  }
}

function credentialSpec(raw) {
  if (!raw || typeof raw !== 'object') return null;
  if (raw.service_account_json && raw.service_account_json.private_key) return { service_account_json: raw.service_account_json };
  if (raw.client_email && raw.private_key) return { service_account_json: raw };
  if (raw.client_id && raw.client_secret && raw.refresh_token) {
    return { client_id: raw.client_id, client_secret: raw.client_secret, refresh_token: raw.refresh_token };
  }
  return null;
}

function loadAccounts(env) {
  const accounts = [];
  for (let n = 1; n <= ACCOUNT_SECRET_CHUNKS; n++) {
    const key = n === 1 ? 'ACCOUNTS_JSON' : `ACCOUNTS_JSON_${n}`;
    const arr = envJSON(env[key], null, key);
    if (arr === null) continue;
    if (!Array.isArray(arr)) throw new Error(`${key} must be a JSON array`);
    for (const raw of arr) {
      const index = accounts.length;
      const spec = credentialSpec(raw);
      if (!spec) {
        throw new Error(`Account #${index} in ${key} needs client_id + client_secret + refresh_token, or a service account key`);
      }
      const name = String((raw && raw.name) || (spec.service_account_json && spec.service_account_json.client_email) || `account-${index}`);
      if (accounts.some(a => a.label === name)) throw new Error(`Duplicate account name "${name}" in ACCOUNTS_JSON`);
      accounts.push(new Credential(spec, name));
    }
  }
  return accounts;
}

function resolveScopeBackend(item, accounts, env) {
  const label = item.name || item.id;
  const type = String(item.type || '').toLowerCase();
  if (type === 'r2') {
    const binding = item.bucket || item.id;
    const bucket = env[binding];
    if (!bucket || typeof bucket.list !== 'function') {
      return { error: `scope entry "${label}" references R2 binding "${binding}", but no [[r2_buckets]] binding named "${binding}" was found in env` };
    }
    return { r2: bucket };
  }

  const inline = credentialSpec(item);
  if (inline) return { cred: new Credential(inline, `scope:${label}`) };
  const ref = item.account;
  if (ref !== undefined && ref !== null && ref !== '') {
    const cred = typeof ref === 'number' ? accounts[ref] : accounts.find(a => a.label === String(ref));
    if (!cred) return { error: `scope entry "${label}" references unknown account ${JSON.stringify(ref)}` };
    return { cred };
  }
  return { error: `scope entry "${label}" has no credentials (set "account" in SCOPE matching an entry in ACCOUNTS_JSON)` };
}

function buildAuthConfig(env) {
  const scope = envJSON(env.SCOPE, [], 'SCOPE');
  if (!Array.isArray(scope) || !scope.length) {
    throw new Error('SCOPE must be a non-empty JSON array of drives/buckets to index');
  }
  scope.forEach((item, i) => {
    if (!item || (!item.id && !item.bucket)) throw new Error(`SCOPE[${i}] is missing "id"`);
  });

  const accounts = loadAccounts(env);
  const backends = [];
  const scopeProblems = [];
  scope.forEach(item => {
    const res = resolveScopeBackend(item, accounts, env);
    if (res.error) scopeProblems.push(res.error);
    backends.push(res);
  });

  return {
    siteName: env.SITE_NAME || 'Google Drive Index',
    scopeProblems,
    backends,
    files_list_page_size: envInt(env.FILES_LIST_PAGE_SIZE, 100),
    search_result_list_page_size: envInt(env.SEARCH_RESULT_LIST_PAGE_SIZE, 100),
    enable_cors_file_down: envBool(env.ENABLE_CORS_FILE_DOWN, false),
    enable_password_file_verify: envBool(env.ENABLE_PASSWORD_FILE_VERIFY, false),
    direct_link_protection: envBool(env.DIRECT_LINK_PROTECTION, false),
    disable_anonymous_download: envBool(env.DISABLE_ANONYMOUS_DOWNLOAD, false),
    file_link_expiry: envInt(env.FILE_LINK_EXPIRY, 7),
    search_all_drives: envBool(env.SEARCH_ALL_DRIVES, true),
    enable_login: envBool(env.ENABLE_LOGIN, false),
    enable_signup: envBool(env.ENABLE_SIGNUP, false),
    enable_social_login: envBool(env.ENABLE_SOCIAL_LOGIN, false),
    google_client_id_for_login: env.LOGIN_GOOGLE_CLIENT_ID || '',
    google_client_secret_for_login: env.LOGIN_GOOGLE_CLIENT_SECRET || '',
    redirect_domain: env.REDIRECT_DOMAIN || '',
    login_database: env.LOGIN_DATABASE || 'Local',
    login_days: envInt(env.LOGIN_DAYS, 7),
    enable_ip_lock: envBool(env.ENABLE_IP_LOCK, false),
    single_session: envBool(env.SINGLE_SESSION, false),
    ip_changed_action: envBool(env.IP_CHANGED_ACTION, false),
    cors_domain: env.CORS_DOMAIN || '*',
    users_list: envJSON(env.USERS_JSON, [], 'USERS_JSON'),
    roots: scope,
  };
}

function validateConfig(env, auth) {
  const missing = [];
  if (!env.CRYPTO_BASE_KEY) missing.push('CRYPTO_BASE_KEY');
  else if (![16, 24, 32].includes(new TextEncoder().encode(env.CRYPTO_BASE_KEY).length)) {
    throw new Error('CRYPTO_BASE_KEY must be exactly 16, 24 or 32 characters (use: openssl rand -hex 16)');
  }
  if (!env.HMAC_BASE_KEY) missing.push('HMAC_BASE_KEY');
  else if (env.HMAC_BASE_KEY.length < 32) {
    throw new Error('HMAC_BASE_KEY must be at least 32 characters (use: openssl rand -hex 32)');
  }
  missing.push(...auth.scopeProblems);
  if (auth.enable_login) {
    const db = auth.login_database.toLowerCase();
    if (db === 'kv' && !env.ENV) missing.push('KV binding "ENV"');
    else if (db === 'd1' && !env.DB) missing.push('D1 binding "DB"');
    else if (db === 'local' && !auth.users_list.length && !auth.enable_social_login) missing.push('USERS_JSON');
    if (auth.enable_social_login && (!auth.google_client_id_for_login || !auth.google_client_secret_for_login || !auth.redirect_domain)) {
      missing.push('LOGIN_GOOGLE_CLIENT_ID / LOGIN_GOOGLE_CLIENT_SECRET / REDIRECT_DOMAIN');
    }
    if ((auth.single_session || auth.ip_changed_action) && !env.ENV) missing.push('KV binding "ENV"');
  }
  if (missing.length) throw new Error('Missing required configuration: ' + missing.join(', '));
}

const GDOC_EXPORT_FORMATS = {
  'application/vnd.google-apps.document':     { name: 'Google Doc',    formats: [{ label: 'PDF',  mime: 'application/pdf', ext: 'pdf' }, { label: 'DOCX', mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', ext: 'docx' }, { label: 'TXT', mime: 'text/plain', ext: 'txt' }] },
  'application/vnd.google-apps.spreadsheet':  { name: 'Google Sheet',  formats: [{ label: 'PDF',  mime: 'application/pdf', ext: 'pdf' }, { label: 'XLSX', mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',           ext: 'xlsx' }, { label: 'CSV', mime: 'text/csv', ext: 'csv' }] },
  'application/vnd.google-apps.presentation': { name: 'Google Slides', formats: [{ label: 'PDF',  mime: 'application/pdf', ext: 'pdf' }, { label: 'PPTX', mime: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',   ext: 'pptx' }] },
};

function htmlSafeJSON(obj) {
  return JSON.stringify(obj).replace(/<\//g, '<\\/');
}

function html(current_drive_order = 0, model = {}) {
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0"/>
  <title>${authConfig.siteName}</title>
  <meta name="robots" content="noindex" />
  <link rel="icon" href="${uiConfig.favicon}">
  <script>try{document.documentElement.setAttribute('data-bs-theme',localStorage.getItem('gdi-theme')||'dark')}catch(_){}</script>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" crossorigin="anonymous">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
  <link rel="stylesheet" href="${css_file}">
  <style>
    .gdi-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
    .gdi-sort-controls { display: flex; align-items: center; gap: 8px; margin-left: auto; }
    .gdi-sort-label { font-size: 13px; color: var(--gdi-text-muted); margin: 0; display: inline-flex; align-items: center; gap: 4px; user-select: none; }
    .gdi-sort-select { background: var(--gdi-surface); border: 1px solid var(--gdi-border); border-radius: 6px; padding: 4px 8px; font-size: 13px; color: var(--gdi-text); outline: none; }
    .gdi-sort-select:focus { border-color: var(--gdi-accent); }
    .gdi-count-bar { border-bottom: 1px solid var(--gdi-border); border-top: none; }
    .gdi-header-select-actions { display: inline-flex; align-items: center; gap: 6px; }
    .gdi-col-name { display: flex; align-items: center; padding-left: 12px !important; }
    .gdi-dl-actions { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
    .gdi-hash-box { background: var(--gdi-surface-2); border: 1px solid var(--gdi-border); border-radius: var(--gdi-radius-sm); padding: 12px 14px; margin-bottom: 10px; }
    .gdi-hash-item { margin-bottom: 8px; }
    .gdi-hash-item:last-child { margin-bottom: 0; }
    .gdi-hash-label { font-size: 11px; font-weight: 600; text-transform: uppercase; color: var(--gdi-text-muted); margin-bottom: 3px; }
    .gdi-hash-row { display: flex; align-items: center; gap: 6px; }
    .gdi-hash-val { flex: 1; min-width: 0; font-size: 12px; font-family: var(--gdi-mono); background: var(--gdi-bg); color: var(--gdi-text); padding: 5px 8px; border: 1px solid var(--gdi-border); border-radius: var(--gdi-radius-sm); outline: none; }
  </style>
  <script>
  window.drive_names = JSON.parse('${htmlSafeJSON(authConfig.roots.map(it => it.name))}');
  window.MODEL = JSON.parse('${htmlSafeJSON(model)}');
  window.current_drive_order = ${current_drive_order};
  window.UI = JSON.parse('${htmlSafeJSON(uiConfig)}');
  window.player_config = JSON.parse('${htmlSafeJSON(player_config)}');
  </script>
  <script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>
  <script src="${app_js_file}"></script>
  <script src="https://cdn.jsdelivr.net/npm/marked@13.0.3/marked.min.js"></script>
</head>
<body>
</body>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" crossorigin="anonymous"></script>
  <script>
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(function(){});
  }
  </script>
  </html>`;
}

function makeHomepage() {
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0">
  <title>${authConfig.siteName}</title>
  <meta name="robots" content="noindex">
  <link rel="icon" href="${uiConfig.favicon}">
  <script>try{document.documentElement.setAttribute('data-bs-theme',localStorage.getItem('gdi-theme')||'dark')}catch(_){}</script>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" crossorigin="anonymous">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
  <link rel="stylesheet" href="${css_file}">
  <script>
    window.drive_names = JSON.parse('${htmlSafeJSON(authConfig.roots.map(it => it.name))}');
    window.UI = JSON.parse('${htmlSafeJSON(uiConfig)}');
    window.player_config = JSON.parse('${htmlSafeJSON(player_config)}');
  </script>
  <script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>
</head>
<body>
  <nav class="gdi-nav">
    <div class="gdi-nav-inner">
      <a class="gdi-logo" href="/">
        ${uiConfig.logo_image ? `<img src="${uiConfig.logo_link_name.startsWith('http') ? uiConfig.logo_link_name : cdn_base + '/images/bhadoo-cloud-logo-white.svg'}" alt="${uiConfig.company_name}" height="30">` : `<i class="bi bi-cloud-fill"></i> ${uiConfig.logo_link_name}`}
      </a>
      <div class="gdi-nav-sep"></div>
      <div class="gdi-nav-search">
        <form class="gdi-search-form" method="get" action="/0:search">
          <input class="gdi-search-input" name="q" type="search" placeholder="Search files..." required>
          <button class="gdi-search-btn" type="submit"><i class="bi bi-search"></i></button>
        </form>
      </div>
      <div class="gdi-nav-actions">
        <button id="theme-toggle" class="gdi-nav-btn" onclick="toggleThemeHP()" title="Toggle theme">
          <i class="bi bi-moon-stars" id="theme-icon"></i>
        </button>
        ${uiConfig.show_logout_button ? `<a class="gdi-nav-btn" href="/logout"><i class="bi bi-box-arrow-right"></i> Logout</a>` : ''}
      </div>
    </div>
  </nav>

  <div id="content" style="padding-top:54px;">
    <div class="gdi-wrap">
      <div class="gdi-drives-header">${authConfig.siteName}</div>
      <div id="list" class="gdi-drives-grid"></div>
      <div id="count" style="display:none;"></div>
    </div>
  </div>

  <footer class="gdi-footer"${uiConfig.hide_footer ? ' style="display:none;"' : ''}>
    ${uiConfig.credit ? `<span>Redesigned by <a href="https://www.npmjs.com/package/@googledrive/index" target="_blank">TheFirstSpeedster</a></span> &middot; ` : ''}
    <span>&copy; ${uiConfig.copyright_year || new Date().getFullYear()} <a href="${uiConfig.company_link}" target="_blank">${uiConfig.company_name}</a></span>
  </footer>

  <script src="${homepage_js_file}"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" crossorigin="anonymous"></script>
  <script>
    function toggleThemeHP() {
      const cur = document.documentElement.getAttribute('data-bs-theme') || 'dark';
      const next = cur === 'dark' ? 'light' : 'dark';
      localStorage.setItem('gdi-theme', next);
      document.documentElement.setAttribute('data-bs-theme', next);
      const icon = document.getElementById('theme-icon');
      if (icon) icon.className = next === 'dark' ? 'bi bi-moon-stars' : 'bi bi-sun';
    }
    (function(){ const t=localStorage.getItem('gdi-theme')||'dark'; const i=document.getElementById('theme-icon'); if(i) i.className = t==='dark'?'bi bi-moon-stars':'bi bi-sun'; })();
  </script>
</body>
</html>`;
}

function makeLoginHtml() {
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login - ${authConfig.siteName}</title>
  <link rel="icon" href="${uiConfig.favicon}">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" crossorigin="anonymous">
</head>
<body class="bg-dark text-white d-flex align-items-center justify-content-center" style="min-height: 100vh;">
  <div class="card bg-secondary text-white p-4" style="max-width: 400px; width: 100%;">
    <h3 class="card-title text-center mb-4">Login</h3>
    <form method="POST" action="/login">
      <div class="mb-3">
        <label for="username" class="form-label">Username</label>
        <input type="text" class="form-control" id="username" name="username" required>
      </div>
      <div class="mb-3">
        <label for="password" class="form-label">Password</label>
        <input type="password" class="form-control" id="password" name="password" required>
      </div>
      <button type="submit" class="btn btn-primary w-100">Sign In</button>
    </form>
    ${authConfig.enable_social_login ? `
    <hr>
    <a href="https://accounts.google.com/o/oauth2/v2/auth?client_id=${authConfig.google_client_id_for_login}&redirect_uri=${encodeURIComponent(authConfig.redirect_domain + '/google_callback')}&response_type=code&scope=email%20profile&access_type=offline" class="btn btn-danger w-100">Sign in with Google</a>
    ` : ''}
  </div>
</body>
</html>`;
}

const not_found = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>404 Not Found</title></head>
<body style="font-family:sans-serif;text-align:center;padding:50px;">
  <h2>404 - Not Found</h2><p>The requested file does not exist.</p>
</body></html>`;

const directlink = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Direct Link Protected</title></head>
<body style="font-family:sans-serif;text-align:center;padding:50px;">
  <h2>Access Denied</h2><p>Direct linking is not allowed. Please browse via the index page.</p>
</body></html>`;

const asn_blocked = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Blocked</title></head>
<body style="font-family:sans-serif;text-align:center;padding:50px;">
  <h2>403 - Forbidden</h2><p>Access from your network or region is restricted.</p>
</body></html>`;

const DriveFixedTerms = {
  gd_root_type: { user_drive: 0, share_drive: 1, r2_bucket: 2 },
  default_file_fields: 'parents,id,name,mimeType,size,createdTime,modifiedTime,iconLink,thumbnailLink,driveId,fileExtension',
  folder_mime_type: 'application/vnd.google-apps.folder',
};

const JSONWebToken = {
  header: { alg: 'RS256', typ: 'JWT' },
  importKey: async function(pemKey) {
    const clean = pemKey.split('\n').map(s => s.trim()).filter(l => l.length && !l.startsWith('---')).join('');
    const binary = atob(clean);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return crypto.subtle.importKey('pkcs8', bytes.buffer, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  },
  generateGCPToken: async function(serviceAccount) {
    const iat = Math.floor(Date.now() / 1000);
    const payload = {
      iss: serviceAccount.client_email,
      scope: 'https://www.googleapis.com/auth/drive',
      aud: 'https://oauth2.googleapis.com/token',
      exp: iat + 3600,
      iat,
    };
    const toBase64Url = s => s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const encPayload = toBase64Url(btoa(JSON.stringify(payload)));
    const encHeader = toBase64Url(btoa(JSON.stringify(this.header)));
    const key = await this.importKey(serviceAccount.private_key);
    const encoder = new TextEncoder();
    const signed = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, encoder.encode(encHeader + '.' + encPayload));
    let binary = '';
    const bytes = new Uint8Array(signed);
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return encHeader + '.' + encPayload + '.' + toBase64Url(btoa(binary));
  },
};

async function encryptString(string) {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(crypto_base_key),
    'AES-CBC',
    false,
    ['encrypt']
  );
  const encryptedData = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv },
    key,
    new TextEncoder().encode(string)
  );
  const encryptedBytes = new Uint8Array(encryptedData);
  const combined = new Uint8Array(iv.length + encryptedBytes.length);
  combined.set(iv);
  combined.set(encryptedBytes, iv.length);
  return btoa(Array.from(combined, b => String.fromCharCode(b)).join(''));
}

async function decryptString(encryptedString) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(crypto_base_key),
    'AES-CBC',
    false,
    ['decrypt']
  );
  const combined = Uint8Array.from(atob(encryptedString), c => c.charCodeAt(0));
  const iv = combined.slice(0, 16);
  const ciphertext = combined.slice(16);
  const decryptedData = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, ciphertext);
  return new TextDecoder().decode(decryptedData);
}

async function genIntegrity(data, key = hmac_base_key) {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', hmacKey, dataBuffer);
  return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function checkintegrity(expectedHex, actualHex) {
  if (!expectedHex || !actualHex) return false;
  return expectedHex === actualHex;
}

function login() {
  return new Response(login_html, {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

function enQuery(data) {
  const _str = [];
  for (const p in data) {
    if (data[p] !== undefined && data[p] !== null) {
      _str.push(encodeURIComponent(p) + '=' + encodeURIComponent(data[p]));
    }
  }
  return _str.join('&');
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function generateLink(raw_file_id, user_ip, order = 0) {
  const file_id = `${order}:${raw_file_id}`;
  const encrypted_id = await encryptString(file_id);
  const expiry = Date.now() + 1000 * 60 * 60 * 24 * authConfig.file_link_expiry;
  const encrypted_expiry = await encryptString(expiry.toString());
  let url;
  if (authConfig.enable_ip_lock && user_ip) {
    const encrypted_ip = await encryptString(user_ip);
    const integrity = await genIntegrity(`${file_id}|${expiry}|${user_ip}`);
    url = `/download.aspx?file=${encodeURIComponent(encrypted_id)}&expiry=${encodeURIComponent(encrypted_expiry)}&ip=${encodeURIComponent(encrypted_ip)}&mac=${encodeURIComponent(integrity)}`;
  } else {
    const integrity = await genIntegrity(`${file_id}|${expiry}`);
    url = `/download.aspx?file=${encodeURIComponent(encrypted_id)}&expiry=${encodeURIComponent(encrypted_expiry)}&mac=${encodeURIComponent(integrity)}`;
  }
  return url;
}

async function apiRequest(request, gd, user_ip) {
  const url = new URL(request.url);
  let path = url.pathname;
  path = path.replace(gd.url_path_prefix, '') || '/';
  const option = {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Content-Type': 'application/json;charset=UTF-8',
    },
  };

  if (path.slice(-1) == '/') {
    const requestData = await request.json().catch(() => ({}));
    const list_result = await gd.request_list_of_files(
      path,
      requestData.page_token || null,
      Number(requestData.page_index) || 0
    );

    if (authConfig.enable_password_file_verify && gd.password) {
      const password = await gd.password(path);
      if (password && password.replace('\n', '') !== requestData.password) {
        return new Response('Y29kZWlzcHJvdGVjdGVk=0Xfi4icvJnclBCZy92dzNXYwJCI6ISZnF2czVWbiwSMwQDI6ISZk92YisHI6IicvJnclJyeYmFzZTY0aXNleGNsdWRlZA==', option);
      }
    }

    list_result.data.files = await Promise.all(list_result.data.files.map(async file => {
      const { driveId, id, mimeType, ...fileWithoutId } = file;
      const encryptedId = await encryptString(id);
      const encryptedDriveId = await encryptString(driveId || '');
      let link = null;
      if (mimeType !== DriveFixedTerms.folder_mime_type) {
        link = await generateLink(id, user_ip, gd.order);
      }
      return {
        ...fileWithoutId,
        id: encryptedId,
        driveId: encryptedDriveId,
        mimeType,
        link,
      };
    }));

    return new Response(JSON.stringify(list_result), option);
  } else {
    const file_json = await gd.get_single_file(path);
    if (!file_json) {
      return new Response(JSON.stringify({ error: 'File not found' }), {
        status: 404,
        headers: option.headers,
      });
    }
    const { driveId, id, ...fileWithoutId } = file_json;
    const encryptedId = await encryptString(id);
    const encryptedDriveId = await encryptString(driveId || '');
    const link = await generateLink(id, user_ip, gd.order);
    return new Response(JSON.stringify({
      ...fileWithoutId,
      id: encryptedId,
      driveId: encryptedDriveId,
      link,
    }), option);
  }
}

async function handleSearch(request, gd, user_ip = '') {
  const option = {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Content-Type': 'application/json;charset=UTF-8',
    },
  };
  const requestData = await request.json().catch(() => ({}));
  const q = requestData.q || '';
  const pageToken = requestData.page_token || null;
  const pageIndex = Number(requestData.page_index) || 0;
  if (!q) {
    return new Response(JSON.stringify({ nextPageToken: null, curPageIndex: 0, data: { files: [] } }), option);
  }
  const searchResult = await gd.searchFilesinDrive(q, pageToken, pageIndex);
  if (!searchResult.data || !searchResult.data.files) {
    return new Response(JSON.stringify({ nextPageToken: null, curPageIndex: 0, data: { files: [] } }), option);
  }
  searchResult.data.files = await Promise.all(searchResult.data.files.map(async file => {
    const { driveId, id, ...fileWithoutId } = file;
    const encryptedId = await encryptString(id);
    const encryptedDriveId = await encryptString(driveId || '');
    const link = await generateLink(id, user_ip, gd.order);
    return {
      ...fileWithoutId,
      id: encryptedId,
      driveId: encryptedDriveId,
      rootIdx: gd.order,
      link,
    };
  }));
  return new Response(JSON.stringify(searchResult), option);
}

async function handleId2Path(request, gd) {
  const option = {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': authConfig.cors_domain,
    },
  };
  try {
    const data = await request.json();
    const id = await decryptString(data.id);
    const result = await gd.findPathById(id);
    if (!result || !result[0]) {
      return new Response(JSON.stringify({ path: null }), { status: 404, headers: option.headers });
    }
    const [foundPath, prefix] = result;
    return new Response(JSON.stringify({ path: '/' + prefix + ':' + foundPath }), option);
  } catch (error) {
    return new Response(JSON.stringify({ message: 'Request Failed or Path Not Found', error: String(error) }), {
      status: 500,
      headers: option.headers,
    });
  }
}

async function findId2Path(gd, url) {
  const id = url.searchParams.get('id');
  const view = url.searchParams.get('view') || 'false';
  if (!id) {
    return new Response(JSON.stringify({ error: 'Missing id parameter' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json;charset=UTF-8' },
    });
  }
  let found_path = null;
  let found_drive_idx = gd.order;
  try {
    const result = await gd.findPathById(id);
    if (result && result[0]) {
      found_path = result[0];
      found_drive_idx = (result[1] !== undefined) ? result[1] : gd.order;
    }
  } catch (_) {}

  if (!found_path) {
    for (let i = 0; i < gds.length; i++) {
      if (gds[i] === gd) continue;
      try {
        const result = await gds[i].findPathById(id);
        if (result && result[0]) {
          found_path = result[0];
          found_drive_idx = (result[1] !== undefined) ? result[1] : i;
          break;
        }
      } catch (_) {}
    }
  }
  if (found_path) {
    const suffix = view === 'true' ? '?a=view' : '';
    return Response.redirect(url.origin + '/' + found_drive_idx + ':' + found_path + suffix, 302);
  }
  return new Response(JSON.stringify({ error: 'File not found' }), {
    status: 404,
    headers: { 'Content-Type': 'application/json;charset=UTF-8' },
  });
}

// ── Google Drive Backend ─────────────────────────────────────────────────────

class googleDrive {
  constructor(authConfig, order) {
    this.order = order;
    this.root = authConfig.roots[order];
    this.root.protect_file_link = this.root.protect_file_link || false;
    this.url_path_prefix = `/${order}:`;
    this.authConfig = authConfig;
    this.credential = authConfig.backends[order].cred;
    this.real_root_id = null;
    this.paths = { '/': this.root.id };
    this.files = {};
    this.passwords = {};
  }

  async init() {
    try {
      await this.getRealRootId();
    } catch (err) {
      console.error(`Drive ${this.order} (${this.root.name || this.root.id}) init failed: ${err.message}`);
    }
  }

  async getRealRootId() {
    if (this.real_root_id) return this.real_root_id;
    const root_obj = await this.findItemById('root');
    if (root_obj && root_obj.id) this.real_root_id = root_obj.id;
    return this.real_root_id;
  }

  async initRootType() {
    const root_id = this.root.id;
    const types = DriveFixedTerms.gd_root_type;
    const explicit_type = this.root.type;
    if (explicit_type === 'shared_drive') {
      this.root_type = types.share_drive;
      return;
    }
    if (explicit_type === 'root' || explicit_type === 'folder') {
      this.root_type = types.user_drive;
      return;
    }
    if (root_id === 'root' || root_id === this.real_root_id) {
      this.root_type = types.user_drive;
    } else {
      this.root_type = types.share_drive;
    }
  }

  async get_single_file(path) {
    if (typeof this.files[path] === 'undefined') {
      this.files[path] = await this.get_single_file_api(path);
    }
    return this.files[path];
  }

  async get_single_file_api(path) {
    const arr = path.split('/');
    let name = arr.pop();
    name = decodeURIComponent(name).replace(/'/g, "\\'");
    const dir = arr.join('/') + '/';
    const parent = await this.findPathId(dir);
    if (!parent) return null;
    const params = {
      includeItemsFromAllDrives: true,
      supportsAllDrives: true,
      q: `'${parent}' in parents and name = '${name}' and trashed = false and mimeType != 'application/vnd.google-apps.shortcut'`,
      fields: 'files(id, name, mimeType, size, createdTime, modifiedTime, iconLink, thumbnailLink, driveId, fileExtension)',
    };
    const url = 'https://www.googleapis.com/drive/v3/files?' + enQuery(params);
    const requestOption = await this.requestOptions();
    let response;
    for (let i = 0; i < 3; i++) {
      response = await fetch(url, requestOption);
      if (response.ok) break;
      await sleep(800 * (i + 1));
    }
    if (!response || !response.ok) return null;
    const data = await response.json();
    return (data.files && data.files[0]) || null;
  }

  async request_list_of_files(path, page_token = null, page_index = 0) {
    const id = await this.findPathId(path);
    return this._list_gdrive_files(id, page_token, page_index);
  }

  async _list_gdrive_files(parent, page_token = null, page_index = 0) {
    if (parent === undefined || parent === null) {
      return { nextPageToken: null, curPageIndex: page_index, data: { files: [] } };
    }
    const params = {
      includeItemsFromAllDrives: true,
      supportsAllDrives: true,
      q: `'${parent}' in parents and trashed = false and name != '.password' and mimeType != 'application/vnd.google-apps.shortcut' and mimeType != 'application/vnd.google-apps.form' and mimeType != 'application/vnd.google-apps.site'`,
      orderBy: 'folder, name, modifiedTime desc',
      fields: 'nextPageToken, files(id, name, mimeType, size, modifiedTime, driveId, kind, fileExtension)',
      pageSize: this.authConfig.files_list_page_size,
    };
    if (page_token) params.pageToken = page_token;
    const url = 'https://www.googleapis.com/drive/v3/files?' + enQuery(params);
    const requestOption = await this.requestOptions();
    let response;
    for (let i = 0; i < 3; i++) {
      response = await fetch(url, requestOption);
      if (response.ok) break;
      await sleep(800 * (i + 1));
    }
    const obj = response && response.ok ? await response.json() : { files: [] };
    if (!obj.files) obj.files = [];
    return {
      nextPageToken: obj.nextPageToken || null,
      curPageIndex: page_index,
      data: obj,
    };
  }

  async password(path) {
    if (this.passwords[path] !== undefined) return this.passwords[path];
    const file = await this.get_single_file(path + '.password');
    if (!file) {
      this.passwords[path] = null;
    } else {
      const url = `https://www.googleapis.com/drive/v3/files/${file.id}?alt=media`;
      const response = await fetch(url, await this.requestOptions());
      this.passwords[path] = response.ok ? await response.text() : null;
    }
    return this.passwords[path];
  }

  async searchFilesinDrive(keyword, page_token = null, page_index = 0) {
    const is_user_drive = this.root_type === DriveFixedTerms.gd_root_type.user_drive;
    const words = keyword.trim().replace(/'/g, "\\'").split(/\s+/).filter(Boolean);
    if (!words.length) return { nextPageToken: null, curPageIndex: page_index, data: { files: [] } };
    const nameFilter = words.map(w => `name contains '${w}'`).join(' and ');
    const params = {
      includeItemsFromAllDrives: true,
      supportsAllDrives: true,
      corpora: is_user_drive ? (this.authConfig.search_all_drives ? 'allDrives' : 'user') : 'drive',
      q: `trashed = false and mimeType != 'application/vnd.google-apps.shortcut' and mimeType != 'application/vnd.google-apps.form' and mimeType != 'application/vnd.google-apps.site' and name != '.password' and (${nameFilter})`,
      fields: 'nextPageToken, files(id, driveId, name, mimeType, size, modifiedTime)',
      pageSize: this.authConfig.search_result_list_page_size,
      orderBy: 'folder, name, modifiedTime desc',
    };
    if (!is_user_drive) params.driveId = this.root.id;
    if (page_token) params.pageToken = page_token;
    const url = 'https://www.googleapis.com/drive/v3/files?' + enQuery(params);
    const response = await fetch(url, await this.requestOptions());
    if (!response.ok) return { nextPageToken: null, curPageIndex: page_index, data: { files: [] } };
    const obj = await response.json();
    return {
      nextPageToken: obj.nextPageToken || null,
      curPageIndex: page_index,
      data: obj,
    };
  }

  async findParentFilesRecursion(child_id) {
    const gd = this;
    const is_user_drive = gd.root_type === DriveFixedTerms.gd_root_type.user_drive;
    const target_top_id = is_user_drive ? await gd.getRealRootId() : gd.root.id;
    const parent_files = [];
    let meet_top = false;

    async function addItsFirstParent(file_obj) {
      if (!file_obj || !file_obj.parents || !file_obj.parents.length) return;
      const first_p_id = file_obj.parents[0];
      if (first_p_id === target_top_id || first_p_id === gd.root.id) {
        meet_top = true;
        return gd.order;
      }
      const p_file_obj = await gd.findItemById(first_p_id);
      if (p_file_obj && p_file_obj.id) {
        parent_files.push(p_file_obj);
        await addItsFirstParent(p_file_obj);
      }
      return gd.order;
    }

    const child_obj = await gd.findItemById(child_id);
    if (!child_obj) return null;
    parent_files.push(child_obj);
    await addItsFirstParent(child_obj);
    return meet_top ? [parent_files, gd.order] : null;
  }

  async findPathById(child_id) {
    let p_files, drive_index_no;
    try {
      const res = await this.findParentFilesRecursion(child_id);
      if (!res) return null;
      [p_files, drive_index_no] = res;
    } catch (_) {
      return null;
    }
    if (!p_files || !p_files.length) return null;
    const cache = [];
    p_files.forEach((value, idx) => {
      const is_folder = idx === 0 ? (p_files[idx].mimeType === DriveFixedTerms.folder_mime_type) : true;
      let p = '/' + p_files.slice(idx).map(it => encodeURIComponent(it.name)).reverse().join('/');
      if (is_folder) p += '/';
      cache.push({ id: p_files[idx].id, path: p });
    });
    return [cache[0].path, drive_index_no];
  }

  async findItemById(id) {
    const url = `https://www.googleapis.com/drive/v3/files/${id}?fields=${DriveFixedTerms.default_file_fields}&supportsAllDrives=true`;
    const res = await fetch(url, await this.requestOptions());
    if (!res.ok) return null;
    return await res.json();
  }

  async findPathId(path) {
    let c_path = '/';
    let c_id = this.paths[c_path];
    const arr = path.replace(/^\/+|\/+$/g, '').split('/').filter(Boolean);
    for (const name of arr) {
      c_path += name + '/';
      if (typeof this.paths[c_path] === 'undefined') {
        const id = await this._findDirId(c_id, name);
        this.paths[c_path] = id;
      }
      c_id = this.paths[c_path];
      if (!c_id) break;
    }
    return this.paths[path] || c_id;
  }

  async _findDirId(parent, name) {
    name = decodeURIComponent(name).replace(/'/g, "\\'");
    if (!parent) return null;
    const params = {
      includeItemsFromAllDrives: true,
      supportsAllDrives: true,
      q: `'${parent}' in parents and mimeType = 'application/vnd.google-apps.folder' and name = '${name}' and trashed = false`,
      fields: 'files(id, name, mimeType)',
    };
    const url = 'https://www.googleapis.com/drive/v3/files?' + enQuery(params);
    const res = await fetch(url, await this.requestOptions());
    if (!res.ok) return null;
    const obj = await res.json();
    return (obj.files && obj.files[0] && obj.files[0].id) || null;
  }

  async requestOptions(headers = {}, method = 'GET') {
    const token = await this._getAccessToken();
    headers['authorization'] = 'Bearer ' + token;
    return { method, headers };
  }

  _getAccessToken() {
    return this.credential.getAccessToken();
  }

  async download(id, range = '', inline = false, exportFmt = null) {
    const requestOption = await this.requestOptions();
    const file = await this.findItemById(id);
    if (!file || !file.name) {
      return new Response('{"error":"Unable to Find this File, Try Again."}', {
        status: 404,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': authConfig.cors_domain },
      });
    }
    const exportEntry = GDOC_EXPORT_FORMATS[file.mimeType];
    if (exportEntry) {
      const targetFmt = exportFmt ? exportEntry.formats.find(f => f.ext === exportFmt) || exportEntry.formats[0] : exportEntry.formats[0];
      const exportUrl = `https://www.googleapis.com/drive/v3/files/${id}/export?mimeType=${encodeURIComponent(targetFmt.mime)}`;
      const res = await fetch(exportUrl, requestOption);
      if (!res.ok) return new Response(await res.text(), { status: res.status });
      const exportRes = new Response(res.body, res);
      const exportName = `${file.name}.${targetFmt.ext}`;
      exportRes.headers.set('Content-Disposition', inline ? 'inline' : `attachment; filename*=UTF-8''${encodeURIComponent(exportName)}`);
      exportRes.headers.set('Content-Type', targetFmt.mime);
      if (authConfig.enable_cors_file_down) exportRes.headers.set('Access-Control-Allow-Origin', '*');
      return exportRes;
    }
    const url = `https://www.googleapis.com/drive/v3/files/${id}?alt=media`;
    if (range) requestOption.headers['Range'] = range;
    const res = await fetch(url, requestOption);
    if (res.ok) {
      const response = new Response(res.body, res);
      response.headers.set('Content-Disposition', inline ? 'inline' : `attachment; filename*=UTF-8''${encodeURIComponent(file.name)}`);
      if (file.size) response.headers.set('Content-Length', file.size);
      if (authConfig.enable_cors_file_down) response.headers.set('Access-Control-Allow-Origin', '*');
      return response;
    }
    return new Response(not_found, { status: res.status, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }
}

// ── Cloudflare R2 Backend ───────────────────────────────────────────────────

class r2Storage {
  constructor(authConfig, order) {
    this.order = order;
    this.root = authConfig.roots[order];
    this.root.protect_file_link = this.root.protect_file_link || false;
    this.url_path_prefix = `/${order}:`;
    this.authConfig = authConfig;
    this.bucket = authConfig.backends[order].r2;
    this.root_type = DriveFixedTerms.gd_root_type.r2_bucket;
    this.prefix = (this.root.prefix || '').replace(/^\/+|\/+$/g, '');
    if (this.prefix) this.prefix += '/';
  }

  async init() {}
  async initRootType() {}

  _cleanPath(path) {
    return path.replace(/^\/+/, '');
  }

  _fullKey(path) {
    return this.prefix + this._cleanPath(path);
  }

  async request_list_of_files(path, page_token = null, page_index = 0) {
    const clean = this._cleanPath(path);
    const dirPrefix = this._fullKey(clean);
    const options = {
      delimiter: '/',
      prefix: dirPrefix,
      limit: this.authConfig.files_list_page_size,
    };
    if (page_token) options.cursor = page_token;
    const listed = await this.bucket.list(options);

    const files = [];
    // Subfolders from common prefixes
    for (const p of listed.delimitedPrefixes || []) {
      const name = p.slice(dirPrefix.length).replace(/\/$/, '');
      if (!name) continue;
      files.push({
        id: p,
        name,
        mimeType: DriveFixedTerms.folder_mime_type,
        size: 0,
        modifiedTime: new Date().toISOString(),
      });
    }

    // Objects
    for (const obj of listed.objects || []) {
      const name = obj.key.slice(dirPrefix.length);
      if (!name || name === '.password') continue;
      files.push({
        id: obj.key,
        name,
        mimeType: obj.httpMetadata?.contentType || 'application/octet-stream',
        size: obj.size,
        modifiedTime: obj.uploaded.toISOString(),
      });
    }

    return {
      nextPageToken: listed.truncated ? listed.cursor : null,
      curPageIndex: page_index,
      data: { files },
    };
  }

  async get_single_file(path) {
    const key = this._fullKey(path);
    const head = await this.bucket.head(key);
    if (!head) return null;
    const name = key.split('/').pop();
    return {
      id: key,
      name,
      mimeType: head.httpMetadata?.contentType || 'application/octet-stream',
      size: head.size,
      modifiedTime: head.uploaded.toISOString(),
    };
  }

  async password(path) {
    const key = this._fullKey(path) + '.password';
    const obj = await this.bucket.get(key);
    if (!obj) return null;
    return await obj.text();
  }

  async searchFilesinDrive(keyword, page_token = null, page_index = 0) {
    const q = keyword.toLowerCase();
    const listed = await this.bucket.list({
      prefix: this.prefix,
      limit: 1000,
    });
    const files = (listed.objects || [])
      .filter(o => o.key.toLowerCase().includes(q) && !o.key.endsWith('.password'))
      .slice(0, this.authConfig.search_result_list_page_size)
      .map(o => ({
        id: o.key,
        name: o.key.split('/').pop(),
        mimeType: o.httpMetadata?.contentType || 'application/octet-stream',
        size: o.size,
        modifiedTime: o.uploaded.toISOString(),
      }));
    return {
      nextPageToken: null,
      curPageIndex: page_index,
      data: { files },
    };
  }

  async findPathById(key) {
    const rel = key.startsWith(this.prefix) ? key.slice(this.prefix.length) : key;
    return ['/' + rel, this.order];
  }

  async findItemById(key) {
    return this.get_single_file(key);
  }

  async download(key, range = '', inline = false) {
    const getOptions = {};
    if (range) {
      const match = /bytes=(\d+)-(\d+)?/.exec(range);
      if (match) {
        getOptions.range = {
          offset: parseInt(match[1], 10),
          length: match[2] ? parseInt(match[2], 10) - parseInt(match[1], 10) + 1 : undefined,
        };
      }
    }
    const obj = await this.bucket.get(key, getOptions);
    if (!obj) {
      return new Response(not_found, { status: 404, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }
    const headers = new Headers();
    obj.writeHttpMetadata(headers);
    headers.set('etag', obj.httpEtag);
    const filename = key.split('/').pop();
    headers.set('Content-Disposition', inline ? 'inline' : `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`);
    if (authConfig.enable_cors_file_down) headers.set('Access-Control-Allow-Origin', '*');
    return new Response(obj.body, { headers });
  }
}

// ── Main dispatcher ──────────────────────────────────────────────────────────

async function download(backend, id, range = '', inline = false, exportFmt = null) {
  if (uiConfig.second_domain_for_dl === true) {
    const res = await fetch(cdn_base + '/assets/disable_download.html');
    return new Response(await res.text(), { headers: { 'content-type': 'text/html;charset=UTF-8' } });
  }
  return backend.download(id, range, inline, exportFmt);
}

function buildUiConfig(env, auth) {
  const domains = envList(env.DOMAINS_FOR_DL);
  domain_for_dl = domains.length ? pickRandom(domains) : '';
  const s = (k, d) => (env[k] !== undefined && env[k] !== '' ? String(env[k]) : d);
  return {
    theme: s('UI_THEME', 'darkly'),
    version: CDN_VERSION,
    debug_mode: envBool(env.UI_DEBUG_MODE, false),
    logo_image: envBool(env.UI_LOGO_IMAGE, true),
    logo_height: s('UI_LOGO_HEIGHT', 'auto'),
    logo_width: s('UI_LOGO_WIDTH', '100px'),
    favicon: s('UI_FAVICON', 'https://raw.githubusercontent.com/GoogleDriveIndex/Google-Drive-Index/master/images/icons/favicon-32x32.png'),
    logo_link_name: s('UI_LOGO_LINK_NAME', 'Google Drive Index'),
    fixed_header: envBool(env.UI_FIXED_HEADER, true),
    header_padding: s('UI_HEADER_PADDING', '80'),
    fixed_footer: envBool(env.UI_FIXED_FOOTER, false),
    hide_footer: envBool(env.UI_HIDE_FOOTER, true),
    header_class: s('UI_HEADER_CLASS', 'navbar-dark bg-dark'),
    footer_class: s('UI_FOOTER_CLASS', 'bg-dark text-white'),
    body_class: s('UI_BODY_CLASS', 'text-white'),
    table_class: s('UI_TABLE_CLASS', 'table-dark table-striped'),
    list_group_class: s('UI_LIST_GROUP_CLASS', 'bg-dark text-white'),
    css_override_color: s('UI_CSS_OVERRIDE_COLOR', ''),
    css_background_color: s('UI_CSS_BACKGROUND_COLOR', ''),
    css_accent_color: s('UI_CSS_ACCENT_COLOR', ''),
    contact_link: s('UI_CONTACT_LINK', '#'),
    company_name: s('UI_COMPANY_NAME', 'Google Drive Index'),
    company_link: s('UI_COMPANY_LINK', '#'),
    credit: envBool(env.UI_CREDIT, true),
    display_size: envBool(env.UI_DISPLAY_SIZE, true),
    display_time: envBool(env.UI_DISPLAY_TIME, false),
    display_download: envBool(env.UI_DISPLAY_DOWNLOAD, true),
    disable_player: envBool(env.UI_DISABLE_PLAYER, false),
    disable_video_download: envBool(env.UI_DISABLE_VIDEO_DOWNLOAD, false),
    allow_selecting_files: envBool(env.UI_ALLOW_SELECTING_FILES, true),
    second_domain_for_dl: envBool(env.UI_SECOND_DOMAIN_FOR_DL, false),
    poster: s('UI_POSTER', ''),
    audio_poster: s('UI_AUDIO_POSTER', ''),
    disable_audio_download: envBool(env.UI_DISABLE_AUDIO_DOWNLOAD, false),
    render_head_md: envBool(env.UI_RENDER_HEAD_MD, true),
    render_readme_md: envBool(env.UI_RENDER_README_MD, true),
    unauthorized_owner_link: s('UI_UNAUTHORIZED_OWNER_LINK', '#'),
    unauthorized_owner_email: s('UI_UNAUTHORIZED_OWNER_EMAIL', ''),
    downloaddomain: domain_for_dl,
    show_logout_button: auth.enable_login,
    show_quota: envBool(env.UI_SHOW_QUOTA, false),
  };
}

async function initDrives() {
  const list = authConfig.roots.map((r, i) => {
    return authConfig.backends[i].r2 ? new r2Storage(authConfig, i) : new googleDrive(authConfig, i);
  });
  await Promise.all(list.map(b => b.init()));
  await Promise.all(list.map(b => b.initRootType()));
  gds.length = 0;
  gds.push(...list);
}

function initConfig(env) {
  if (configReady) return;
  environment = env.ENVIRONMENT || 'production';
  CDN_VERSION = '2.5.9';
  blocked_region = envList(env.BLOCKED_REGION).map(x => String(x).toUpperCase());
  blocked_asn = envList(env.BLOCKED_ASN).map(x => parseInt(x, 10)).filter(Number.isFinite);
  authConfig = buildAuthConfig(env);
  validateConfig(env, authConfig);
  crypto_base_key = env.CRYPTO_BASE_KEY;
  hmac_base_key = env.HMAC_BASE_KEY;
  uiConfig = buildUiConfig(env, authConfig);
  player_config = {
    player: env.PLAYER || 'videojs',
    videojs_version: '8.12.0',
    plyr_io_version: '3.7.8',
    jwplayer_version: '8.16.2',
  };
  ENV = env.ENV;
  DB = env.DB;
  cdn_base = 'https://cdn.jsdelivr.net/npm/@googledrive/index@' + CDN_VERSION;
  dev_mode = environment !== 'production';
  app_js_file = '/app.js';
  css_file = environment === 'local' ? 'http://127.0.0.1:5500/assets/gdi.css' : cdn_base + '/assets/gdi.min.css';
  homepage_js_file = environment === 'local' ? 'http://127.0.0.1:5500/assets/homepage.js' : cdn_base + '/assets/homepage.min.js';
  homepage = makeHomepage();
  login_html = makeLoginHtml();
  configReady = true;
}

async function handleRequest(request, event) {
  const region = request.headers.get('cf-ipcountry');
  const asn_servers = request.cf?.asn;
  const referer = request.headers.get('Referer');
  const user_ip = request.headers.get('CF-Connecting-IP');
  const url = new URL(request.url);
  const path = url.pathname;
  const hostname = url.hostname;

  if (path === '/app.js') {
    return new Response(BUNDLED_APP_JS, {
      status: 200,
      headers: {
        'Content-Type': 'application/javascript; charset=utf-8',
        'Cache-Control': 'public, max-age=3600',
      },
    });
  }

  if (path === '/sw.js') {
    const swResp = await fetch(cdn_base + '/sw.js');
    if (!swResp.ok) return new Response('// unavailable', { status: 200, headers: { 'Content-Type': 'application/javascript' } });
    return new Response(await swResp.text(), {
      status: 200,
      headers: { 'Content-Type': 'application/javascript; charset=utf-8', 'Cache-Control': 'no-cache' },
    });
  }

  if (path === '/logout') {
    const response = new Response('', { status: 302, headers: { Location: authConfig.enable_login ? '/login' : '/' } });
    response.headers.set('Set-Cookie', 'session=; path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
    return response;
  }

  if (authConfig.enable_login) {
    const login_database = authConfig.login_database.toLowerCase();
    if (path === '/download.aspx' && !authConfig.disable_anonymous_download) {
      // anonymous download allowed
    } else if (path === '/login' && request.method === 'POST') {
      const formData = await request.formData();
      const u = formData.get('username');
      const p = formData.get('password');
      let ok = false;
      if (login_database === 'local') {
        ok = authConfig.users_list.some(it => it.username === u && it.password === p);
      } else if (login_database === 'kv') {
        const stored = await ENV.get(u);
        ok = stored !== null && stored === p;
      } else if (login_database === 'd1') {
        const row = await DB.prepare('SELECT password FROM users WHERE username = ?').bind(u).first();
        ok = row && row.password === p;
      }
      if (ok) {
        const exp = Date.now() + 86400000 * authConfig.login_days;
        const cookie = await encryptString(`${u}|${exp}`);
        const resp = new Response('', { status: 302, headers: { Location: '/' } });
        resp.headers.set('Set-Cookie', `session=${encodeURIComponent(cookie)}; path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${86400 * authConfig.login_days}`);
        return resp;
      }
      return new Response('Invalid credentials', { status: 401 });
    } else {
      const cookieHeader = request.headers.get('Cookie') || '';
      const match = cookieHeader.match(/(?:^|;\s*)session=([^;]+)/);
      let authed = false;
      if (match) {
        try {
          const dec = await decryptString(decodeURIComponent(match[1]));
          const [u, exp] = dec.split('|');
          if (u && Number(exp) > Date.now()) authed = true;
        } catch (_) {}
      }
      if (!authed) return login();
    }
  }

  if (!drivesReady) {
    drivesReady = initDrives().catch(err => { drivesReady = null; throw err; });
  }
  await drivesReady;

  let gd;

  function redirectToIndexPage() {
    return Response.redirect(`${url.origin}/0:/`, 302);
  }

  if (region && blocked_region.includes(region.toUpperCase())) {
    return new Response(asn_blocked, { status: 403, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }
  if (asn_servers && blocked_asn.includes(asn_servers)) {
    return new Response(asn_blocked, { status: 403, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }

  if (path === '/') {
    return new Response(homepage, { status: 200, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }

  if (path === '/findpath') {
    const id = url.searchParams.get('id');
    const view = url.searchParams.get('view') || 'false';
    if (!id) return new Response(JSON.stringify({ error: 'Missing id parameter' }), { status: 400 });
    for (let i = 0; i < gds.length; i++) {
      try {
        const result = await gds[i].findPathById(id);
        if (result && result[0]) {
          const suffix = view === 'true' ? '?a=view' : '';
          return Response.redirect(url.origin + '/' + i + ':' + result[0] + suffix, 302);
        }
      } catch (_) {}
    }
    return new Response(JSON.stringify({ error: 'File not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
  }

  if (path === '/download.aspx') {
    let file, expiry;
    try {
      file = await decryptString(url.searchParams.get('file'));
      expiry = await decryptString(url.searchParams.get('expiry'));
    } catch (_) {
      return new Response('Invalid Request!', { status: 400, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }
    if (Number(expiry) < Date.now()) {
      return new Response('Link Expired!', { status: 401, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }
    const mac = url.searchParams.get('mac');
    const expected = (authConfig.enable_ip_lock && user_ip)
      ? await genIntegrity(`${file}|${expiry}|${user_ip}`)
      : await genIntegrity(`${file}|${expiry}`);
    if (!(await checkintegrity(mac, expected))) {
      return new Response('Invalid Request!', { status: 401, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }

    const sep = file.indexOf(':');
    const order = sep > 0 ? Number(file.slice(0, sep)) : 0;
    const file_id = sep > 0 ? file.slice(sep + 1) : file;
    const backend = gds[order];
    if (!backend) return new Response('Invalid Request!', { status: 400 });
    const range = request.headers.get('Range');
    const inline = 'true' === url.searchParams.get('inline');
    const fmt = url.searchParams.get('fmt') || null;
    return download(backend, file_id, range, inline, fmt);
  }

  if (authConfig.direct_link_protection) {
    if (!referer || !referer.includes(hostname)) {
      return new Response(directlink, { status: 401, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }
  }

  const command_reg = /^\/(?<num>\d+):(?<command>[a-zA-Z0-9]+)(\/.*)?$/g;
  const match = command_reg.exec(path);
  if (match) {
    const order = Number(match.groups.num);
    if (order >= 0 && order < gds.length) {
      gd = gds[order];
    } else {
      return redirectToIndexPage();
    }
    const command = match.groups.command;
    if (command === 'search') {
      if (request.method === 'POST') return handleSearch(request, gd, user_ip);
      const q = (url.searchParams.get('q') || '').replace(/'/g, '').replace(/"/g, '');
      return new Response(html(gd.order, { q, is_search_page: true, root_type: gd.root_type }), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }
    if (command === 'id2path' && request.method === 'POST') return handleId2Path(request, gd);
    if (command === 'findpath' && request.method === 'GET') return findId2Path(gd, url);
    if (command === 'quota' && request.method === 'GET') {
      if (gd.requestOptions) {
        const res = await fetch('https://www.googleapis.com/drive/v3/about?fields=storageQuota,user', await gd.requestOptions());
        return new Response(await res.text(), { status: res.status, headers: { 'Content-Type': 'application/json' } });
      }
      return new Response(JSON.stringify({ quotaBytesTotal: '0', quotaBytesUsed: '0' }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  const common_reg = /^\/\d+:\/.*$/g;
  if (!path.match(common_reg)) return redirectToIndexPage();
  const split = path.split('/');
  const order = Number(split[1].slice(0, -1));
  if (order >= 0 && order < gds.length) {
    gd = gds[order];
  } else {
    return redirectToIndexPage();
  }

  if (request.method === 'POST') return apiRequest(request, gd, user_ip);

  const action = url.searchParams.get('a');
  if (path.slice(-1) === '/' || action !== null) {
    return new Response(html(gd.order, { root_type: gd.root_type }), {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }

  const file = await gd.get_single_file(path.replace(gd.url_path_prefix, ''));
  if (gd.root.protect_file_link && authConfig.enable_login) return login();
  if (!file || !file.id) {
    return new Response(not_found, { status: 404, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }
  const range = request.headers.get('Range');
  const inline = 'true' === url.searchParams.get('inline');
  const fmt = url.searchParams.get('fmt') || null;
  return download(gd, file.id, range, inline, fmt);
}

export default {
  async fetch(request, env, ctx) {
    try {
      initConfig(env);
    } catch (err) {
      console.error(err.message);
      return new Response('Configuration error: ' + err.message, { status: 500 });
    }
    return handleRequest(request, ctx).catch(err => {
      console.error(err.stack || err.message);
      return new Response('Internal Server Error', { status: 500 });
    });
  },
};
