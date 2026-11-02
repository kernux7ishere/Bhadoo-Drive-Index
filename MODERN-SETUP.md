# Modern Setup Guide (Wrangler / GitHub Actions)

This guide replaces the old copy-paste workflow. You now deploy with
`wrangler deploy` — no manual code copying required. All secrets are
stored in Cloudflare and never committed to the repository.

> **Scope**: this project indexes **Google Drive only**. It does not
> support OneDrive, Dropbox, or any other storage backend.

---

## 1. Obtain Google OAuth Credentials

### 1.1 Create a GCP project and enable the Drive API

1. Go to <https://console.developers.google.com/>.
2. Click **Select a project → New Project**, name it anything.
3. Open **APIs & Services → Library**, search for **Google Drive API**,
   click it, then click **Enable**.

### 1.2 Configure the OAuth consent screen

1. Go to **APIs & Services → OAuth consent screen**.
2. Choose **External**, click **Create**.
3. Fill in the required app name and your email.
4. On the **Scopes** step, click **Add or remove scopes** and add:
   ```
   https://www.googleapis.com/auth/drive
   ```
5. On the **Test users** step, add the Google account that owns the
   drive you want to index.
6. Save and continue through to the end.

### 1.3 Create an OAuth client (Desktop App)

1. Go to **APIs & Services → Credentials → Create Credentials →
   OAuth client ID**.
2. Choose **Desktop app**, name it anything, click **Create**.
3. Copy the **Client ID** and **Client Secret** — you'll need them
   shortly.

### 1.4 Generate a refresh token

Use the `worker/worker-generator.js` helper (deploy it as a temporary
Cloudflare Worker, follow the on-screen steps) or obtain a refresh
token manually with any OAuth 2.0 tool using:

- **Authorization URL**: `https://accounts.google.com/o/oauth2/auth`
- **Token URL**: `https://oauth2.googleapis.com/token`
- **Scope**: `https://www.googleapis.com/auth/drive`
- **Grant type**: Authorization Code
- **Redirect URI**: `urn:ietf:wg:oauth:2.0:oob`

Save the resulting **refresh token**.

---

## 2. Deploy

### 2.1 Prerequisites

- Node.js 18+
- A [Cloudflare account](https://dash.cloudflare.com/sign-up)

### 2.2 Install dependencies

```bash
npm install
```

### 2.3 Authenticate with Cloudflare

```bash
npx wrangler login
```

### 2.4 Set secrets (stored in Cloudflare, never in git)

```bash
npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put GOOGLE_CLIENT_SECRET
npx wrangler secret put GOOGLE_REFRESH_TOKEN
npx wrangler secret put CRYPTO_BASE_KEY   # 16/24/32 chars: openssl rand -hex 16
npx wrangler secret put HMAC_BASE_KEY     # 32+ chars:      openssl rand -hex 32
```

`CRYPTO_BASE_KEY` and `HMAC_BASE_KEY` sign and encrypt download links and
sessions. v2.5.9 no longer ships default keys, so the Worker refuses to start
until you set your own.

Enter each value when prompted. For a **service account** instead of
OAuth, also run:

```bash
npx wrangler secret put SERVICE_ACCOUNT_JSON
```

and paste the entire contents of your service account `.json` file as
one line, then set `USE_SERVICE_ACCOUNT = "true"` in `wrangler.toml`.

### 2.4a Multiple Google accounts

Skip the three `GOOGLE_*` secrets and put every account in one secret,
`ACCOUNTS_JSON`: a JSON array where each entry has a unique `name` and either
OAuth credentials or a service account key.

```json
[
  {"name":"work","client_id":"...","client_secret":"...","refresh_token":"..."},
  {"name":"sa1","service_account_json":{"client_email":"...","private_key":"..."}}
]
```

Each root in `ROOTS` then selects its account with `"account": "<name>"`
(a numeric array index also works). Roots without `account` fall back to the
`GOOGLE_*` / `SERVICE_ACCOUNT_JSON` secrets, so existing setups keep working.
Several roots may share one account (for example many Shared Drives of one
login). Each account keeps its own access token, and download links remember
which account to use.

Cloudflare limits a secret to 5 KB. If the array is larger, split it across
`ACCOUNTS_JSON`, `ACCOUNTS_JSON_2`, ... `ACCOUNTS_JSON_9`.

**Already use rclone?** Convert its remotes instead of typing this by hand:

```bash
npm run rclone:import                 # interactive: a / e <list> / g <list>
npm run rclone:import -- --all --verify --push
npm run rclone:import -- --get work 3 --dev-vars .dev.vars
```

The script reads the `type = drive` remotes in `rclone.conf`, merges remotes that
share a login, and writes `accounts.json` (secret, mode 0600) and `roots.json`
(public) to `./bhadoo-secrets`. `--verify` checks each refresh token with Google,
and `--push` uploads the secrets with `wrangler secret put`, splitting them into
`ACCOUNTS_JSON_N` automatically. It prints the `ROOTS = '...'` line to paste into
`wrangler.toml`. Delete the output directory afterwards. Remotes that use rclone's
built-in OAuth client are skipped because their client secret is not stored in
`rclone.conf`.

### 2.5 Configure your drive roots

Edit the `ROOTS` variable in `wrangler.toml`. It is a JSON array; each
entry is one indexed drive or folder.

```toml
# Single personal drive (root)
ROOTS = '[{"id":"root","type":"root","name":"My Drive","protect_file_link":false}]'

# Shared / Team Drive — replace the ID with your own
ROOTS = '[{"id":"0AOM2i7MQiuWIUk9PVA","type":"shared_drive","name":"Team Drive","protect_file_link":false}]'

# Multiple drives
ROOTS = '[{"id":"root","type":"root","name":"Personal"},{"id":"0AOM2i7MQiuWIUk9PVA","type":"shared_drive","name":"Team"}]'
```

Add `"account":"<name>"` to a root to use an `ACCOUNTS_JSON` entry (see 2.4a).

The `id` field is either `"root"` for a personal drive, a **Shared
Drive ID** (the last path segment from the Drive URL), or a **folder
ID**.

> **Search limitation**: search only works when `id` is `"root"` or a
> Shared Drive ID. It does not work for a plain subfolder ID.

### 2.6 Deploy

```bash
npx wrangler deploy
```

---

## 3. Protect access to a drive

### 3.1 Login system (site-wide, recommended)

Set `ENABLE_LOGIN = "true"` in `wrangler.toml`, then provide users:

- `LOGIN_DATABASE = "Local"`: `npx wrangler secret put USERS_JSON` with
  `[{"username":"admin","password":"a-strong-password"}]`
- `LOGIN_DATABASE = "KV"` or `"D1"`: add the matching `ENV` / `DB` binding.

Per root, `"protect_file_link": true` also requires a login for file
downloads from that root. Add `DISABLE_ANONYMOUS_DOWNLOAD = "true"` and
`DIRECT_LINK_PROTECTION = "true"` to block unauthenticated direct links.

**Enable login before indexing private data on a public Worker.**

### 3.2 Folder-level `.password` file

Requires `ENABLE_PASSWORD_FILE_VERIFY = "true"` (default is `false`).

Create a file named `.password` inside any Google Drive folder you want
to protect. The file should contain only the password text (plain,
no quotes). The index will prompt visitors for this password before
showing that folder's contents. The `.password` file itself is never
served through the index.

---

## 4. Configuration reference

Everything below is a plain `[vars]` entry in `wrangler.toml` (strings only).
Only `SITE_NAME`, `ENVIRONMENT`, `ROOTS` and `USE_SERVICE_ACCOUNT` are active by
default; the rest are commented out and use the defaults in `src/worker.js`.
Uncomment what you want to change, then run `npx wrangler deploy` again.
Workers Free allows 32 variables (vars + secrets) per Worker, so enable only
what you need or use Workers Paid.

| Group | Variables |
|---|---|
| General | `SITE_NAME`, `ENVIRONMENT` (`production` default), `ROOTS`, `USE_SERVICE_ACCOUNT` |
| Listing | `FILES_LIST_PAGE_SIZE`, `SEARCH_RESULT_LIST_PAGE_SIZE`, `SEARCH_ALL_DRIVES` |
| Access | `ENABLE_PASSWORD_FILE_VERIFY`, `DIRECT_LINK_PROTECTION`, `DISABLE_ANONYMOUS_DOWNLOAD`, `FILE_LINK_EXPIRY`, `ENABLE_CORS_FILE_DOWN`, `CORS_DOMAIN`, `BLOCKED_REGION`, `BLOCKED_ASN`, `DOMAINS_FOR_DL` |
| Login | `ENABLE_LOGIN`, `ENABLE_SIGNUP`, `ENABLE_SOCIAL_LOGIN`, `LOGIN_DATABASE` (`Local`/`KV`/`D1`), `LOGIN_DAYS`, `ENABLE_IP_LOCK`, `SINGLE_SESSION`, `IP_CHANGED_ACTION`, `REDIRECT_DOMAIN` |
| UI | `UI_THEME`, `UI_LOGO_IMAGE`, `UI_LOGO_HEIGHT`, `UI_LOGO_WIDTH`, `UI_FAVICON`, `UI_LOGO_LINK_NAME`, `UI_FIXED_HEADER`, `UI_HEADER_PADDING`, `UI_FIXED_FOOTER`, `UI_HIDE_FOOTER`, `UI_*_CLASS`, `UI_CSS_*_COLOR`, `UI_CONTACT_LINK`, `UI_COMPANY_NAME`, `UI_COMPANY_LINK`, `UI_CREDIT`, `UI_DISPLAY_*`, `UI_DISABLE_*`, `UI_ALLOW_SELECTING_FILES`, `UI_SECOND_DOMAIN_FOR_DL`, `UI_POSTER`, `UI_AUDIO_POSTER`, `UI_RENDER_HEAD_MD`, `UI_RENDER_README_MD`, `UI_UNAUTHORIZED_OWNER_LINK`, `UI_UNAUTHORIZED_OWNER_EMAIL`, `UI_SHOW_QUOTA` |

Secrets (set with `wrangler secret put`, never in `wrangler.toml`):
`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REFRESH_TOKEN`,
`CRYPTO_BASE_KEY`, `HMAC_BASE_KEY`, and optionally `SERVICE_ACCOUNT_JSON`
(one account or a JSON array; one is picked at random per isolate),
`ACCOUNTS_JSON` (+ `ACCOUNTS_JSON_2`..`_9`), `USERS_JSON` (for `LOGIN_DATABASE=Local`), `LOGIN_GOOGLE_CLIENT_ID`,
`LOGIN_GOOGLE_CLIENT_SECRET`.

For `LOGIN_DATABASE=KV` add a `[[kv_namespaces]]` binding named `ENV`; for
`D1` add a `[[d1_databases]]` binding named `DB`.

---

## 5. Local development

```bash
cp .dev.vars.example .dev.vars
# Edit .dev.vars and fill in your real credentials
npx wrangler dev
```

`.dev.vars` is listed in `.gitignore` and must never be committed.

---

## 6. Security reminders

- **Never commit** `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`,
  `GOOGLE_REFRESH_TOKEN`, `CRYPTO_BASE_KEY`, `HMAC_BASE_KEY`, or `SERVICE_ACCOUNT_JSON` to git. Use
  `wrangler secret put` for all of these.
- **Enable `ENABLE_LOGIN`** before making the Worker public if the
  indexed drive is not intended to be publicly accessible.
- The `.password` mechanism stores the password inside Google Drive
  itself — not in this repository or in Cloudflare.
- `wrangler.toml` is safe to commit; it contains no secrets.
- `.dev.vars` is git-ignored; keep it that way.
