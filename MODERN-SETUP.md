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
```

Enter each value when prompted. For a **service account** instead of
OAuth, also run:

```bash
npx wrangler secret put SERVICE_ACCOUNT_JSON
```

and paste the entire contents of your service account `.json` file as
one line, then set `USE_SERVICE_ACCOUNT = "true"` in `wrangler.toml`.

### 2.5 Configure your drive roots

Edit the `ROOTS` variable in `wrangler.toml`. It is a JSON array; each
entry is one indexed drive or folder.

```toml
# Single personal drive (root)
ROOTS = '[{"id":"root","name":"My Drive","protect_file_link":false}]'

# Shared / Team Drive — replace the ID with your own
ROOTS = '[{"id":"0AOM2i7MQiuWIUk9PVA","name":"Team Drive","protect_file_link":false}]'

# Multiple drives
ROOTS = '[{"id":"root","name":"Personal"},{"id":"0AOM2i7MQiuWIUk9PVA","name":"Team"}]'
```

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

### 3.1 HTTP Basic Auth (per-drive, via `ROOTS`)

Add an `"auth"` object to a root entry in `ROOTS`:

```toml
ROOTS = '[{"id":"root","name":"My Drive","protect_file_link":true,"auth":{"alice":"password1","bob":"password2"}}]'
```

- Keys are usernames, values are passwords.
- **Enable this before exposing any private data on a public Worker.**

### 3.2 Folder-level `.password` file

Create a file named `.password` inside any Google Drive folder you want
to protect. The file should contain only the password text (plain,
no quotes). The index will prompt visitors for this password before
showing that folder's contents. The `.password` file itself is never
served through the index.

---

## 4. UI customisation

All UI options are plain `[vars]` in `wrangler.toml`. Edit them and
re-run `npx wrangler deploy` — no code changes needed.

| Variable | Default | Purpose |
|---|---|---|
| `SITE_NAME` | `Bhadoo Drive Index` | Browser tab title |
| `UI_THEME` | `slate` | [Bootswatch](https://bootswatch.com) theme name |
| `UI_LOGO_IMAGE` | `true` | `true` = image logo, `false` = text |
| `UI_LOGO_LINK_NAME` | *(CDN URL)* | Image URL (if `UI_LOGO_IMAGE=true`) or site name text |
| `UI_LOGO_WIDTH` | `100px` | Logo width (CSS value) |
| `UI_FAVICON` | *(CDN URL)* | Favicon URL |
| `UI_FIXED_HEADER` | `true` | Sticky header |
| `UI_HEADER_PADDING` | `60` | Body top padding in px (match to header state) |
| `UI_FIXED_FOOTER` | `false` | Sticky footer |
| `UI_HEADER_STYLE_CLASS` | `navbar-dark bg-primary` | Bootstrap navbar classes |
| `UI_FOOTER_STYLE_CLASS` | `bg-primary` | Bootstrap footer classes |
| `UI_CSS_A_TAG_COLOR` | `white` | Link colour |
| `UI_CSS_P_TAG_COLOR` | `white` | Paragraph text colour |
| `UI_FOLDER_TEXT_COLOR` | `white` | Folder name colour |
| `UI_CONTACT_LINK` | — | URL for the Contact button |
| `UI_COPYRIGHT_YEAR` | current year | Copyright year text |
| `UI_COMPANY_NAME` | — | Footer company name |
| `UI_COMPANY_LINK` | — | Footer company URL |
| `UI_CREDIT` | `true` | Show upstream project credit |
| `UI_DISPLAY_SIZE` | `true` | Show file sizes |
| `UI_DISPLAY_TIME` | `false` | Show modified times |
| `UI_DISPLAY_DOWNLOAD` | `true` | Show download buttons |
| `UI_DISABLE_PLAYER` | `false` | Hide audio/video player |
| `UI_DISABLE_VIDEO_DOWNLOAD` | `false` | Hide video download button |
| `UI_SECOND_DOMAIN_FOR_DL` | `false` | Serve downloads from a different domain |
| `UI_DOWNLOAD_DOMAIN` | *(empty)* | Download domain URL (requires `UI_SECOND_DOMAIN_FOR_DL=true`) |
| `UI_POSTER` | *(CDN URL)* | Default video poster image URL |
| `UI_AUDIO_POSTER` | *(CDN URL)* | Default audio poster image URL |
| `UI_RENDER_HEAD_MD` | `true` | Render `Head.md` in folders |
| `UI_RENDER_README_MD` | `true` | Render `Readme.md` in folders |
| `UI_DISPLAY_DRIVE_LINK` | `false` | Show direct Google Drive link button |
| `UI_PLYR_IO_VERSION` | `3.6.4` | Plyr.io player version |
| `UI_PLYR_IO_VIDEO_RES` | `16:9` | Default video aspect ratio |
| `UI_UNAUTHORIZED_OWNER_LINK` | — | URL shown on 401 error page |
| `UI_UNAUTHORIZED_OWNER_EMAIL` | — | Email shown on 401 error page |
| `UI_ARC_CODE` | *(empty)* | arc.io widget code (leave empty to disable) |
| `FILES_LIST_PAGE_SIZE` | `50` | Files per page |
| `SEARCH_RESULT_LIST_PAGE_SIZE` | `50` | Search results per page |
| `ENABLE_CORS_FILE_DOWN` | `false` | Add CORS header to file downloads |
| `ENABLE_PASSWORD_FILE_VERIFY` | `true` | Enable `.password` file protection |

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
  `GOOGLE_REFRESH_TOKEN`, or `SERVICE_ACCOUNT_JSON` to git. Use
  `wrangler secret put` for all of these.
- **Enable `auth`** on any root before making the Worker public if the
  indexed drive is not intended to be publicly accessible.
- The `.password` mechanism stores the password inside Google Drive
  itself — not in this repository or in Cloudflare.
- `wrangler.toml` is safe to commit; it contains no secrets.
- `.dev.vars` is git-ignored; keep it that way.
