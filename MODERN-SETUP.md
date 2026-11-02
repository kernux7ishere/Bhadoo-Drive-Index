# Modern Setup Guide (Wrangler / GitHub Actions)

Deploy with `wrangler deploy`. All credentials and tokens are stored as Cloudflare secrets and never committed to the repository.

Supported backends:
- **Google Drive** (Personal My Drive, Shared Drives, subfolders via OAuth or Service Accounts)
- **Cloudflare R2** (via native `[[r2_buckets]]` Worker bindings)

---

## 1. Quick Start

### 1.1 Install dependencies
```bash
npm install
```

### 1.2 Authenticate with Cloudflare
```bash
npx wrangler login
```

### 1.3 Set Encryption Secrets (Required)
```bash
npx wrangler secret put CRYPTO_BASE_KEY   # 16/24/32 chars: openssl rand -hex 16
npx wrangler secret put HMAC_BASE_KEY     # 32+ chars:      openssl rand -hex 32
```

---

## 2. Storage Setup

### Option A: Google Drive (Multiple Accounts / Shared Drives)

All Google credentials live in the `ACCOUNTS_JSON` secret as a JSON array:
```json
[
  { "name": "work", "client_id": "...", "client_secret": "...", "refresh_token": "..." },
  { "name": "sa_team", "service_account_json": { "client_email": "...", "private_key": "..." } }
]
```

**Already use rclone?** Import directly:
```bash
npm run rclone:import
```
It reads your `rclone.conf`, creates `bhadoo-secrets/accounts.json`, and offers to upload it to Cloudflare automatically.

Set `SCOPE` in `wrangler.toml`:
```toml
SCOPE = '[
  {"id":"root", "type":"root", "name":"Work Drive", "account":"work"},
  {"id":"0AOM2i7MQiuWIUk9PVA", "type":"shared_drive", "name":"Team Drive", "account":"sa_team"}
]'
```

---

### Option B: Cloudflare R2 Bucket

1. Bind your R2 bucket in `wrangler.toml`:
```toml
[[r2_buckets]]
binding = "MY_STORE"
bucket_name = "my-public-bucket"
```

2. Add the R2 backend to `SCOPE` in `wrangler.toml`:
```toml
SCOPE = '[
  {"id":"MY_STORE", "type":"r2", "name":"R2 Storage", "prefix":""}
]'
```
*(You can mix both Google Drives and R2 buckets in the same `SCOPE` array!)*

---

## 3. Deploy

```bash
npx wrangler deploy
```

---

## 4. Local Development

```bash
cp .dev.vars.example .dev.vars
# Fill in real keys in .dev.vars
npx wrangler dev
```
`.dev.vars` is git-ignored and never committed.
