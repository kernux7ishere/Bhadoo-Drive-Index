#!/usr/bin/env python3
"""
Convert rclone.conf `drive` remotes into Bhadoo Drive Index accounts + roots.

Run it on the machine that holds rclone.conf. The output contains OAuth refresh
tokens: never paste it into chat, never commit it.

Outputs (in --out-dir, default ./bhadoo-secrets):
  accounts.json  SECRET   [{"name", "client_id", "client_secret", "refresh_token"}, ...]
                          or {"name", "service_account_json": {...}} entries.
                          Becomes the Worker secret ACCOUNTS_JSON.
  roots.json     public   [{"id", "type", "name", "account", "protect_file_link"}, ...]
                          Goes in the ROOTS var of wrangler.toml.

Roots point at accounts BY NAME ("account": "work"), so several remotes that
share one login (e.g. many Shared Drives of one account) reuse one credential.
Remotes with identical credentials are merged automatically.

Selection (interactive prompt unless a flag is given):
  a              all drives
  e <list>       all except the listed ones
  g <list>       only the listed ones
  <list> is names and/or numbers separated by spaces or commas.

Examples:
  python3 scripts/rclone-to-accounts.py
  python3 scripts/rclone-to-accounts.py --all --verify
  python3 scripts/rclone-to-accounts.py --get work 3 --push
  python3 scripts/rclone-to-accounts.py --exclude old-drive --dev-vars .dev.vars

Skipped with a reason (tokens are never printed):
  - no refresh_token / token field is not JSON
  - empty client_id/client_secret: rclone's built-in client is not stored in
    rclone.conf, so Bhadoo cannot reuse that token. Re-create the remote with
    your own OAuth client.
  - scope that cannot read file contents (drive.file, drive.appfolder, ...)
"""

import argparse
import configparser
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

READ_SCOPES = {"drive", "drive.readonly"}
SECRET_LIMIT = 4800  # Cloudflare caps one secret at 5 KB
MAX_CHUNKS = 9       # worker reads ACCOUNTS_JSON, ACCOUNTS_JSON_2 .. _9
TOKEN_URL = "https://oauth2.googleapis.com/token"


def err(msg):
    print(msg, file=sys.stderr)


def default_config_path():
    env = os.environ.get("RCLONE_CONFIG")
    if env:
        return env
    try:
        out = subprocess.run(["rclone", "config", "file"], capture_output=True, text=True, timeout=10).stdout
        for line in out.splitlines():
            if line.strip().startswith("/") or line.strip()[1:3] == ":\\":
                return line.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return os.path.expanduser("~/.config/rclone/rclone.conf")


def parse_args():
    p = argparse.ArgumentParser(description="rclone.conf -> Bhadoo accounts.json + roots.json")
    p.add_argument("--config", default=None, help="path to rclone.conf (default: $RCLONE_CONFIG or `rclone config file`)")
    p.add_argument("--out-dir", default="./bhadoo-secrets", help="where to write accounts.json and roots.json")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--all", action="store_true", help="select all drives, no prompt")
    g.add_argument("--exclude", nargs="+", metavar="DRIVE", help="select all except these names/numbers")
    g.add_argument("--get", nargs="+", metavar="DRIVE", help="select only these names/numbers")
    p.add_argument("--verify", action="store_true", help="exchange each refresh token with Google and drop dead ones")
    p.add_argument("--push", action="store_true", help="run `wrangler secret put ACCOUNTS_JSON[_N]` for you")
    p.add_argument("--dev-vars", metavar="FILE", help="also write ACCOUNTS_JSON and ROOTS into this .dev.vars file")
    p.add_argument("--keep-names", action="store_true", help="never merge remotes that share credentials")
    return p.parse_args()


def load_drives(path):
    if not os.path.isfile(path):
        err(f"ERROR: {path} not found (use --config)")
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if text.lstrip().startswith("# Encrypted rclone configuration"):
        err("ERROR: rclone.conf is encrypted. Run `rclone config touch` after removing the password "
            "(rclone config -> s -> a), or export a decrypted copy, then retry.")
        sys.exit(1)
    cfg = configparser.ConfigParser(interpolation=None, strict=False)
    cfg.read_string(text)
    drives = []
    for name in cfg.sections():
        sec = cfg[name]
        if sec.get("type", "").strip() != "drive":
            continue
        drives.append({
            "name": name,
            "client_id": sec.get("client_id", "").strip(),
            "client_secret": sec.get("client_secret", "").strip(),
            "scope": sec.get("scope", "").strip(),
            "team_drive": sec.get("team_drive", "").strip(),
            "root_folder_id": sec.get("root_folder_id", "").strip(),
            "token_raw": sec.get("token", "").strip(),
            "sa_file": sec.get("service_account_file", "").strip(),
            "sa_inline": sec.get("service_account_credentials", "").strip(),
        })
    return drives


def root_for(d):
    """Return (id, type) describing what this remote exposes."""
    if d["root_folder_id"]:
        return d["root_folder_id"], "folder"
    if d["team_drive"]:
        return d["team_drive"], "shared_drive"
    return "root", "root"


def flatten(tokens):
    out = []
    for t in tokens:
        out.extend(x for x in t.replace(",", " ").split() if x)
    return out


def resolve(tokens, drives):
    by_number = {str(i): d["name"] for i, d in enumerate(drives, 1)}
    names = {d["name"] for d in drives}
    found, unknown = [], []
    for tok in flatten(tokens):
        if tok in names:
            found.append(tok)
        elif tok in by_number:
            found.append(by_number[tok])
        else:
            unknown.append(tok)
    for tok in unknown:
        err(f"WARN: no such drive '{tok}', ignoring")
    return found


def select(mode, tokens, drives):
    chosen = resolve(tokens, drives)
    if mode == "g":
        return [d["name"] for d in drives if d["name"] in chosen]
    return [d["name"] for d in drives if d["name"] not in chosen]


def describe(d):
    if d["sa_file"] or d["sa_inline"]:
        return "service account"
    if not (d["client_id"] and d["client_secret"]):
        return "NO own client (will be skipped)"
    return "ok"


def ask(drives):
    width = max(len(d["name"]) for d in drives)
    print("\nDrive remotes in rclone.conf\n" + "-" * 64)
    for i, d in enumerate(drives, 1):
        rid, rtype = root_for(d)
        print(f"  {i:>2}. {d['name']:<{width}}  {rtype:<12} {rid:<20} {describe(d)}")
    print("-" * 64)
    print("a = all   |   e <list> = all except   |   g <list> = only these")
    print("e.g.  a   |   e old-drive   |   g work 3,4")
    while True:
        try:
            line = input("Select > ").strip()
        except (EOFError, KeyboardInterrupt):
            err("\nCancelled.")
            sys.exit(1)
        parts = flatten([line])
        if not parts:
            continue
        mode = parts[0].lower()
        if mode == "a":
            return [d["name"] for d in drives]
        if mode in ("e", "g") and len(parts) > 1:
            return select(mode, parts[1:], drives)
        err("Start with a, e <list> or g <list>.")


def load_service_account(d):
    raw = d["sa_inline"]
    if not raw and d["sa_file"]:
        path = os.path.expanduser(d["sa_file"])
        try:
            with open(path, encoding="utf-8") as f:
                raw = f.read()
        except OSError as e:
            return None, f"cannot read service_account_file ({e.strerror})"
    try:
        sa = json.loads(raw)
    except json.JSONDecodeError:
        return None, "service account credentials are not valid JSON"
    if not sa.get("client_email") or not sa.get("private_key"):
        return None, "service account JSON lacks client_email/private_key"
    return sa, None


def credential_for(d):
    """Return (credential dict, key for dedupe, warning) or (None, None, skip reason)."""
    if d["sa_file"] or d["sa_inline"]:
        sa, why = load_service_account(d)
        if not sa:
            return None, None, why
        return {"service_account_json": sa}, ("sa", sa["client_email"]), None
    try:
        token = json.loads(d["token_raw"]) if d["token_raw"] else {}
    except json.JSONDecodeError:
        return None, None, "token field is not valid JSON"
    refresh = (token.get("refresh_token") or "").strip()
    if not refresh:
        return None, None, "no refresh_token in stored token"
    if not d["client_id"] or not d["client_secret"]:
        return None, None, "no client_id/client_secret (rclone built-in client; re-create the remote with your own)"
    if d["scope"] and d["scope"].split(",")[0] not in READ_SCOPES:
        return None, None, f"scope '{d['scope']}' cannot read file contents"
    cred = {"client_id": d["client_id"], "client_secret": d["client_secret"], "refresh_token": refresh}
    return cred, ("oauth", d["client_id"], refresh), None


def verify(cred):
    """Return None when Google accepts the credential, else a short reason."""
    if "service_account_json" in cred:
        return None  # a JWT exchange needs crypto libs; the Worker reports it on first use
    body = urllib.parse.urlencode({**cred, "grant_type": "refresh_token"}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(TOKEN_URL, data=body), timeout=20):
            return None
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read()).get("error", f"HTTP {e.code}")
        except (ValueError, OSError):
            return f"HTTP {e.code}"
    except OSError as e:
        return f"network error ({e})"


def build(drives, selected, merge, check):
    by_name = {d["name"]: d for d in drives}
    accounts, roots, skipped = [], [], []
    seen = {}
    for name in selected:
        d = by_name[name]
        cred, key, why = credential_for(d)
        if not cred:
            skipped.append((name, why))
            continue
        if merge and key in seen:
            account_name = seen[key]
        else:
            if check:
                bad = verify(cred)
                if bad:
                    skipped.append((name, f"Google rejected the credential: {bad}"))
                    continue
            account_name = name
            seen[key] = name
            accounts.append({"name": name, **cred})
        rid, rtype = root_for(d)
        roots.append({"id": rid, "type": rtype, "name": name, "account": account_name, "protect_file_link": False})
    return accounts, roots, skipped


def chunk_accounts(accounts):
    """Pack accounts into JSON arrays that each fit one Cloudflare secret."""
    chunks, cur = [], []
    for acc in accounts:
        trial = cur + [acc]
        if cur and len(json.dumps(trial, separators=(",", ":"))) > SECRET_LIMIT:
            chunks.append(cur)
            trial = [acc]
        if len(json.dumps(trial, separators=(",", ":"))) > SECRET_LIMIT:
            raise SystemExit(f"ERROR: account '{acc['name']}' alone exceeds the {SECRET_LIMIT}-byte secret limit")
        cur = trial
    if cur:
        chunks.append(cur)
    if len(chunks) > MAX_CHUNKS:
        raise SystemExit(f"ERROR: needs {len(chunks)} secrets, the Worker reads at most {MAX_CHUNKS}")
    return chunks


def secret_name(i):
    return "ACCOUNTS_JSON" if i == 0 else f"ACCOUNTS_JSON_{i + 1}"


def write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(path, 0o600)


def update_dev_vars(path, values):
    lines = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            lines = [ln for ln in f.read().splitlines() if ln.split("=", 1)[0] not in values]
    lines += [f"{k}={v}" for k, v in values.items()]
    write_private(path, "\n".join(lines) + "\n")


def push(chunks):
    for i, chunk in enumerate(chunks):
        name = secret_name(i)
        payload = json.dumps(chunk, separators=(",", ":"))
        print(f"  wrangler secret put {name} ...", end=" ", flush=True)
        r = subprocess.run(["npx", "wrangler", "secret", "put", name], input=payload, text=True, capture_output=True)
        if r.returncode != 0:
            print("FAILED")
            err(r.stderr.strip())
            return False
        print("ok")
    return True


def main():
    args = parse_args()
    path = args.config or default_config_path()
    drives = load_drives(path)
    if not drives:
        err("ERROR: no `type = drive` remotes found in rclone.conf")
        return 1

    if args.all:
        selected = [d["name"] for d in drives]
    elif args.exclude:
        selected = select("e", args.exclude, drives)
    elif args.get:
        selected = select("g", args.get, drives)
    else:
        selected = ask(drives)
    if not selected:
        err("ERROR: nothing selected")
        return 1

    accounts, roots, skipped = build(drives, selected, not args.keep_names, args.verify)
    for name, why in skipped:
        err(f"skipped {name}: {why}")
    if not accounts:
        err("ERROR: no drive could be converted; nothing written")
        return 1

    chunks = chunk_accounts(accounts)
    os.makedirs(args.out_dir, exist_ok=True)
    out = os.path.abspath(args.out_dir)
    os.chmod(out, 0o700)
    write_private(os.path.join(out, "accounts.json"), json.dumps(accounts, indent=2) + "\n")
    with open(os.path.join(out, "roots.json"), "w", encoding="utf-8") as f:
        json.dump(roots, f, indent=2)
        f.write("\n")
    roots_line = "ROOTS = '" + json.dumps(roots, separators=(",", ":")).replace("'", "\\'") + "'"

    if args.dev_vars:
        update_dev_vars(args.dev_vars, {
            "ACCOUNTS_JSON": json.dumps(chunks[0], separators=(",", ":")),
            **{secret_name(i): json.dumps(c, separators=(",", ":")) for i, c in enumerate(chunks) if i},
            "ROOTS": json.dumps(roots, separators=(",", ":")),
        })

    print(f"\nConverted {len(roots)} drive(s) using {len(accounts)} account(s)")
    for r in roots:
        print(f"  {r['name']:<20} {r['type']:<12} id={r['id']:<20} account={r['account']}")
    print(f"\naccounts.json (0600): {os.path.join(out, 'accounts.json')}")
    print(f"roots.json:           {os.path.join(out, 'roots.json')}")
    if args.dev_vars:
        print(f"updated:              {args.dev_vars}")

    print("\nNext:")
    if args.push:
        print("  Uploading secrets to Cloudflare:")
        if not push(chunks):
            err("Push failed; run `npx wrangler secret put ACCOUNTS_JSON` manually.")
            return 1
    else:
        names = ", ".join(secret_name(i) for i in range(len(chunks)))
        print(f"  1. npx wrangler secret put {names.split(', ')[0]}   (paste the one-line JSON; --push does this for you)")
        if len(chunks) > 1:
            print(f"     {len(chunks)} secrets are needed: {names}. Re-run with --push to split them automatically.")
    print("  2. Put this in wrangler.toml [vars]:")
    print(f"     {roots_line}")
    print("  3. npx wrangler deploy, then delete the output directory.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
