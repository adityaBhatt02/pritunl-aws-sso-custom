# pritunl-aws-sso-custom

A one-click installer and custom patch set that adds full SSO/SAML support to a self-hosted [Pritunl](https://pritunl.com/) VPN on Amazon Linux 2023.

Out of the box, Pritunl's open-source edition has incomplete SAML support and no clean way to wire in an external Identity Provider. This repo fixes that — apply it to a fresh EC2 and you get a fully working VPN with SSO login via **Prism (Keycloak)** or **AWS IAM Identity Center**, split-tunnel domain routing, and a self-serve admin UI for SAML configuration.

---

## What This Does

- **One-command install** on any fresh Amazon Linux 2023 EC2
- **SAML SSO login** — users go to `/login` → authenticate with your IdP → download VPN profile → connect
- **`/saml-settings` UI** — admin page to configure IdP without touching config files
- **`/domain-routes` UI** — admin page to manage split-tunnel domain rules
- **AWS IAM Identity Center** and **Other SAML 2.0 IdPs** (Prism/Keycloak, Okta, etc.) supported
- **10 bug fixes** applied automatically to the Pritunl source to make all of the above work

---

## Architecture

```
User browser
     │
     ▼
nginx :443 / :80
     │  (reverse proxy)
     ├──► pritunl-web :9443   (Pritunl admin + SSO handler)
     └──► static files        (/saml-settings, /domain-routes HTML)

VPN client
     │
     ▼
pritunl :1194 UDP   (OpenVPN tunnel)

MongoDB :27017      (Pritunl config + custom collections)

pritunl-domain-resolver  (background service, evaluates domain routes)
```

---

## Prerequisites

- **EC2**: Amazon Linux 2023, `t3.small` minimum
- **Security group inbound rules**:
  | Port | Protocol | Purpose |
  |------|----------|---------|
  | 22 | TCP | SSH |
  | 80 | TCP | HTTP (redirect) |
  | 443 | TCP | HTTPS admin + login |
  | 8443 | TCP | SAML callback |
  | 1194 | UDP | VPN tunnel |
- **Domain**: an A record pointing to the EC2's public IP (e.g. `vpn.company.com`)
- **DNS propagated** before running the installer

---

## Install

SSH into the fresh EC2, then:

```bash
curl -s https://raw.githubusercontent.com/adityaBhatt02/pritunl-aws-sso-custom/main/install.sh -o install.sh
chmod +x install.sh
sudo bash install.sh
```

> **Note:** Do not pipe directly through `curl | bash` — the script uses `read` prompts for IP and domain that require an interactive shell.

When prompted:
```
Enter server IP (e.g. 54.123.45.67): <your EC2 public IP>
Enter domain (e.g. vpn.company.com):  <your domain>
```

The script takes ~3–5 minutes. A fully green output looks like:

```
  ✓ mongod running
  ✓ pritunl running
  ✓ pritunl-web running
  ✓ nginx running
  ✓ /etc/pritunl/saml/settings.json exists
  ✓ SAML sp section present: https://vpn.company.com:8443/sso/callback
```

---

## Post-Install Setup (Manual Steps)

These five steps must be done after the script completes — they require the admin UI.

### 1. Get the admin password

```bash
sudo pritunl default-password
```

Login at `https://<your-domain>/pritunl-admin` and immediately change the password under **Administrator**.

### 2. Create Organization and Server

In the Pritunl admin panel:
- **Users** → **Add Organization** → give it a name (e.g. `default`)
- **Servers** → **Add Server** → leave defaults → **Add Server**
- Click **Attach Organization** → select your org
- Click **Start Server**

### 3. Set sso_org

Pritunl needs to know which Organization to place SSO-authenticated users into. Run this after creating the org:

```bash
sudo /usr/lib/pritunl/usr/bin/python3 -c "
import pymongo
c = pymongo.MongoClient('mongodb://localhost:27017')
db = c['pritunl']
org = db['organizations'].find_one()
db['settings'].update_one({'_id':'app'},{'\$set':{'sso_org':org['_id']}},upsert=True)
print('sso_org set to:', str(org['_id']))
"
```

This only needs to be done once. All SSO users will be automatically placed into that org.

### 4. Create the SAML app in your IdP

#### Option A — Prism (Keycloak)

In **Prism → Custom Applications → Add Application**:

| Field | Value |
|-------|-------|
| Client ID | `https://<your-domain>` |
| ACS URL | `https://<your-domain>:8443/sso/callback` |
| Name ID Format | `Email` |
| Sign Assertions | ON |
| Sign Response | ON |
| Client Signature Required | OFF |

Then:
- **Mappers → Add Mapper**
  - Mapper Type: `User Attribute`
  - User Attribute: `Email`
  - SAML Attribute Name: `email`
- **Assign Users** to the app

#### Option B — AWS IAM Identity Center

In **IAM Identity Center → Applications → Add Application → Custom SAML 2.0**:

| Field | Value |
|-------|-------|
| Application ACS URL | `https://<your-domain>:8443/sso/callback` |
| Application SAML audience | `https://<your-domain>` |

Then:
- Download the IAM Identity Center SAML metadata to get the certificate
- Note your **Identity Store ID**, **Application ARN**, and **AWS Region**
- Assign users or groups to the application

### 5. Configure SAML settings

Go to `https://<your-domain>/saml-settings` (requires being logged into the admin panel).

#### For Prism / Other SAML 2.0 IdP:

Select the **Other IdP** tab and fill:

| Field | Value |
|-------|-------|
| IdP SSO URL | Login URL from your Prism app |
| IdP Issuer URL | `https://login.prism.cloudkeeper.com/realms/<realm>` |
| IdP x509 Certificate | Base64 cert from Prism metadata (no `BEGIN`/`END` lines) |

To extract the certificate from Prism metadata:
```bash
curl -s https://login.prism.cloudkeeper.com/realms/<realm>/protocol/saml/descriptor \
  | grep -o '<ds:X509Certificate>[^<]*</ds:X509Certificate>' \
  | head -1 | sed 's/<[^>]*>//g'
```

#### For AWS IAM Identity Center:

Select the **AWS IAM Identity Center** tab and fill:

| Field | Value |
|-------|-------|
| IdP SSO URL | IAM Identity Center SAML sign-in URL |
| IdP Issuer URL | IAM Identity Center SAML issuer URL |
| IdP x509 Certificate | Certificate from IAM Identity Center metadata |
| Identity Store ID | From IAM Identity Center settings |
| Application ARN | From your application in IAM Identity Center |
| AWS Region | Your IAM Identity Center region |

Click **Save Settings**.

> The two IdP tabs are mutually exclusive — saving on one tab automatically clears the other tab's fields.

### 6. Test

```
https://<your-domain>/login  →  Sign in with SSO
```

The user authenticates with the IdP, gets redirected back, and is offered a `.ovpn` profile to download and import into the Pritunl client.

---

## User Management

### Prism / Keycloak

Users need:
1. An account in the Prism realm
2. Assignment to the Pritunl VPN application in Prism

**Recommended:** Create a group (e.g. `vpn-users`) in Prism, assign that group to the Pritunl app, then add/remove users from the group. New employees get VPN access the moment they're added to the group.

To revoke access: remove the user from the group or unassign from the app. Takes effect immediately — the user cannot complete SAML login without an active assignment.

### AWS IAM Identity Center

Assign users or groups to the application in IAM Identity Center. The `aws_idp_check.py` module performs an additional check at VPN connect time (not just login time) to verify the user is still assigned.

---

## Admin Pages

| URL | Description |
|-----|-------------|
| `/pritunl-admin` | Pritunl admin panel (users, servers, orgs) |
| `/login` | End-user SSO login page |
| `/saml-settings` | Configure IdP (SAML URLs, cert, AWS fields) |
| `/domain-routes` | Manage split-tunnel domain routing rules |

All custom pages require an active admin session (login to `/pritunl-admin` first).

---

## Repository Structure

```
pritunl-aws-sso-custom/
├── install.sh                          # One-click installer
├── patches/
│   ├── sso.py                          # SAML handler — /saml-settings save/get, /sso/callback
│   ├── auth.py                         # Auth helpers — session_light_auth
│   ├── key.py                          # Key handler — SSO-aware profile delivery
│   ├── static.py                       # Static file handler — registers /saml-settings, /domain-routes
│   ├── domain_routes_handler.py        # Domain routes API handler
│   ├── authorizer/authorizer.py        # VPN connect-time auth (AWS IDC check)
│   ├── mongo/__init__.py (mongo.py)    # MongoDB collection fallback fix
│   ├── aws_idp_check.py                # AWS IAM Identity Center connect-time user check
│   ├── app.py                          # Pritunl app init
│   ├── server/server.py (server.py)    # Server host address fix
│   └── domain_resolver.py             # Domain route resolver
├── www/
│   ├── saml-settings.html              # SAML config UI
│   └── domain-routes.html             # Domain routing UI
├── config/
│   ├── nginx/pritunl.conf              # nginx reverse proxy config
│   └── systemd/env.conf               # systemd env drop-in
└── scripts/
    └── set_sso_org.py                  # Helper to set sso_org after org creation
```

---

## Bugs Fixed by the Installer

The installer automatically patches the Pritunl source to fix these issues:

| # | Fix | Problem |
|---|-----|---------|
| 1 | `domain_routes_handler` — use pymongo directly | `mongo.get_collection()` throws `TypeError` for unregistered collections |
| 2 | `domain_routes_handler` — use `session_light_auth` | `session_auth` blocks CSRF-less requests to `/domain-routes` |
| 3 | `mongo/__init__.py` — fallback to pymongo for any unknown collection | Prevents whack-a-mole fixing of every unregistered collection individually |
| 4 | `sso.py` — always write `sp` section on save | Without `sp` block, `OneLogin_Saml2_Auth` throws `sp_not_found` |
| 5 | Create `/etc/pritunl/saml/` directory | Missing directory causes `FileNotFoundError` on first SAML config save |
| 6 | All domain/SSO settings via `pritunl set` CLI | Raw pymongo writes are cached out — only CLI writes reach the live settings system |
| 7 | Set `server_port 9443` before nginx starts | Port 443 conflict between `pritunl-web` and nginx causes crash loop |
| 8 | nginx — `PR-Validated: true` on all location blocks | Missing header caused auth failures on `/domain-routes` and `/saml-settings` |
| 9 | nginx — `PR-Forwarded-Url` uses domain not IP | Wrong host in header causes `get_url_root()` to build incorrect callback URLs |
| 10 | Pre-write `sp` section to `settings.json` before first boot | Ensures SP block exists from the very first SAML request |

Additional automatic fixes:
- `set-mongodb` configured before any `pritunl set` commands (prevents "Empty host" error)
- `acme_domain` cleared to prevent Let's Encrypt auto-cert attempts (rate limits block `pritunl-web` startup)
- `auto_public_host`, `auto_public_address`, `public_address` all set to the server IP (prevents wrong IP in VPN profile `remote` line)
- Smart wait loop polls for `pritunl-web` on port 9443 before starting nginx (eliminates startup race condition)

---

## Troubleshooting

**pritunl-web not running after install**
```bash
sudo journalctl -u pritunl -n 50 --no-pager | grep -i "error\|acme\|port"
sudo systemctl restart pritunl
sleep 20
sudo systemctl status pritunl-web
```

**nginx fails to start (port 443 conflict)**
```bash
sudo ss -tlnp | grep 443
# If pritunl-web is on 443, server_port didn't apply yet:
sudo pritunl set app.server_port 9443
sudo systemctl restart pritunl && sleep 15
sudo systemctl start nginx
```

**SSO login returns 401 or 500**
```bash
sudo tail -20 /var/log/pritunl.log
# Common causes:
# - sso_org not set → run set_sso_org.py
# - No AttributeStatement → add email mapper in IdP
# - Wrong ACS URL in IdP app → must be https://<domain>:8443/sso/callback
```

**SAML error: sp_not_found**
```bash
sudo cat /etc/pritunl/saml/settings.json | python3 -m json.tool | grep -A5 '"sp"'
# If sp section missing, re-run Fix 10 from the installer or manually write it
```

**VPN profile has wrong IP in remote line**
```bash
sudo /usr/lib/pritunl/usr/bin/python3 -c "
import pymongo
db = pymongo.MongoClient('mongodb://localhost:27017')['pritunl']
print(list(db['hosts'].find({}, {'public_address':1,'auto_public_host':1})))
"
# Fix:
sudo /usr/lib/pritunl/usr/bin/python3 -c "
import pymongo
db = pymongo.MongoClient('mongodb://localhost:27017')['pritunl']
db['hosts'].update_many({}, {'\$set': {'public_address':'<IP>','auto_public_address':'<IP>','auto_public_host':'<IP>'}})
"
```

**domain-routes or saml-settings returns 401**
- Make sure you are logged into `/pritunl-admin` first — the custom pages share the admin session cookie
- If logged in and still 401, check nginx has `PR-Validated true` on those location blocks:
```bash
grep -A5 "saml-settings\|domain-routes" /etc/nginx/conf.d/pritunl.conf | grep PR-Validated
```

---

## Re-running on an Existing EC2

The installer is idempotent — running it again on an EC2 that already has Pritunl installed is safe. All `dnf install` steps skip if packages are already present, patches are re-applied, and settings are re-written. Useful for picking up repo updates:

```bash
curl -s https://raw.githubusercontent.com/adityaBhatt02/pritunl-aws-sso-custom/main/install.sh -o install.sh
chmod +x install.sh
sudo bash install.sh
```

---

## Syncing Live Changes Back to the Repo

If you patch files directly on an EC2, sync them back before they're lost:

```bash
cd /opt/pritunl-aws-sso-custom
BASE="/usr/lib/pritunl/usr/lib/python3.9/site-packages/pritunl"

sudo cp $BASE/handlers/sso.py               patches/sso.py
sudo cp $BASE/handlers/domain_routes_handler.py patches/domain_routes_handler.py
sudo cp $BASE/handlers/static.py            patches/static.py
sudo cp $BASE/handlers/auth.py              patches/auth.py
sudo cp $BASE/handlers/key.py               patches/key.py
sudo cp $BASE/mongo/__init__.py             patches/mongo.py
sudo cp $BASE/aws_idp_check.py              patches/aws_idp_check.py
sudo cp $BASE/app.py                        patches/app.py
sudo cp $BASE/server/server.py              patches/server.py
sudo cp $BASE/domain_resolver.py            patches/domain_resolver.py
sudo cp /usr/share/pritunl/www/saml-settings.html  www/saml-settings.html
sudo cp /usr/share/pritunl/www/domain-routes.html  www/domain-routes.html

sudo chown ec2-user:ec2-user patches/* www/*.html

git add -A
git commit -m "Sync: updated patches from live EC2"
git push origin main
```

---

## License

MIT
