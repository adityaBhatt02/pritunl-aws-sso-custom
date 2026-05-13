# Pritunl AWS SSO Integration

Custom implementation of AWS Identity Center (SSO) authentication for Pritunl VPN — built without a Pritunl Enterprise license.

## What This Does

Pritunl's built-in SSO requires an Enterprise license (~$1000/year). This project bypasses that entirely and implements a fully custom SSO flow using AWS IAM Identity Center and SAML 2.0.

### Features

- **Self-service profile download** — users visit a login page, authenticate via AWS SSO, and download their own VPN profile. No admin involvement needed.
- **Separate admin login** — admins access Pritunl's dashboard via a separate URL using username + password.
- **VPN connect authentication** — when a user connects their VPN client, a browser SSO popup verifies their AWS identity before allowing the connection.
- **Live AWS IDP check on every connect** — on every subsequent connection, the user is silently verified against AWS Identity Center in real time. If they are removed from AWS, they cannot connect — even with a valid profile.
- **Stolen profile protection** — if someone imports another user's profile, the SSO popup will detect the identity mismatch and block the connection.
- **No Pritunl Enterprise license required.**

---

## Architecture

```
User flow (profile download):
  https://<server>/login
    → SSO button
    → AWS IAM Identity Center (SAML)
    → POST /sso/callback
    → Profile download page

Admin flow:
  https://<server>/pritunl-admin
    → Pritunl username + password login

VPN client connect flow (first time):
  Pritunl client → POST /key/ovpn → GET /key/request
    → Redirect to /sso/callback?key_state=<token>
    → AWS IAM Identity Center (SAML)
    → POST /sso/callback
    → Identity check (SSO email must match profile owner)
    → server_sso_token stored in MongoDB
    → Redirect to /success
    → Client polls → VPN connected

VPN client connect flow (subsequent):
  Pritunl client → silent AWS IDP check via boto3
    → User verified in Identity Center
    → Connected (no browser popup)
```

### Port Layout

| Port | Purpose |
|------|---------|
| 443  | Public — login page, SSO flow, admin login (nginx) |
| 8443 | Public — Pritunl client API, SSO callback, key/request (nginx) |
| 9443 | Internal — Pritunl web frontend (pritunl-web) |
| 9756 | Internal — Pritunl Flask backend (pritunl daemon) |

---

## Prerequisites

- Ubuntu 22.04 / 24.04
- Pritunl installed (any version, no license needed)
- AWS account with IAM Identity Center enabled
- AWS SAML application configured in Identity Center
- Python packages inside Pritunl's bundled Python:
  - `boto3`
  - `python3-saml` (`onelogin`)
  - `pyOpenSSL`
  - `PyNaCl`

---

## AWS Setup

### 1. Create a SAML Application in AWS Identity Center

1. Go to **IAM Identity Center → Applications → Add Application**
2. Choose **Custom SAML 2.0 application**
3. Set the following:
   - **ACS URL**: `https://<your-server>:8443/sso/callback`
   - **Entity ID / Audience**: `https://<your-server>`
4. Under **Attribute mappings**, add:
   - `email` → `${user:email}`
   - `firstname` → `${user:givenName}`
   - `lastname` → `${user:familyName}`
5. Download the **IdP metadata** and note:
   - SSO URL
   - IdP Entity ID
   - x509 Certificate

### 2. Assign Users

In the application, assign the users or groups who should have VPN access. Only assigned users can download profiles and connect.

### 3. Create IAM Credentials for boto3

Create an IAM user or role with these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sso-admin:ListApplicationAssignments",
        "identitystore:DescribeUser",
        "identitystore:ListGroupMemberships"
      ],
      "Resource": "*"
    }
  ]
}
```

Save credentials to `/root/.aws/credentials`:

```ini
[default]
aws_access_key_id = YOUR_KEY
aws_secret_access_key = YOUR_SECRET
```

---

## Installation

### 1. Clone the repo

```bash
git clone https://github.com/yourname/pritunl-aws-sso
cd pritunl-aws-sso
```

### 2. Copy patch files

```bash
PRITUNL_PKG="/usr/lib/pritunl/usr/lib/python3.9/site-packages/pritunl"

# Backup originals
cp $PRITUNL_PKG/authorizer/authorizer.py  $PRITUNL_PKG/authorizer/authorizer.py.bak
cp $PRITUNL_PKG/handlers/key.py           $PRITUNL_PKG/handlers/key.py.bak
cp $PRITUNL_PKG/handlers/sso.py           $PRITUNL_PKG/handlers/sso.py.bak
cp $PRITUNL_PKG/handlers/auth.py          $PRITUNL_PKG/handlers/auth.py.bak
cp $PRITUNL_PKG/handlers/static.py        $PRITUNL_PKG/handlers/static.py.bak
cp $PRITUNL_PKG/app.py                    $PRITUNL_PKG/app.py.bak
cp $PRITUNL_PKG/auth/administrator.py     $PRITUNL_PKG/auth/administrator.py.bak
cp $PRITUNL_PKG/setup/mongo.py            $PRITUNL_PKG/setup/mongo.py.bak

# Copy patches
cp patches/authorizer.py  $PRITUNL_PKG/authorizer/authorizer.py
cp patches/key.py         $PRITUNL_PKG/handlers/key.py
cp patches/sso.py         $PRITUNL_PKG/handlers/sso.py
cp patches/auth.py        $PRITUNL_PKG/handlers/auth.py
cp patches/static.py      $PRITUNL_PKG/handlers/static.py
cp patches/app.py         $PRITUNL_PKG/app.py
cp patches/administrator.py $PRITUNL_PKG/auth/administrator.py
cp patches/mongo.py       $PRITUNL_PKG/setup/mongo.py
cp patches/aws_idp_check.py $PRITUNL_PKG/aws_idp_check.py
```

### 3. Configure SAML settings

```bash
mkdir -p /etc/pritunl/saml
cp config/saml/settings.json /etc/pritunl/saml/settings.json
```

Edit `/etc/pritunl/saml/settings.json` and fill in your AWS IdP details:

```json
{
  "strict": false,
  "debug": false,
  "sp": {
    "entityId": "https://<your-server>",
    "assertionConsumerService": {
      "url": "https://<your-server>:8443/sso/callback",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    },
    "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    "x509cert": "",
    "privateKey": ""
  },
  "idp": {
    "entityId": "<AWS_IDP_ENTITY_ID>",
    "singleSignOnService": {
      "url": "<AWS_SSO_URL>",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    },
    "x509cert": "<AWS_IDP_CERT>"
  }
}
```

### 4. Update aws_idp_check.py

Edit `$PRITUNL_PKG/aws_idp_check.py` and set your values:

```python
IDENTITY_STORE_ID = 'd-xxxxxxxxxx'        # From IAM Identity Center
INSTANCE_ARN      = 'arn:aws:sso:::instance/ssoins-xxxxxxxxxx'
APPLICATION_ARN   = 'arn:aws:sso::<account-id>:application/ssoins-xxx/apl-xxx'
AWS_REGION        = 'us-east-1'
```

### 5. Update authorizer.py

Edit `$PRITUNL_PKG/authorizer/authorizer.py` and set the same values in `_check_sso`:

```python
IDENTITY_STORE_ID = 'd-xxxxxxxxxx'
APPLICATION_ARN   = 'arn:aws:sso::<account>:application/...'
AWS_REGION        = 'us-east-1'
```

### 6. Configure nginx

```bash
cp config/nginx/pritunl /etc/nginx/sites-enabled/pritunl
```

Edit `/etc/nginx/sites-enabled/pritunl` and replace `<your-server-ip>` with your server's IP or domain.

```bash
nginx -t && systemctl reload nginx
```

### 7. Restart Pritunl

```bash
systemctl restart pritunl
```

### 8. Verify syntax

```bash
/usr/lib/pritunl/usr/bin/python3 -c "
import sys
sys.path.insert(0, '/usr/lib/pritunl/usr/lib/python3.9/site-packages')
from pritunl.handlers import key, sso, auth
from pritunl.authorizer import authorizer
print('All syntax OK')
" 2>&1 | grep -v FutureWarning
```

---

## Configuration

### Pritunl Server Settings

In the Pritunl admin dashboard, on the VPN server:
- **Single Sign-On**: Enabled
- **Bypass SSO Auth**: Disabled

In MongoDB, verify:
```bash
mongosh pritunl --eval 'db.servers.find({},{name:1,sso_auth:1}).forEach(printjson)'
# Expected: sso_auth: true

mongosh pritunl --eval 'db.settings.find({_id:"app"},{sso:1,sso_org:1}).forEach(printjson)'
# Expected: sso: 'saml'
```

---

## How the Code Works

### `handlers/sso.py`
- `sso_callback_get` — handles the initial GET to `/sso/callback`. If `key_state` param is present (VPN client flow), saves it as SAML `RelayState` so AWS echoes it back in the POST.
- `sso_callback_post` — handles AWS's POST response. Reads `RelayState` to detect VPN vs web flow. For VPN flow: verifies SSO identity matches profile owner, creates `server_sso_token`, redirects to `/success`. For web flow: redirects to profile download page.

### `handlers/key.py`
- `key_request_get` — intercepts the Pritunl client's SSO request. Instead of calling Pritunl's paid auth server, stores the pending key in MongoDB and redirects the browser to our own SAML flow with `key_state` embedded.

### `authorizer/authorizer.py`
- `_check_sso_token` — simplified to set `has_sso_token=True`, bypassing Pritunl's enterprise token validation.
- `_check_sso` — performs live AWS Identity Center verification on every connect using boto3. Local users (`auth_type=local`) bypass this check.

### `aws_idp_check.py`
- Standalone module that checks if a user email is assigned to the VPN application in AWS Identity Center. Includes a 5-minute in-memory cache to avoid hitting the AWS API on every packet.

### `setup/mongo.py`
- Registers the `key_sso_pending` collection in Pritunl's MongoDB collection registry.

### `handlers/auth.py`
- Disables normal password login at `/auth/session`. Only SSO users and emergency access (`PRITUNL_EMERGENCY=1`) can authenticate.

---

## URL Reference

| URL | Access | Description |
|-----|--------|-------------|
| `https://<server>/login` | Public | SSO login button for normal users |
| `https://<server>/sso` | Public | Redirects to AWS SSO |
| `https://<server>/pritunl-admin` | Admin only | Pritunl dashboard (username + password) |
| `https://<server>:8443/sso/callback` | AWS callback | SAML assertion endpoint |
| `https://<server>:8443/key/request` | Pritunl client | Client SSO token request |
| `https://<server>:8443/success` | Browser | Shown after successful client auth |

---

## Security Model

| Threat | Protection |
|--------|-----------|
| User removed from AWS IDP | Blocked on next connect — live IDP check via boto3 |
| Stolen VPN profile | SSO identity must match profile owner — mismatch blocked |
| Brute force admin | Pritunl's own rate limiting + separate admin URL |
| Unauthorized profile download | Must be assigned to SAML app in AWS to complete SSO |
| Session hijacking | Pritunl's existing session security unchanged |

---

## Troubleshooting

### VPN client gets 500 on connect
```bash
journalctl -u pritunl -n 50 --no-pager | grep -i error
```

### SSO redirects to profile page instead of /success
Check that `RelayState` is being passed correctly:
```bash
grep -n "RelayState\|key_state" \
  /usr/lib/pritunl/usr/lib/python3.9/site-packages/pritunl/handlers/sso.py
```

### AWS IDP check failing
```bash
# Test manually
/usr/lib/pritunl/usr/bin/python3 -c "
import sys
sys.path.insert(0, '/usr/lib/pritunl/usr/lib/python3.9/site-packages')
from pritunl import aws_idp_check
print(aws_idp_check.is_user_allowed('user@example.com'))
"
```

### Emergency admin access
If SSO is broken and you need admin access:
```bash
PRITUNL_EMERGENCY=1 systemctl restart pritunl
# Then log in at https://<server>/pritunl-admin with username/password
# Unset after fixing:
systemctl restart pritunl
```

---

## Rollback

```bash
PRITUNL_PKG="/usr/lib/pritunl/usr/lib/python3.9/site-packages/pritunl"
for f in authorizer/authorizer key handlers/key handlers/sso handlers/auth handlers/static app auth/administrator setup/mongo; do
  [ -f "$PRITUNL_PKG/$f.py.bak" ] && cp "$PRITUNL_PKG/$f.py.bak" "$PRITUNL_PKG/$f.py"
done
systemctl restart pritunl
```

---

## License

This project patches Pritunl open-source code. Pritunl is licensed under the Pritunl License. This integration code is MIT licensed.
