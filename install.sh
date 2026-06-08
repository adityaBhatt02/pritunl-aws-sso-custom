#!/bin/bash
# =============================================================
# Pritunl AWS SSO Custom - One-Click Installer
# Supports: Amazon Linux 2023
# Usage: curl -s https://raw.githubusercontent.com/adityaBhatt02/pritunl-aws-sso-custom/main/install.sh | sudo bash
# =============================================================

set -e

REPO="https://github.com/adityaBhatt02/pritunl-aws-sso-custom.git"
REPO_DIR="/opt/pritunl-aws-sso-custom"
BASE="/usr/lib/pritunl/usr/lib/python3.9/site-packages/pritunl"
ENV_FILE="/etc/pritunl-custom.env"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
die()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo ""
echo "============================================"
echo "  Pritunl AWS SSO Custom Installer"
echo "============================================"
echo ""

# ── Get IP and Domain ──────────────────────────
read -p "Enter server IP (e.g. 54.123.45.67): " SERVER_IP
read -p "Enter domain (e.g. vpn.company.com):  " SERVER_HOST

if [ -z "$SERVER_IP" ] || [ -z "$SERVER_HOST" ]; then
    die "Both IP and domain are required"
fi

echo ""
log "Installing with:"
echo "    IP:     $SERVER_IP"
echo "    Domain: $SERVER_HOST"
echo ""

# ── Step 1: Install MongoDB ────────────────────
log "Step 1: Installing MongoDB..."
cat > /etc/yum.repos.d/mongodb-org-7.0.repo << 'EOF'
[mongodb-org-7.0]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/amazon/2023/mongodb-org/7.0/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://pgp.mongodb.com/server-7.0.asc
EOF

dnf install -y mongodb-org
systemctl enable mongod
systemctl start mongod
log "MongoDB installed and started"

# ── Step 2: Install Pritunl ────────────────────
log "Step 2: Installing Pritunl..."
cat > /etc/yum.repos.d/pritunl.repo << 'EOF'
[pritunl]
name=Pritunl Repository
baseurl=https://repo.pritunl.com/stable/yum/amazonlinux/2023/
gpgcheck=1
enabled=1
EOF

rpm --import https://raw.githubusercontent.com/pritunl/pgp/master/pritunl_repo_pub.asc

dnf install -y pritunl
systemctl enable pritunl
log "Pritunl installed"

# Install required Python dependencies
log "Installing Python dependencies..."
/usr/lib/pritunl/usr/bin/pip3 install python3-saml
log "Python dependencies installed"

# ── Step 3: Install nginx ──────────────────────
log "Step 3: Installing nginx..."
dnf install -y nginx
systemctl enable nginx
log "nginx installed"

# ── Step 4: Clone repo ─────────────────────────
log "Step 4: Installing git and cloning repository..."
dnf install -y git
if [ -d "$REPO_DIR" ]; then
    cd $REPO_DIR && git pull origin main
else
    git clone $REPO $REPO_DIR
fi
log "Repository cloned to $REPO_DIR"

# ── Step 5: Write env file ─────────────────────
log "Step 5: Writing environment file..."
cat > $ENV_FILE << EOF
SERVER_HOST=$SERVER_HOST
SERVER_IP=$SERVER_IP
PRITUNL_EMERGENCY=1
EOF
chmod 600 $ENV_FILE
log "Environment file written to $ENV_FILE"

# ── Step 6: Apply all patches ─────────────────
log "Step 6: Applying patches..."

cp $REPO_DIR/patches/sso.py           $BASE/handlers/sso.py
cp $REPO_DIR/patches/key.py           $BASE/handlers/key.py
cp $REPO_DIR/patches/auth.py          $BASE/handlers/auth.py
cp $REPO_DIR/patches/static.py        $BASE/handlers/static.py
cp $REPO_DIR/patches/authorizer.py    $BASE/authorizer/authorizer.py
cp $REPO_DIR/patches/aws_idp_check.py $BASE/aws_idp_check.py
chmod 666 $BASE/aws_idp_check.py
cp $REPO_DIR/patches/mongo.py         $BASE/mongo/__init__.py
cp $REPO_DIR/patches/app.py           $BASE/app.py
cp $REPO_DIR/patches/server.py        $BASE/server/server.py
cp $REPO_DIR/patches/domain_resolver.py       $BASE/domain_resolver.py
cp $REPO_DIR/patches/domain_routes_handler.py $BASE/handlers/domain_routes_handler.py

# Copy HTML pages
cp $REPO_DIR/www/domain-routes.html /usr/share/pritunl/www/domain-routes.html
cp $REPO_DIR/www/saml-settings.html /usr/share/pritunl/www/saml-settings.html

log "Patches applied"

# ── FIX 1: domain_routes_handler - use pymongo directly ──────
log "Fix 1: Patching domain_routes_handler to use pymongo..."
python3 << PYEOF
path = '$BASE/handlers/domain_routes_handler.py'
with open(path, 'r') as f:
    lines = f.readlines()

new_lines = []
added_pymongo = False
for i, line in enumerate(lines, 1):
    if 'import datetime' in line and not added_pymongo:
        new_lines.append(line)
        new_lines.append('import pymongo\n')
        added_pymongo = True
    elif "return mongo.get_collection('domain_routes')" in line:
        new_lines.append("    client = pymongo.MongoClient('mongodb://localhost:27017')\n")
        new_lines.append("    return client['pritunl']['domain_routes']\n")
    else:
        new_lines.append(line)

with open(path, 'w') as f:
    f.writelines(new_lines)
print("domain_routes_handler pymongo fix applied")
PYEOF

# ── FIX 2: domain_routes_handler - use session_light_auth ────
log "Fix 2: Patching domain_routes_handler to use session_light_auth..."
sed -i 's/@auth\.session_auth/@auth.session_light_auth/g' \
    $BASE/handlers/domain_routes_handler.py
log "session_light_auth fix applied"

# ── FIX 3: mongo/__init__.py - fallback to pymongo for ANY unregistered collection ──
# This single fix covers: key_sso_pending, domain_routes, and all other unregistered
# collections — no more whack-a-mole fixing individual handlers
log "Fix 3: Patching mongo get_collection to fallback to pymongo for any unregistered collection..."
python3 << PYEOF
path = '$BASE/mongo/__init__.py'
with open(path, 'r') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if "raise TypeError('Invalid collection name')" in line:
        new_lines.append("        import pymongo as _pymongo\n")
        new_lines.append("        _client = _pymongo.MongoClient('mongodb://localhost:27017')\n")
        new_lines.append("        coll = _client['pritunl'][name]\n")
        new_lines.append("        coll.name_str = name\n")
        new_lines.append("        return coll\n")
    else:
        new_lines.append(line)

with open(path, 'w') as f:
    f.writelines(new_lines)
print("mongo get_collection fallback fix applied")
PYEOF

# ── FIX 4: sso.py - always write sp section to settings.json on save ─
# Without this, saving /saml-settings writes only idp section → sp_not_found error
log "Fix 4: Patching sso.py to always write sp section on save..."
python3 << PYEOF
path = '$BASE/handlers/sso.py'
with open(path, 'r') as f:
    content = f.read()

old = "    with open(saml_path, 'w') as f:\n        _json.dump(saml, f, indent=2)"
new = """    # Always ensure SP section is present so OneLogin_Saml2 doesn't throw sp_not_found
    saml.setdefault('sp', {
        'entityId': 'https://$SERVER_HOST',
        'assertionConsumerService': {
            'url': 'https://$SERVER_HOST:8443/sso/callback',
            'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
        },
        'NameIDFormat': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
    })
    with open(saml_path, 'w') as f:
        _json.dump(saml, f, indent=2)"""

if old in content:
    content = content.replace(old, new)
    with open(path, 'w') as f:
        f.write(content)
    print("sso.py sp section fix applied")
else:
    print("WARNING: sso.py pattern not found - check manually")
PYEOF

# ── FIX 5: Create SAML directory ─────────────────────────────
# Without this, PUT /saml/config returns 500 (FileNotFoundError)
log "Fix 5: Creating SAML settings directory..."
mkdir -p /etc/pritunl/saml
log "SAML directory created"

# ── FIX 10: Write initial saml settings.json with correct sp section ─
# Do this before starting pritunl so the sp section exists from first boot
log "Fix 10: Writing initial SAML settings.json with sp section..."
python3 << PYEOF
import json, os

saml_path = '/etc/pritunl/saml/settings.json'

if os.path.exists(saml_path):
    with open(saml_path, 'r') as f:
        try:
            saml = json.load(f)
        except:
            saml = {}
else:
    saml = {}

saml['sp'] = {
    'entityId': 'https://$SERVER_HOST',
    'assertionConsumerService': {
        'url': 'https://$SERVER_HOST:8443/sso/callback',
        'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
    },
    'NameIDFormat': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
}

with open(saml_path, 'w') as f:
    json.dump(saml, f, indent=2)
print("SAML settings.json sp section written")
PYEOF

# ── Step 7: Configure nginx ────────────────────
log "Step 7: Generating SSL certificate and configuring nginx..."

if [ ! -f /etc/nginx/pritunl-nginx.crt ]; then
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/nginx/pritunl-nginx.key \
        -out /etc/nginx/pritunl-nginx.crt \
        -subj "/CN=$SERVER_HOST"
    log "Self-signed SSL cert generated"
fi

cp $REPO_DIR/config/nginx/pritunl.conf /etc/nginx/conf.d/pritunl.conf

# Replace hardcoded domain and IP with actual values
sed -i "s/vpn1\.addyops\.fun/$SERVER_HOST/g" /etc/nginx/conf.d/pritunl.conf
sed -i "s/100\.28\.54\.145/$SERVER_IP/g"     /etc/nginx/conf.d/pritunl.conf

# ── FIX 8: nginx - ensure ALL location blocks have PR-Validated true ──
# Missing PR-Validated on /domain-routes and /saml-settings blocks caused auth failures
log "Fix 8: Ensuring all nginx location blocks have PR-Validated true..."
python3 << 'PYEOF'
import re

path = '/etc/nginx/conf.d/pritunl.conf'
with open(path, 'r') as f:
    content = f.read()

lines = content.split('\n')
result = []
i = 0
while i < len(lines):
    line = lines[i]
    if re.match(r'\s+location[\s=~]', line):
        block = [line]
        depth = line.count('{') - line.count('}')
        i += 1
        while i < len(lines) and depth > 0:
            block.append(lines[i])
            depth += lines[i].count('{') - lines[i].count('}')
            i += 1
        block_str = '\n'.join(block)
        if 'PR-Forwarded-Url' in block_str and 'PR-Validated' not in block_str:
            new_block = []
            for bl in block:
                if 'PR-Forwarded-Url' in bl:
                    indent = len(bl) - len(bl.lstrip())
                    new_block.append(' ' * indent + 'proxy_set_header PR-Validated true;')
                new_block.append(bl)
            result.extend(new_block)
        else:
            result.extend(block)
    else:
        result.append(line)
        i += 1

with open(path, 'w') as f:
    f.write('\n'.join(result))
print("nginx PR-Validated fix applied")
PYEOF

# ── FIX 9: nginx - ensure PR-Forwarded-Url uses domain not IP ─
# If nginx config has the IP instead of domain, get_url_root() returns wrong host
# which causes sso/callback to redirect to the old IP
log "Fix 9: Ensuring nginx PR-Forwarded-Url uses domain not IP..."
sed -i "s|PR-Forwarded-Url https://$SERVER_IP|PR-Forwarded-Url https://$SERVER_HOST|g" \
    /etc/nginx/conf.d/pritunl.conf

nginx -t || die "nginx config invalid - check /etc/nginx/conf.d/pritunl.conf"
log "nginx configured"

# ── Step 8: Wire env into systemd ─────────────
log "Step 8: Wiring env file into systemd..."
mkdir -p /etc/systemd/system/pritunl.service.d
cp $REPO_DIR/config/systemd/env.conf \
    /etc/systemd/system/pritunl.service.d/env.conf
systemctl daemon-reload
log "Systemd env wired"

# ── Step 9: Install domain resolver service ───
log "Step 9: Installing domain resolver service..."
cp $BASE/domain_resolver.py /usr/local/bin/domain_resolver.py

cat > /etc/systemd/system/pritunl-domain-resolver.service << 'EOF'
[Unit]
Description=Pritunl Domain Route Resolver
After=mongod.service pritunl.service
Requires=mongod.service

[Service]
Type=simple
WorkingDirectory=/usr/local/bin
ExecStart=/usr/lib/pritunl/usr/bin/python3 /usr/local/bin/domain_resolver.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable pritunl-domain-resolver
log "Domain resolver service installed"

# ── Step 10: Start pritunl, configure, then start nginx ───────
# ORDER MATTERS:
#   1. Start pritunl first so 'pritunl set' works
#   2. Set server_port 9443 BEFORE nginx starts so pritunl-web doesn't fight for 443
#   3. Then configure all settings
#   4. Then start nginx
log "Step 10: Starting pritunl..."
systemctl start pritunl

log "Waiting for pritunl to fully initialize..."
sleep 12

# ── Set MongoDB URI first — required before any 'pritunl set' command ──
# Without this, pritunl set fails with "Empty host" error
log "Configuring MongoDB URI..."
pritunl set-mongodb mongodb://localhost:27017/pritunl
sleep 3

# ── FIX 6: Set all domain/SSO settings via pritunl CLI ───────
# Use 'pritunl set' (not raw pymongo) so settings are written to the live
# in-memory settings system — raw pymongo writes are cached out on restart
log "Fix 6: Setting domain and SSO settings via pritunl CLI..."

# server_port MUST be 9443 — setting it to 443 causes pritunl-web to try binding
# port 443 directly, clashing with nginx → web server crash loop
pritunl set app.server_port 9443
pritunl set app.server_ssl true
pritunl set app.redirect_server false

# These are the critical SSO settings: server_sso_url drives the browser popup URL
# that the Pritunl client opens. If not set, it falls back to public_addr which
# may be the wrong IP (especially on fresh EC2 with no stored host.public_addr)
pritunl set app.server_sso_url $SERVER_HOST
pritunl set app.acme_domain $SERVER_HOST
pritunl set app.sso saml

# Disable conf sync - prevents profile sync issues
pritunl set user.conf_sync false

log "Pritunl CLI settings configured"

# ── FIX 7: Set MongoDB settings directly ─────────────────────
# These fields aren't exposed via 'pritunl set' CLI so we write to MongoDB directly.
# server_hostname → used in various URL building code
# host public_address / auto_public_host → used in VPN profile 'remote' line generation
log "Fix 7: Configuring MongoDB host and server settings..."
python3 << PYEOF
import pymongo

client = pymongo.MongoClient('mongodb://localhost:27017')
db = client['pritunl']

# server_hostname used by some URL builders
db['settings'].update_one(
    {'_id': 'app'},
    {'\$set': {
        'server_hostname': '$SERVER_HOST',
        # server_port stays 9443 (already set via CLI above)
    }},
    upsert=True
)

# Fix host public address.
# auto_public_host takes priority over auto_public_address in host.public_addr property.
# If it's None, falls through to auto_public_address (detected from EC2 metadata).
# We set all three to be safe — this ensures 'remote' line in .ovpn has the right IP.
db['hosts'].update_many(
    {},
    {'\$set': {
        'public_address': '$SERVER_IP',
        'auto_public_address': '$SERVER_IP',
        'auto_public_host': '$SERVER_IP',
    }}
)

print("MongoDB host/server settings configured")
PYEOF

# ── FIX 7b: Set sso_org - requires an org to exist ───────────
# sso_org must be set or /sso/callback returns "No SSO org configured" → 500.
# An org won't exist at install time (admin creates it via UI), so we try to set
# it if one already exists (re-installs), and print instructions for fresh installs.
log "Fix 7b: Setting sso_org if organization exists..."
python3 << PYEOF
import pymongo
from bson import ObjectId

client = pymongo.MongoClient('mongodb://localhost:27017')
db = client['pritunl']

orgs = list(db['organizations'].find({}, {'_id': 1, 'name': 1}))
if orgs:
    org_id = orgs[0]['_id']
    db['settings'].update_one(
        {'_id': 'app'},
        {'\$set': {'sso_org': org_id}},
        upsert=True
    )
    print("sso_org set to:", orgs[0].get('name', str(org_id)), "(" + str(org_id) + ")")
else:
    print("No org found yet - run this after creating org in admin panel:")
    print("")
    print("  sudo python3 -c \"")
    print("  import pymongo; c=pymongo.MongoClient('mongodb://localhost:27017')")
    print("  db=c['pritunl']")
    print("  org=db['organizations'].find_one()")
    print("  db['settings'].update_one({'_id':'app'},{'\\\$set':{'sso_org':org['_id']}},upsert=True)")
    print("  print('sso_org set to:', str(org['_id']))\"")
PYEOF

# ── Step 11: Restart pritunl to pick up all config changes ────
log "Step 11: Restarting pritunl to apply all settings..."
systemctl restart pritunl
sleep 8
log "Pritunl restarted"

# ── Step 12: Start nginx and resolver ─────────────────────────
log "Step 12: Starting nginx and domain resolver..."
systemctl start nginx
systemctl start pritunl-domain-resolver
log "All services started"

# ── Final verification ────────────────────────
echo ""
log "Verifying setup..."
echo ""

# Check services
for svc in mongod pritunl pritunl-web nginx; do
    if systemctl is-active --quiet $svc; then
        echo -e "  ${GREEN}✓${NC} $svc running"
    else
        echo -e "  ${RED}✗${NC} $svc NOT running - check: journalctl -u $svc -n 30"
    fi
done

# Check key settings
echo ""
echo "  Key settings:"
pritunl get app.server_sso_url 2>/dev/null | sed 's/^/    /'
pritunl get app.sso 2>/dev/null | sed 's/^/    /'
pritunl get app.acme_domain 2>/dev/null | sed 's/^/    /'
pritunl get user.conf_sync 2>/dev/null | sed 's/^/    /'

# Check nginx PR-Validated coverage
PR_VAL_COUNT=$(grep -c "PR-Validated" /etc/nginx/conf.d/pritunl.conf 2>/dev/null || echo 0)
echo "    nginx PR-Validated headers: $PR_VAL_COUNT blocks"

# Check SAML dir and sp section
if [ -f /etc/pritunl/saml/settings.json ]; then
    echo -e "  ${GREEN}✓${NC} /etc/pritunl/saml/settings.json exists"
    python3 -c "
import json
with open('/etc/pritunl/saml/settings.json') as f:
    s=json.load(f)
if 'sp' in s:
    print('  \033[0;32m✓\033[0m SAML sp section present:', s['sp'].get('assertionConsumerService',{}).get('url',''))
else:
    print('  \033[0;31m✗\033[0m SAML sp section MISSING')
"
else
    echo -e "  ${RED}✗${NC} /etc/pritunl/saml/settings.json missing"
fi

# ── Done ───────────────────────────────────────
echo ""
echo "============================================"
echo -e "  ${GREEN}Setup Complete!${NC}"
echo "============================================"
echo ""
echo "  Admin panel: https://$SERVER_HOST/pritunl-admin"
echo "  User login:  https://$SERVER_HOST/login"
echo "  SAML config: https://$SERVER_HOST/saml-settings"
echo "  Domain mgmt: https://$SERVER_HOST/domain-routes"
echo ""
echo "  Next steps:"
echo "  1. Get admin password:"
echo "     sudo pritunl default-password"
echo ""
echo "  2. Login to admin panel → Users → Add Organization"
echo "     Then run the sso_org command printed above (or re-run installer)"
echo ""
echo "  3. Admin panel → Servers → Add Server → link to org → Start"
echo ""
echo "  4. In AWS IAM Identity Center, configure your SAML app:"
echo "     - ACS URL:      https://$SERVER_HOST:8443/sso/callback"
echo "     - Audience URI: https://$SERVER_HOST"
echo "     - Start URL:    https://$SERVER_HOST/login"
echo "     - Assign users to the app"
echo ""
echo "  5. Fill /saml-settings with values from your AWS SAML app:"
echo "     - IdP SSO URL:    IAM Identity Center sign-in URL"
echo "     - IdP Issuer URL: IAM Identity Center issuer URL"
echo "     - Certificate:    base64 content only (no BEGIN/END lines)"
echo "     - Identity Store ID, App ARN, AWS Region"
echo "     Click Save Settings"
echo ""
echo "  6. Test: https://$SERVER_HOST/login → Sign in with SSO"
echo ""
echo -e "  ${YELLOW}NOTE:${NC} If you had an old EC2 with a different SAML app,"
echo "  use that old app's metadata in step 5 and update its ACS URL"
echo "  to https://$SERVER_HOST:8443/sso/callback in AWS."
echo "  Using a brand new SAML app may conflict with browser-cached"
echo "  sessions from the old app until cookies are cleared."
echo ""