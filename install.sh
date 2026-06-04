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

# Wait for Pritunl to fully install so python path exists
sleep 3

cp $REPO_DIR/patches/sso.py           $BASE/handlers/sso.py
cp $REPO_DIR/patches/key.py           $BASE/handlers/key.py
cp $REPO_DIR/patches/auth.py          $BASE/handlers/auth.py
cp $REPO_DIR/patches/static.py        $BASE/handlers/static.py
cp $REPO_DIR/patches/authorizer.py    $BASE/authorizer/authorizer.py
cp $REPO_DIR/patches/aws_idp_check.py $BASE/aws_idp_check.py
cp $REPO_DIR/patches/app.py           $BASE/app.py
cp $REPO_DIR/patches/server.py        $BASE/server/server.py
cp $REPO_DIR/patches/domain_resolver.py       $BASE/domain_resolver.py
cp $REPO_DIR/patches/domain_routes_handler.py $BASE/handlers/domain_routes_handler.py

# Copy HTML pages
cp $REPO_DIR/www/domain-routes.html /usr/share/pritunl/www/domain-routes.html

log "Patches applied"

# ── Step 6b: Configure Pritunl to internal port only ──
log "Step 6b: Configuring Pritunl to listen on localhost only..."
pritunl set app.server_port 9443
pritunl set app.server_ssl true
pritunl set app.redirect_server false

# ── Step 7: Configure nginx ────────────────────
log "Step 7: Generating SSL certificate and configuring nginx..."
systemctl start mongod
sleep 3
systemctl start pritunl
sleep 5
# Generate self-signed cert if Pritunl hasn't created one yet
if [ ! -f /etc/nginx/pritunl-nginx.crt ]; then
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/nginx/pritunl-nginx.key \
        -out /etc/nginx/pritunl-nginx.crt \
        -subj "/CN=$SERVER_HOST"
    log "Self-signed SSL cert generated"
fi

# Copy nginx config and substitute placeholders
cp $REPO_DIR/config/nginx/pritunl.conf /etc/nginx/conf.d/pritunl.conf

# Replace hardcoded domain and IP with actual values
sed -i "s/vpn1\.addyops\.fun/$SERVER_HOST/g" /etc/nginx/conf.d/pritunl.conf
sed -i "s/100\.28\.54\.145/$SERVER_IP/g"     /etc/nginx/conf.d/pritunl.conf

# Make sure server_name has both domain and IP
python3 << PYEOF
path = '/etc/nginx/conf.d/pritunl.conf'
with open(path, 'r') as f:
    content = f.read()
content = content.replace(
    f'server_name $SERVER_HOST $SERVER_HOST;',
    f'server_name $SERVER_HOST $SERVER_IP;'
)
content = content.replace(
    f'server_name $SERVER_HOST;',
    f'server_name $SERVER_HOST $SERVER_IP;'
)
with open(path, 'w') as f:
    f.write(content)
PYEOF

nginx -t || die "nginx config invalid"
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

# ── Step 10: Start everything ─────────────────
log "Step 10: Starting all services..."
systemctl start pritunl
sleep 5
systemctl start nginx
systemctl start pritunl-domain-resolver

# ── Done ───────────────────────────────────────
echo ""
echo "============================================"
echo -e "  ${GREEN}Setup Complete!${NC}"
echo "============================================"
echo ""
echo "  Admin panel (IP):     https://$SERVER_IP/pritunl-admin"
echo "  Admin panel (Domain): https://$SERVER_HOST/pritunl-admin"
echo "  User login:           https://$SERVER_HOST/login"
echo "  Domain routes:        https://$SERVER_HOST/domain-routes"
echo "  SAML settings:        https://$SERVER_HOST/saml-settings"
echo ""
echo "  Next steps:"
echo "  1. Get admin password: sudo pritunl default-password"
echo "  2. Configure SAML at:  https://$SERVER_HOST/saml-settings"
echo "  3. Update AWS SAML ACS URL to: https://$SERVER_HOST:8443/sso/callback"
echo ""
echo "  To change domain later:"
echo "  sudo nano $ENV_FILE"
echo "  sudo systemctl restart pritunl"
echo ""
