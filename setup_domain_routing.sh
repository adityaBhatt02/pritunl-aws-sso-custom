#!/bin/bash
# setup_domain_routing.sh
# Run this on the EC2 to set up domain-based routing
# Usage: sudo bash setup_domain_routing.sh

set -e

BASE="/usr/lib/pritunl/usr/lib/python3.9/site-packages/pritunl"
REPO="/opt/pritunl-aws-sso-custom"
SERVER_PY="$BASE/server/server.py"

echo "=== Step 1: Copy domain_resolver.py to patches ==="
cp "$REPO/patches/domain_resolver.py" "$BASE/../../../domain_resolver.py" 2>/dev/null || true

echo "=== Step 2: Patch server.py to inject domain routes ==="

# Add MongoClient import if not already there
if ! grep -q "MongoClient as _MongoClient" "$SERVER_PY"; then
    sed -i '1s/^/from pymongo import MongoClient as _MongoClient\n/' "$SERVER_PY"
    echo "Added MongoClient import"
fi

# Find the return line inside get_routes and inject before it
# The return is: return routes + list(routes_dict.values())
if ! grep -q "_inject_domain_routes" "$SERVER_PY"; then
    python3 << 'PYEOF'
import re

path = '/usr/lib/pritunl/usr/lib/python3.9/site-packages/pritunl/server/server.py'

with open(path, 'r') as f:
    content = f.read()

injection = '''
        # ── DOMAIN ROUTE INJECTION ──────────────────────────────────
        try:
            from pymongo import MongoClient as _MongoClient
            _mclient = _MongoClient('mongodb://localhost:27017/pritunl')
            _mdb = _mclient['pritunl']
            _domain_docs = list(_mdb['domain_routes'].find(
                {'resolved_ips': {'$exists': True, '$ne': []}}))
            _mclient.close()
            for _doc in _domain_docs:
                _domain = _doc.get('domain', '')
                _nat = _doc.get('nat', True)
                for _ip in _doc.get('resolved_ips', []):
                    _network = f'{_ip}/32'
                    if _network not in routes_dict:
                        routes_dict[_network] = {
                            'id': _network.encode().hex(),
                            'server': self.id,
                            'network': _network,
                            'comment': f'domain:{_domain}',
                            'metric': 0,
                            'nat': _nat,
                            'nat_interface': None,
                            'nat_netmap': None,
                            'advertise': None,
                            'vpc_region': None,
                            'vpc_id': None,
                            'net_gateway': False,
                            'virtual_network': False,
                            'network_link': False,
                            'server_link': False,
                            'link_virtual_network': False,
                        }
        except Exception as _e:
            pass
        # ── END DOMAIN ROUTE INJECTION ───────────────────────────────
'''

# Find the return statement inside get_routes
target = '        return routes + list(routes_dict.values())'
if target in content:
    content = content.replace(target, injection + '\n' + target, 1)
    with open(path, 'w') as f:
        f.write(content)
    print("✅ server.py patched successfully")
else:
    # Try alternate return pattern
    target2 = '        return routes + list(routes_dict.values())\n'
    if target2 in content:
        content = content.replace(target2, injection + '\n' + target2, 1)
        with open(path, 'w') as f:
            f.write(content)
        print("✅ server.py patched successfully (pattern 2)")
    else:
        print("❌ Could not find return statement - manual patch needed")
        # Show context around routes_dict.values
        import subprocess
        subprocess.run(['grep', '-n', 'routes_dict.values', path])
PYEOF
else
    echo "server.py already patched"
fi

echo "=== Step 3: Install domain resolver service ==="
cat > /etc/systemd/system/pritunl-domain-resolver.service << 'EOF'
[Unit]
Description=Pritunl Domain Route Resolver
After=mongod.service pritunl.service
Requires=mongod.service

[Service]
Type=simple
ExecStart=/usr/lib/pritunl/usr/bin/python3 /opt/pritunl-aws-sso-custom/patches/domain_resolver.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable pritunl-domain-resolver
systemctl start pritunl-domain-resolver

echo "=== Step 4: Restart Pritunl ==="
systemctl restart pritunl

echo ""
echo "=== Done! ==="
echo "Domain resolver status:"
systemctl status pritunl-domain-resolver --no-pager | head -5
echo ""
echo "Test adding a domain route:"
echo "mongosh pritunl --eval \"db.domain_routes.insertOne({domain:'snowflake.amazonaws.com', nat:true, resolved_ips:[]})\""
echo ""
echo "Check resolved IPs after 30 seconds:"
echo "mongosh pritunl --eval \"db.domain_routes.find().pretty()\""
