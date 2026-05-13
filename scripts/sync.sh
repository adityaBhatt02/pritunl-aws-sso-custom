#!/bin/bash

BASE="/usr/lib/pritunl/usr/lib/python3.9/site-packages/pritunl"

cp $BASE/authorizer/authorizer.py ~/pritunl-custom/patches/
cp $BASE/handlers/key.py ~/pritunl-custom/patches/
cp $BASE/handlers/sso.py ~/pritunl-custom/patches/
cp $BASE/handlers/auth.py ~/pritunl-custom/patches/
cp $BASE/handlers/static.py ~/pritunl-custom/patches/
cp $BASE/app.py ~/pritunl-custom/patches/
cp $BASE/auth/administrator.py ~/pritunl-custom/patches/
cp $BASE/setup/mongo.py ~/pritunl-custom/patches/
cp $BASE/aws_idp_check.py ~/pritunl-custom/patches/

cp /etc/nginx/sites-enabled/pritunl \
~/pritunl-custom/config/nginx/
