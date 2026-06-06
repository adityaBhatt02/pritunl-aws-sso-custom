"""
AWS Identity Center VPN Access Checker
Checks if a user is assigned to the Pritunl VPN application at connect time.
Called by authorizer on every VPN connect attempt.
"""

import boto3
import logging
import threading

log = logging.getLogger('pritunl')

# ── CONFIG ────────────────────────────────────────────────────────────────────
IDENTITY_STORE_ID = ''
INSTANCE_ARN      = 'arn:aws:sso:::instance/ssoins-722326aeca663a25'
APPLICATION_ARN   = ''
AWS_REGION        = ''
# ─────────────────────────────────────────────────────────────────────────────

# Simple in-memory cache to avoid hitting AWS on every packet
# Cache valid for 5 minutes
_cache = {}
_cache_lock = threading.Lock()
_CACHE_TTL = 3600  # 1 hour - safe since boto3 checks on first connect

import time

def _get_cached(email):
    with _cache_lock:
        entry = _cache.get(email)
        if entry:
            result, timestamp = entry
            if time.time() - timestamp < _CACHE_TTL:
                return result
            else:
                del _cache[email]
    return None

def _set_cache(email, result):
    with _cache_lock:
        _cache[email] = (result, time.time())

def is_user_allowed(email):
    """
    Returns True if user email is assigned to Pritunl VPN app in AWS IDP.
    Returns False if not assigned or any error occurs.
    """
    if not email:
        log.warning('AWS IDP check: no email provided')
        return False

    # Check cache first
    cached = _get_cached(email)
    if cached is not None:
        log.info('AWS IDP check (cached): %s -> %s' % (email, cached))
        return cached

    try:
        sso_admin = boto3.client('sso-admin',     region_name=AWS_REGION)
        idstore   = boto3.client('identitystore', region_name=AWS_REGION)

        # Get all users assigned to the VPN app
        paginator = sso_admin.get_paginator('list_application_assignments')
        for page in paginator.paginate(ApplicationArn=APPLICATION_ARN):
            for assignment in page['ApplicationAssignments']:
                principal_id   = assignment['PrincipalId']
                principal_type = assignment['PrincipalType']

                if principal_type == 'USER':
                    # Get user email
                    user_email = _get_user_email(idstore, principal_id)
                    if user_email and user_email.lower() == email.lower():
                        log.info('AWS IDP check: ALLOWED %s' % email)
                        _set_cache(email, True)
                        return True

                elif principal_type == 'GROUP':
                    # Check all group members
                    if _is_in_group(idstore, principal_id, email):
                        log.info('AWS IDP check: ALLOWED (via group) %s' % email)
                        _set_cache(email, True)
                        return True

        log.warning('AWS IDP check: DENIED %s (not in app)' % email)
        _set_cache(email, False)
        return False

    except Exception as e:
        log.error('AWS IDP check ERROR for %s: %s' % (email, str(e)))
        # On AWS API error, DENY by default (fail secure)
        return False


def _get_user_email(idstore, user_id):
    """Get primary email for a user ID"""
    try:
        user = idstore.describe_user(
            IdentityStoreId=IDENTITY_STORE_ID,
            UserId=user_id
        )
        for e in user.get('Emails', []):
            if e.get('Primary'):
                return e.get('Value')
        if user.get('Emails'):
            return user['Emails'][0].get('Value')
        return user.get('UserName')
    except Exception as e:
        log.error('AWS IDP get user email error: %s' % str(e))
        return None


def _is_in_group(idstore, group_id, email):
    """Check if email is a member of a group"""
    try:
        paginator = idstore.get_paginator('list_group_memberships')
        for page in paginator.paginate(
            IdentityStoreId=IDENTITY_STORE_ID,
            GroupId=group_id
        ):
            for member in page['GroupMemberships']:
                member_id = member['MemberId']['UserId']
                member_email = _get_user_email(idstore, member_id)
                if member_email and member_email.lower() == email.lower():
                    return True
    except Exception as e:
        log.error('AWS IDP group check error: %s' % str(e))
    return False


def warm_cache():
    """
    Pre-fetch all users assigned to the VPN app and cache them.
    Call this at startup so first connect is instant.
    """
    try:
        sso_admin = boto3.client('sso-admin', region_name=AWS_REGION)
        idstore   = boto3.client('identitystore', region_name=AWS_REGION)

        paginator = sso_admin.get_paginator('list_application_assignments')
        for page in paginator.paginate(ApplicationArn=APPLICATION_ARN):
            for assignment in page['ApplicationAssignments']:
                principal_id   = assignment['PrincipalId']
                principal_type = assignment['PrincipalType']

                if principal_type == 'USER':
                    email = _get_user_email(idstore, principal_id)
                    if email:
                        _set_cache(email.lower(), True)
                        log.info('AWS IDP cache warmed: %s' % email)

                elif principal_type == 'GROUP':
                    gpaginator = idstore.get_paginator('list_group_memberships')
                    for gpage in gpaginator.paginate(
                        IdentityStoreId=IDENTITY_STORE_ID,
                        GroupId=principal_id,
                    ):
                        for member in gpage['GroupMemberships']:
                            email = _get_user_email(idstore, member['MemberId']['UserId'])
                            if email:
                                _set_cache(email.lower(), True)
                                log.info('AWS IDP cache warmed (group): %s' % email)

        log.info('AWS IDP cache warm complete')
    except Exception as e:
        log.warning('AWS IDP cache warm failed: %s' % str(e))

def invalidate_cache(email=None):
    """Invalidate cache for a specific user or all users"""
    with _cache_lock:
        if email:
            _cache.pop(email, None)
        else:
            _cache.clear()
