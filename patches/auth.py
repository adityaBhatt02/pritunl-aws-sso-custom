from pritunl.constants import *
from pritunl.exceptions import *
from pritunl import settings
from pritunl import auth
from pritunl import utils
from pritunl import app
from pritunl import event
from pritunl import organization
from pritunl import sso
from pritunl import logger
from pritunl import journal
from pritunl import limiter
from pritunl import database

import flask
import time
import random
import json
import base64
import nacl.secret
import nacl.utils as nacl_utils

def _get_web_secret():
    import base64 as _b64
    secret = settings.local.web_secret
    if secret and len(secret) == 32:
        return secret
    try:
        raw = settings.app.cookie_web_secret
        if raw:
            decoded = _b64.b64decode(raw)
            if len(decoded) == 32:
                settings.local.web_secret = decoded
                return decoded
    except Exception:
        pass
    new_secret = nacl_utils.random(32)
    settings.local.web_secret = new_secret
    settings.app.cookie_web_secret = _b64.b64encode(new_secret).decode()
    settings.commit()
    return new_secret

def _auth_radius(username, password, remote_addr):
    sso_mode = settings.app.sso

    valid, org_names, groups = sso.verify_radius(username, password)
    if not valid:
        journal.entry(
            journal.SSO_AUTH_FAILURE,
            user_name=username,
            remote_address=remote_addr,
            reason=journal.SSO_AUTH_REASON_RADIUS_FAILED,
            reason_long='Radius authentication failed',
        )
        return utils.jsonify({
            'error': AUTH_INVALID,
            'error_msg': AUTH_INVALID_MSG,
        }, 401)

    org_id = settings.app.sso_org
    if org_names:
        not_found = False
        for org_name in org_names:
            org = organization.get_by_name(org_name, fields=('_id'))
            if org:
                not_found = False
                org_id = org.id
                break
            else:
                not_found = True

        if not_found:
            logger.warning('Supplied org names do not exist',
                'sso',
                sso_type='radius',
                user_name=username,
                org_names=org_names,
            )

    valid, org_id_new, groups2 = sso.plugin_sso_authenticate(
        sso_type='radius',
        user_name=username,
        user_email=None,
        remote_ip=utils.get_remote_addr(),
        sso_org_names=org_names,
    )
    if valid:
        org_id = org_id_new or org_id
    else:
        journal.entry(
            journal.SSO_AUTH_FAILURE,
            user_name=username,
            remote_address=remote_addr,
            reason=journal.SSO_AUTH_REASON_PLUGIN_FAILED,
            reason_long='Radius plugin authentication failed',
        )
        logger.error('Radius plugin authentication not valid', 'sso',
            username=username,
        )
        return utils.jsonify({
            'error': AUTH_INVALID,
            'error_msg': AUTH_INVALID_MSG,
        }, 401)

    groups = ((groups or set()) | (groups2 or set())) or None

    if DUO_AUTH in sso_mode:
        try:
            duo_auth = sso.Duo(
                username=username,
                factor=settings.app.sso_duo_mode,
                remote_ip=utils.get_remote_addr(),
                auth_type='Key',
            )
            valid = duo_auth.authenticate()
        except InvalidUser:
            logger.error('Duo authentication username not valid', 'sso',
                username=username,
            )
            journal.entry(
                journal.SSO_AUTH_FAILURE,
                user_name=username,
                remote_address=remote_addr,
                reason=journal.SSO_AUTH_REASON_DUO_FAILED,
                reason_long='Duo authentication invalid username',
            )
            return utils.jsonify({
                'error': AUTH_INVALID,
                'error_msg': AUTH_INVALID_MSG,
            }, 401)
        if valid:
            valid, org_id_new, groups2 = sso.plugin_sso_authenticate(
                sso_type='duo',
                user_name=username,
                user_email=None,
                remote_ip=utils.get_remote_addr(),
            )
            if valid:
                org_id = org_id_new or org_id
            else:
                journal.entry(
                    journal.SSO_AUTH_FAILURE,
                    user_name=username,
                    remote_address=remote_addr,
                    reason=journal.SSO_AUTH_REASON_PLUGIN_FAILED,
                    reason_long='Duo plugin authentication failed',
                )
                logger.error('Duo plugin authentication not valid', 'sso',
                    username=username,
                )
                return utils.jsonify({
                    'error': AUTH_INVALID,
                    'error_msg': AUTH_INVALID_MSG,
                }, 401)

            groups = ((groups or set()) | (groups2 or set())) or None
        else:
            logger.error('Duo authentication not valid', 'sso',
                username=username,
            )
            journal.entry(
                journal.SSO_AUTH_FAILURE,
                user_name=username,
                remote_address=remote_addr,
                reason=journal.SSO_AUTH_REASON_DUO_FAILED,
                reason_long='Duo authentication failed',
            )
            return utils.jsonify({
                'error': AUTH_INVALID,
                'error_msg': AUTH_INVALID_MSG,
            }, 401)

    groups = ((groups or set()) | (groups2 or set())) or None

    org = organization.get_by_id(org_id)
    if not org:
        logger.error('Organization for sso does not exist', 'auth',
            org_id=org_id,
        )
        return flask.abort(405)

    usr = org.find_user(name=username)
    if not usr:
        usr = org.new_user(name=username, type=CERT_CLIENT,
            auth_type=sso_mode, groups=list(groups) if groups else None)

        usr.audit_event(
            'user_created',
            'User created with single sign-on',
            remote_addr=remote_addr,
        )

        journal.entry(
            journal.USER_CREATE,
            usr.journal_data,
            event_long='User created with single sign-on',
            remote_address=remote_addr,
        )

        event.Event(type=ORGS_UPDATED)
        event.Event(type=USERS_UPDATED, resource_id=org.id)
        event.Event(type=SERVERS_UPDATED)
    else:
        if usr.disabled:
            return utils.jsonify({
                'error': AUTH_DISABLED,
                'error_msg': AUTH_DISABLED_MSG,
            }, 403)

        if groups and groups - set(usr.groups or []):
            usr.groups = list(set(usr.groups or []) | groups)
            usr.commit('groups')

        if usr.auth_type != sso_mode:
            usr.auth_type = sso_mode
            usr.set_pin(None)
            usr.commit(('auth_type', 'pin'))

    key_link = org.create_user_key_link(usr.id, one_time=True)

    journal.entry(
        journal.SSO_AUTH_SUCCESS,
        usr.journal_data,
        key_id_hash=utils.unsafe_md5(key_link['id'].encode()).hexdigest(),
        remote_address=remote_addr,
    )

    usr.audit_event('user_profile',
        'User profile viewed from single sign-on',
        remote_addr=utils.get_remote_addr(),
    )

    journal.entry(
        journal.USER_PROFILE_SUCCESS,
        usr.journal_data,
        event_long='User profile viewed from single sign-on',
        remote_address=remote_addr,
    )

    return utils.jsonify({
        'redirect': utils.get_url_root() + key_link['view_url'],
    }, 202)

def _auth_plugin(username, password, remote_addr):
    if not settings.local.sub_plan or \
            'enterprise' not in settings.local.sub_plan:
        journal.entry(
            journal.ADMIN_AUTH_FAILURE,
            user_name=username,
            remote_address=remote_addr,
            reason=journal.ADMIN_AUTH_REASON_INVALID_USERNAME,
            reason_long='Invalid username',
        )
        return utils.jsonify({
            'error': AUTH_INVALID_USERNAME,
            'error_msg': AUTH_INVALID_USERNAME_MSG,
        }, 401)

    has_plugin, valid, org_id, groups = sso.plugin_login_authenticate(
        user_name=username,
        password=password,
        remote_ip=remote_addr,
    )

    if not has_plugin:
        journal.entry(
            journal.ADMIN_AUTH_FAILURE,
            user_name=username,
            remote_address=remote_addr,
            reason=journal.ADMIN_AUTH_REASON_INVALID_USERNAME,
            reason_long='Invalid username',
        )
        return utils.jsonify({
            'error': AUTH_INVALID_USERNAME,
            'error_msg': AUTH_INVALID_USERNAME_MSG,
        }, 401)

    if not valid:
        journal.entry(
            journal.SSO_AUTH_REASON_PLUGIN_FAILED,
            user_name=username,
            remote_address=remote_addr,
            reason=journal.SSO_AUTH_REASON_PLUGIN_FAILED,
            reason_long='Plugin authentication failed',
        )
        return utils.jsonify({
            'error': AUTH_INVALID,
            'error_msg': AUTH_INVALID_MSG,
        }, 401)

    if not org_id:
        logger.error(
            'Login plugin did not return valid organization name',
            'auth',
            org_name=org_id,
            user_name=username,
        )
        return utils.jsonify({
            'error': AUTH_INVALID,
            'error_msg': AUTH_INVALID_MSG,
        }, 401)

    org = organization.get_by_id(org_id)
    if not org:
        logger.error('Organization for sso does not exist', 'auth',
            org_id=org_id,
        )
        return flask.abort(405)

    usr = org.find_user(name=username)
    if not usr:
        usr = org.new_user(name=username, type=CERT_CLIENT,
            auth_type=PLUGIN_AUTH, groups=list(groups) if groups else None)
        usr.audit_event(
            'user_created',
            'User created with plugin authentication',
            remote_addr=utils.get_remote_addr(),
        )

        journal.entry(
            journal.USER_CREATE,
            usr.journal_data,
            event_long='User created with plugin authentication',
            remote_address=remote_addr,
        )

        event.Event(type=ORGS_UPDATED)
        event.Event(type=USERS_UPDATED, resource_id=org.id)
        event.Event(type=SERVERS_UPDATED)
    else:
        if usr.disabled:
            return utils.jsonify({
                'error': AUTH_DISABLED,
                'error_msg': AUTH_DISABLED_MSG,
            }, 403)

        if groups and groups - set(usr.groups or []):
            usr.groups = list(set(usr.groups or []) | groups)
            usr.commit('groups')

        if usr.auth_type != PLUGIN_AUTH:
            usr.auth_type = PLUGIN_AUTH
            usr.set_pin(None)
            usr.commit(('auth_type', 'pin'))

    key_link = org.create_user_key_link(usr.id, one_time=True)

    usr.audit_event('user_profile',
        'User profile viewed from plugin authentication',
        remote_addr=utils.get_remote_addr(),
    )

    journal.entry(
        journal.USER_PROFILE_SUCCESS,
        usr.journal_data,
        event_long='User profile viewed from plugin authentication',
        remote_address=remote_addr,
    )

    return utils.jsonify({
        'redirect': utils.get_url_root() + key_link['view_url'],
    }, 202)

@app.app.route('/auth/session', methods=['POST'])
@auth.open_auth
def auth_session_post():
    import os
    remote_addr = utils.get_remote_addr()

    sso_email = flask.session.get('sso_email')
    if sso_email:
        admin = auth.get_by_username(sso_email)
        if admin:
            flask.session['session_id'] = admin.new_session()
            flask.session['admin_id'] = str(admin.id)
            flask.session['timestamp'] = int(utils.time_now())
            utils.set_flask_sig()
            import base64 as _b64, json as _json, time as _time
            from nacl.secret import SecretBox as _SecretBox
            _web_secret = _b64.b64decode(settings.app.cookie_web_secret)
            _token_data = _json.dumps({
                'id': str(admin.id),
                'ttl': int(_time.time()) + 86400
            }).encode()
            _box = _SecretBox(_web_secret)
            _encrypted = _box.encrypt(_token_data)
            _token_cookie = _b64.urlsafe_b64encode(_encrypted).decode()
            _resp = utils.jsonify({'authenticated': True, 'default': admin.default or False})
            _resp.set_cookie('token', _token_cookie, secure=True, httponly=True, samesite='Lax', path='/')
            return _resp

    if os.environ.get('PRITUNL_EMERGENCY') == '1':
        username = str(flask.request.json.get('username', ''))[:128]
        password = flask.request.json.get('password', '')
        if password:
            password = password[:128]
        admin = auth.get_by_username(username)
        if admin and admin.auth_check(password, None, None, remote_addr):
            flask.session['session_id'] = admin.new_session()
            flask.session['admin_id'] = str(admin.id)
            flask.session['timestamp'] = int(utils.time_now())
            utils.set_flask_sig()
            import base64 as _b64, json as _json, time as _time
            from nacl.secret import SecretBox as _SecretBox
            _web_secret = _b64.b64decode(settings.app.cookie_web_secret)
            _token_data = _json.dumps({
                'id': str(admin.id),
                'ttl': int(_time.time()) + 86400
            }).encode()
            _box = _SecretBox(_web_secret)
            _encrypted = _box.encrypt(_token_data)
            _token_cookie = _b64.urlsafe_b64encode(_encrypted).decode()
            _resp = utils.jsonify({'authenticated': True, 'default': admin.default or False})
            _resp.set_cookie('token', _token_cookie, secure=True, httponly=True, samesite='Lax', path='/')
            return _resp
        return utils.jsonify({'error': AUTH_INVALID, 'error_msg': AUTH_INVALID_MSG}, 401)

    journal.entry(
        journal.ADMIN_AUTH_FAILURE,
        remote_address=remote_addr,
        reason='password_disabled',
        reason_long='Password login disabled, SSO required',
    )
    return utils.jsonify({
        'error': 'sso_required',
        'error_msg': 'Password login is disabled. Please use SSO login.',
    }, 401)


@app.app.route('/auth/session', methods=['DELETE'])
@auth.open_auth
def auth_delete():
    admin_id = utils.session_opt_str('admin_id')
    if admin_id:
        admin_id = admin_id[:512]
    session_id = utils.session_opt_str('session_id')
    if session_id:
        session_id = session_id[:512]
    remote_addr = utils.get_remote_addr()

    journal.entry(
        journal.ADMIN_SESSION_END,
        admin_id=admin_id,
        session_id=session_id,
        remote_address=remote_addr,
    )

    if admin_id and session_id:
        admin_id = database.ParseObjectId(admin_id)
        auth.clear_session(admin_id, str(session_id))
    flask.session.clear()

    return utils.jsonify({
        'authenticated': False,
    }, token=False)

@app.app.route('/state', methods=['GET'])
@auth.session_light_auth
def auth_state_get():
    return utils.jsonify({
        'super_user': flask.g.administrator.super_user,
        'csrf_token': auth.get_token(flask.g.administrator.id),
        'theme': settings.app.theme,
        'user': settings.local.sub_url_key,
        'active': settings.local.sub_active,
        'plan': settings.local.sub_plan,
        'version': settings.local.version_int,
        'sso': settings.app.sso,
    })
