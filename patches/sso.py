from pritunl.constants import *
from pritunl.exceptions import *
from pritunl import utils
from pritunl import static
from pritunl import organization
from pritunl import user
from pritunl import settings
from pritunl import app
from pritunl import auth
from pritunl import mongo
from pritunl import sso
from pritunl import event
from pritunl import logger
from pritunl import journal

import flask
import hmac
import hashlib
import base64
import urllib.parse
import requests

import json as _json
from onelogin.saml2.auth import OneLogin_Saml2_Auth

SAML_SETTINGS_PATH = '/etc/pritunl/saml/settings.json'

def _load_saml_settings():
    with open(SAML_SETTINGS_PATH, 'r') as f:
        return _json.load(f)

def _prepare_saml_request(request):
    # Use 8443 as the canonical SAML port (matches ACS URL in settings.json)
    # regardless of which port the actual request came in on
    return {
        'https': 'on',
        'http_host': '107.21.31.183:8443',
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy(),
        'server_port': '8443',
        'query_string': request.query_string.decode('utf-8'),
    }

def _validate_user(username, email, sso_mode, org_id, groups, remote_addr,
        http_redirect=False, yubico_id=None):
    usr = user.find_user_auth(name=username, auth_type=sso_mode)
    if not usr:
        org = organization.get_by_id(org_id)
        if not org:
            logger.error('Organization for sso does not exist', 'sso',
                org_id=org_id,
            )
            return flask.abort(405)

        usr = org.find_user(name=username)
    else:
        if usr.org_id != org_id:
            logger.info('User organization changed, moving user', 'sso',
                user_name=username,
                user_email=email,
                remote_ip=remote_addr,
                cur_org_id=usr.org_id,
                new_org_id=org_id,
            )

            org = organization.get_by_id(org_id)
            if not org:
                logger.error('Organization for sso does not exist', 'sso',
                    org_id=org_id,
                )
                return flask.abort(405)

            usr.remove()
            old_org_id = usr.org_id

            new_usr = org.new_user(
                name=usr.name,
                email=usr.email,
                pin=usr.pin,
                type=usr.type,
                groups=usr.groups,
                auth_type=usr.auth_type,
                yubico_id=usr.yubico_id,
                disabled=usr.disabled,
                resource_id=usr.resource_id,
                bypass_secondary=usr.bypass_secondary,
                client_to_client=usr.client_to_client,
                mac_addresses=usr.mac_addresses,
                dns_servers=usr.dns_servers,
                dns_suffix=usr.dns_suffix,
                port_forwarding=usr.port_forwarding,
            )
            new_usr.otp_secret = usr.otp_secret

            usr = new_usr
            usr.commit()

            event.Event(type=ORGS_UPDATED)
            event.Event(type=USERS_UPDATED, resource_id=old_org_id)
            event.Event(type=USERS_UPDATED, resource_id=org.id)
            event.Event(type=SERVERS_UPDATED)

        org = usr.org

    if not usr:
        usr = org.new_user(name=username, email=email, type=CERT_CLIENT,
            auth_type=sso_mode, yubico_id=yubico_id,
            groups=list(groups) if groups else [])
        usr.audit_event('user_created', 'User created with single sign-on',
            remote_addr=remote_addr)

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
        if yubico_id and usr.yubico_id and yubico_id != usr.yubico_id:
            journal.entry(
                journal.SSO_AUTH_FAILURE,
                user_name=username,
                remote_address=remote_addr,
                reason=journal.SSO_AUTH_REASON_INVALID_YUBIKEY,
                reason_long='Invalid yubikey id',
            )

            return utils.jsonify({
                'error': YUBIKEY_INVALID,
                'error_msg': YUBIKEY_INVALID_MSG,
            }, 401)

        if usr.disabled:
            return flask.abort(403)

        changed = False

        if yubico_id and not usr.yubico_id:
            changed = True
            usr.yubico_id = yubico_id
            usr.commit('yubico_id')

        if groups and groups != set(usr.groups or []):
            changed = True
            usr.groups = list(groups)
            usr.commit('groups')

        if usr.auth_type != sso_mode:
            changed = True
            usr.auth_type = sso_mode
            usr.commit('auth_type')

        if changed:
            journal.entry(
                journal.SSO_AUTH_UPDATE,
                user_name=username,
                remote_address=remote_addr,
                reason=journal.SSO_AUTH_REASON_MODIFIED,
                reason_long='User sso attributes modified',
            )

            usr.clear_auth_cache()
            usr.disconnect()
            event.Event(type=USERS_UPDATED, resource_id=org.id)

    key_link = org.create_user_key_link(usr.id, one_time=True)

    usr.audit_event('user_profile',
        'User profile viewed from single sign-on',
        remote_addr=remote_addr,
    )

    journal.entry(
        journal.SSO_AUTH_SUCCESS,
        usr.journal_data,
        key_id_hash=utils.unsafe_md5(key_link['id'].encode()).hexdigest(),
        remote_address=remote_addr,
    )

    journal.entry(
        journal.USER_PROFILE_SUCCESS,
        usr.journal_data,
        remote_address=remote_addr,
        event_long='User profile viewed from single sign-on',
    )

    if http_redirect:
        return utils.redirect(utils.get_url_root() + key_link['view_url'])
    else:
        return utils.jsonify({
            'redirect': utils.get_url_root() + key_link['view_url'],
        }, 200)

@app.app.route('/sso/authenticate', methods=['POST'])
@auth.open_auth
def sso_authenticate_post():
    if settings.app.sso != DUO_AUTH or \
            settings.app.sso_duo_mode == 'passcode':
        return flask.abort(405)

    remote_addr = utils.get_remote_addr()
    username = utils.json_filter_str('username')
    usernames = [username]
    email = None
    if '@' in username:
        email = username
        usernames.append(username.split('@')[0])

    valid = False
    for i, username in enumerate(usernames):
        try:
            duo_auth = sso.Duo(
                username=username,
                factor=settings.app.sso_duo_mode,
                remote_ip=remote_addr,
                auth_type='Key',
            )
            valid = duo_auth.authenticate()
            break
        except InvalidUser:
            if i == len(usernames) - 1:
                logger.warning('Invalid duo username', 'sso',
                    username=username,
                )

    if valid:
        valid, org_id, groups = sso.plugin_sso_authenticate(
            sso_type='duo',
            user_name=username,
            user_email=email,
            remote_ip=remote_addr,
        )
        if not valid:
            logger.warning('Duo plugin authentication not valid', 'sso',
                username=username,
            )

            journal.entry(
                journal.SSO_AUTH_FAILURE,
                user_name=username,
                remote_address=remote_addr,
                reason=journal.SSO_AUTH_REASON_PLUGIN_FAILED,
                reason_long='Duo plugin authentication failed',
            )

            return flask.abort(401)
        groups = set(groups or [])
    else:
        logger.warning('Duo authentication not valid', 'sso',
            username=username,
        )

        journal.entry(
            journal.SSO_AUTH_FAILURE,
            user_name=username,
            remote_address=remote_addr,
            reason=journal.SSO_AUTH_REASON_DUO_FAILED,
            reason_long='Duo authentication failed',
        )

        return flask.abort(401)

    if not org_id:
        org_id = settings.app.sso_org

    return _validate_user(username, email, DUO_AUTH, org_id, groups,
        remote_addr)

@app.app.route('/sso/request', methods=['GET'])
@auth.open_auth
def sso_request_get():
    sso_mode = settings.app.sso

    if sso_mode not in (AZURE_AUTH, AZURE_DUO_AUTH, AZURE_YUBICO_AUTH,
            GOOGLE_AUTH, GOOGLE_DUO_AUTH, GOOGLE_YUBICO_AUTH,
            AUTHZERO_AUTH, AUTHZERO_DUO_AUTH, AUTHZERO_YUBICO_AUTH,
            SLACK_AUTH, SLACK_DUO_AUTH, SLACK_YUBICO_AUTH, SAML_AUTH,
            SAML_DUO_AUTH, SAML_YUBICO_AUTH, SAML_OKTA_AUTH,
            SAML_OKTA_DUO_AUTH, SAML_OKTA_YUBICO_AUTH, SAML_ONELOGIN_AUTH,
            SAML_ONELOGIN_DUO_AUTH, SAML_ONELOGIN_YUBICO_AUTH,
            SAML_JUMPCLOUD_AUTH, SAML_JUMPCLOUD_DUO_AUTH,
            SAML_JUMPCLOUD_YUBICO_AUTH):
        return flask.abort(404)

    state = utils.rand_str(64)
    secret = utils.rand_str(64)
    callback = utils.get_url_root() + '/sso/callback'
    auth_server = AUTH_SERVER
    if settings.app.dedicated:
        auth_server = settings.app.dedicated

    if not settings.local.sub_active:
        logger.error('Subscription must be active for sso', 'sso')
        return flask.abort(405)

    if AZURE_AUTH in sso_mode:
        resp = requests.post(auth_server + '/v1/request/azure',
            headers={
                'Content-Type': 'application/json',
            },
            json={
                'license': settings.app.license,
                'callback': callback,
                'state': state,
                'secret': secret,
                'region': settings.app.sso_azure_region or '',
                'directory_id': settings.app.sso_azure_directory_id,
                'app_id': settings.app.sso_azure_app_id,
                'app_secret': settings.app.sso_azure_app_secret,
            },
        )

        if resp.status_code != 200:
            logger.error('Azure auth server error, ' +
                'check https://docs.pritunl.com/kb/vpn/outage', 'sso',
                status_code=resp.status_code,
                content=resp.content,
            )

            if resp.status_code == 401:
                return flask.abort(405)

            return flask.abort(500)

        tokens_collection = mongo.get_collection('sso_tokens')
        tokens_collection.insert_one({
            '_id': state,
            'type': AZURE_AUTH,
            'secret': secret,
            'timestamp': utils.now(),
        })

        data = resp.json()

        return utils.redirect(data['url'])

    elif GOOGLE_AUTH in sso_mode:
        resp = requests.post(auth_server + '/v1/request/google',
            headers={
                'Content-Type': 'application/json',
            },
            json={
                'license': settings.app.license,
                'callback': callback,
                'state': state,
                'secret': secret,
            },
        )

        if resp.status_code != 200:
            logger.error('Google auth server error, ' +
                'check https://docs.pritunl.com/kb/vpn/outage', 'sso',
                status_code=resp.status_code,
                content=resp.content,
            )

            if resp.status_code == 401:
                return flask.abort(405)

            return flask.abort(500)

        tokens_collection = mongo.get_collection('sso_tokens')
        tokens_collection.insert_one({
            '_id': state,
            'type': GOOGLE_AUTH,
            'secret': secret,
            'timestamp': utils.now(),
        })

        data = resp.json()

        return utils.redirect(data['url'])

    elif AUTHZERO_AUTH in sso_mode:
        resp = requests.post(auth_server + '/v1/request/authzero',
            headers={
                'Content-Type': 'application/json',
            },
            json={
                'license': settings.app.license,
                'callback': callback,
                'state': state,
                'secret': secret,
                'app_domain': settings.app.sso_authzero_domain,
                'app_id': settings.app.sso_authzero_app_id,
                'app_secret': settings.app.sso_authzero_app_secret,
            },
        )

        if resp.status_code != 200:
            logger.error('Auth0 auth server error, ' +
                'check https://docs.pritunl.com/kb/vpn/outage', 'sso',
                status_code=resp.status_code,
                content=resp.content,
            )

            if resp.status_code == 401:
                return flask.abort(405)

            return flask.abort(500)

        tokens_collection = mongo.get_collection('sso_tokens')
        tokens_collection.insert_one({
            '_id': state,
            'type': AUTHZERO_AUTH,
            'secret': secret,
            'timestamp': utils.now(),
        })

        data = resp.json()

        return utils.redirect(data['url'])

    elif SLACK_AUTH in sso_mode:
        resp = requests.post(auth_server + '/v1/request/slack',
            headers={
                'Content-Type': 'application/json',
            },
            json={
                'license': settings.app.license,
                'callback': callback,
                'state': state,
                'secret': secret,
            },
        )

        if resp.status_code != 200:
            logger.error('Slack auth server error, ' +
                'check https://docs.pritunl.com/kb/vpn/outage', 'sso',
                status_code=resp.status_code,
                content=resp.content,
            )

            if resp.status_code == 401:
                return flask.abort(405)

            return flask.abort(500)

        tokens_collection = mongo.get_collection('sso_tokens')
        tokens_collection.insert_one({
            '_id': state,
            'type': SLACK_AUTH,
            'secret': secret,
            'timestamp': utils.now(),
        })

        data = resp.json()

        return utils.redirect(data['url'])

    elif SAML_AUTH in sso_mode:
        resp = requests.post(auth_server + '/v1/request/saml',
            headers={
                'Content-Type': 'application/json',
            },
            json={
                'license': settings.app.license,
                'callback': callback,
                'state': state,
                'secret': secret,
                'sso_url': settings.app.sso_saml_url,
                'issuer_url': settings.app.sso_saml_issuer_url,
                'cert': settings.app.sso_saml_cert,
            },
        )

        if resp.status_code != 200:
            logger.error('Saml auth server error, ' +
                'check https://docs.pritunl.com/kb/vpn/outage', 'sso',
                status_code=resp.status_code,
                content=resp.content,
            )

            if resp.status_code == 401:
                return flask.abort(405)

            return flask.abort(500)

        tokens_collection = mongo.get_collection('sso_tokens')
        tokens_collection.insert_one({
            '_id': state,
            'type': SAML_AUTH,
            'secret': secret,
            'timestamp': utils.now(),
        })

        return flask.Response(
            status=200,
            response=resp.content,
            content_type="text/html;charset=utf-8",
        )

    else:
        return flask.abort(404)

@app.app.route('/sso/callback', methods=['GET'])
@auth.open_auth
def sso_callback_get():
    if not flask.request.args.get('state'):
        saml_settings = _load_saml_settings()
        req = _prepare_saml_request(flask.request)
        saml_auth = OneLogin_Saml2_Auth(req, saml_settings)
        org_id = settings.app.sso_org
        if not org_id:
            logger.error('No SSO org configured', 'sso')
            return flask.abort(500)
        flask.session['sso_org_id'] = str(org_id)
        key_state = flask.request.args.get('key_state')
        if key_state:
            redirect_url = saml_auth.login(return_to=key_state)
        else:
            redirect_url = saml_auth.login()
        return flask.redirect(redirect_url)

    sso_mode = settings.app.sso

    if sso_mode not in (AZURE_AUTH, AZURE_DUO_AUTH, AZURE_YUBICO_AUTH,
            GOOGLE_AUTH, GOOGLE_DUO_AUTH, GOOGLE_YUBICO_AUTH,
            AUTHZERO_AUTH, AUTHZERO_DUO_AUTH, AUTHZERO_YUBICO_AUTH,
            SLACK_AUTH, SLACK_DUO_AUTH, SLACK_YUBICO_AUTH, SAML_AUTH,
            SAML_DUO_AUTH, SAML_YUBICO_AUTH, SAML_OKTA_AUTH,
            SAML_OKTA_DUO_AUTH, SAML_OKTA_YUBICO_AUTH, SAML_ONELOGIN_AUTH,
            SAML_ONELOGIN_DUO_AUTH, SAML_ONELOGIN_YUBICO_AUTH,
            SAML_JUMPCLOUD_AUTH, SAML_JUMPCLOUD_DUO_AUTH,
            SAML_JUMPCLOUD_YUBICO_AUTH):
        return flask.abort(405)

    remote_addr = utils.get_remote_addr()
    state = flask.request.args.get('state')
    sig = flask.request.args.get('sig')

    tokens_collection = mongo.get_collection('sso_tokens')
    doc = tokens_collection.find_one_and_delete({
        '_id': state,
    })

    if not doc:
        return flask.abort(404)

    query = flask.request.query_string.split('&sig='.encode())[0]
    test_sig = base64.urlsafe_b64encode(hmac.new(str(doc['secret']).encode(),
        query, hashlib.sha512).digest()).decode()
    if not utils.const_compare(sig, test_sig):
        journal.entry(
            journal.SSO_AUTH_FAILURE,
            state=state,
            remote_address=remote_addr,
            reason=journal.SSO_AUTH_REASON_INVALID_CALLBACK,
            reason_long='Signature mismatch',
        )
        return flask.abort(401)

    params = urllib.parse.parse_qs(query.decode())

    if doc.get('type') == SAML_AUTH:
        username = params.get('username')[0]
        email = params.get('email', [None])[0]

        org_names = []
        if params.get('org'):
            org_names_param = params.get('org')[0]
            if ';' in org_names_param:
                org_names = org_names_param.split(';')
            else:
                org_names = org_names_param.split(',')
            org_names = [utils.filter_unicode(x) for x in org_names if x]
        org_names = sorted(org_names)

        groups = []
        if params.get('groups'):
            groups_param = params.get('groups')[0]
            if ';' in groups_param:
                groups = groups_param.split(';')
            else:
                groups = groups_param.split(',')
            groups = [utils.filter_unicode(x) for x in groups if x]
        groups = set(groups)

        if not username:
            return flask.abort(406)

        org_id = settings.app.sso_org
        if org_names:
            not_found = False
            for org_name in org_names:
                org = organization.get_by_name(
                    org_name,
                    fields=('_id'),
                )
                if org:
                    not_found = False
                    org_id = org.id
                    break
                else:
                    not_found = True

            if not_found:
                logger.warning('Supplied org names do not exists',
                    'sso',
                    sso_type=doc.get('type'),
                    user_name=username,
                    user_email=email,
                    org_names=org_names,
                )

        valid, org_id_new, groups2 = sso.plugin_sso_authenticate(
            sso_type='saml',
            user_name=username,
            user_email=email,
            remote_ip=remote_addr,
            sso_org_names=org_names,
            sso_group_names=groups,
        )
        if valid:
            org_id = org_id_new or org_id
        else:
            logger.error('Saml plugin authentication not valid', 'sso',
                username=username,
            )

            journal.entry(
                journal.SSO_AUTH_FAILURE,
                user_name=username,
                remote_address=remote_addr,
                reason=journal.SSO_AUTH_REASON_PLUGIN_FAILED,
                reason_long='Saml plugin authentication failed',
            )

            return flask.abort(401)

        groups = groups | set(groups2 or [])
    elif doc.get('type') == SLACK_AUTH:
        username = params.get('username')[0]
        email = None
        user_team = params.get('team')[0]
        org_names = params.get('orgs', [''])[0]
        org_names = org_names.split(',')
        org_names = [utils.filter_unicode(x) for x in org_names]

        if user_team != settings.app.sso_match[0]:
            journal.entry(
                journal.SSO_AUTH_FAILURE,
                user_name=username,
                remote_address=remote_addr,
                reason=journal.SSO_AUTH_REASON_SLACK_FAILED,
                reason_long='Slack team not valid',
            )

            return flask.abort(401)

        not_found = False
        org_id = settings.app.sso_org
        for org_name in org_names:
            org = organization.get_by_name(
                org_name,
                fields=('_id'),
            )
            if org:
                not_found = False
                org_id = org.id
                break
            else:
                not_found = True

        if not_found:
            logger.warning('Supplied org names do not exists',
                'sso',
                sso_type=doc.get('type'),
                user_name=username,
                user_email=email,
                org_names=org_names,
            )

        valid, org_id_new, groups = sso.plugin_sso_authenticate(
            sso_type='slack',
            user_name=username,
            user_email=email,
            remote_ip=remote_addr,
            sso_org_names=org_names,
        )
        if valid:
            org_id = org_id_new or org_id
        else:
            logger.error('Slack plugin authentication not valid', 'sso',
                username=username,
            )

            journal.entry(
                journal.SSO_AUTH_FAILURE,
                user_name=username,
                remote_address=remote_addr,
                reason=journal.SSO_AUTH_REASON_PLUGIN_FAILED,
                reason_long='Slack plugin authentication failed',
            )

            return flask.abort(401)
        groups = set(groups or [])
    elif doc.get('type') == GOOGLE_AUTH:
        username = params.get('username')[0]
        email = username

        valid, google_groups = sso.verify_google(username)
        if not valid:
            journal.entry(
                journal.SSO_AUTH_FAILURE,
                user_name=username,
                remote_address=remote_addr,
                reason=journal.SSO_AUTH_REASON_GOOGLE_FAILED,
                reason_long='Google authentication failed',
            )

            return flask.abort(401)

        org_id = settings.app.sso_org

        valid, org_id_new, groups = sso.plugin_sso_authenticate(
            sso_type='google',
            user_name=username,
            user_email=email,
            remote_ip=remote_addr,
            sso_group_names=google_groups,
        )
        if valid:
            org_id = org_id_new or org_id
        else:
            logger.error('Google plugin authentication not valid', 'sso',
                username=username,
            )

            journal.entry(
                journal.SSO_AUTH_FAILURE,
                user_name=username,
                remote_address=remote_addr,
                reason=journal.SSO_AUTH_REASON_PLUGIN_FAILED,
                reason_long='Google plugin authentication failed',
            )

            return flask.abort(401)
        groups = set(groups or [])

        if settings.app.sso_google_mode == 'groups':
            groups = groups | set(google_groups)
        else:
            not_found = False
            google_groups = sorted(google_groups)
            for org_name in google_groups:
                org = organization.get_by_name(
                    org_name,
                    fields=('_id'),
                )
                if org:
                    not_found = False
                    org_id = org.id
                    break
                else:
                    not_found = True

            if not_found:
                logger.warning('Supplied org names do not exists',
                    'sso',
                    sso_type=doc.get('type'),
                    user_name=username,
                    user_email=email,
                    org_names=google_groups,
                )
    elif doc.get('type') == AZURE_AUTH:
        username = params.get('username')[0]
        email = None

        tenant, username = username.split('/', 2)
        if tenant != settings.app.sso_azure_directory_id:
            logger.error('Azure directory ID mismatch', 'sso',
                username=username,
            )

            journal.entry(
                journal.SSO_AUTH_FAILURE,
                user_name=username,
                azure_tenant=tenant,
                remote_address=remote_addr,
                reason=journal.SSO_AUTH_REASON_AZURE_FAILED,
                reason_long='Azure directory ID mismatch',
            )

            return flask.abort(401)

        valid, azure_groups = sso.verify_azure(username)
        if not valid:
            journal.entry(
                journal.SSO_AUTH_FAILURE,
                user_name=username,
                remote_address=remote_addr,
                reason=journal.SSO_AUTH_REASON_AZURE_FAILED,
                reason_long='Azure authentication failed',
            )

            return flask.abort(401)

        org_id = settings.app.sso_org

        valid, org_id_new, groups = sso.plugin_sso_authenticate(
            sso_type='azure',
            user_name=username,
            user_email=email,
            remote_ip=remote_addr,
            sso_group_names=azure_groups,
        )
        if valid:
            org_id = org_id_new or org_id
        else:
            logger.error('Azure plugin authentication not valid', 'sso',
                username=username,
            )

            journal.entry(
                journal.SSO_AUTH_FAILURE,
                user_name=username,
                remote_address=remote_addr,
                reason=journal.SSO_AUTH_REASON_PLUGIN_FAILED,
                reason_long='Azure plugin authentication failed',
            )

            return flask.abort(401)
        groups = set(groups or [])

        if settings.app.sso_azure_mode == 'groups':
            groups = groups | set(azure_groups)
        else:
            not_found = False
            azure_groups = sorted(azure_groups)
            for org_name in azure_groups:
                org = organization.get_by_name(
                    org_name,
                    fields=('_id'),
                )
                if org:
                    not_found = False
                    org_id = org.id
                    break
                else:
                    not_found = True

            if not_found:
                logger.warning('Supplied org names do not exists',
                    'sso',
                    sso_type=doc.get('type'),
                    user_name=username,
                    user_email=email,
                    org_names=azure_groups,
                )
    elif doc.get('type') == AUTHZERO_AUTH:
        username = params.get('username')[0]
        if params.get('email'):
            email = params.get('email')[0]
        else:
            email = None

        valid, authzero_groups = sso.verify_authzero(username)
        if not valid:
            journal.entry(
                journal.SSO_AUTH_FAILURE,
                user_name=username,
                remote_address=remote_addr,
                reason=journal.SSO_AUTH_REASON_AUTHZERO_FAILED,
                reason_long='Auth0 authentication failed',
            )

            return flask.abort(401)

        org_id = settings.app.sso_org

        valid, org_id_new, groups = sso.plugin_sso_authenticate(
            sso_type='authzero',
            user_name=username,
            user_email=email,
            remote_ip=remote_addr,
        )
        if valid:
            org_id = org_id_new or org_id
        else:
            logger.error('Auth0 plugin authentication not valid', 'sso',
                username=username,
            )

            journal.entry(
                journal.SSO_AUTH_FAILURE,
                user_name=username,
                remote_address=remote_addr,
                reason=journal.SSO_AUTH_REASON_PLUGIN_FAILED,
                reason_long='Auth0 plugin authentication failed',
            )

            return flask.abort(401)
        groups = set(groups or [])

        if settings.app.sso_authzero_mode == 'groups':
            groups = groups | set(authzero_groups)
        else:
            not_found = False
            authzero_groups = sorted(authzero_groups)
            for org_name in authzero_groups:
                org = organization.get_by_name(
                    org_name,
                    fields=('_id'),
                )
                if org:
                    not_found = False
                    org_id = org.id
                    break
                else:
                    not_found = True

            if not_found:
                logger.warning('Supplied org names do not exists',
                    'sso',
                    sso_type=doc.get('type'),
                    user_name=username,
                    user_email=email,
                    org_names=authzero_groups,
                )
    else:
        logger.error('Unknown sso type', 'sso',
            sso_type=doc.get('type'),
        )
        return flask.abort(401)

    if DUO_AUTH in sso_mode:
        token = utils.generate_secret()

        tokens_collection = mongo.get_collection('sso_tokens')
        tokens_collection.insert_one({
            '_id': token,
            'type': DUO_AUTH,
            'username': username,
            'email': email,
            'org_id': org_id,
            'groups': list(groups) if groups else None,
            'timestamp': utils.now(),
        })

        duo_page = static.StaticFile(settings.conf.www_path,
            'duo.html', cache=False, gzip=False)

        sso_duo_mode = settings.app.sso_duo_mode
        if sso_duo_mode == 'passcode':
            duo_mode = 'passcode'
        elif sso_duo_mode == 'phone':
            duo_mode = 'phone'
        else:
            duo_mode = 'push'

        body_class = duo_mode
        if settings.app.theme == 'dark':
            body_class += ' dark'

        duo_page.data = duo_page.data.replace('<%= body_class %>', body_class)
        duo_page.data = duo_page.data.replace('<%= token %>', token)
        duo_page.data = duo_page.data.replace('<%= duo_mode %>', duo_mode)
        duo_page.data = duo_page.data.replace(
            '<%= post_path %>', '/sso/duo')

        return duo_page.get_response()

    if YUBICO_AUTH in sso_mode:
        token = utils.generate_secret()

        tokens_collection = mongo.get_collection('sso_tokens')
        tokens_collection.insert_one({
            '_id': token,
            'type': YUBICO_AUTH,
            'username': username,
            'email': email,
            'org_id': org_id,
            'groups': list(groups) if groups else None,
            'timestamp': utils.now(),
        })

        yubico_page = static.StaticFile(settings.conf.www_path,
            'yubico.html', cache=False, gzip=False)

        if settings.app.theme == 'dark':
            yubico_page.data = yubico_page.data.replace(
                '<body>', '<body class="dark">')
        yubico_page.data = yubico_page.data.replace('<%= token %>', token)
        yubico_page.data = yubico_page.data.replace(
            '<%= post_path %>', '/sso/yubico')

        return yubico_page.get_response()

    return _validate_user(username, email, sso_mode, org_id, groups,
        remote_addr, http_redirect=True)

@app.app.route('/sso/duo', methods=['POST'])
@auth.open_auth
def sso_duo_post():
    remote_addr = utils.get_remote_addr()
    sso_mode = settings.app.sso
    token = utils.filter_str(flask.request.json.get('token')) or None
    passcode = utils.filter_str(flask.request.json.get('passcode')) or ''

    if sso_mode not in (DUO_AUTH, AZURE_DUO_AUTH, GOOGLE_DUO_AUTH,
            SLACK_DUO_AUTH, SAML_DUO_AUTH, SAML_OKTA_DUO_AUTH,
            SAML_ONELOGIN_DUO_AUTH, SAML_JUMPCLOUD_DUO_AUTH,
            RADIUS_DUO_AUTH):
        return flask.abort(404)

    if not token:
        return utils.jsonify({
            'error': TOKEN_INVALID,
            'error_msg': TOKEN_INVALID_MSG,
        }, 401)

    tokens_collection = mongo.get_collection('sso_tokens')
    doc = tokens_collection.find_one_and_delete({
        '_id': token,
    })
    if not doc or doc['_id'] != token or doc['type'] != DUO_AUTH:
        journal.entry(
            journal.SSO_AUTH_FAILURE,
            remote_address=remote_addr,
            reason=journal.SSO_AUTH_REASON_INVALID_TOKEN,
            reason_long='Invalid Duo authentication token',
        )

        return utils.jsonify({
            'error': TOKEN_INVALID,
            'error_msg': TOKEN_INVALID_MSG,
        }, 401)

    username = doc['username']
    email = doc['email']
    org_id = doc['org_id']
    groups = set(doc['groups'] or [])

    if settings.app.sso_duo_mode == 'passcode':
        duo_auth = sso.Duo(
            username=username,
            factor=settings.app.sso_duo_mode,
            remote_ip=remote_addr,
            auth_type='Key',
            passcode=passcode,
        )
        valid = duo_auth.authenticate()
        if not valid:
            logger.warning('Duo authentication not valid', 'sso',
                username=username,
            )

            journal.entry(
                journal.SSO_AUTH_FAILURE,
                username=username,
                remote_address=remote_addr,
                reason=journal.SSO_AUTH_REASON_DUO_FAILED,
                reason_long='Duo passcode authentication failed',
            )

            return utils.jsonify({
                'error': PASSCODE_INVALID,
                'error_msg': PASSCODE_INVALID_MSG,
            }, 401)
    else:
        duo_auth = sso.Duo(
            username=username,
            factor=settings.app.sso_duo_mode,
            remote_ip=remote_addr,
            auth_type='Key',
        )
        valid = duo_auth.authenticate()
        if not valid:
            logger.warning('Duo authentication not valid', 'sso',
                username=username,
            )

            journal.entry(
                journal.SSO_AUTH_FAILURE,
                remote_address=remote_addr,
                reason=journal.SSO_AUTH_REASON_DUO_FAILED,
                reason_long='Duo authentication failed',
            )

            return utils.jsonify({
                'error': DUO_FAILED,
                'error_msg': DUO_FAILED_MSG,
            }, 401)

    valid, org_id_new, groups2 = sso.plugin_sso_authenticate(
        sso_type='duo',
        user_name=username,
        user_email=email,
        remote_ip=remote_addr,
    )
    if valid:
        org_id = org_id_new or org_id
    else:
        logger.warning('Duo plugin authentication not valid', 'sso',
            username=username,
        )

        journal.entry(
            journal.SSO_AUTH_FAILURE,
            user_name=username,
            remote_address=remote_addr,
            reason=journal.SSO_AUTH_REASON_PLUGIN_FAILED,
            reason_long='Duo plugin authentication failed',
        )

        return flask.abort(401)

    groups = groups | set(groups2 or [])

    return _validate_user(username, email, sso_mode, org_id, groups,
        remote_addr)

@app.app.route('/sso/yubico', methods=['POST'])
@auth.open_auth
def sso_yubico_post():
    remote_addr = utils.get_remote_addr()
    sso_mode = settings.app.sso
    token = utils.filter_str(flask.request.json.get('token')) or None
    key = utils.filter_str(flask.request.json.get('key')) or None

    if sso_mode not in (AZURE_YUBICO_AUTH, GOOGLE_YUBICO_AUTH,
            AUTHZERO_YUBICO_AUTH, SLACK_YUBICO_AUTH, SAML_YUBICO_AUTH,
            SAML_OKTA_YUBICO_AUTH, SAML_ONELOGIN_YUBICO_AUTH,
            SAML_JUMPCLOUD_YUBICO_AUTH):
        return flask.abort(404)

    if not token or not key:
        return utils.jsonify({
            'error': TOKEN_INVALID,
            'error_msg': TOKEN_INVALID_MSG,
        }, 401)

    tokens_collection = mongo.get_collection('sso_tokens')
    doc = tokens_collection.find_one_and_delete({
        '_id': token,
    })
    if not doc or doc['_id'] != token or doc['type'] != YUBICO_AUTH:
        journal.entry(
            journal.SSO_AUTH_FAILURE,
            remote_address=remote_addr,
            reason=journal.SSO_AUTH_REASON_INVALID_TOKEN,
            reason_long='Invalid Yubikey authentication token',
        )

        return utils.jsonify({
            'error': TOKEN_INVALID,
            'error_msg': TOKEN_INVALID_MSG,
        }, 401)

    username = doc['username']
    email = doc['email']
    org_id = doc['org_id']
    groups = set(doc['groups'] or [])

    valid, yubico_id = sso.auth_yubico(key)
    if not valid or not yubico_id:
        journal.entry(
            journal.SSO_AUTH_FAILURE,
            username=username,
            remote_address=remote_addr,
            reason=journal.SSO_AUTH_REASON_YUBIKEY_FAILED,
            reason_long='Yubikey authentication failed',
        )

        return utils.jsonify({
            'error': YUBIKEY_INVALID,
            'error_msg': YUBIKEY_INVALID_MSG,
        }, 401)

    return _validate_user(username, email, sso_mode, org_id, groups,
        remote_addr, yubico_id=yubico_id)


@app.app.route('/sso/callback', methods=['POST'])
@auth.open_auth
def sso_callback_post():
    saml_settings = _load_saml_settings()
    req = _prepare_saml_request(flask.request)
    saml_auth = OneLogin_Saml2_Auth(req, saml_settings)

    saml_auth.process_response()
    errors = saml_auth.get_errors()
    remote_addr = utils.get_remote_addr()

    if errors:
        logger.error('SAML authentication error', 'sso',
            errors=errors,
            reason=saml_auth.get_last_error_reason(),
        )
        return flask.abort(401)

    if not saml_auth.is_authenticated():
        logger.error('SAML user not authenticated', 'sso')
        return flask.abort(401)

    
    attributes = saml_auth.get_attributes()
    email = None

    if 'email' in attributes:
        email = attributes['email'][0]
    elif 'https://aws.amazon.com/SAML/Attributes/RoleSessionName' in attributes:
        email = attributes['https://aws.amazon.com/SAML/Attributes/RoleSessionName'][0]

    username = email or saml_auth.get_nameid()
    with open('/tmp/sso_debug.log', 'a') as _f:
        _f.write('SAML attributes: %s\n' % str(attributes))
        _f.write('SAML nameid: %s\n' % str(saml_auth.get_nameid()))
        _f.write('SAML email: %s\n' % str(email))
        _f.write('SAML username resolved: %s\n' % str(username))

    if not username:
        logger.error('SAML response missing username/email', 'sso')
        return flask.abort(406)

    flask.session['sso_email'] = username
    flask.session['sso_authenticated'] = True

    admin_user = auth.get_by_username(username)
    if not admin_user:
        admin_user = auth.get_by_username(username.split('@')[0])

    if admin_user:
        logger.info('SSO admin detected, skipping to normal user flow: ' + username, 'sso')
    from pritunl import database
    raw_org_id = flask.session.get('sso_org_id') or settings.app.sso_org
    try:
        org_id = database.ParseObjectId(str(raw_org_id))
    except:
        org_id = raw_org_id

    if not org_id:
        logger.error('No org_id for SSO user', 'sso')
        return flask.abort(500)

    org = organization.get_by_id(org_id)
    if not org:
        logger.error('Organization not found for SSO', 'sso')
        return flask.abort(405)

    usr = org.find_user(name=username)
    if not usr:
        usr = org.new_user(
            name=username,
            email=email,
            type=CERT_CLIENT,
            auth_type='saml',
            groups=[],
        )
        usr.audit_event('user_created',
            'User created with SAML SSO',
            remote_addr=remote_addr,
        )
        event.Event(type=ORGS_UPDATED)
        event.Event(type=USERS_UPDATED, resource_id=org.id)
        event.Event(type=SERVERS_UPDATED)

    if usr.disabled:
        return flask.abort(403)

    # Auto-generate proper cert if missing or has wrong subject format
    if not usr.certificate or not usr.private_key or 'O=company' in (usr.certificate or ''):
        import subprocess, tempfile, os, shutil
        org_id = str(org.id)
        user_id = str(usr.id)
        tmp = tempfile.mkdtemp()
        try:
            ca_cert_path = os.path.join(tmp, 'ca.crt')
            ca_key_path  = os.path.join(tmp, 'ca.key')
            key_path     = os.path.join(tmp, 'user.key')
            csr_path     = os.path.join(tmp, 'user.csr')
            cert_path    = os.path.join(tmp, 'user.crt')
            ext_path     = os.path.join(tmp, 'ext.cnf')
            srl_path     = os.path.join(tmp, 'ca.srl')
            org.write_file('ca_certificate', ca_cert_path, chmod=0o600)
            org.write_file('ca_private_key', ca_key_path, chmod=0o600)
            with open(srl_path, 'w') as _f: _f.write('01\n')
            with open(ext_path, 'w') as _f:
                _f.write('[client_ext]\nkeyUsage = critical,digitalSignature,keyEncipherment\nbasicConstraints = CA:false\nextendedKeyUsage = clientAuth\nsubjectKeyIdentifier = hash\n')
            subprocess.run(['openssl', 'genrsa', '-out', key_path, '2048'], capture_output=True)
            subprocess.run(['openssl', 'req', '-new', '-key', key_path,
                '-subj', '/O=%s/CN=%s' % (org_id, user_id),
                '-out', csr_path], capture_output=True)
            subprocess.run(['openssl', 'x509', '-req',
                '-in', csr_path, '-CA', ca_cert_path, '-CAkey', ca_key_path,
                '-CAserial', srl_path, '-out', cert_path,
                '-days', '3650', '-sha256',
                '-extfile', ext_path, '-extensions', 'client_ext'],
                capture_output=True)
            v = subprocess.run(['openssl', 'verify', '-CAfile', ca_cert_path, cert_path],
                capture_output=True, text=True)
            if 'OK' in v.stdout:
                usr.certificate = open(cert_path).read()
                usr.private_key = open(key_path).read()
                usr.commit(('certificate', 'private_key'))
                logger.info('Auto-generated cert for SSO user', 'sso', user_name=usr.name)
            else:
                logger.error('Auto cert verify failed', 'sso', user_name=usr.name)
        except Exception as _e:
            logger.error('Auto cert generation failed', 'sso', error=str(_e))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    flask.session['sso_user_id'] = str(usr.id)

    # Check if this is a VPN client connect flow
    # key_state was passed as RelayState, AWS echoes it back in POST
    relay_state = flask.request.form.get('RelayState') or ''
    # Only treat as key flow if it looks like our 64-char key token
    if len(relay_state) >= 32 and '/' not in relay_state and '.' not in relay_state:
        key_state = relay_state
    else:
        key_state = None
    with open('/tmp/sso_debug.log', 'a') as f: f.write('key_state from session: %s | session keys: %s\n' % (str(key_state), str(list(flask.session.keys()))))
    if key_state:
        # Client connect flow - verify identity matches profile owner
        pending_collection = mongo.get_collection('key_sso_pending')
        key_doc = pending_collection.find_one_and_delete({'_id': key_state})

        if not key_doc:
            logger.warning('Key SSO pending doc not found, falling back to web flow', 'sso',
                key_state=key_state)
            key_state = None

        # Get profile owner
        profile_org = organization.get_by_id(key_doc['org_id'])
        profile_usr = profile_org.get_user(id=key_doc['user_id'])

        if not profile_usr:
            logger.error('Profile user not found', 'sso')
            return flask.abort(404)

        # CRITICAL SECURITY CHECK
        # Person logging into AWS SSO must be the same as profile owner
        sso_identity = username
        profile_identity = profile_usr.email or profile_usr.name

        if sso_identity.lower() != profile_identity.lower():
            logger.warning(
                'SSO identity mismatch - stolen profile attempt blocked',
                'sso',
                sso_identity=sso_identity,
                profile_identity=profile_identity,
            )
            return flask.Response(
                status=200,
                response='''<!DOCTYPE html>
<html>
<head><title>Authentication Failed</title>
<style>body{background:#1a1a1a;color:#fff;font-family:Arial;
display:flex;justify-content:center;align-items:center;height:100vh;margin:0;}
.box{text-align:center;padding:40px;background:#2a2a2a;border-radius:8px;}
h2{color:#e74c3c;}a{color:#428bca;}</style></head>
<body><div class="box">
<h2>Authentication Failed</h2>
<p>Your identity does not match this VPN profile.</p>
<p>Please download your own profile from
<a href="https://107.21.31.183/login">here</a>.</p>
</div></body></html>''',
                content_type="text/html;charset=utf-8",
            )

        # Identity verified - create SSO token for authorizer
        from pritunl import messenger
        tokens_collection = mongo.get_collection('server_sso_tokens')
        tokens_collection.insert_one({
            '_id': key_doc['token'],
            'user_id': usr.id,
            'server_id': key_doc['server_id'],
            'stage': 'open',
            'timestamp': utils.now(),
        })

        # Notify authorizer
        messenger.publish('tokens', 'authorized', extra={
            'user_id': usr.id,
            'server_id': key_doc['server_id'],
            'token': key_doc['token'],
        })

        logger.info('VPN client SSO auth successful', 'sso',
            username=username,
            server_id=str(key_doc['server_id']),
        )

        # Redirect to success - Pritunl client is polling for this
        return flask.redirect('https://107.21.31.183:8443/success')

    # Normal web flow - profile download
    key_link = org.create_user_key_link(usr.id, one_time=True)
    redirect_url = 'https://107.21.31.183:8443' + key_link['view_url']
    logger.info('SSO user login: ' + redirect_url, 'sso')
    return flask.redirect(redirect_url)
