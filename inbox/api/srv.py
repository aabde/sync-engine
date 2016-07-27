from flask import Flask, request, jsonify, make_response, g
from flask.ext.restful import reqparse
from werkzeug.exceptions import default_exceptions, HTTPException
from sqlalchemy.orm.exc import NoResultFound

from inbox.api.kellogs import APIEncoder
from nylas.logging import get_logger
from inbox.models import Namespace, Account
from inbox.models.session import global_session_scope
from inbox.api.validation import (bounded_str, ValidatableArgument,
                                  strict_parse_args, limit)
from inbox.api.validation import valid_public_id

from ns_api import app as ns_api
from ns_api import DEFAULT_LIMIT

from inbox.webhooks.gpush_notifications import app as webhooks_api

from inbox.util.startup import preflight
from inbox.util.url import provider_from_address
from inbox.auth.base import handler_from_provider
from inbox.models.session import session_scope
from inbox.api.err import (err, APIException, NotFoundError, InputError,
                           AccountDoesNotExistError)
from inbox.basicauth import NotSupportedError
from inbox.util.url import url_concat
import os

app = Flask(__name__)
# Handle both /endpoint and /endpoint/ without redirecting.
# Note that we need to set this *before* registering the blueprint.
app.url_map.strict_slashes = False
app.config['API_KEY'] = os.environ['MAIL_API_KEY']

def secure_compare(a, b):
    if not a or not b or len(a) != len(b):
        return False
    res = 0
    for x, y in zip(a, b):
        res |= ord(x) ^ ord(y)
    return res == 0

def default_json_error(ex):
    """ Exception -> flask JSON responder """
    logger = get_logger()
    logger.error('Uncaught error thrown by Flask/Werkzeug', exc_info=ex)
    response = jsonify(message=str(ex), type='api_error')
    response.status_code = (ex.code
                            if isinstance(ex, HTTPException)
                            else 500)
    return response

# Patch all error handlers in werkzeug
for code in default_exceptions.iterkeys():
    app.error_handler_spec[None][code] = default_json_error

@app.before_request
def auth():
    AUTH_ERROR_MSG = ("Could not verify access credential.", 401,
                     {'WWW-Authenticate': 'Basic realm="API '
                      'Access Token Required"'})

    token = request.headers.get('X-API-KEY', None)

    if not secure_compare(token, app.config['API_KEY']):
        return make_response(AUTH_ERROR_MSG)

    """ Check for account ID on all non-root URLS """
    if request.path in ('/accounts', '/accounts/', '/', '/provider', '/accounts/create') \
                        or request.path.startswith('/w/'):
        return

    if not request.authorization or not request.authorization.username:

        auth_header = request.headers.get('Authorization', None)

        if not auth_header:
            return make_response(AUTH_ERROR_MSG)

        parts = auth_header.split()

        if (len(parts) != 2 or parts[0].lower() != 'bearer' or not parts[1]):
            return make_response(AUTH_ERROR_MSG)
        namespace_public_id = parts[1]

    else:
        namespace_public_id = request.authorization.username

    with global_session_scope() as db_session:
        try:
            valid_public_id(namespace_public_id)
            namespace = db_session.query(Namespace) \
                .filter(Namespace.public_id == namespace_public_id).one()
            g.namespace_id = namespace.id
            g.account_id = namespace.account.id
        except NoResultFound:
            return make_response(AUTH_ERROR_MSG)


@app.after_request
def finish(response):
    origin = request.headers.get('origin')
    if origin:  # means it's just a regular request
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Headers'] = \
            'Authorization,Content-Type'
        response.headers['Access-Control-Allow-Methods'] = \
            'GET,PUT,POST,DELETE,OPTIONS,PATCH'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

accounts_disabled = True

@app.route('/accounts/')
def ns_all():
    if accounts_disabled:
        return err(404, 'Not found')
    """ Return all namespaces """
    # We do this outside the blueprint to support the case of an empty
    # public_id.  However, this means the before_request isn't run, so we need
    # to make our own session
    with global_session_scope() as db_session:
        parser = reqparse.RequestParser(argument_class=ValidatableArgument)
        parser.add_argument('limit', default=DEFAULT_LIMIT, type=limit,
                            location='args')
        parser.add_argument('offset', default=0, type=int, location='args')
        parser.add_argument('email_address', type=bounded_str, location='args')
        args = strict_parse_args(parser, request.args)

        query = db_session.query(Namespace)
        if args['email_address']:
            query = query.join(Account)
            query = query.filter_by(email_address=args['email_address'])

        query = query.limit(args['limit'])
        if args['offset']:
            query = query.offset(args['offset'])

        namespaces = query.all()
        encoder = APIEncoder()
        return encoder.jsonify(namespaces)


@app.route('/logout')
def logout():
    """ Utility function used to force browsers to reset cached HTTP Basic Auth
        credentials """
    return make_response((
        "<meta http-equiv='refresh' content='0; url=/''>.",
        401,
        {'WWW-Authenticate': 'Basic realm="API Access Token Required"'}))

@app.route('/provider', methods=['POST'])
def account_provider():
    data = request.get_json(force=True)
    email_address = data.get('email_address')
    if not email_address:
        return err(400, 'email_address required')
    else:
        response = {}
        provider = provider_from_address(email_address)
        if provider == 'unknown':
            provider = 'custom'
        response['provider'] = provider
        if provider == 'gmail':
            auth_handler = handler_from_provider(provider)
            url_args = {'redirect_uri': auth_handler.OAUTH_REDIRECT_URI,
                        'client_id': auth_handler.OAUTH_CLIENT_ID,
                        'response_type': 'code',
                        'scope': auth_handler.OAUTH_SCOPE,
                        'access_type': 'offline'}
            url_args['login_hint'] = email_address
            url = url_concat(auth_handler.OAUTH_AUTHENTICATE_URL, url_args)
            response['auth_url'] = url
        encoder = APIEncoder()
        return encoder.jsonify(response)

@app.route('/accounts/create', methods=['POST'])
def account_add():
    data = request.get_json(force=True)
    auth_info = {}

    if not data.get('email_address'):
        return err(400, 'email_address required')

    email_address = data.get('email_address')
    provider = data.get('provider')
    
    if not provider:
        provider = provider_from_address(email_address)

    if provider == 'unknown':
        provider = 'custom'

    auth_handler = handler_from_provider(provider)
    
    if provider == 'custom':
        if not (data.get('imap_server_host') and data.get('imap_password') and data.get('smtp_server_host')):
            return err(400, 'Missing information, cannot create account')
        else:
            auth_info = {
                'email': email_address,
                'provider': provider,
                'imap_server_host': data.get('imap_server_host'),
                'imap_server_port': 993,
                'imap_username': email_address,
                'imap_password': data.get('imap_password'),
                'smtp_server_host': data.get('smtp_server_host'),
                'smtp_server_port': 587,
                'smtp_username': email_address,
                'smtp_password': data.get('imap_password'),
                'ssl_required': data.get('ssl_required') == 'true'
            }
            imap_server_port = int(data.get('imap_server_port'))
            if imap_server_port:
                auth_info['imap_server_port'] = imap_server_port
            smtp_server_port = int(data.get('smtp_server_port'))
            if smtp_server_port:
                auth_info['smtp_server_port'] = smtp_server_port
            imap_username = int(data.get('imap_username'))
            if imap_username:
                auth_info['imap_username'] = imap_username
            smtp_username = int(data.get('smtp_username'))
            if smtp_username:
                auth_info['smtp_username'] = smtp_username
            smtp_password = int(data.get('smtp_password'))
            if smtp_password:
                auth_info['smtp_password'] = smtp_password
    elif provider == 'gmail':
        if not data.get('auth_code'):
            return err(400, 'Missing information, cannot create account')
        auth_code = data.get('auth_code')
        try:
            auth_info = auth_handler._get_authenticated_user(auth_code)
            auth_info['provider'] = provider
            auth_info['contacts'] = True
            auth_info['events'] = True
        except OAuthError:
            return err(400, 'Invalid authorization code')
    else:
        if not data.get('password'):
            return err(400, 'Missing information, cannot create account')
        else:
            auth_info = {
                'email': email_address,
                'provider': provider,
                'password': data.get('password')
            }

    preflight()

    with session_scope(0) as db_session:
        account = db_session.query(Account).filter_by(
            email_address=email_address).first()
        if account is not None:
            return err(400, 'Already have this account!')

        account = auth_handler.create_account(email_address, auth_info)
        
        try:
            if auth_handler.verify_account(account):
                db_session.add(account)
                db_session.commit()
        except NotSupportedError as e:
            return err(400, 'Error registering account')

        encoder = APIEncoder()
        return encoder.jsonify(db_session.query(Namespace).join(Account).filter_by(email_address=email_address).first())
    

app.register_blueprint(ns_api)
app.register_blueprint(webhooks_api)  # /w/...
