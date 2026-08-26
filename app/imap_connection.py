import imaplib
import json
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_MICROSOFT_SCOPE = 'https://outlook.office365.com/.default'
DEFAULT_TOKEN_URL = 'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'


class OAuth2TokenError(Exception):
	pass


def load_config(configuration):
	"""Load and validate the mailbox connection configuration."""
	imap_config = configuration['imap']
	authentication = imap_config.get('authentication', 'password').lower()
	if authentication not in ['password', 'oauth2']:
		raise ValueError("The IMAP authentication method must be 'password' or 'oauth2'")

	loaded_config = {
		'host': imap_config['host'],
		'port': int(imap_config['port']),
		'user': imap_config['user'],
		'folder': imap_config['folder'],
		'authentication': authentication
	}

	if authentication == 'password':
		loaded_config['password'] = imap_config['password']
		return loaded_config

	oauth2_config = imap_config.get('oauth2', {})
	for parameter in ['client_id', 'client_secret']:
		if not oauth2_config.get(parameter):
			raise ValueError("Missing OAuth2 parameter: {}".format(parameter))

	tenant_id = oauth2_config.get('tenant_id', '')
	token_url = oauth2_config.get('token_url', DEFAULT_TOKEN_URL)
	if '{tenant_id}' in token_url:
		if not tenant_id:
			raise ValueError('Missing OAuth2 parameter: tenant_id')
		token_url = token_url.replace('{tenant_id}', urllib.parse.quote(tenant_id, safe=''))

	loaded_config['oauth2'] = {
		'client_id': oauth2_config['client_id'],
		'client_secret': oauth2_config['client_secret'],
		'scope': oauth2_config.get('scope', DEFAULT_MICROSOFT_SCOPE),
		'token_url': token_url
	}
	return loaded_config


def acquire_access_token(oauth2_config):
	"""Acquire an OAuth2 access token using the client credentials grant."""
	request_body = urllib.parse.urlencode({
		'client_id': oauth2_config['client_id'],
		'client_secret': oauth2_config['client_secret'],
		'scope': oauth2_config['scope'],
		'grant_type': 'client_credentials'
	}).encode('utf-8')
	request = urllib.request.Request(
		oauth2_config['token_url'],
		data=request_body,
		headers={'Content-Type': 'application/x-www-form-urlencoded'}
	)

	try:
		with urllib.request.urlopen(request, timeout=30) as response:
			token_response = json.loads(response.read().decode('utf-8'))
	except urllib.error.HTTPError as error:
		raise OAuth2TokenError(_format_token_error(error.code, error.read())) from error
	except (urllib.error.URLError, ValueError) as error:
		raise OAuth2TokenError('Unable to obtain OAuth2 access token: {}'.format(error)) from error

	access_token = token_response.get('access_token')
	if not access_token:
		raise OAuth2TokenError('OAuth2 token response does not contain an access_token')
	return access_token


def _format_token_error(status_code, response_body):
	try:
		error_response = json.loads(response_body.decode('utf-8'))
		error_name = error_response.get('error', 'unknown_error')
		error_description = error_response.get('error_description', 'No error description returned')
		return 'OAuth2 token request failed with HTTP {}: {} ({})'.format(
			status_code, error_name, error_description
		)
	except (ValueError, UnicodeDecodeError):
		return 'OAuth2 token request failed with HTTP {}'.format(status_code)


def connect(config):
	"""Open an SSL IMAP connection and authenticate with password or OAuth2."""
	access_token = None
	if config['authentication'] == 'oauth2':
		access_token = acquire_access_token(config['oauth2'])

	connection = imaplib.IMAP4_SSL(config['host'], config['port'])
	if config['authentication'] == 'password':
		connection.login(config['user'], config['password'])
	else:
		xoauth2 = 'user={0}\x01auth=Bearer {1}\x01\x01'.format(config['user'], access_token)
		connection.authenticate('XOAUTH2', lambda challenge: xoauth2.encode('utf-8'))
	return connection
