import json
import os
import sys
import unittest
import urllib.parse
from unittest import mock


APP_DIRECTORY = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'app')
sys.path.insert(0, APP_DIRECTORY)

import imap_connection


class FakeResponse:
	def __init__(self, payload):
		self.payload = payload

	def __enter__(self):
		return self

	def __exit__(self, exception_type, exception, traceback):
		return False

	def read(self):
		return json.dumps(self.payload).encode('utf-8')


class ImapConnectionTest(unittest.TestCase):
	def test_existing_password_configuration_remains_supported(self):
		configuration = {
			'imap': {
				'host': 'imap.example.com',
				'port': '993',
				'user': 'mailbox@example.com',
				'password': 'app-password',
				'folder': 'inbox'
			}
		}

		loaded = imap_connection.load_config(configuration)

		self.assertEqual('password', loaded['authentication'])
		self.assertEqual(993, loaded['port'])
		self.assertEqual('app-password', loaded['password'])

	@mock.patch('imap_connection.imaplib.IMAP4_SSL')
	def test_password_authentication_uses_imap_login(self, imap_ssl):
		config = {
			'host': 'imap.example.com',
			'port': 993,
			'user': 'mailbox@example.com',
			'folder': 'inbox',
			'authentication': 'password',
			'password': 'app-password'
		}

		connection = imap_connection.connect(config)

		imap_ssl.assert_called_once_with('imap.example.com', 993)
		connection.login.assert_called_once_with('mailbox@example.com', 'app-password')
		connection.authenticate.assert_not_called()

	@mock.patch('imap_connection.urllib.request.urlopen')
	@mock.patch('imap_connection.imaplib.IMAP4_SSL')
	def test_oauth2_authentication_uses_client_credentials_and_xoauth2(self, imap_ssl, urlopen):
		urlopen.return_value = FakeResponse({'access_token': 'access-token'})
		configuration = {
			'imap': {
				'host': 'outlook.office365.com',
				'port': '993',
				'user': 'mailbox@example.com',
				'folder': 'inbox',
				'authentication': 'oauth2',
				'oauth2': {
					'tenant_id': 'tenant-id',
					'client_id': 'client-id',
					'client_secret': 'client-secret'
				}
			}
		}
		config = imap_connection.load_config(configuration)

		connection = imap_connection.connect(config)

		request = urlopen.call_args.args[0]
		request_parameters = urllib.parse.parse_qs(request.data.decode('utf-8'))
		self.assertEqual('https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token', request.full_url)
		self.assertEqual(['client-id'], request_parameters['client_id'])
		self.assertEqual(['client-secret'], request_parameters['client_secret'])
		self.assertEqual(['client_credentials'], request_parameters['grant_type'])
		self.assertEqual([imap_connection.DEFAULT_MICROSOFT_SCOPE], request_parameters['scope'])

		mechanism, callback = connection.authenticate.call_args.args
		self.assertEqual('XOAUTH2', mechanism)
		self.assertEqual(
			b'user=mailbox@example.com\x01auth=Bearer access-token\x01\x01',
			callback(None)
		)
		connection.login.assert_not_called()

	def test_oauth2_configuration_requires_client_credentials(self):
		configuration = {
			'imap': {
				'host': 'outlook.office365.com',
				'port': '993',
				'user': 'mailbox@example.com',
				'folder': 'inbox',
				'authentication': 'oauth2',
				'oauth2': {'tenant_id': 'tenant-id'}
			}
		}

		with self.assertRaisesRegex(ValueError, 'client_id'):
			imap_connection.load_config(configuration)


if __name__ == '__main__':
	unittest.main()
