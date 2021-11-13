import logging.config
import imaplib
import io
import json
import base64
import hashlib
import re
import email
import emoji
import urllib.parse
import traceback
import ioc_finder
import thehive4py.api, thehive4py.models, thehive4py.query

# Global variable used for logging
log = None

# Global variable needed to use the API
api_thehive = None

# Global variable used for the configuration
config = {}

# Global variable used for the whitelist
whitelist = {}


def connect_to_IMAP_server(wsl):
	# Create the connection to the IMAP server using host and port
	connection = imaplib.IMAP4_SSL(config['imapHost'], config['imapPort'])
	# Log in using username and password
	connection.login(config['imapUser'],config['imapPassword'])
	log.info('Connected to email {0} server {1}:{2}/{3}'.format(config['imapUser'], config['imapHost'], config['imapPort'], config['imapFolder']))
	wsl.emit_info('Connected to email {0} server {1}:{2}/{3}'.format(config['imapUser'], config['imapHost'], config['imapPort'], config['imapFolder']))
	return connection


# Check if an observable is whitelisted with an exact match or with a regex match
def is_whitelisted(obs_type, obs_value):
	found = False
	if ((not found) and (obs_value in whitelist[obs_type+'Exact'])):
		found = True
	if ((not found) and (obs_type == 'domain')):
		for regex in whitelist['regexDomainsInSubdomains']:
			if re.search(regex, obs_value):
				found = True
	if ((not found) and (obs_type == 'url')):
		for regex in whitelist['regexDomainsInURLs']:
			if re.search(regex, obs_value):
				found = True
	if ((not found) and (obs_type == 'mail')):
		for regex in whitelist['regexDomainsInEmails']:
			if re.search(regex, obs_value):
				found = True
	if ((not found) and (obs_type not in ['hash', 'filetype'])):
		for regex in whitelist[obs_type+'Regex']:
			if re.search(regex, obs_value):
				found = True
	return found


# Use the ioc-finder module to extract observables from a string buffer and add to the list only if they are not whitelisted
def search_observables(buffer, wsl):
	observables = []
	iocs = {}
	iocs['email_addresses'] = ioc_finder.parse_email_addresses(buffer)
	iocs['ipv4s'] = ioc_finder.parse_ipv4_addresses(buffer)
	iocs['domains'] = ioc_finder.parse_domain_names(buffer)
	# Option to parse URLs without a scheme (e.g. without https://)
	iocs['urls'] = ioc_finder.parse_urls(buffer, parse_urls_without_scheme=False)
	for mail in iocs['email_addresses']:
		if is_whitelisted('mail', mail):
			log.info("Skipped whitelisted observable mail: {0}".format(mail))
			wsl.emit_info("Skipped whitelisted observable mail: {0}".format(mail))
		else:
			log.info("Found observable mail: {0}".format(mail))
			wsl.emit_info("Found observable mail: {0}".format(mail))
			observables.append({'type': 'mail', 'value': mail})
	for ip in iocs['ipv4s']:
		if is_whitelisted('ip', ip):
			log.info("Skipped whitelisted observable ip: {0}".format(ip))
			wsl.emit_info("Skipped whitelisted observable ip: {0}".format(ip))
		else:
			log.info("Found observable ip: {0}".format(ip))	  
			wsl.emit_info("Found observable ip: {0}".format(ip))			
			observables.append({'type': 'ip', 'value': ip})
	for domain in iocs['domains']:
		if is_whitelisted('domain', domain):
			log.info("Skipped whitelisted observable domain: {0}".format(domain))
			wsl.emit_info("Skipped whitelisted observable domain: {0}".format(domain))
		else:
			log.info("Found observable domain: {0}".format(domain))
			wsl.emit_info("Found observable domain: {0}".format(domain))
			observables.append({'type': 'domain', 'value': domain})
	for url in iocs['urls']:
		if is_whitelisted('url', url):
			log.info("Skipped whitelisted observable url: {0}".format(url))
			wsl.emit_info("Skipped whitelisted observable url: {0}".format(url))
		else:
			log.info("Found observable url: {0}".format(url))
			wsl.emit_info("Found observable url: {0}".format(url))
			observables.append({'type': 'url', 'value': url})
	return observables


# Use the mail UID of the selected email to fetch only that email from the mailbox
def obtain_eml(connection, mail_uid, wsl):

	# Read all the unseen emails from this folder
	connection.select(config['imapFolder'])
	typ, dat = connection.search(None, '(UNSEEN)')

	# The dat[0] variable contains the IDs of all the unread emails
	# The IDs are obtained by using the split function and the length of the array is the number of unread emails
	# If the selected mail uid is present in the list, then process only that email
	if mail_uid.encode() in dat[0].split():
		typ, dat = connection.fetch(mail_uid.encode(), '(RFC822)')
		if typ != 'OK':
			log.error(dat[-1])
			wsl.emit_error(dat[-1])
		message = dat[0][1]
		# The fetch operation flags the message as seen by default
		log.info("Message {0} flagged as read".format(mail_uid))
		wsl.emit_info("Message {0} flagged as read".format(mail_uid))
		
		# Obtain the From field of the external email that will be used to send the verdict to the user
		msg = email.message_from_bytes(message)
		decode = email.header.decode_header(msg['From'])[0]
		if decode[1] is not None:
			external_from_field = decode[0].decode(decode[1])
		else:
			external_from_field = str(decode[0])
		parsed_from_field = email.utils.parseaddr(external_from_field)
		if len(parsed_from_field) > 1:
			external_from_field = parsed_from_field[1]

		# Variable used to detect the mimetype of the email parts
		mimetype = None

		# Variable that will contain the internal EML file
		internal_msg = None
		
		# Walk the multipart structure of the email (now only the EML part is needed)
		for part in msg.walk():
			mimetype = part.get_content_type()
			# If the content type of this part is the rfc822 message, then stop because the EML attachment is the last part
			# If there is any other part after the rfc822 part, then it may be related to the internal email, so it must not be considered
			# Both message/rfc822 and application/octet-stream types are considered due to differences in how the attachment is handled by different mail clients
			if mimetype in ['application/octet-stream', 'message/rfc822']:
				# Obtain the internal EML file in both cases
				if mimetype == 'application/octet-stream':
					eml_payload = part.get_payload(decode=1)
					internal_msg = email.message_from_bytes(eml_payload)
				elif mimetype == 'message/rfc822':
					eml_payload = part.get_payload(decode=0)[0]
					try:
						internal_msg = email.message_from_string(base64.b64decode(str(eml_payload)).decode())
					except:
						internal_msg = eml_payload

				# If the EML attachment has been found, then break the for
				break
				
		return internal_msg, external_from_field

	else:
		# Handle multiple analysts that select the same email from more than one tab
		log.error("The email with UID {} has already been analyzed. Please refresh the page and retry.".format(mail_uid))
		wsl.emit_error("The email with UID {} has already been analyzed. Please refresh the page and retry.".format(mail_uid))
		return



# Parse the EML file and extract the observables
def parse_eml(internal_msg, wsl):

	# Obtain the subject of the internal email
	# This is not straightforward since the subject might be splitted in two or more parts
	decode_subj = email.header.decode_header(internal_msg['Subject'])
	decoded_elements_subj = []
	for decode_elem in decode_subj:
		if decode_elem[1] is not None:
			if str(decode_elem[1]) == 'unknown-8bit':
				decoded_elements_subj.append(decode_elem[0].decode())
			else:
				decoded_elements_subj.append(decode_elem[0].decode(decode_elem[1]))
		else:
			if(isinstance(decode_elem[0], str)):
				decoded_elements_subj.append(str(decode_elem[0]))
			else:
				decoded_elements_subj.append(decode_elem[0].decode())
		subject_field = ''.join(decoded_elements_subj)

	log.info("Analyzing attached message with subject: {}".format(subject_field))
	wsl.emit_info("Analyzing attached message with subject: {}".format(subject_field))

	# List of attachments of the internal email
	attachments = []

	# List of attachment hashes
	hashes_attachments = []

	# List of observables found in the body of the internal email
	observables_body = []

	# Dictionary containing a list of observables found in each header field
	observables_header = {}

	# List of header fields to consider when searching for observables in the header
	header_fields_list = [
		'To', 
		'From', 
		'Sender',
		'Cc',
		'Delivered-To',
		'Return-Path', 
		'Reply-To',
		'Bounces-to',
		'Received', 
		'X-Received', 
		'X-OriginatorOrg', 
		'X-Sender-IP', 
		'X-Originating-IP',
		'X-SenderIP',
		'X-Originating-Email'
	]
	
	# Extract header fields 
	parser = email.parser.HeaderParser()
	header_fields = parser.parsestr(internal_msg.as_string())

	# Search the observables in the values of all the selected header fields
	# Since a field may appear more than one time (e.g. Received:), the lists need to be initialized and then extended
	i = 0
	while  i < len(header_fields.keys()):
		if header_fields.keys()[i] in header_fields_list:
			if not observables_header.get(header_fields.keys()[i]):
				observables_header[header_fields.keys()[i]] = []
			observables_header[header_fields.keys()[i]].extend(search_observables(header_fields.values()[i], wsl))
		i+=1
	
	# Walk the multipart structure of the internal email 
	for part in internal_msg.walk():
		mimetype = part.get_content_type()
		content_disposition = part.get_content_disposition()
		if content_disposition != "attachment":
			# Extract the observables from the body (from both text/plain and text/html parts) using the search_observables function
			if mimetype == "text/plain":
				try:
					body = part.get_payload(decode=True).decode()
				except UnicodeDecodeError:
					body = part.get_payload(decode=True).decode('ISO-8859-1')
				observables_body.extend(search_observables(body, wsl))
			elif mimetype == "text/html":
				try:
					html = part.get_payload(decode=True).decode()
				except UnicodeDecodeError:
					html = part.get_payload(decode=True).decode('ISO-8859-1')
				# Handle URL encoding
				html_urldecoded = urllib.parse.unquote(html.replace("&amp;", "&"))
				observables_body.extend(search_observables(html_urldecoded, wsl))
		# Extract attachments
		else:
			filename = part.get_filename()
			if filename and mimetype:
				# Add the attachment if it is not whitelisted (in terms of filename or filetype)
				if is_whitelisted('filename', filename) or is_whitelisted('filetype', mimetype):
					log.info("Skipped whitelisted observable file: {0}".format(filename))
					wsl.emit_info("Skipped whitelisted observable file: {0}".format(filename))
				else:
					inmem_file = io.BytesIO(part.get_payload(decode=1))
					attachments.append((inmem_file, filename))
					log.info("Found observable file: {0}".format(filename))
					wsl.emit_info("Found observable file: {0}".format(filename))
					# Calculate the hash of the just found attachment
					sha256 = hashlib.sha256()
					sha256.update(part.get_payload(decode=1))
					hash_attachment = {}
					hash_attachment['hashValue'] = sha256.hexdigest()
					hash_attachment['hashedAttachment'] = filename
					if is_whitelisted('hash', hash_attachment['hashValue']):
						log.info("Skipped whitelisted observable hash: {0}".format(hash_attachment['hashValue']))
						wsl.emit_info("Skipped whitelisted observable hash: {0}".format(hash_attachment['hashValue']))
					else:
						hashes_attachments.append(hash_attachment)
						log.info("Found observable hash {0} calculated from file: {1}".format(hash_attachment['hashValue'], filename))
						wsl.emit_info("Found observable hash {0} calculated from file: {1}".format(hash_attachment['hashValue'], filename))

	# Create a tuple containing the eml file and the name it should have as an observable
	filename = subject_field + ".eml"
	inmem_file = io.BytesIO()
	gen = email.generator.BytesGenerator(inmem_file)
	gen.flatten(internal_msg)
	eml_file_tuple = (inmem_file, filename)

	# Workaround to prevent HTML tags to appear inside the URLs (splits on < or >)
	for observable_body in observables_body:
		if observable_body['type'] == "url":
			observable_body['value'] = observable_body['value'].replace(">", "<").split("<")[0]

	return subject_field, observables_header, observables_body, attachments, hashes_attachments, eml_file_tuple


# Create the case on TheHive and add the observables to it
def create_case(subject_field, observables_header, observables_body, attachments, hashes_attachments, eml_file_tuple, wsl):

	# Create the case template first if it does not exist
	if(len(api_thehive.find_case_templates(query = thehive4py.query.Eq("name", 'ThePhish')).json())) == 0:
		task_notification = thehive4py.models.CaseTask(title = 'ThePhish notification')
		task_analysis = thehive4py.models.CaseTask(title = 'ThePhish analysis')
		task_result = thehive4py.models.CaseTask(title = 'ThePhish result')
		case_template = thehive4py.models.CaseTemplate(name		= 'ThePhish',
													   titlePrefix = '[ThePhish] ',
													   tasks	   = [task_notification, task_analysis, task_result])
		response = api_thehive.create_case_template(case_template)
		if response.status_code == 201:
			log.info('Template ThePhish created successfully')
			wsl.emit_info('Template ThePhish created successfully')
		else:
			log.error('Cannot create template: {0} ({1})'.format(response.status_code, response.text))
			wsl.emit_error('Cannot create template: {0} ({1})'.format(response.status_code, response.text))
			return 

	
	# Create the case on TheHive
	# The emojis are removed to prevent problems when exporting the case to MISP
	case = thehive4py.models.Case(title		= emoji.replace_emoji(subject_field),
				tlp		  = int(config['caseTLP']), 
				pap		  = int(config['casePAP']),
				flag		 = False,
				tags		 = config['caseTags'],
				description  = 'Case created automatically by ThePhish',
				template	 = 'ThePhish')
	response = api_thehive.create_case(case)
	if response.status_code == 201:
		new_case = response
		new_id = new_case.json()['id']
		new_case_id = new_case.json()['caseId']
		log.info('Created case {}'.format(new_case_id))
		wsl.emit_info('Created case {}'.format(new_case_id))

		# Add observables found in the mail header
		for header_field in observables_header:
			for observable_header in observables_header[header_field]:
				observable = thehive4py.models.CaseObservable(
					dataType = observable_header['type'],
					data	 = observable_header['value'],
					ioc	  = False,
					tags	 = ['email', 'email_header', 'email_header_{}'.format(header_field)],
					message  = 'Found in the {} field of the email header'.format(header_field)
					)
				response = api_thehive.create_case_observable(new_id, observable)
				if response.status_code == 201:
					log.info('Added observable {0}: {1} to case {2}'.format(observable_header['type'], observable_header['value'], new_case_id))
					wsl.emit_info('Added observable {0}: {1} to case {2}'.format(observable_header['type'], observable_header['value'], new_case_id))
				else:
					log.debug('Cannot add observable {0}: {1} - {2} ({3})'.format(observable_header['type'], observable_header['value'], response.status_code, response.text))

		# Add observables found in the mail body
		for observable_body in observables_body:
			observable = thehive4py.models.CaseObservable(
				dataType = observable_body['type'],
				data	 = observable_body['value'],
				ioc	  = False,
				tags	 = ['email', 'email_body'],
				message  = 'Found in the email body'
				)
			response = api_thehive.create_case_observable(new_id, observable)
			if response.status_code == 201:
				log.info('Added observable {0}: {1} to case {2}'.format(observable_body['type'], observable_body['value'], new_case_id))
				wsl.emit_info('Added observable {0}: {1} to case {2}'.format(observable_body['type'], observable_body['value'], new_case_id))
			else:
				log.debug('Cannot add observable {0}: {1} - {2} ({3})'.format(observable_body['type'], observable_body['value'], response.status_code, response.text))

		# Add attachments
		for attachment in attachments:
			observable = thehive4py.models.CaseObservable(
				dataType='file',
				data	= attachment,
				ioc	 = False,
				tags	= ['email', 'email_attachment'],
				message = 'Found as email attachment'
				)
			response = api_thehive.create_case_observable(new_id, observable)
			if response.status_code == 201:
				log.info('Added observable file {0} to case {1}'.format(attachment[1], new_case_id))
				wsl.emit_info('Added observable file {0} to case {1}'.format(attachment[1], new_case_id))
			else:
				log.debug('Cannot add observable: file {0} - {1} ({2})'.format(attachment[1], response.status_code, response.text))

		# Add hashes of the attachments
		for hash_attachment in hashes_attachments:
			observable = thehive4py.models.CaseObservable(
				dataType = 'hash',
				data	 = hash_attachment['hashValue'],
				ioc	  = False,
				tags	 = ['email', 'email_attachment_hash'],
				message  = 'Hash of attachment "{}"'.format(hash_attachment['hashedAttachment'])
				)
			response = api_thehive.create_case_observable(new_id, observable)
			if response.status_code == 201:
				log.info('Added observable hash: {0} to case {1}'.format(hash_attachment['hashValue'], new_case_id))
				wsl.emit_info('Added observable hash: {0} to case {1}'.format(hash_attachment['hashValue'], new_case_id))
			else:
				log.debug('Cannot add observable hash: {0} - {1} ({2})'.format(hash_attachment['hashValue'], response.status_code, response.text))

		# Add eml file (using the tuple)
		if eml_file_tuple:
			observable = thehive4py.models.CaseObservable(
				dataType='file',
				data	= eml_file_tuple,
				ioc	 = False,
				tags	= ['email', 'email_sample'],
				message = 'Attached email in eml format'
				)
			response = api_thehive.create_case_observable(new_id, observable)
			if response.status_code == 201:
				log.info('Added observable file {0} to case {1}'.format(eml_file_tuple[1], new_case_id))
				wsl.emit_info('Added observable file {0} to case {1}'.format(eml_file_tuple[1], new_case_id))
			else:
				log.debug('Cannot add observable: file {0} - {1} ({2})'.format(eml_file_tuple[1], response.status_code, response.text))

	else:
		log.error('Cannot create case: {0} ({1})'.format(response.status_code, response.text))
		wsl.emit_error('Cannot create case: {0} ({1})'.format(response.status_code, response.text))
		return
	
	# Return the id of the just created case on which to run the analysis
	return new_case

# Main function called from outside 
# The wsl is not a global variable to support multiple tabs 
def main(wsl, mail_uid):

	global config
	global whitelist
	global log
	global api_thehive

	# Logging configuration
	try:
		with open('logging_conf.json') as log_conf:
			log_conf_dict = json.load(log_conf)
			logging.config.dictConfig(log_conf_dict)
	except Exception as e: 
		print("[ERROR]_[list_emails]: Error while trying to open the file 'logging_conf.json'. It cannot be read or it is not valid: {}".format(traceback.format_exc()))
		return 
	log = logging.getLogger(__name__)

	try:
		with open('configuration.json') as conf_file:
			conf_dict = json.load(conf_file)
			
			# IMAP configuration
			config['imapHost'] = conf_dict['imap']['host']
			config['imapPort'] = int(conf_dict['imap']['port'])
			config['imapUser'] = conf_dict['imap']['user']
			config['imapPassword'] = conf_dict['imap']['password']
			config['imapFolder'] = conf_dict['imap']['folder']

			# TheHive configuration
			config['thehiveURL'] = conf_dict['thehive']['url']
			config['thehiveApiKey'] = conf_dict['thehive']['apikey']

			# New case configuration
			config['caseTLP'] = conf_dict['case']['tlp']
			config['casePAP'] = conf_dict['case']['pap']
			config['caseTags'] = conf_dict['case']['tags']

	except Exception as e: 
		log.error("Error while trying to open the file 'configuration.json': {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to open the file 'configuration.json'")
		return

	# Read the whitelist file, which is composed by various parts:
	# - The exact matching part
	# - The regex matching part
	# - Three lists of domains that are used to whitelist subdomains, URLs and email addresses that contain them
	try:
		with open('whitelist.json') as whitelist_file:
			whitelist_dict = json.load(whitelist_file)
			whitelist['mailExact'] = whitelist_dict['exactMatching']['mail']
			whitelist['mailRegex'] = whitelist_dict['regexMatching']['mail']
			whitelist['ipExact'] = whitelist_dict['exactMatching']['ip']
			whitelist['ipRegex'] = whitelist_dict['regexMatching']['ip']
			whitelist['domainExact'] = whitelist_dict['exactMatching']['domain']
			whitelist['domainRegex'] = whitelist_dict['regexMatching']['domain']
			whitelist['urlExact'] = whitelist_dict['exactMatching']['url']
			whitelist['urlRegex'] = whitelist_dict['regexMatching']['url']
			whitelist['filenameExact'] = whitelist_dict['exactMatching']['filename']
			whitelist['filenameRegex'] = whitelist_dict['regexMatching']['filename']
			whitelist['filetypeExact'] = whitelist_dict['exactMatching']['filetype']
			whitelist['hashExact'] = whitelist_dict['exactMatching']['hash']

			# The domains in the last three lists are used to create three lists of regular expressions that serve to whitelist subdomains, URLs and email addresses based on those domains
			whitelist['regexDomainsInSubdomains'] = [r'^(.+\.|){0}$'.format(domain.replace(r'.', r'\.')) for domain in whitelist_dict['domainsInSubdomains']]
			whitelist['regexDomainsInURLs'] = [r'^(http|https):\/\/([^\/]+\.|){0}(\/.*|\?.*|\#.*|)$'.format(domain.replace(r'.', r'\.')) for domain in whitelist_dict['domainsInURLs']]
			whitelist['regexDomainsInEmails'] = [r'^.+@(.+\.|){0}$'.format(domain.replace(r'.', r'\.')) for domain in whitelist_dict['domainsInEmails']]
	
	except Exception as e: 
		log.error("Error while trying to open the file 'whitelist.json': {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to open the file 'whitelist.json'")
		return

	# Object needed to use TheHive4py
	api_thehive = thehive4py.api.TheHiveApi(config['thehiveURL'], config['thehiveApiKey'])

	# Connect to IMAP server
	try:
		connection = connect_to_IMAP_server(wsl)
	except Exception as e:
		log.error("Error while trying to connect to IMAP server: {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to connect to IMAP server")
		return

	# Call the obtain_eml function
	try:
		internal_msg, external_from_field = obtain_eml(connection, mail_uid, wsl)
	except Exception as e:
		log.error("Error while trying to obtain the internal eml file: {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to obtain the internal eml file")
		return

	# Call the parse_eml function
	try:
		subject_field, observables_header, observables_body, attachments, hashes_attachments, eml_file_tuple = parse_eml(internal_msg, wsl)
	except Exception as e:
		log.error("Error while trying to parse the internal eml file: {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to parse the internal eml file")
		return

	# Call the create_case function
	try:
		new_case = create_case(subject_field, observables_header, observables_body, attachments, hashes_attachments, eml_file_tuple, wsl)
	except Exception as e:
		log.error("Error while trying to create the case: {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to create the case")
		return

	return new_case, external_from_field