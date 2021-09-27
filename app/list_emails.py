import logging.config
import imaplib
import json
import email
import base64
import traceback
import bs4
import magic

# Global variable used for logging
log = None

# Global variable used for the configuration
config = {}


def connect_to_IMAP_server():
	# Create the connection to the IMAP server using host and port
	connection = imaplib.IMAP4_SSL(config['imapHost'], config['imapPort'])
	# Log in using username and password
	connection.login(config['imapUser'], config['imapPassword'])
	log.info('Connected to {0}@{1}:{2}/{3}'.format(config['imapUser'], config['imapHost'], config['imapPort'], config['imapFolder']))
	return connection

# Fetch all the unread emails in the specified folder that have an EML attachment and return their information
def retrieve_emails(connection):
	# Read all the unseen email from this folder
	connection.select(config['imapFolder'])
	typ, dat = connection.search(None, '(UNSEEN)')
	# The dat[0] variable contains the IDs of all the unread emails
	# The IDs are obtained by using the split function and the length of the array is the number of unread emails
	new_emails = len(dat[0].split())
	log.info("{} unread messages to process".format(new_emails))

	# Variable that will contain the information related to the unread emails to show on the web interface
	emails_info = []

	# For each ID (unread email) in dat[0] select the RFC822 message 
	for num in dat[0].split():
		typ, dat = connection.fetch(num, '(RFC822)')
		if typ != 'OK':
			log.error(dat[-1])
		message = dat[0][1]

		# When an email is read (fetched), it is flagged as seen
		# To prevent that, it is flagged again as unseen by removing the seen flag
		# That is because the email must be fetched again during the case creation procedure
		connection.store(num, '-FLAGS', '\\Seen')

		# Obtain the Subject and From fields of the email 
		msg = email.message_from_bytes(message)
		decode = email.header.decode_header(msg['From'])[-1]
		if decode[1] is not None:
			from_field = decode[0].decode(decode[1])
		else:
			from_field = str(decode[0])
		decode = email.header.decode_header(msg['Subject'])[-1]
		if decode[1] is not None:
			subject_field = decode[0].decode(decode[1])
		else:
			subject_field = str(decode[0])
		log.info("Message from: {0} with subject: {1}".format(from_field, subject_field))

		# This will contain the body of the email
		body = None

		# True if an EML attachment is found for the current email
		eml_attachment_found = False

		# True if there is a text/plain part in the email multipart structure
		is_there_text = False

		# Walk the multipart structure of the email
		# If there is a text/plain part, set the corresponding variable to True
		# However, if that text/plain part is found after the message/rfc822, then it is the text/plain part of the EML attachment and must not be considered
		for part in msg.walk():
			if part.get_content_type() == "text/plain":
				is_there_text = True
			elif part.get_content_type() == "message/rfc822":
				break

		# This will contain the Subject field of the email 
		attached_mail_subject = ''

		# Walk the multipart structure of the email again
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
					# Use the magic module to obtain the mimetype after the decoding procedure
					# If it was octet-stream before the decode, it must become rfc/822, else that means that it was not an EML attachment and must be ignored
					if magic.from_buffer(eml_payload, mime=True) not in ['text/plain', 'message/rfc822']:
						continue
				elif mimetype == 'message/rfc822':
					eml_payload = part.get_payload(decode=0)[0]
					try:
						internal_msg = email.message_from_string(base64.b64decode(str(eml_payload)).decode()) 
					except:
						internal_msg = eml_payload
				
				# Set to true to consider this as an email to include in the list to return to the client
				eml_attachment_found = True

				# Obtain the subject of the internal email
				# This is not straightforward since the subject might be splitted in two or more parts
				decode = email.header.decode_header(internal_msg['Subject'])
				decoded_elements = []
				for decode_elem in decode:
					if decode_elem[1] is not None:
						if str(decode_elem[1]) == 'unknown-8bit':
							decoded_elements.append(decode_elem[0].decode())
						else:
							decoded_elements.append(decode_elem[0].decode(decode_elem[1]))
					else:
						if(isinstance(decode_elem[0], str)):
							decoded_elements.append(str(decode_elem[0]))
						else:
							decoded_elements.append(decode_elem[0].decode())
					attached_mail_subject = ''.join(decoded_elements)
				log.info("Found attached mail with subject: {0} ({1})".format(attached_mail_subject, mimetype))

				# If the EML attachment has been found, then break the for
				break

			# If it is not an EML attachment, then check if it is multipart/mixed, but only if there is no text/plain part before 
			# the EML attachment, because in that case the body will be obtained from the text/plain part
			elif mimetype == "multipart/mixed":
				if is_there_text == False:
					part_payload = part.get_payload()[0]
					# Variabile per vedere se c'e' un text plain in questomultipart mixed (visto che fuori non ci stava)
					# True if there is a text/plain part in this multipart/mixed, since there was no text/plain part before
					is_there_text_in_multipart = False
					# Walk the subparts of this multipart 
					# If there is a text/plain part here, set the corresponding variable to True
					for subpart in part_payload.walk():
						if subpart.get_content_type() == "text/plain":
							is_there_text_in_multipart = True
					# Walk the subparts of this multipart again 
					# If the first part is a text/plain part then use it to populate the body
					# Else, if the first part is text/html and there is a text/plain part, then it will be skipped
					# because the text/plain part might be located after the current text/html part
					# Otherwise, if the first part is text/html and there is no text/plain part, then use it to populate the body
					for subpart in part_payload.walk():
						if subpart.get_content_type() == "text/plain":
							if not body:
								try:
									body = subpart.get_payload(decode=True).decode()
								except UnicodeDecodeError:
									body = subpart.get_payload(decode=True).decode('ISO-8859-1')
						# Use the bs4 module to obtain the text from the text/html part
						elif subpart.get_content_type() == "text/html":
							if is_there_text_in_multipart == False:
								try:
									html = subpart.get_payload(decode=True).decode()
								except UnicodeDecodeError:
									html = subpart.get_payload(decode=True).decode('ISO-8859-1')
								if not body:
									soup = bs4.BeautifulSoup(html, 'html.parser')
									body = soup.body.div.p.span.contents[0]
			# Else if there was a text/plain part outside of the multipart/mixed part, the branch related to the multipart/mixed part is not executed
			# The body will in fact be populated from this text/plain part
			elif mimetype == "text/plain":
				if is_there_text == True:
					if not body:
						try:
							body = part.get_payload(decode=True).decode()
						except UnicodeDecodeError:
							body = part.get_payload(decode=True).decode('ISO-8859-1')
			# If neither a text/plain part nor a multipart/mixed part has been encountered before this text/html part
			# then use it to populate the body using the bs4 module
			elif mimetype == "text/html":
				try:
					html = part.get_payload(decode=True).decode()
				except UnicodeDecodeError:
					html = part.get_payload(decode=True).decode('ISO-8859-1')
				if not body:
					soup = bs4.BeautifulSoup(html, 'html.parser')
					body = soup.body.div.p.span.contents[0] 

		# If there is an eml attachment in this email, then add to the list of emails the information on this email, which are:
		# - UID of the email in the mailbox
		# - From and Subject field of the external email
		# - Arrival date of the external email
		# - Body of the external email
		# - Subject field of the internal email (EML attachment)
		if (eml_attachment_found == True):
			email_info = {}
			email_info['mailUID'] = num.decode()
			email_info['from'] = from_field
			email_info['subject'] = subject_field
			email_info['date'] = msg['Date']
			email_info['body'] = body
			email_info['attachedMail'] = attached_mail_subject

			# Problematic characters substitution
			for key in email_info:
				# single quote
				email_info[key] = email_info[key].encode("unicode-escape").decode().replace(r'\x92', '\'').encode().decode("unicode-escape")
			emails_info.append(email_info)

	return emails_info

# Main function called from outside 
def main():

	global config
	global log
	
	# Logging configuration
	try:
		with open('logging_conf.json') as log_conf:
			log_conf_dict = json.load(log_conf)
			logging.config.dictConfig(log_conf_dict)
	except Exception as e: 
		print("[ERROR]_[list_emails]: Error while trying to open the file 'logging_conf.json'. It cannot be read or it is not valid: {}".format(traceback.format_exc()))
		return 
	log = logging.getLogger(__name__)

	# IMAP configuration
	try:
		with open('configuration.json') as conf_file:
			conf_dict = json.load(conf_file)
			
			# IMAP config
			config['imapHost'] = conf_dict['imap']['host']
			config['imapPort'] = int(conf_dict['imap']['port'])
			config['imapUser'] = conf_dict['imap']['user']
			config['imapPassword'] = conf_dict['imap']['password']
			config['imapFolder'] = conf_dict['imap']['folder']

	except Exception as e: 
		log.error("Error while trying to open the file 'configuration.json': {}".format(traceback.format_exc()))
		return

	# Connect to IMAP server
	try:
		connection = connect_to_IMAP_server()
	except Exception as e:
		log.error("Error while trying to connect to IMAP server: {}".format(traceback.format_exc()))
		return

	# Call the retrieve_emails function
	try:
		emails_info = retrieve_emails(connection)
	except Exception as e:
		log.error("Error while trying to retrieve the emails: {}".format(traceback.format_exc()))
		return
	return emails_info

