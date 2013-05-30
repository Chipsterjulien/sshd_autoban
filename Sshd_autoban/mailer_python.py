#!/usr/bin/env python3
# -*- coding: utf-8 -*-


__author__           = "Julien Freyermuth"
__copyright__        = "Copyright (c) 2013, Julien Freyermuth"
__license__          = "GPL v3"
__version__          = "0.2"
__description__      = "Script who sent email with gmail (or other)"


# ** Changelop
#
#    v0.2 - Adding config file
#         - Adding subprocess to find abuse mail
#         - Solve some bugs
#
#    v0.1 - Create this script
# **


import os, sys, smtplib, logging, yaml, subprocess, datetime
from email.mime.text import MIMEText

logging.basicConfig(filename='/var/log/sshd_autoban/error_mail.log',format='%(asctime)s %(message)s',level=logging.DEBUG)

# Chargement du fichier de configuration
data = None
try:
	file_yaml = open('/etc/sshd_autoban/sshd_autoban.conf', 'r')
	data      = yaml.safe_load(file_yaml.read())
	file_yaml.close()

except yaml.parser.ParserError as e:
	print("Unable to load configuration. Mistake : \"%s\"\nVerify you have start systemd-journal-gatewayd.service" %(e))
	logging.critical("Unable to load configuration. Mistake : \"%s\"\nVerify you have start systemd-journal-gatewayd.service" %(e))
	sys.exit(2)

if not data:
	print("\"%s\" is an empty file !" % (conf))
	logging.critical("\"%s\" is an empty file !" %(conf))
	sys.exit(2)

# On va forker
try:
	pid = os.fork()
	if pid > 0:
		sys.exit(0)

except OSError as e:
	logging.critical("Unable to fork ! %s, %d" %(e.strerror, e.errno))
	sys.exit(1)

os.chdir("/")
os.setsid()
os.umask(0)

try:
	pid = os.fork()
	if pid > 0:
		sys.exit(0)

except OSError as e:
	logging.critical("Unable to fork ! %s, %d" %(e.strerror, e.errno))
	sys.exit(1)

ip  = sys.argv[1]
out = subprocess.getoutput('whois %s' %(ip)).split('\n')
to  = None

for line in out:
	if 'abuse'in line:
		for word in line.split(' '):
			if '@' in word:
				to = word
				break
		break

if to == None:
	logging.info("There aren't abuse email for the IP \"%s\" !" %(ip))

From = data['email']
text = "Hello.\n\nHours utc : %s\n\nI inform you that following the ip \"%s\" address has been used a few seconds ago to attack my computer.\nThank you for making the necessary\n\nBest regards\nJulien" % (datetime.datetime.utcnow(), ip)
msg  = MIMEText(text, 'plain', 'utf-8')
msg['Subject'] = "Your IP \"%s\" attacked my computer" %(ip)
msg['From']    = From

try:
	server = None
	if data['ssl']:
		server = smtplib.SMTP_SSL(data['smtp'], data['port'])
	elif data['ssl'] == False:
		server = smtplib.SMTP(data['smtp'], data['port'])
	else:
		logging.critical('ssl option unknown in config file')
		sys.exit(2)

	server.set_debuglevel(False)
	server.ehlo
	server.login(data['login'], data['password'])
	try:
		server.sendmail(From, to, msg.as_string())
	finally:
		server.quit()

	logging.info("Mail where send to \"%s\"" %(to))

except Exception as e:
	logging.error("Unable to send a mail; %s" % (str(e)))
	sys.exit(2)
