#!/usr/bin/python
import sys
import re
import getpass
from os.path import expanduser
try:
	import xml.etree.ElementTree as ET
except ImportError:
	print "[x] ERROR: Cannot find ElementTree. Please install it"
	exit()
try:
	import gnupg
except ImportError:
	print "[x] ERROR: Cannot find python-gnupg. Please install it"
	exit()

USAGE = '''
Usage: {0} <file> <command> [param]
Commands available:
list:		list all available account by name
search <what>:	search <what> account name
add <what>:	add <what> account name
del <what>:	delete <what> account name
mod <what>:	modify <what> account name
dump:		dump file content in plain text
'''

INIT_GPG = ""
CRYPTFILE = ""
COMMAND = ""
# get user home directory in which .gnupg resides
HOMEDIR = expanduser("~") + "/.gnupg"
# change this to False to disable GPG agent feature
USEAGENT=True
# specify the email address key to encrypt CRYPTFILE
EMAIL = ""


def warn_print(s):
	print "[!] WARNINIG: {0}".format(s)

def error_print(s):
	print "[x] ERROR: {0}".format(s)

def fancy_print(s):
	print "[*] {0}".format(s)

def account_print(ac):
	user = ""
	passwd = ""
	url = ""
	extra = ""
	name = ac.get('name')
	if ac.find('username') is not None:
		user = ac.find('username').text
	if ac.find('password') is not None:
		passwd = ac.find('password').text
	if ac.find('url') is not None:
		url = ac.find('url').text
	if ac.find('extra') is not None:
		extra = ac.find('extra').text

	fancy_print("Account name: {0}".format(name))
	if user:
		fancy_print("Username: {0}".format(user))
	if passwd:
		fancy_print("Password: {0}".format(passwd))
	if url:
		fancy_print("URL: {0}".format(url))
	if extra:
		fancy_print("Extra: {0}".format(extra))
	print

def init_gpg():
	global INIT_GPG
	global COMMAND
	global EMAIL

	INIT_GPG = gnupg.GPG(gnupghome=HOMEDIR,use_agent=USEAGENT)
	try:
		f = open(CRYPTFILE, 'r')
	except IOError:
		return False

	enc_data = f.read()
	if USEAGENT is False:
		dec_data = INIT_GPG.decrypt(enc_data,passphrase=getpass.getpass("Password to decrypt: "))
	else:
		dec_data = INIT_GPG.decrypt(enc_data)
	f.close()
	EMAIL = extract_email(dec_data.stderr)
	return dec_data

def dump_content():
	d_data = init_gpg()
	if d_data is False:
		error_print("File doesn't exist!")
	else:
		tree = ET.ElementTree(ET.fromstring(d_data.data))
		ET.dump(tree.getroot())

def encrypt_tree(r):
	enc_d = INIT_GPG.encrypt(ET.tostring(r),EMAIL,armor=False)
	if enc_d.ok is False:
		print enc_d.stderr
		return False
	return enc_d.data

def get_accounts(f):
	tree = ET.ElementTree(ET.fromstring(f))
	root = tree.getroot()
	return root.findall('account')

def  extract_email(d):
	if EMAIL is not None:
		# 'd' is data.stderr
		regex = re.compile(("([a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`"
			"{|}~-]+)*(@|\sat\s)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(\.|"
			"\sdot\s))+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)"))
		# re.findall() returns two email address: USER_HINT and
		# who encrypt the key, who is the second item.
		return re.findall(regex, d)[1][0]
	return EMAIL

def write_enc_file(root):
	global EMAIL
	em = raw_input("Which key to you want to use [{0}]: ".format(EMAIL))
	if len(em) > 0 and em is not EMAIL:
		EMAIL = em

	e = encrypt_tree(root)
	if e is False:
		error_print("Cannot encrypt data!")
		return False
	f = open(CRYPTFILE,'w+')
	f.write(e)
	f.close()
	return True

def list_accounts(f):
	for account in get_accounts(f):
		account_print(account)

def destroy_account(d, s):
	tree = ET.ElementTree(ET.fromstring(d))
	root = tree.getroot()
	for ac in root.findall('account'):
		# warning! if two accounts have the same 'name'
		# only one will be removed!
		# Need some checks :)
		if re.search(s, ac.get('name')):
			root.remove(ac)
			return root
	return False

def modify_account(d, s):
	tree = ET.ElementTree(ET.fromstring(d))
	root = tree.getroot()
	for ac in root.findall('account'):
		if re.search(s, ac.get('name')):
			new = create_account(ac.get('name'), ac)
			if new is not False:
				root.remove(ac)
				root.append(new)
				return root
			else:
				return False
	return False

def create_account(a, d):
	user = ""
	passwd = ""
	url = ""
	extra = ""
	new_account = ET.Element("account", {'name': a })
	if d is not None:
		if d.find('username') is not None:
			user = d.find('username').text
		if d.find('password') is not None:
			passwd = d.find('password').text
		if d.find('url') is not None:
			url = d.find('url').text
		if d.find('extra') is not None:
			extra = d.find('extra').text
		
	text = raw_input("Enter an username [{0}]: ".format(user))
	if not text:
		warn_print("You didn't insert any username")
	else:
		user = ET.SubElement(new_account, "username")
		user.text = text

	text = raw_input("Enter a password or passhprase [{0}]: ".format(passwd))
	if not text:
		warn_print("You didn't insert any password")
	else:
		passwd = ET.SubElement(new_account, "password")
		passwd.text = text
	text = raw_input("Enter an URL associated to login [{0}]: ".format(url))
	if not text:
		warn_print("You didn't insert any URL")
	else:
		url = ET.SubElement(new_account,"url")
		url.text = text
	text = raw_input("Enter extra text [{0}]: ".format(extra))
	if text:
		extra = ET.SubElement(new_account, "extra")
		extra.text = text
	
	if len(user) > 0 and len(passwd) > 0 and len(url) > 0 and len(extra) > 0 :
		return False
	return new_account

def find_account(d,s):
	ac_list = []
	for ac in get_accounts(d):
		if re.search(s, ac.get('name')): 
			ac_list.append(ac)
	if len(ac_list) == 0:
		return False
	return ac_list

def search_account(s):
	d_data = init_gpg()
	if d_data is False:
		error_print("File doesn't exist!")
		return False

	if d_data.ok is False:
		print d_data.stderr
		return False
	# now 'ac' is typeof list
	acs = find_account(d_data.data,s)
	if acs is not False:
		for ac in acs:
			account_print(ac)
	else:
		return False

	return True

def add_account(a):
	# first, create new node
	if search_account(a) is True:
		warn_print("Account name already exits!")
		return False

	acc = create_account(a, None)
	if acc is False:
		error_print("Cannot create empty account!")
		return False;
	# second, decrypt the old file
	d_data = init_gpg()
	if d_data is False:
		warn_print("File doesn't exist! Will be created...")
		root = ET.Element('accounts')
	elif d_data.ok is False:
		print d_data.stderr
		return False
	else:
		tree = ET.ElementTree(ET.fromstring(d_data.data))
		root = tree.getroot()

	root.append(acc)
	return write_enc_file(root)

def del_account(a):
	d_data = init_gpg()
	if d_data is False:
		error_print("File doesn't exist!")
		return False
	if d_data.ok is False:
		print d_data.stderr
		return False
	new_data = destroy_account(d_data.data, a)
	if new_data is False:
		error_print("Account not found!")
		return False
	return write_enc_file(new_data)

def mod_account(a):
	d_data = init_gpg()
	if d_data is False:
		error_print("File doesn't exist!")
		return False
	if d_data.ok is False:
		print d_data.stderr
		return False
	new_d = modify_account(d_data.data, a)
	if new_d is False:
		return False
	return write_enc_file(new_d)

if len(sys.argv) < 3:
	print USAGE.format(sys.argv[0])
	exit()

CRYPTFILE = sys.argv[1]
COMMAND = sys.argv[2]

if COMMAND == "list":
	d_data = init_gpg()
	if d_data is False:
		error_print("File doesn't exist!")
		exit()
	if d_data.ok is False:
		print d_data.stderr
		exit()
	list_accounts(d_data.data)
elif COMMAND == "search":
	if len(sys.argv) < 4:
		print USAGE.format(sys.argv[0])
		error_print("Type a search string!")
		exit()
	s_key = sys.argv[3]
	if search_account(s_key) is False:
		error_print("Account not found!")
	exit()
elif COMMAND == "add":
	if len(sys.argv) < 4:
		print USAGE.format(sys.argv[0])
		error_print("Specify an account name!")
		exit()
	a_name = sys.argv[3]
	if add_account(a_name) is True:
		fancy_print("Account added!")
	else:
		error_print("Account not added!")
	exit()
elif COMMAND == "del":
	if len(sys.argv) < 4:
		print USAGE.format(sys.argv[0])
		error_print("Specify an account name!")
		exit()
	d_name = sys.argv[3]
	if del_account(d_name) is True:
		fancy_print("Account deleted!")
	else:
		error_print("Account not deleted!")
	exit()
elif COMMAND == "mod":
	if len(sys.argv) < 4:
		print USAGE.format(sys.argv[0])
		error_print("Specify an account name!")
		exit()
	d_name = sys.argv[3]
	if mod_account(d_name) is True:
		fancy_print("Account successfully modified!")
	else:
		error_print("Account not modified!")
	exit()
elif COMMAND == "dump":
	dump_content()
	exit()
else:
	print USAGE.format(sys.argv[0])
	error_print("Command not found!")
	exit()
