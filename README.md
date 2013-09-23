** PYGPMANAGER: PYthon Gpg Password MANAGER

pygpmanager is a simple python script to manager custom-crafted XML encrypted password file.
It reads, parses and writes an XML file with the following structure:

<accounts>
	<account name="test01">
		<username>user01</username>
		<password>passwd01</password>
		<url>http://site.com/login</url>
		<extra>additional notes</extra>
	</account>
</accounts>

then it encrypts it with GnuPG.

** REQUIREMENTS
Python - use your packet manager to install it or compile from source
GnuPG - pip install python-gnupg
ElementTre - pip install elementtree

If you don't have pip installed...install it NAO! :)

** USAGE
$ python pygpmanager.py 
Usage: pygpmanager.py <file> <command> [param]
Commands available:
list:		list all available account by name
search <what>:	search <what> account name
add <what>:	add <what> account name
del <what>:	delete <what> account name
dump:		dump file content in plain text

$ python pygpmanager.py passfile list
[*] Account name: test01
[*] Username: user01
[*] Password: password01
[*] URL: myloginpage.com

[*] Account name: testa account 02
[*] Username: usernametest
[*] Password: mypassword
[*] URL: http://site.to.login

