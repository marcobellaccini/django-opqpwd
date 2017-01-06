=====
opqpwd
=====

opqpwd is a password manager REST service with client-side encryption.
It uses Django and Django REST framework.

opqpwd stands for "opaque passwords": it encrypts password on the client-side,
making them "opaque" to the server.
Moreover, user registration and authentication is performed using salted hashes
of user-chosen username and password:
this boosts users anonimity with respect to traditional services, hiding even 
the service-registration username.

Passwords (and metadata) are stored in your favorite database as Base64-encoded, 
encrypted JSON.
Encryption is performed using AES-256-CBC, with HMAC-SHA-256 authentication.
scrypt is used as key derivation function.

It features an example command-line client (you can find it in 
the bin folder).

opqpwd was written by Marco Bellaccini - marco.bellaccini(at!)gmail.com.

BEWARE: OPQPWD IS PROOF-OF-CONCEPT SOFTWARE, FOR TESTING PURPOSES ONLY.

Quick start
-----------

1.  Make sure you meet all software dependencies (Django REST Framework, 
    scrypt, pycrypto, requests and, of course, Django).

2.  Add "opqpwd" and "rest_framework" (of course, you have to install 
    Django REST Framework too!) to your INSTALLED_APPS setting like this::

     INSTALLED_APPS = [
         ...
         'rest_framework',
         'opqpwd',
     ]

3.  Include the opqpwd URLconf in your project urls.py like this::

     url(r'^', include('opqpwd.urls')),

4.  Run `python manage.py migrate` to create the opqpwd models.

5.  Start the development server (BEWARE: in a real environment you should run 
    it over https, however, as already stated, THIS IS A PROOF-OF-CONCEPT 
    SOFTWARE, FOR TESTING PURPOSES ONLY).

6.  Start the cli-client script::
    opqpwdcliclient

    Note: if you installed the package as a user library, the script will
    likely be in '.local/bin' in your home folder

7.  Connect to the development server::
    connect http://127.0.0.1:8000

8.  Register a user::
    adduser
    (if you want, you can also generate an authentication token to use along 
    with the password)

9.  Login::
    login

10. Add a password to the db::
    addpassword

11. List all stored passwords titles::
    printall

12. Print details of the password you just stored::
    print 1

13. Upload encrypted passwords to the server::
    save

14. Get help with the other commands::
    help