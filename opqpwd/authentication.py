#   Copyright 2016 Marco Bellaccini
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from django.contrib.auth.models import User
from opqpwd.models import UserCred, B64REGEX, SCRYPT_KEYLEN_BASE64
from opqpwd.cryptofun import scrypt32, fromB64
import re

# function to check password
def checkPassword(username, password):

    # check if username and password are valid Base64 of the right len
    validB64 = re.compile(B64REGEX)
    if not (validB64.match(username) and validB64.match(password) and len(username)==SCRYPT_KEYLEN_BASE64 and len(password)==SCRYPT_KEYLEN_BASE64):
        return False
    
    # check if user exists
    try:
        user = UserCred.objects.get(husername=username)
    except UserCred.DoesNotExist:
        return False    
    
    # convert password to bytes
    hpassword = fromB64(password)    
    # get salt
    hpassword_salt = fromB64(user.hpassword_salt)
    # get salted password
    hhpassword = scrypt32(hpassword, hpassword_salt)
    # get the expected password for the user
    exp_hpassword = fromB64(user.hpassword)
    if hhpassword == exp_hpassword:
        return True
    return False

class UserCredBackend(object):
    """
    Authenticate against opqpwd user db
    
    """

    def authenticate(self, username=None, password=None):
        if checkPassword(username, password):
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                # Create a new user. There's no need to set a password
                # because only the password from settings.py is checked.
                user = User(username=username)
                #user.is_staff = True
                #user.is_superuser = True
                user.save()
            return user
        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
