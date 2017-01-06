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

from django.db import models
from django.core.validators import RegexValidator
from django.contrib.auth.models import User
from django.dispatch import receiver
from Crypto import Random
from .cryptofun import scrypt32, toB64, fromB64

# number of characters of a 32 bytes scrypt-derived key in Base64 (used for scrypt-encrypted user password)
SCRYPT_KEYLEN_BASE64 = 44

# number of characters for a 32 byte salt in Base64 (used for scrypt-encrypted passwords of users)
SALT_LEN_BASE64 = 44

# number of characters of an encrypted password list in Base64
ENCPASSLIST_LEN = 266924

# Base64 regex
B64REGEX = "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"

class UserCred(models.Model):
    husername = models.CharField(unique=True, max_length=SCRYPT_KEYLEN_BASE64, validators=[RegexValidator(regex=B64REGEX, message='Expecting Base64 string'), RegexValidator(regex='^.{' + str(SCRYPT_KEYLEN_BASE64) + '}$', message='length has to be ' + str(SCRYPT_KEYLEN_BASE64))])
    hpassword = models.CharField(max_length=SCRYPT_KEYLEN_BASE64, validators=[RegexValidator(regex=B64REGEX, message='Expecting Base64 string'), RegexValidator(regex='^.{' + str(SCRYPT_KEYLEN_BASE64) + '}$', message='length has to be ' + str(SCRYPT_KEYLEN_BASE64))])
    hpassword_salt = models.CharField(max_length=SALT_LEN_BASE64, validators=[RegexValidator(regex=B64REGEX, message='Expecting Base64 string'), RegexValidator(regex='^.{' + str(SALT_LEN_BASE64) + '}$', message='length has to be ' + str(SALT_LEN_BASE64))])
    owner = models.OneToOneField('auth.User', related_name='usercred', on_delete=models.CASCADE)

    # override save to deal with the salt
    def save(self, *args, **kwargs):
        # generate random salt
        rng = Random.new()
        hpassword_salt_bytes = rng.read(32)
        # get salted password
        self.hpassword = toB64(scrypt32(fromB64(self.hpassword), hpassword_salt_bytes))
        self.hpassword_salt = toB64(hpassword_salt_bytes)
        # set owner
        try:
            self.owner = User.objects.get(username=self.husername)
        except User.DoesNotExist:
            # Create a new user. There's no need to set a password
            # because only the password from settings.py is checked.
            user = User(username=self.husername)
            #user.is_staff = True
            #user.is_superuser = True
            user.save()
            self.owner = User.objects.get(username=self.husername)
        
        super(UserCred, self).save(*args, **kwargs) # Call the "real" save() method.

    class Meta:
        ordering = ('husername','hpassword','hpassword_salt')

# this deletes the django user associated with the UserCred that was deleted        
@receiver(models.signals.post_delete, sender=UserCred)
def delete_file(sender, instance, *args, **kwargs):
    """ Deletes user from django db on `post_delete` """
    if instance.husername:
        user = User.objects.get(username=instance.husername)
        user.delete()

        
class PasswordData(models.Model):
    encpasslist = models.TextField(max_length=ENCPASSLIST_LEN, validators=[RegexValidator(regex=B64REGEX, message='Expecting Base64 string'), RegexValidator(regex='^.{' + str(ENCPASSLIST_LEN) + '}$', message='length has to be ' + str(ENCPASSLIST_LEN))])
    owner = models.OneToOneField('auth.User', related_name='passworddata', on_delete=models.CASCADE)

    