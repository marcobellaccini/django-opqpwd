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

from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64encode, b64decode
import scrypt

# PKCS #7 padding
def pkcs7pad(data):
    length = 16 - (len(data) % 16)
    data += bytes([length])*length
    return data

# PKCS #7 unpadding
def unpkcs7pad(data):
    data = data[:-data[-1]]
    return data

# run scrypt key derivation function to generate 32 bytes of key
def scrypt32(data, salt):
    return scrypt.hash(data, salt, N=16384, r=8, p=1, buflen=32)
    
# convert to utf8 Base64
def toB64(data):
    return b64encode(data).decode("utf-8")
    
# convert from utf8 Base64 to bytes
def fromB64(data):
    return b64decode(data)

# function to encrypt and authenticate data
# it uses AES256-CBC to encrypt, HMAC-SHA256 to authenticate,
# and scrypt to derive keys from password and salts
# internal random key is generated with pycrypto prng
# input:
# ptext - plaintext input data
# password - password
# salthmac - salt to use to derive the HMAC key from password
# saltenc - salt to use to derive the encryption key from password

def encAuth(ptext, password, salthmac, saltenc):
    assert salthmac != saltenc, "You should use different salts for hmac and encryption"
    
    # initialize random number generator
    # using pycrypto cryptographic PRNG (based on "Fortuna" by N. Ferguson 
    # and B. Schneier, with the OS RNG, time.clock() and time.time() as
    # entropy sources)
    rng = Random.new()

    # generate a 32 bytes random key for encryption
    rndkey_for_enc = rng.read(32)
    
    # generate a 32 bytes random key for authentication
    rndkey_for_hmac = rng.read(32)
    
    # authenticate plaintext
    hmac0 = HMAC.new(rndkey_for_hmac, digestmod=SHA256)
    hmac0.update(ptext)
    hmac0_h = hmac0.digest()
    
    # encrypt plaintext and its hmac
    iv0 = rng.read(16)
    cipher0 = AES.new(rndkey_for_enc, AES.MODE_CBC, iv0)
    ctext0 = cipher0.encrypt(pkcs7pad(ptext + hmac0_h))

    # derive keys to encrypt and authenticate the random keys and the internal IV  
    key_hmac_rnd = scrypt32(password, salthmac)
    key_enc_rnd = scrypt32(password, saltenc)
    
    # authenticate the random keys and the internal IV
    hmac1 = HMAC.new(key_hmac_rnd, digestmod=SHA256)
    hmac1.update(rndkey_for_enc + rndkey_for_hmac + iv0)
    hmac1_h = hmac1.digest()
    
    # encrypt the random keys, the internal IV and their hmac
    iv1 = rng.read(16)
    cipher1 = AES.new(key_enc_rnd, AES.MODE_CBC, iv1)
    ctext1 = cipher1.encrypt(pkcs7pad(rndkey_for_enc + rndkey_for_hmac + iv0 + hmac1_h))
    
    # return the result
    # i.e.: the concatenation of external iv, encrypted keys and encrypted plaintext
    return iv1 + ctext1 + ctext0
    
# function to decrypt and authenticate data encrypted using encAuth
def decAuth(ctext, password, salthmac, saltenc):
    assert len(ctext) >= 176, "Ciphertext is too short"
    
    # derive keys to decrypt and authenticate the random keys and the internal IV  
    key_hmac_rnd = scrypt32(password, salthmac)
    key_enc_rnd = scrypt32(password, saltenc)
    
    # get the external IV
    iv1 = ctext[:16]
    
    # get the encrypted keys and internal iv
    ctext1 = ctext[16:144]
    
    # get the encrypted plaintext
    ctext0 = ctext[144:]
    
    # decrypt the random keys and the internal IV
    cipher1 = AES.new(key_enc_rnd, AES.MODE_CBC, iv1)
    ptext1 = unpkcs7pad(cipher1.decrypt(ctext1))
    
    # get the random keys, the internal IV and the hmac
    rndkey_for_enc = ptext1[:32]
    rndkey_for_hmac = ptext1[32:64]
    iv0 = ptext1[64:80]
    exp_hmac1_h = ptext1[80:]
    
    # check the external hmac
    hmac1 = HMAC.new(key_hmac_rnd, digestmod=SHA256)
    hmac1.update(rndkey_for_enc + rndkey_for_hmac + iv0)
    hmac1_h = hmac1.digest()
    assert exp_hmac1_h == hmac1_h, "Wrong password or data is corrupted (bad external HMAC)."
    
    # decrypt the encrypted plaintext
    cipher0 = AES.new(rndkey_for_enc, AES.MODE_CBC, iv0)
    ptext0 = unpkcs7pad(cipher0.decrypt(ctext0))
    
    # get the plaintext and its hmac
    ptext = ptext0[:-32]
    exp_hmac0_h = ptext0[-32:]
    
    # check the internal hmac
    hmac0 = HMAC.new(rndkey_for_hmac, digestmod=SHA256)
    hmac0.update(ptext)
    hmac0_h = hmac0.digest()
    assert exp_hmac0_h == hmac0_h, "Data is corrupted: bad internal HMAC."
    
    # return the plaintext
    return ptext
