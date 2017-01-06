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

from opqpwd.cryptofun import encAuth, decAuth, scrypt32, fromB64
import json
import requests
from Crypto import Random
from base64 import b64encode
from math import floor

# salts
husername_salt = "hw3T7&22JOp21nnw.6,hhwjw3Qs=iiwe"
hpassword_salt = "G36jjdb55$$f$-j7GGTssw49dm;jjuec"
encpasslist_hmac_salt = "8lmWhhi6&$mmNG8nv5BYd2::0hqZZff4"
encpasslist_enc_salt = "mp00j(.dbRRvW2285GB0x3mr(nd?982f"  
token_hmac_salt = "pl?dR377/im)dgF4s$-m_swHFLaa5mw0"
token_enc_salt = "i6MMd$%s0c3/mmplJHWM=100dlleRR%f"

PASSLIST_LEN = 200000

# token file format header
token_format_header = bytes("OPQPWDTOKENv001", "utf8")

# function to pad to fixed size
def padthis(sdata, length):
    # convert to  bytes first
    data = bytes(sdata, "utf8")
    al = len(data)
    assert al <= length, "This is too long..."
    padlen = length - al
    return data + padlen*b'\x00'
    
# function to unpad from fixed size
def unpadthis(data):
    return data.decode("utf-8").rstrip("\0")
    
# function that returns an empty string for null input
# returns the input string for non-null input
def nulltoempty(stdata):
    if stdata == None:
        return ""
    return stdata

# function to add new user
def adduser(username, password, baseurl, token=None):
    
    # derive hashed username and password
    husername = scrypt32(username, husername_salt)
    hpassword = scrypt32(password, hpassword_salt)
    
    b64husername = b64encode(husername).decode("utf-8")
    b64hpassword = b64encode(hpassword).decode("utf-8")
    
    # prepare rest request
    data = {"husername" : b64husername,"hpassword" : b64hpassword}
    data_json = json.dumps(data)
    headers = {'Content-type': 'application/json'}

    url = baseurl + '/users/'
    
    # send request to create user
    response = requests.post(url, data=data_json, headers=headers)
    
    if response.status_code != 201:
        return False
        
    # register empty password list for user
    if not save(username, password, list(), baseurl):
        return False
    
    return True
    
# function to delete user
def deluser(username, password, baseurl):
    
    # derive hashed username and password
    husername = scrypt32(username, husername_salt)
    hpassword = scrypt32(password, hpassword_salt)
    
    b64husername = b64encode(husername).decode("utf-8")
    b64hpassword = b64encode(hpassword).decode("utf-8")
    
    # prepare rest request
    headers = {'Content-type': 'application/json'}
    
    # authentication
    auth = requests.auth.HTTPBasicAuth(b64husername, b64hpassword)

    url = baseurl + '/users/' + b64husername + '/'
    
    # send request
    response = requests.delete(url, headers=headers, auth=auth)
    
    if response.status_code != 204:
        print(response.status_code)
        return False
    
    return True

# function to save the password list on the server   
def save(username, password, plist, baseurl):
    # derive hashed username and password
    husername = scrypt32(username, husername_salt)
    hpassword = scrypt32(password, hpassword_salt)
    
    # convert to  Base64
    b64husername = b64encode(husername).decode("utf-8")
    b64hpassword = b64encode(hpassword).decode("utf-8")
    
    # encrypt and authenticate password list
    encpasslist = encAuth(padthis(json.dumps(plist), PASSLIST_LEN), password, encpasslist_hmac_salt, encpasslist_enc_salt)
    b64passlist = b64encode(encpasslist).decode("utf-8")
    
    # prepare rest request
    data = {"encpasslist" : b64passlist}
    data_json = json.dumps(data)
    headers = {'Content-type': 'application/json'}
    
    # authentication
    auth = requests.auth.HTTPBasicAuth(b64husername, b64hpassword)

    url = baseurl + '/password/' + b64husername + '/'
    
    # send request
    response = requests.put(url, data=data_json, headers=headers, auth=auth)
    
    if response.status_code != 200:
        return False
    
    return True

    
# function to get the password list of a user
def getpasswordlist(username, password, baseurl):
    
    # derive hashed username and password
    husername = scrypt32(username, husername_salt)
    hpassword = scrypt32(password, hpassword_salt)
    
    # convert to  Base64
    b64husername = b64encode(husername).decode("utf-8")
    b64hpassword = b64encode(hpassword).decode("utf-8")
    
    # authentication
    auth = requests.auth.HTTPBasicAuth(b64husername, b64hpassword)

    # headers    
    headers = {'Content-type': 'application/json'}

    url = baseurl + '/password/' + b64husername + '/'
    
    # send request
    response = requests.get(url, headers=headers, auth=auth)
    
    assert response.status_code == 200, "Error getting password list"
    
    encpasslist = fromB64(response.json()["encpasslist"])

    # decrypt and authenticate password list
    passlist = json.loads(unpadthis(decAuth(encpasslist, password, encpasslist_hmac_salt, encpasslist_enc_salt)))
    
    return passlist

    
# function to check for connectivity
def checkconn(baseurl, username=None, password=None):

    # headers    
    headers = {'Content-type': 'application/json'}

    url = baseurl + '/users/'
    
    if username != None and password != None:
        # derive hashed username and password
        husername = scrypt32(username, husername_salt)
        hpassword = scrypt32(password, hpassword_salt)
        
        # convert to Base64
        b64husername = b64encode(husername).decode("utf-8")
        b64hpassword = b64encode(hpassword).decode("utf-8")
    
        # authentication
        auth = requests.auth.HTTPBasicAuth(b64husername, b64hpassword)
        
        # send authenticated request
        response = requests.options(url, headers=headers, auth=auth)
    else:
        # send unauthenticated request
        response = requests.options(url, headers=headers)
    
    if response.status_code != 200:
        return False
    
    return True
    
# function to print passworddata list as a nice table
def printsummary(plist):
    column_width=25
    print("INDEX".ljust(column_width), end='')
    print("TITLE".ljust(column_width), end='')
    print('\n')
    
    index = 1
    for row in plist:  
        print(str(index).ljust(column_width), end='')
        index += 1
        # print title only
        print(row["title"].ljust(column_width), end='')         
        print('\n')
        
# function to print paddworddata details
def printdetail(plist, index):
    column_width=25
    try:
        row = plist[index-1]
    except IndexError:
        print("No such entry in password list.")
        return
    print("INDEX:".ljust(column_width), end='')
    print(str(index).ljust(column_width), end='')
    print('\n')
    print("TITLE:".ljust(column_width), end='')
    print(row["title"].ljust(column_width), end='') 
    print('\n')
    print("USERNAME:".ljust(column_width), end='')
    print(row["username"].ljust(column_width), end='') 
    print('\n')
    print("PASSWORD:".ljust(column_width), end='')
    print(row["password"].ljust(column_width), end='') 
    print('\n')
    print("URL:".ljust(column_width), end='')
    print(row["url"].ljust(column_width), end='') 
    print('\n')
    print("NOTES:".ljust(column_width), end='')
    print(row["notes"].ljust(column_width), end='') 
    print('\n')
    

# function to generate token file
def gentokenfile(path):
    # initialize random number generator
    rng = Random.new()
    # generate random token
    token = rng.read(32)
    # write file
    try:
        # open file
        tfile = open(path, 'wb')
        # write data
        tfile.write(token_format_header + token)
        # close file
        tfile.close()
    except IOError:
        print("Unable to write token file.")
        return False
    # return True on success
    return True

# function to read token from token file
def gettoken(path):
    try:
        # open file
        tfile = open(path, 'rb')
        # read data
        tokendata = tfile.read()
        # close file
        tfile.close()
    except IOError:
        print("Unable to read token file.")
        return None
    # first check of file format
    header = tokendata[:len(token_format_header)]
    if header != token_format_header:
        print("Invalid token file.")
        return None
    # get token
    token = tokendata[len(token_format_header):]
    # check token length
    if len(token) != 32:
        print("Invalid token: wrong size.")
        return None
    # return token
    return token

# function to generate a random char of given length
# it will output a random char in ASCII range 32-126
# (uppercase and lowercase letters, digits and simple symbols)
# n=126-32=94; k=8; q=floor(2^k/n)=2
# rb in range [0;nq-1=187]
# rb mod n
def genchar(rng):
    # blacklisted chars
    blacklist = " " # blacklist whitespace
    rstart = 32
    rend = 126
    n = rend - rstart
    k = 8
    q = int(floor(2**k/n))
    # get a random byte until it is in the range [0,187=(126-32)]
    while True:
        rb = rng.read(1)
        if rb <= (n*q-1).to_bytes(1, byteorder="little"):
            ch = str((rstart+(int().from_bytes(rb, byteorder='little'))%n).to_bytes(1, byteorder="little"), "utf8")
            if ch not in blacklist:
                break
    return ch
    

# function to generate a random password of given length
def genpassw(length):
    # initialize random number generator
    rng = Random.new()
    # initialize string
    passw = ""
    for i in range(length):
        passw += genchar(rng)
    return passw



# add password to password list
def addToPasslist(passlist, passworddata):
    # check for valid title
    if passworddata["title"] == None or passworddata["title"] == "":
        print("Invalid title.")
        raise ValueError
    
    # check if passworddata with that title exists
    for pd in passlist:
        if passworddata["title"] == pd["title"]:
            # Entry with this title already exists!
            raise ValueError    
    
    passlist.append({"title":passworddata["title"],
    "username":passworddata["username"],"password":passworddata["password"],
    "url":passworddata["url"],"notes":passworddata["notes"]})
    
    return passlist

# delete password from password list (by title)
def delFromPasslist(passlist, title):
    for pd in passlist:
        if title == pd["title"]:
            passlist.remove(pd)
            return passlist
    print("No entries with that title were found!")
    raise ValueError
    
# delete password from password list (by index)
def delFromPasslistByIndex(passlist, index):
    if not (0 < index <= len(passlist)):
        # There is no password in such position.
        raise IndexError
    passlist.pop(index-1)
    return passlist
    
# update password in password list
def updToPasslist(passlist, passworddata, index):
    if not (0 < index <= len(passlist)):
        # There is no password in such position.
        raise IndexError
        
    # check if passworddata with that title exists (and it is not that one we are modifying)
    for idx,pd in enumerate(passlist):
        if passworddata["title"] == pd["title"] and idx != index-1:
            # Entry with this title already exists!
            raise ValueError 
        
    passlist[index-1]["title"] = passworddata["title"]
    passlist[index-1]["username"] = passworddata["username"]
    passlist[index-1]["password"] = passworddata["password"]
    passlist[index-1]["url"] = passworddata["url"]
    passlist[index-1]["notes"] = passworddata["notes"]
    return passlist

