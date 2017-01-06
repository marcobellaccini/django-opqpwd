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

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase, APILiveServerTestCase
from base64 import b64encode
from opqpwd.models import UserCred, PasswordData, SCRYPT_KEYLEN_BASE64, ENCPASSLIST_LEN
from opqpwd.cryptofun import encAuth, scrypt32
from opqpwd import clientfun


import scrypt

# constant salts
husername_salt = "hw3T7&22JOp21nnw.6,hhwjw3Qs=iiwe"
hpassword_salt = "G36jjdb55$$f$-j7GGTssw49dm;jjuec"
encpasslist_hmac_salt = "8lmWhhi6&$mmNG8nv5BYd2::0hqZZff4"
encpasslist_enc_salt = "mp00j(.dbRRvW2285GB0x3mr(nd?982f" 

PASSLIST_LEN = 200000

# get Base64 result from scrypt key derivation function
def scryptBase64(password, salt):
    return b64encode(scrypt.hash(password, salt, N=16384, r=8, p=1, buflen=32))
    
# function to register a user
def regUser(username, password, client):
    # derive hashed username and password
    husername = scrypt32(username, husername_salt)
    hpassword = scrypt32(password, hpassword_salt)
    # convert to Base64
    husernameb64 = b64encode(husername).decode("utf-8")
    hpasswordb64 = b64encode(hpassword).decode("utf-8")
    # prepare request
    url = reverse('userlist')
    data = {'husername': husernameb64, 'hpassword': hpasswordb64}
    # send request and return response
    return client.post(url, data, format='json')


class userTests(APITestCase):
    
    # test credentials
    username1 = "test_user"
    password1 = "superfoo"
    username2 = "test_user2"
    password2 = "djafoo"
    
    # test password lists
    passlist1 = PASSLIST_LEN * b"\x00"
    passlist2 = PASSLIST_LEN * b"\x01"
    
    # derive hashed username and password
    husername1 = scrypt32(username1, husername_salt)
    hpassword1 = scrypt32(password1, hpassword_salt)
    husername2 = scrypt32(username2, husername_salt)
    hpassword2 = scrypt32(password2, hpassword_salt)
    
    # encrypt and authenticate password list
    encpasslist1 = encAuth(passlist1, password1, encpasslist_hmac_salt, encpasslist_enc_salt)
    encpasslist2 = encAuth(passlist2, password2, encpasslist_hmac_salt, encpasslist_enc_salt)
    
    # convert to Base64
    husername1b64 = b64encode(husername1).decode("utf-8")
    hpassword1b64 = b64encode(hpassword1).decode("utf-8")
    encpasslist1b64 = b64encode(encpasslist1).decode("utf-8")
    husername2b64 = b64encode(husername2).decode("utf-8")
    hpassword2b64 = b64encode(hpassword2).decode("utf-8")
    encpasslist2b64 = b64encode(encpasslist2).decode("utf-8")
    
    def test_adduser(self):
        """
        Try to register a new user.
        """
        response = regUser(self.username1, self.password1, self.client)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UserCred.objects.count(), 1)
        self.assertEqual(UserCred.objects.get().husername, self.husername1b64 )
        self.assertEqual(PasswordData.objects.count(), 1)
        
        
    def test_readduser(self):
        """
        Try to register an already registered user.
        """
        response = regUser(self.username1, self.password1, self.client)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UserCred.objects.count(), 1)
        self.assertEqual(UserCred.objects.get().husername, self.husername1b64 )
        self.assertEqual(PasswordData.objects.count(), 1)
        
        response = regUser(self.username1, self.password2, self.client)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(UserCred.objects.count(), 1)
        self.assertEqual(UserCred.objects.get().husername, self.husername1b64 )
        self.assertEqual(PasswordData.objects.count(), 1)
        
    def test_adduser_invalid_husername_len(self):
        """
        Try to register a user with a too short (but valid Base64) husername.
        """
        url = reverse('userlist')
        data = {'husername': 'QQ==', 'hpassword': self.hpassword1b64}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(UserCred.objects.count(), 0)
        self.assertEqual(response.content, bytes('{"husername":["length has to be ' + str(SCRYPT_KEYLEN_BASE64) + '"]}', encoding="utf-8"))
        self.assertEqual(PasswordData.objects.count(), 0)
        
    def test_adduser_invalid_husername_b64(self):
        """
        Try to register a user with an invalid Base64 husername (with the right length).
        """
        url = reverse('userlist')
        lbadB64husername = list(self.husername1b64)
        lbadB64husername[2] = "-"
        badB64husername = "".join(lbadB64husername)
        data = {'husername': badB64husername, 'hpassword': self.hpassword1b64}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(UserCred.objects.count(), 0)
        self.assertEqual(response.content, b'{"husername":["Expecting Base64 string"]}')
        self.assertEqual(PasswordData.objects.count(), 0)
        
    def test_adduser_invalid_hpassword_len(self):
        """
        Try to register a user with a too short (but valid Base64) hpassword.
        """
        url = reverse('userlist')
        data = {'husername': self.husername1b64, 'hpassword': 'QQ=='}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(UserCred.objects.count(), 0)
        self.assertEqual(response.content, bytes('{"hpassword":["length has to be ' + str(SCRYPT_KEYLEN_BASE64) + '"]}', encoding="utf-8"))
        self.assertEqual(PasswordData.objects.count(), 0)
        
    def test_adduser_invalid_hpassword_b64(self):
        """
        Try to register a user with an invalid Base64 hpassword (with the right length).
        """
        url = reverse('userlist')
        lbadB64hpassword = list(self.hpassword1b64)
        lbadB64hpassword[2] = "-"
        badB64hpassword = "".join(lbadB64hpassword)
        data = {'husername': self.husername1b64, 'hpassword': badB64hpassword}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(UserCred.objects.count(), 0)
        self.assertEqual(response.content, b'{"hpassword":["Expecting Base64 string"]}')
        self.assertEqual(PasswordData.objects.count(), 0)
        
        
    def test_updateuser(self):
        """
        Try to update an already registered user.
        """
        url = reverse('userlist')
        data = {'husername': self.husername1b64, 'hpassword': self.hpassword1b64}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UserCred.objects.count(), 1)
        self.assertEqual(UserCred.objects.get().husername, self.husername1b64 )
        oldId = UserCred.objects.get().id
        
        # modified data (different password)
        data2 = {'husername': self.husername1b64, 'hpassword': self.hpassword2b64}
        
        # authentication
        self.client.credentials(HTTP_AUTHORIZATION = 'Basic ' + b64encode(bytes(self.husername1b64+':'+self.hpassword1b64,"utf8")).decode("utf-8"))        
        
        urldetail = reverse('userdetail', args=(self.husername1b64,))
        response = self.client.put(urldetail, data2, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(UserCred.objects.count(), 1)
        self.assertEqual(UserCred.objects.get().husername, self.husername1b64 )
        newId = UserCred.objects.get().id
        self.assertEqual(oldId,newId)
        
    def test_updateuser_noauth(self):
        """
        Try to update an already registered user without authenticating.
        """
        url = reverse('userlist')
        data = {'husername': self.husername1b64, 'hpassword': self.hpassword1b64}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UserCred.objects.count(), 1)
        self.assertEqual(UserCred.objects.get().husername, self.husername1b64 )
        oldId = UserCred.objects.get().id
        
        # modified data (different password)
        data2 = {'husername': self.husername1b64, 'hpassword': self.hpassword2b64}
        
        # NO authentication
        
        urldetail = reverse('userdetail', args=(self.husername1b64,))
        response = self.client.put(urldetail, data2, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(UserCred.objects.count(), 1)
        self.assertEqual(UserCred.objects.get().husername, self.husername1b64 )
        newId = UserCred.objects.get().id
        self.assertEqual(oldId,newId)
        self.assertEqual(response.content, b'{"detail":"Authentication credentials were not provided."}')
        
        
    def test_updateuser_wrongpass(self):
        """
        Try to update an already registered user, using a wrong password.
        """
        url = reverse('userlist')
        data = {'husername': self.husername1b64, 'hpassword': self.hpassword1b64}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UserCred.objects.count(), 1)
        self.assertEqual(UserCred.objects.get().husername, self.husername1b64 )
        oldId = UserCred.objects.get().id
        
        
        # get bad hpassword
        badhpassword = scrypt32("wrongPassw", hpassword_salt)
        test_badhpassword = b64encode(badhpassword).decode("utf-8")
        
        # modified data (different password)
        data2 = {'husername': self.husername1b64, 'hpassword': self.hpassword2b64}
        
        # authentication
        self.client.credentials(HTTP_AUTHORIZATION = 'Basic ' + b64encode(bytes(self.husername1b64+':'+test_badhpassword,"utf8")).decode("utf-8"))
        
        urldetail = reverse('userdetail', args=(self.husername1b64,))
        response = self.client.put(urldetail, data2, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(UserCred.objects.count(), 1)
        self.assertEqual(UserCred.objects.get().husername, self.husername1b64 )
        newId = UserCred.objects.get().id
        self.assertEqual(oldId,newId)
        self.assertEqual(response.content, b'{"detail":"Invalid username/password."}')        
        
    def test_updateuser_otheruser(self):
        """
        Try to update a user using credentials of another user.
        """
        url = reverse('userlist')
        data = {'husername': self.husername1b64, 'hpassword': self.hpassword1b64}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UserCred.objects.count(), 1)
        self.assertEqual(UserCred.objects.get().husername, self.husername1b64 )
        
        # create another user
        usernameB = "test_user2"
        passwordB = "superfoo2"
        husernameB = scrypt32(usernameB, husername_salt)
        hpasswordB = scrypt32(passwordB, hpassword_salt)
        test_husernameB = b64encode(husernameB).decode("utf-8")
        test_hpasswordB = b64encode(hpasswordB).decode("utf-8")
        
        # register the other user
        data = {'husername': test_husernameB, 'hpassword': test_hpasswordB}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UserCred.objects.count(), 2)
        self.assertEqual(UserCred.objects.get(husername=test_husernameB).husername, test_husernameB )
        
        
        # modified data (different password)
        data2 = {'husername': self.husername1b64, 'hpassword': self.hpassword2b64}
        
        # authentication
        self.client.credentials(HTTP_AUTHORIZATION = 'Basic ' + b64encode(bytes(test_husernameB+':'+test_hpasswordB,"utf8")).decode("utf-8"))
        
        urldetail = reverse('userdetail', args=(self.husername1b64,))
        response = self.client.put(urldetail, data2, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(UserCred.objects.count(), 2)
        self.assertEqual(UserCred.objects.get(husername=self.husername1b64).husername, self.husername1b64 )
        self.assertEqual(response.content, b'{"detail":"You do not have permission to perform this action."}')
        
    def test_deleteuser(self):
        """
        Create user, then delete it.
        """
        response = regUser(self.username1, self.password1, self.client)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UserCred.objects.count(), 1)
        self.assertEqual(UserCred.objects.get().husername, self.husername1b64 )
        self.assertEqual(PasswordData.objects.count(), 1)
        
        # authentication
        self.client.credentials(HTTP_AUTHORIZATION = 'Basic ' + b64encode(bytes(self.husername1b64+':'+self.hpassword1b64,"utf8")).decode("utf-8"))        
        
        urldetail = reverse('userdetail', args=(self.husername1b64,))
        response = self.client.delete(urldetail, format='json')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(UserCred.objects.count(), 0)
        self.assertEqual(PasswordData.objects.count(), 0)
        
    def test_deleteuser_noauth(self):
        """
        Create user, then try to delete it without authenticating.
        """
        response = regUser(self.username1, self.password1, self.client)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UserCred.objects.count(), 1)
        self.assertEqual(UserCred.objects.get().husername, self.husername1b64 )
        self.assertEqual(PasswordData.objects.count(), 1)
        
        urldetail = reverse('userdetail', args=(self.husername1b64,))
        response = self.client.delete(urldetail, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(UserCred.objects.count(), 1)
        self.assertEqual(response.content, b'{"detail":"Authentication credentials were not provided."}')
        self.assertEqual(PasswordData.objects.count(), 1)
        
    def test_deleteuser_wrongpass(self):
        """
        Create user, then try to delete it using a wrong password.
        """
        response = regUser(self.username1, self.password1, self.client)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UserCred.objects.count(), 1)
        self.assertEqual(UserCred.objects.get().husername, self.husername1b64 )
        self.assertEqual(PasswordData.objects.count(), 1)
        
        # get bad hpassword
        badhpassword = scrypt32("wrongPassw", hpassword_salt)
        test_badhpassword = b64encode(badhpassword).decode("utf-8")
        
        # authentication
        self.client.credentials(HTTP_AUTHORIZATION = 'Basic ' + b64encode(bytes(self.husername1b64+':'+test_badhpassword,"utf8")).decode("utf-8"))
        
        urldetail = reverse('userdetail', args=(self.husername1b64,))
        response = self.client.delete(urldetail, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(UserCred.objects.count(), 1)
        self.assertEqual(response.content, b'{"detail":"Invalid username/password."}')
        self.assertEqual(PasswordData.objects.count(), 1)
        
    def test_deleteuser_otheruser(self):
        """
        Create user, then try delete it, authenticating as another user.
        """
        response = regUser(self.username1, self.password1, self.client)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UserCred.objects.count(), 1)
        self.assertEqual(UserCred.objects.get().husername, self.husername1b64 )
        
        response = regUser(self.username2, self.password2, self.client)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UserCred.objects.count(), 2)
        self.assertEqual(UserCred.objects.get(husername=self.husername2b64).husername, self.husername2b64 )
        
        # authentication
        self.client.credentials(HTTP_AUTHORIZATION = 'Basic ' + b64encode(bytes(self.husername2b64+':'+self.hpassword2b64,"utf8")).decode("utf-8"))        
        
        urldetail = reverse('userdetail', args=(self.husername1b64,))
        response = self.client.delete(urldetail, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(UserCred.objects.count(), 2)
        self.assertEqual(response.content, b'{"detail":"You do not have permission to perform this action."}')
        
    def test_password(self):
        """
        Try to save a new password list for a user.
        """
        # register user
        response = regUser(self.username1, self.password1, self.client)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UserCred.objects.count(), 1)
        self.assertEqual(UserCred.objects.get().husername, self.husername1b64 )
        
        # register password list
        # prepare request
        url = reverse('passworddetail', args=(self.husername1b64,))
        data = {'encpasslist': self.encpasslist1b64}
        # authentication
        self.client.credentials(HTTP_AUTHORIZATION = 'Basic ' + b64encode(bytes(self.husername1b64+':'+self.hpassword1b64,"utf8")).decode("utf-8"))
        # send request and return response
        response = self.client.put(url, data, format='json')
    
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(PasswordData.objects.count(), 1)
        self.assertEqual(PasswordData.objects.get().encpasslist, self.encpasslist1b64 )
        
    def test_password_invalid_len(self):
        """
        Try to register a too short (but valid Base64) password list.
        """
        # register user
        response = regUser(self.username1, self.password1, self.client)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UserCred.objects.count(), 1)
        self.assertEqual(UserCred.objects.get().husername, self.husername1b64 )
        
        url = reverse('passworddetail', args=(self.husername1b64,))
        data = {'encpasslist': 'QQ=='}
        
        # authentication
        self.client.credentials(HTTP_AUTHORIZATION = 'Basic ' + b64encode(bytes(self.husername1b64+':'+self.hpassword1b64,"utf8")).decode("utf-8"))
        response = self.client.put(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(PasswordData.objects.get().encpasslist, ENCPASSLIST_LEN*'A' )
        self.assertEqual(response.content, bytes('{"encpasslist":["length has to be ' + str(ENCPASSLIST_LEN) + '"]}', encoding="utf-8"))
        
    def test_password_invalid_b64(self):
        """
        Try to register an invalid Base64 password list (with the right length).
        """
        # register user
        response = regUser(self.username1, self.password1, self.client)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UserCred.objects.count(), 1)
        self.assertEqual(UserCred.objects.get().husername, self.husername1b64 )
        
        lbadB64encpasslist = list(self.encpasslist1b64)
        lbadB64encpasslist[2] = "-"
        badB64encpasslist = "".join(lbadB64encpasslist)        
        
        url = reverse('passworddetail', args=(self.husername1b64,))
        data = {'encpasslist': badB64encpasslist}
        # authentication
        self.client.credentials(HTTP_AUTHORIZATION = 'Basic ' + b64encode(bytes(self.husername1b64+':'+self.hpassword1b64,"utf8")).decode("utf-8"))
        response = self.client.put(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(PasswordData.objects.get().encpasslist, ENCPASSLIST_LEN*'A' )
        self.assertEqual(response.content, b'{"encpasslist":["Expecting Base64 string"]}')
        
        
class allowedMethodsTests(APITestCase):
    
    def test_userlist(self):
        """
        Try to list users with a GET on /users/.
        """
        url = reverse('userlist')
        response = self.client.get(url, format='json')
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertEqual(response.content, b'{"detail":"Method \\"GET\\" not allowed."}')
        
class clientEmulationTests(APILiveServerTestCase):
    
    def test_clientemu_1(self):
        """
        Performs an emulation of a client connecting to the server and performing the following actions:
        -connect to the server
        -add a user
        -login
        -add a password
        -try to re-add the same password
        -add another password
        -edit the first password
        -delete the first password
        -delete a non-existing password
        -delete the user
        
        
        """
        # test credentials
        username = "test_user"
        password = "superfoo"
        
        # test password data 1
        pdtitle1 = 'title1'
        pdusername1 = 'user1'
        pdpassword1 = 'mypassnum1'
        pdurl1 = 'https://foobarfoobar/index.foo/foo'
        pdnotes1 = 'My foo login'
        expdic1 = {"title":pdtitle1, "username":pdusername1, "password":pdpassword1, "url":pdurl1, "notes":pdnotes1}
        
        # test password data 1b
        pdtitle1b = 'title1b'
        pdusername1b = 'user1b'
        pdpassword1b = 'mypassnum1b'
        pdurl1b = 'https://modifiedfoobarfoobar/index.foo/foomod'
        pdnotes1b = 'My edited foo login'
        expdic1b = {"title":pdtitle1b, "username":pdusername1b, "password":pdpassword1b, "url":pdurl1b, "notes":pdnotes1b}
        
        # test password data 2
        pdtitle2 = 'title2 title2'
        pdusername2 = 'usernamen2'
        pdpassword2 = 'mypassnum2'
        pdurl2 = 'https://foobarfoobar2/index.foo/foo'
        pdnotes2 = 'My second foo login'
        expdic2 = {"title":pdtitle2, "username":pdusername2, "password":pdpassword2, "url":pdurl2, "notes":pdnotes2}
        
        # connect to the server (connection test)
        resp = clientfun.checkconn(baseurl=self.live_server_url, username=None, password=None)
        self.assertEqual(resp, True)
        
        # add a user
        resp = clientfun.adduser(username=username, password=password, baseurl=self.live_server_url)
        self.assertEqual(resp, True)
        self.assertEqual(UserCred.objects.count(), 1)
        self.assertEqual(PasswordData.objects.count(), 1)
        
        # login
        resp = clientfun.checkconn(self.live_server_url, username=username, password=password)
        self.assertEqual(resp, True)
        plist = clientfun.getpasswordlist(username=username, password=password, baseurl=self.live_server_url)
        self.assertEqual(plist, list())
        
        # add a password and (emulate a) print all passwords
        plist = clientfun.addToPasslist(plist, expdic1)
        explist = list()
        explist.append(expdic1)
        self.assertEqual(plist, explist)
        
        # try to re-add the same password
        self.assertRaises(ValueError, clientfun.addToPasslist, passlist=plist, passworddata=expdic1)
        explist = list()
        explist.append(expdic1)
        self.assertEqual(plist, explist)
        
        # add another password and (emulate a) print all passwords
        plist = clientfun.addToPasslist(plist, expdic2)
        explist = list()
        explist.append(expdic1)
        explist.append(expdic2)
        self.assertEqual(plist, explist)
        
        # edit the first password and (emulate a) print all passwords
        plist = clientfun.updToPasslist(plist, expdic1b, 1)
        explist = list()
        explist.append(expdic1b)
        explist.append(expdic2)
        self.assertEqual(plist, explist)
        
        # delete the first password and (emulate a) print all passwords
        plist = clientfun.delFromPasslistByIndex(plist, 1)
        explist = list()
        explist.append(expdic2)
        self.assertEqual(plist, explist)
        
        # delete a non-existing password and (emulate a) print all passwords
        self.assertRaises(IndexError, clientfun.delFromPasslistByIndex, passlist=plist, index=2)
        explist = list()
        explist.append(expdic2)
        self.assertEqual(plist, explist)
        
        # delete user
        resp = clientfun.deluser(username=username, password=password, baseurl=self.live_server_url)
        self.assertEqual(resp, True)
        self.assertEqual(UserCred.objects.count(), 0)
        self.assertEqual(PasswordData.objects.count(), 0)
        