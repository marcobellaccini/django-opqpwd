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

from opqpwd.models import UserCred, PasswordData, ENCPASSLIST_LEN
from opqpwd.serializers import UserCredSerializerNoHpass, UserCredSerializerNoSalt, PasswordDataSerializer
from opqpwd.permissions import OwnerOnly
from rest_framework import generics
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.http import Http404
from .cryptofun import scrypt32, fromB64
from rest_framework.authentication import SessionAuthentication, BasicAuthentication

# function to check password
def checkPassword(serializer, user):
    # get hpassword from serializer and convert to bytes
    hpassword = fromB64(serializer.validated_data.get('hpassword'))
    # get salt
    hpassword_salt = fromB64(user.hpassword_salt)
    # get salted password
    hhpassword = scrypt32(hpassword, hpassword_salt)
    # get the expected password for the user
    exp_hpassword = fromB64(user.hpassword)
    if hhpassword == exp_hpassword:
        return True
    return False
    

# view for creating users
class UserCredCreate(generics.CreateAPIView):
    queryset = UserCred.objects.all()
    serializer_class = UserCredSerializerNoSalt
    #permission_classes = (permissions.IsAuthenticatedOrReadOnly,)
    
    # override perform_create to handle owner
    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)
    
    # override list method
    # def list(self, request):
        # Note the use of `get_queryset()` instead of `self.queryset`
        #queryset = self.get_queryset()
        #serializer = UserCredSerializerNoHpass(queryset, many=True)
        #return Response(serializer.data)
        
    # override post method to deal with the salt
    def post(self, request, format=None):
        serializer = UserCredSerializerNoSalt(data=request.data)
        if serializer.is_valid():
            # create UserCred
            serializer.save()
            # create placeholder Password
            phpasslist = PasswordData(encpasslist=ENCPASSLIST_LEN*'A', owner=User.objects.get(username=serializer.validated_data.get('husername')))
            phpasslist.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# view for editing existing users
class UserCredDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = UserCred.objects.all()
    serializer_class = UserCredSerializerNoSalt
    permission_classes = (OwnerOnly,)
    authentication_classes = (SessionAuthentication, BasicAuthentication)
    
    def get_object(self, husername):
        try:
            obj = UserCred.objects.get(husername=husername)
            # check permissions
            self.check_object_permissions(self.request, obj)
            return obj
        except UserCred.DoesNotExist:
            raise Http404
    
    # override get method to avoid printing hpassword
    def get(self, request, husername, format=None):
        # Note the use of `get_queryset()` instead of `self.queryset`
        user = self.get_object(husername)
        serializer = UserCredSerializerNoHpass(user)
        return Response(serializer.data)
        
    # override put method to deal with the salt
    def put(self, request, husername, format=None):
        user = self.get_object(husername)
        serializer = UserCredSerializerNoSalt(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    # override delete to use husername as parameter
    def delete(self, request, husername, format=None):
        user = self.get_object(husername)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

        
    
# view for editing existing passwords 
class PasswordDataDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = PasswordData.objects.all()
    serializer_class = PasswordDataSerializer
    permission_classes = (OwnerOnly,)
    authentication_classes = (SessionAuthentication, BasicAuthentication)
    
    def get_object(self, owner):
        try:
            user = User.objects.get(username=owner)
            obj = PasswordData.objects.get(owner=user)
            # check permissions
            self.check_object_permissions(self.request, obj)
            return obj
        except UserCred.DoesNotExist:
            raise Http404
    
    # override get method to lookup by owner
    def get(self, request, owner, format=None):
        # Note the use of `get_queryset()` instead of `self.queryset`
        passlist = self.get_object(owner)
        serializer = PasswordDataSerializer(passlist)
        return Response(serializer.data)
        
    # override put method to lookup by owner
    def put(self, request, owner, format=None):
        passwordlist = self.get_object(owner)
        serializer = PasswordDataSerializer(passwordlist, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    # override delete to lookup by owner
    def delete(self, request, owner, format=None):
        passwordlist = self.get_object(owner)
        passwordlist.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
