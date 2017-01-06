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

from rest_framework import serializers
from opqpwd.models import UserCred, PasswordData


# serializer for users
class UserCredSerializer(serializers.ModelSerializer):
    owner = serializers.SlugRelatedField(slug_field='username', read_only=True)
    class Meta:
        model = UserCred
        fields = ('id', 'husername', 'hpassword', 'hpassword_salt')
        
# serializer for reading user data
class UserCredSerializerNoHpass(UserCredSerializer):
    class Meta:
        model = UserCred
        fields = ('id', 'husername')
        
# serializer for posting new users
class UserCredSerializerNoSalt(UserCredSerializer):
    class Meta:
        model = UserCred
        fields = ('id', 'husername', 'hpassword')
        
# serializer for passwords
class PasswordDataSerializer(serializers.ModelSerializer):
    owner = serializers.SlugRelatedField(slug_field='username', read_only=True)
    
    class Meta:
        model = PasswordData
        fields = ('id', 'encpasslist', 'owner')

