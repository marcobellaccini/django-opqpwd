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

from django.conf.urls import url
from rest_framework.urlpatterns import format_suffix_patterns
from opqpwd import views
from django.conf.urls import include

urlpatterns = [
    url(r'^users/$', views.UserCredCreate.as_view(), name="userlist"),
    url(r'^users/(?P<husername>' + '(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)' + ')/$', views.UserCredDetail.as_view(), name="userdetail"),
    url(r'^password/(?P<owner>' + '(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)' + ')/$', views.PasswordDataDetail.as_view(), name="passworddetail"),
]

urlpatterns += [
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
]

urlpatterns = format_suffix_patterns(urlpatterns)