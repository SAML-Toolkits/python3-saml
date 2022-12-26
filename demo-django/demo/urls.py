from django.urls import re_path
from django.contrib import admin
from .views import attrs, index, metadata
admin.autodiscover()

urlpatterns = [
    re_path(r'^$', index, name='index'),
    re_path(r'^attrs/$', attrs, name='attrs'),
    re_path(r'^metadata/$', metadata, name='metadata'),
]
