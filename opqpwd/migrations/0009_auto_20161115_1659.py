# -*- coding: utf-8 -*-
# Generated by Django 1.10.2 on 2016-11-15 16:59
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('opqpwd', '0008_auto_20161115_1630'),
    ]

    operations = [
        migrations.AlterField(
            model_name='password',
            name='owner',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='passwordrelname', to=settings.AUTH_USER_MODEL),
        ),
    ]
