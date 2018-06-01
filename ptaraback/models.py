import datetime
import binascii
import os

from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token
from django.conf import settings


# from django.utils import timezone
# from django.utils.encoding import python_2_unicode_compatible
# from django.utils.translation import ugettext_lazy as _
# from django.contrib.auth.hashers import check_password, make_password
# from django.contrib.auth.models import _user_has_perm, _user_get_all_permissions, _user_has_module_perms

"""
class ptaraUsers(models.Model):
    id =  models.AutoField(primary_key=True)
    email = models.EmailField()
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=100, null=True)"""


# token is: 4bd97c6a3da72d83cee684617f43718811db4d88
@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)
