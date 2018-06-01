from django.contrib.auth import authenticate, get_user_model
from django.utils.translation import ugettext_lazy as _
from django.db.models import Q
from rest_framework import serializers
#from rest_framework_mongoengine.serializers import DocumentSerializer
from rest_framework.exceptions import ValidationError
from rest_framework.fields import CharField, EmailField

#from ptaraback.models import ptaraUsers


User = get_user_model()

class UserCreateSerializer(serializers.ModelSerializer):
    #id = serializers.IntegerField(read_only=False)
    email = EmailField(label='Email address')
    #email2 = EmailField(label='Confirm Email')
    class Meta:
        model = User
        fields = [
            'username',
            'email',
            'password',
        ]
        extra_kwargs = {'password': {'write_only': True}}

    """def validate(self, data):
        email = data['email']
        qs_email = User.objects.filter(email=email)
        if qs_email.exists():
            raise ValidationError("Email already used and registered")
        return data"""

    """def email_validation(self, value):
        data = self.get_initial()
        email = data.get("email2")
        email2 = value
        if email != email2:
            raise ValidationError("Unmatched email")
        qs_email = User.objects.filter(email=email)
        if qs_email.exists():
            raise ValidationError("Email already used and registered")
        return value

    def email_validation2(self, value):
        data = self.get_initial()
        email = data.get("email")
        email2 = value
        if email != email2:
            raise ValidationError("Unmatched email")
        return value"""



    def create(self, validated_data):

        """user = ptaraUsers.objects.create(
            username=validated_data['username'],
            email = validated_data['email'],
        )"""

        username = validated_data['username']
        email = validated_data['email']
        password = validated_data['password']
        user_obj = User(
            username = username,
            email = email
        )
        user_obj.set_password(validated_data['password'])
        user_obj.save()
        return validated_data

class UserLoginSerializer(serializers.ModelSerializer):

    #token = CharField(allow_blank=True, read_only=True)
    username = CharField(required=False, allow_blank=True)
    email = EmailField(label='Email Address', required=False, allow_blank=True)
    class Meta:
        model = User
        fields = [
            'username',
            'email',
            'password',
            #'token',
        ]
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        user_obj = None
        email = data.get("email", None)
        username = data.get("username", None)
        password = data["password"]
        if not email and not username:
            raise ValidationError("Username and email is required to login")

        user = User.objects.filter(
                Q(email=email) |
                Q(username=username)
            ).distinct()
        user = user.exclude(email_isnull=True).exclude(email_iexact='')
        if user.exists() and user.count() == 1:
            user_obj = user.first()
        else:
            raise ValidationError("This username or email is not valid")

        if user_obj:
            if not user_obj.check_password(password):
                raise ValidationError("Incorrect credentials - try again")

        return data




"""
class AuthTokenSerializer(serializers.Serializer):
    username = serializers.CharField(label=_("Username"))
    password = serializers.CharField(label=_("Password"), style={'input_type': 'password'})

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = authenticate(username=username, password=password)

            if user:
                # From Django 1.10 onwards the `authenticate` call simply
                # returns `None` for is_active=False users.
                # (Assuming the default `ModelBackend` authentication backend.)
                if not user.is_active:
                    msg = _('User account is disabled.')
                    raise serializers.ValidationError(msg)
            else:
                msg = _('Unable to log in with provided credentials.')
                raise serializers.ValidationError(msg)
        else:
            msg = _('Must include "username" and "password".')
            raise serializers.ValidationError(msg)

        attrs['user'] = user
        return attrs"""

"""
class UserSerializer2(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=False)

    class Meta:
        model = ptaraUsers
        fields = '__all__'"""

