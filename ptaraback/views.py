from django.shortcuts import render
from rest_framework import views, mixins, permissions, exceptions
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
#from ptaraback.serializers import *
from django.contrib.auth import get_user_model
from ptaraback.models import *

from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST

from .serializers import (
    UserCreateSerializer,
    UserLoginSerializer
)

User = get_user_model()

from rest_framework import viewsets

# Create your views here.
class UserCreateView(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [
        permissions.AllowAny
    ]
    serializer_class = UserCreateSerializer#Serializer


class UserLoginView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = UserLoginSerializer

    def post(self, request, *args, **kwargs):
        data = request.data
        serializer = UserLoginSerializer(data=data)
        if serializer.is_valid(raise_exception=True):
            new_data = serializer.data
            return Response(new_data, status=HTTP_200_OK)
        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

"""
class UsersList(APIView):
    def get(self, request):
        users = ptaraUsers.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

    def post(self):
        pass"""

"""
class UserFormView(View):
    form_class = UserForm

    #display blank form
    def get(self, request):
        form = self.form_class(None)
        return render(request, {'form': form})

    #process form data
    def post(self, request):
        form = self.form_class(request.POST)

        if form.is_valid():
            user = form.save(commit=False)

            #clean (normalized data)
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user.set_password(password)
            user.save()

            user = authenticate(username=username, password=password)

            if user is not None:
                if user.is_active:
                    login(request, user)
                    request.user()
                #return redirect()
        return render(request, {'form': form})"""

"""
class PtarabackList(mixins.ListModelMixin,
                  mixins.RetrieveModelMixin,
                  viewsets.GenericViewSet):

    permission_classes = (permissions.IsAuthenticated, )
    authentication_classes = (TokenAuthentication, )

    queryset = User.objects.all()
    lookup_field = 'id'
    serializer_class = UserSerializer

    def get_queryset(self):
        return User.objects.all()


class ObtainAuthToken(views.APIView):
        throttle_classes = ()
        permission_classes = ()
        authentication_classes = [TokenAuthentication, ]
        # parser_classes = (parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser,)
        # renderer_classes = (renderers.JSONRenderer,)
        serializer_class = AuthTokenSerializer

        def post(self, request, *args, **kwargs):
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data['user']
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key})

obtain_auth_token = ObtainAuthToken.as_view()"""

