from django.shortcuts import render
from .serializers import *
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
import random, base64
from django.conf.global_settings import EMAIL_HOST
from cleverSpace.settings import ENC_KEY
from .models import *
from rest_framework_simplejwt.tokens import RefreshToken

# Create your views here.

class Register(APIView):
    def get(self, request):
        users = User.objects.all()
        print(users)
        serializer = UserSerializer(users, many=True)
        return Response({"Users": serializer.data})

    def post(self, request):
        data = request.data
        user, created = User.objects.get_or_create(username=data["username"])
        # key = ENC_KEY
        # print(key)
        # cipher = AES.new(key, AES.MODE_EAX)
        # ciphertext, tag = cipher.encrypt_and_digest(bytes(data["password"], "utf-8"))
        # nonce = cipher.nonce
        # print(ciphertext, "abcd", nonce)
        # cipher = AES.new(key, AES.MODE_EAX, nonce)
        # data_ = cipher.decrypt_and_verify(ciphertext, tag)
        # print(data_, "data")
        if created:
            try:
                user.set_password(data["password"])
                user.save()
                otp_obj = OTP.objects.get_or_create(user=user)

                return Response({"status": status.HTTP_201_CREATED, "data": "user created successfully"})
            except():
                return Response({"status": status.HTTP_400_BAD_REQUEST, "data": "Invalid Password"})
        else:
            return Response({"status": status.HTTP_400_BAD_REQUEST, "data": "User with same username already exists."})


class SendOTP(APIView):
    def post(self, request):
        data = request.data
        otp = ''.join(["{}".format(random.randint(0, 9)) for num in range(0, 6)])
        user = User.objects.filter(username=data["username"]).first()
        print(user.password)
        if user:
            otp_obj, created = OTP.objects.get_or_create(user=user)
            otp_obj.otp = otp
            otp_obj.save()
            send_mail(
                'OTP | CleverSpace',
                f'{otp} is the One Time Password (OTP) to login to CleverSpace.',
                EMAIL_HOST,
                [data["username"]],
                fail_silently=False,
            )
            return Response({"status": status.HTTP_200_OK, "data": "OTP sent."})
        else:
            return Response({"status": status.HTTP_404_NOT_FOUND, "data": "User not found."})

class VerifyOTP(APIView):
    def post(self, request):
        data = request.data
        user = User.objects.filter(username=data["username"]).first()
        otp_obj = OTP.objects.get(user=user)
        if data["otp"] == otp_obj.otp:
            token = RefreshToken.for_user(user)
            return Response({'refresh': str(token), 'access': str(token.access_token)})
        else:
            return Response({"status": status.HTTP_401_UNAUTHORIZED, "data": "Invalid OTP."})
