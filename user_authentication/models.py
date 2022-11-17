from django.db import models
from django.contrib.auth.models import User

# Create your models here.


class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.DO_NOTHING, blank=True, null=False)
    otp = models.CharField(max_length=6, null=False, blank=True)
    password = models.CharField(max_length=200, null=False, blank=True)

    def __int__(self):
        return self.user

