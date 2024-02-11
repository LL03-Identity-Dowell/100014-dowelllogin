from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser
from django.utils.crypto import get_random_string
Role_CHOICES = (
    ("Super_Admin", "Super Admin"),
    ("Company_Lead", "Company Lead"),
    ("Org_Lead", "Orgnisation Lead"),
    ("Dept_Lead", "Department Lead"),
    ("Client_Admin", "Client Admin"),
    ("Proj_Lead", "Project Lead"),
    ("Team_Member", "Team Member"),
    ("Hr", "Hr"),
    ("User", "User"),

)
def get_profile_image_path(self,filename):
    return f'profile_images/{"profile_image.jpg"}'
def get_default_profile_image():
    return 'user.png'
class Account(AbstractUser):
    role = models.CharField(
        max_length = 300,
        default="User"
        )
    datatype=models.CharField(
        max_length = 100,
        default="Testing"
        )
    profile_image=models.ImageField(max_length=255,upload_to=get_profile_image_path,null=True,blank=True,default=get_default_profile_image)
    teamcode=models.CharField(max_length=20,null=True)
    phonecode=models.CharField(max_length=20,null=True)
    phone=models.CharField(max_length=20,null=True)
    current_task=models.CharField(max_length=200,null=True)

class GuestAccount(models.Model):
    username=models.CharField(max_length=20,unique=False)
    email=models.CharField(max_length=30,unique=True)
    is_activated=models.BooleanField(default=False)
    otp=models.IntegerField(null=True)
    token=models.CharField(max_length=300,null=True)
    expiry=models.DateTimeField(default=timezone.now)
    class Meta:
        db_table="GuestAccount"

class mobile_sms(models.Model):
    username=models.CharField(max_length=20,default="user")
    phone=models.CharField(max_length=15,unique=True)
    sms=models.IntegerField(null=True)
    expiry=models.DateTimeField(default=timezone.now)

class logos(models.Model):
    url=models.CharField(max_length=1000)
    logo=models.CharField(max_length=200)
    url_ip=models.CharField(max_length=24)
    others=models.CharField(max_length=2000)
    url_id=models.CharField(unique=True,max_length=300, editable=False, default=get_random_string(22))

class CustomSession(models.Model):
    sessionID=models.CharField(max_length=2000)
    info=models.TextField()
    document=models.TextField()
    status=models.CharField(max_length=50, null=True,blank=True)

class RandomSession(models.Model):
    sessionID=models.CharField(max_length=2000)
    username=models.CharField(max_length=2000)
    status=models.CharField(max_length=50, null=True,blank=True)
    added=models.DateTimeField(default=timezone.now)

class QR_Creation(models.Model):
    info=models.TextField(null=True)
    qrid=models.CharField(max_length=2000)
    password=models.CharField(max_length=2000)
    status=models.CharField(max_length=50, null=True,blank=True)

class LiveStatus(models.Model):
    sessionID=models.CharField(max_length=2000)
    username=models.CharField(max_length=2000)
    product=models.CharField(max_length=100)
    status=models.CharField(max_length=50, null=True,blank=True)
    date_created=models.CharField(max_length=1000)
    date_updated=models.CharField(max_length=1000,null=True,blank=True)
    updated=models.DateTimeField(null=True,blank=True)
    created=models.DateTimeField(null=True,blank=True)

class Live_QR_Status(models.Model):
    qrid=models.CharField(max_length=2000)
    product=models.CharField(max_length=100)
    status=models.CharField(max_length=50, null=True,blank=True)
    updated=models.DateTimeField(null=True,blank=True)
    created=models.DateTimeField(null=True,blank=True)

class Live_Public_Status(models.Model):
    unique_key=models.CharField(max_length=2000)
    product=models.CharField(max_length=100)
    status=models.CharField(max_length=50, null=True,blank=True)
    updated=models.DateTimeField(null=True,blank=True)
    created=models.DateTimeField(null=True,blank=True)

class Linkbased_RandomSession(models.Model):
    sessionID=models.CharField(max_length=1000)
    info=models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    status=models.CharField(max_length=50, null=True,blank=True,default="logout")

class Location_check(models.Model):
    username=models.CharField(max_length=1000,unique=True)
    usual=models.TextField()
    unusual=models.TextField(null=True,blank=True)
    def __str__(self):
        return self.username

class products(models.Model):
    product=models.CharField(max_length=1000,unique=True)
    url=models.CharField(max_length=1000,blank=True)
    ip=models.CharField(max_length=1000,blank=True)
    status=models.CharField(max_length=100,default="active")

class Face_Login(models.Model):
    username=models.CharField(max_length=20,unique=True)
    image=models.CharField(max_length=10000)
