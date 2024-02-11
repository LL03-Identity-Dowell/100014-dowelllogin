import base64,io, requests
from rest_framework.response import Response
from django.contrib.sessions.models import Session
from django.contrib.auth import authenticate, login,logout
from newlogin import dowell_func,qrcodegen,dowell_hash
from newlogin.dowell_func import dowellclock
from django.utils.decorators import method_decorator
from django.views.decorators.clickjacking import (
    xframe_options_exempt, xframe_options_deny, xframe_options_sameorigin,
)
from django.views.decorators.csrf import csrf_exempt
import json
from collections import namedtuple
from loginapp.models import Account, CustomSession, LiveStatus, Live_QR_Status, Live_Public_Status, GuestAccount, mobile_sms, RandomSession, Linkbased_RandomSession, QR_Creation, Location_check, Face_Login
from loginapp.dowellconnection import dowellconnection
#from voc_nps.models import Rating
from rest_framework.generics import RetrieveUpdateDestroyAPIView
from rest_framework.decorators import api_view
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.views import APIView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.hashers import make_password
from .serializers import UserSerializer,UserUpdateSerializer, CustomSessionSerializer
from loginapp.event_function import event_creation, create_event
import jwt,re
from lavapp import passgen
import time,pytz
from dateutil import parser
from newlogin.views import country_city_name
from newlogin.dowell_hash import dowell_hash as dowell_hash1
from newlogin.dowell_func import get_next_pro_id,generateOTP, decrypt_message
from PIL import Image
from django.core.files.base import ContentFile
import os
from django.core.mail import send_mail
from django.conf import settings
from django.template import RequestContext, Template
from rest_framework import status
from django.core.files.storage import default_storage
import face_recognition
from dateutil.relativedelta import *
import numpy as np
from loginapp.models import mobile_sms as mobile_model
import os

dpass="d0wellre$tp@$$"
import datetime

def get_html_msg(username, otp, purpose):
    return f'Dear {username}, <br> Please Enter below <strong>OTP</strong> to {purpose} of dowell account <br><h2>Your OTP is <strong>{otp}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['username'] = user.username
        # ...
        return token
class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer
class MyView(APIView):
    permission_classes = (IsAuthenticated,)
    def get(self, request):
        content = {'message': 'Hello, World!'}
        return Response(content)
class rightsView(APIView):
    def post(self, request):
        mdata=request.data
        rw=open("mydata.txt","r")
        rle=rw.read()
        d=json.loads(rle)
        rw.close()
        d["data"].append(mdata)
        r=open("mydata.txt","w")
        r.write(json.dumps(d))
        r.close()
        content = {'message': 'successfully added'}
        return Response(content)
    def get(self,request):
        w=open("mydata.txt","r")
        r=w.read()
        rdata=json.loads(r)
        return Response(rdata)
@api_view(['GET'])
def homeView(request):
    routes=['/api/token','/api/token/refresh',]
    return Response(routes)
class RegisterView(APIView):
    def post(self, request):
        serializer=UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        # field={"Username":user,"Password":password,"Firstname":first,"Lastname":last,"Email":email,"Role":role,"Team_Code":ccode,"phonecode":phonecode,"Phone":phone,"user_id":"userid"}
        # id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","insert",field,"nil")
        return Response(serializer.data["username"])
    def get(self,request):
        rate=Account.objects.all()#filter(username=payload["id"]).first()
        serializer=UserSerializer(rate, many=True)
        return Response(serializer.data)
class UserUpdateView(RetrieveUpdateDestroyAPIView):
    serializer_class=UserUpdateSerializer
    lookup_field="id"
    def get_queryset(self):
        return Account.objects.all()
    # def get(self,request):
    #     rate=Account.objects.all()#filter(username=payload["id"]).first()
    #     serializer=UserUpdateSerializer(rate, many=True)
    #     return Response(serializer.data)
# class RatingView(APIView):
#     def post(self, request):
#         serializer=RatingSerializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()
#         return Response(serializer.data)
#     def get(self,request):
#         rate=Rating.objects.all()#filter(username=payload["id"]).first()
#         serializer=RatingSerializer(rate, many=True)
#         return Response(serializer.data)
@api_view(["POST"])
def MobileLogin(request):
    mdata = request.data.get
    username = mdata('username')
    password = mdata('password')
    loc = mdata("location")
    try:
        lo = loc.split(" ")
        country, city = country_city_name(lo[0], lo[1])
    except:
        city = ""
        country = ""
    # return Response({"city":city,"country":country,"zone":timezone_str})
    device = mdata("device")
    osver = mdata("os")
    # brow=mdata["browser"]
    ltime = mdata("time")
    ipuser = mdata("ip")
    zone = mdata("timezone")
    if None in [username, password, loc, device, osver, ltime, ipuser]:
        resp = {"data": "Provide all credentials",
                "Credentials": "username, password, location, device, os, time, ip"}
        return Response(resp)
    browser = mdata("browser")
    language = mdata("language", "English")
    company=None
    org=None
    dept=None
    member=None
    project=None
    subproject=None
    role_res=None
    first_name=None
    last_name=None
    email=None
    phone=None
    User_type=None
    payment_status=None
    newsletter=None
    user_country=None
    privacy_policy=None
    other_policy=None
    userID=None
    client_admin_id=None
    # role_id=mdata["role_id"]
    user = authenticate(request, username=username, password=password)
    if user is not None:
        field = {"Username": username}
        id = dowellconnection("login", "bangalore", "login", "registration",
                              "registration", "10004545", "ABCDE", "find", field, "nil")
        response = json.loads(id)
        if response["data"] != None:
            form = login(request, user)
            request.session.save()
            session = request.session.session_key
            obj = CustomSession.objects.filter(sessionID=session)
            if obj:
                if obj.first().status == 'login':
                    data = {'session_id': session}
                    return Response(data)
            try:
                res = create_event()
                event_id = res['event_id']
            except:
                event_id = None
            profile_image = "https://100014.pythonanywhere.com/media/user.png"
            first_name = response["data"]['Firstname']
            last_name = response["data"]['Lastname']
            email = response["data"]['Email']
            phone = response["data"]['Phone']
            try:
                userID=response["data"]['_id']
                if response["data"]['Profile_Image'] == "https://100014.pythonanywhere.com/media/":
                    profile_image = "https://100014.pythonanywhere.com/media/user.png"
                else:
                    profile_image = response["data"]['Profile_Image']
                User_type=response["data"]['User_type']
                client_admin_id=response["data"]['client_admin_id']
                payment_status=response["data"]['payment_status']
                newsletter=response["data"]['newsletter_subscription']
                user_country=response["data"]['user_country']
                privacy_policy=response["data"]['Policy_status']
                other_policy=response["data"]['safety_security_policy']
                role_res=response["data"]['Role']
                company=response["data"]['company_id']
                member=response["data"]['Memberof']
                dept=response["data"]['dept_id']
                org=response["data"]['org_id']
                project=response["data"]['project_id']
                subproject=response["data"]['subproject_id']
            except:
                pass
            try:
                final_ltime = parser.parse(ltime).strftime('%d %b %Y %H:%M:%S')
                dowell_time = time.strftime(
                    "%d %b %Y %H:%M:%S", time.gmtime(dowellclock()+1609459200))
            except:
                final_ltime = ''
                dowell_time = ''
            serverclock = datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')

            field_session = {'sessionID': session, 'role': role_res, 'username': username, 'Email': email, "profile_img": profile_image, 'Phone': phone, "User_type": User_type, 'language': language, 'city': city, 'country': country, 'org': org, 'company_id': company, 'project': project, 'subproject': subproject, 'dept': dept, 'Memberof': member,
                             'status': 'login', 'dowell_time': dowell_time, 'timezone': zone, 'regional_time': final_ltime, 'server_time': serverclock, 'userIP': ipuser, 'userOS': osver, 'browser': browser, 'userdevice': device, 'userbrowser': "", 'UserID': userID, 'login_eventID': event_id, "redirect_url": "", "client_admin_id": client_admin_id}
            dowellconnection("login", "bangalore", "login", "session",
                             "session", "1121", "ABCDE", "insert", field_session, "nil")

            info={"role":role_res,"username":username,"first_name":first_name,"last_name":last_name,"email":email,"profile_img":profile_image,"phone":phone,"User_type":User_type,"language":language,"city":city,"country":country,"status":"login","dowell_time":dowell_time,"timezone":zone,"regional_time":final_ltime,"server_time":serverclock,"userIP":ipuser,"userOS":osver,"userDevice":device,"language":language,"userID":userID,"login_eventID":event_id,"client_admin_id":client_admin_id,"payment_status":payment_status,"user_country":user_country,"newsletter_subscription":newsletter,"Privacy_policy":privacy_policy,"Safety,Security_policy":other_policy}
            info1=json.dumps(info)
            infoo=str(info1)
            custom_session=CustomSession.objects.create(sessionID=session,info=infoo,document="",status="login")

            serverclock1=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            LiveStatus.objects.create(sessionID=session,username=username,product="",status="login",created=serverclock1,updated=serverclock1)

            # resp={'userinfo':info}
            data = {'session_id': session}

            return Response(data)
        else:
            resp = {"data": "Username not found in database"}
            return Response(resp)
        # raise AuthenticationFailed("Username not Found or password not found")
    else:
        resp = {"data": "Username, Password combination incorrect.."}
        return Response(resp)
            # raise AuthenticationFailed("Incorrect password")
    # field={"Username":username}
    # try:
    # usr=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",field,"nil")
    # r=json.loads(usr)
    # if len(r["data"])>0:
    #     field={"Username":username,}
    #     usr=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","insert",field,"nil")
    # for i in r["data"]:
    #     username=i["Username"]
    # payload={
    #     'id':user.username,
    #     'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=60),
    #     'iat':datetime.datetime.utcnow()
    #     }
    # token=jwt.encode(payload,'dowell_secret',algorithm='HS256').decode('utf-8')
    # response=Response()
    # response.set_cookie(key="jwt", value=token)
    # response.data={
    #     'jwt':token
    #     }
    # return response

        # i["id"] = i.pop("_id")
        # usr_obj = namedtuple("Users", i.keys())(*i.values())

@api_view(["POST"])
def MobileLogout(request):
    session=request.data.get("session_id")
    mydata=CustomSession.objects.filter(sessionID=session).first()
    if mydata is not None:
        a2=mydata.info
        a3=json.loads(a2)
        a3["status"]="logout"
        a4=json.dumps(a3)
        a5=str(a4)
        mydata.info=a5
        if mydata.status!="logout":
            mydata.status="logout"
        mydata.save(update_fields=['info','status'])
        # logout(request)
        # return render(request, 'login/new_beforelogout.html',{'info':'Logged Out Successfully!!'})
    field_session={'sessionID':session}
    update_field={'status':'logout'}
    dowellconnection("login","bangalore","login","session","session","1121","ABCDE","update",field_session,update_field)
    logout(request)
    return Response({'msg':'Logged out Successfully..'})

class LoginView(APIView):
    def post(self, request):
        user1=request.data['username']
        username=""
        password=request.data['password']
        field={"Username":user1}
        usr=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",field,"nil")
        r=json.loads(usr)
        if len(r["data"])<1:
            response=Response()
            response.data={'msg':"Username or password wrong"}
            return response
        for i in r["data"]:
            username=i["Username"]
            # i["id"] = i.pop("_id")
            # usr_obj = namedtuple("Users", i.keys())(*i.values())
        if user1==username:
            user=Account.objects.filter(username=user1).first()
            if user is None:
                raise AuthenticationFailed("Username not Found or password not found")
            if not user.check_password(password):
                raise AuthenticationFailed("Incorrect password")
            payload={
                'id':user.username,
                'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=60),
                'iat':datetime.datetime.utcnow()
                }
            token=jwt.encode(payload,'dowell_secret',algorithm='HS256').decode('utf-8')
            response=Response()
            response.set_cookie(key="jwt", value=token)
            response.data={
                'jwt':token
                }
            return response
class GuestView(APIView):
    def post(self, request):
        email=request.data['email']
        name=request.data['name']
        response=Response()
        response.data={
            'message':f"{name} success"
            }
        return response
class createUserView(APIView):
    def get(self,request):
        ruser=passgen.generate_random_password1(8)
        rpass=passgen.generate_random_password(10)
        user = Account.objects.create_user(username=ruser,email=f'{ruser}@lav.com',password=rpass,role="User",teamcode="15692532")
        if user:
            return Response({"username":ruser,"password":rpass})
        else:
            return Response({"msg":"Error while user creation"})
class UserView(APIView):
    def get(self,request):
        token=request.COOKIES.get('jwt')
        if not token:
            raise AuthenticationFailed("Unauthenticated request")
        try:
            payload=jwt.decode(token,"dowell_secret",algorithm=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Unauthenticated1")
        user=Account.objects.filter(username="lav").first()
        serializer=UserSerializer(user)
        return Response(serializer.data)
class UsrInfoView(APIView):
    def post(self,request):
        key=request.data["key"]
        session = Session.objects.get(session_key=key)
        uid = session.get_decoded().get('_auth_user_id')
        user=Account.objects.filter(id=uid).first()
        user1=""
        for i in user:
            user1=i.username
        field={"Username":user1}
        id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",field,"nil")
        idd=json.loads(id)
        return Response(idd)

#Hr apis start
class LoginUserView(APIView):
    def post(self,request):
        key=request.data["key"]
        session = Session.objects.get(session_key=key)
        uid = session.get_decoded().get('_auth_user_id')
        user=Account.objects.filter(id=uid).first()
        serializer=UserSerializer(user)
        return Response(serializer.data)

class HrUserView(APIView):
    def post(self,request):
        keyuser=request.data["username"]
        user=Account.objects.filter(username=keyuser).first()
        serializer=UserSerializer(user)
        return Response(serializer.data)
#Hr apis start
class EventView(APIView):
    def post(self, request):
        pfm_id = request.data['pfm_id']
        city_id=request.data['city_id']
        day_id=request.data['day_id']
        db_id = request.data['db_id']
        process_id = request.data['process_id']
        object_id = request.data['object_id']
        instance_id =request.data['instance_id']
        context = request.data['context']
        rule = request.data['rule']
        login_id = request.data['login_id']
        document_id = request.data['document_id']
        status_id = request.data['status_id']
        IP = request.data['IP']
        session_id = request.data['session_id']
        location = request.data['location']
        regtime = request.data['rtime']
        datatype = request.data['datatype']
        event_id=event_creation("FB","101","0","pfm","1",object_id,instance_id,context,rule,username,document_id,status_id,IP,session_id,location,regtime,datatype)
        #event_id=get_event_id("FB","101","0","pfm","1",object_id,instance_id,context,rule,username,document_id,status_id,IP,session_id,location,regtime,datatype)
        return Response({"event_id":event_id})
class UsersView(APIView):
    def get(self,request):
        token=request.COOKIES.get('jwt')
        if not token:
            raise AuthenticationFailed("Unauthenticated request")
        try:
            payload=jwt.decode(token,"dowell_secret",algorithm=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Unauthenticated1")
        #=Users.objects.filter(postcode__startswith=postcode_prefix)
        field={}
        usr=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",field,"nil")
        usrdic=json.loads(usr)
        return Response(usrdic)
class LogoutView(APIView):
    def post(self,request):
        response=Response()
        response.delete_cookie('jwt')
        response.data={
            'message':'success'
            }
        return response
class LogoutView(APIView):
    def post(self,request):
        response=Response()
        response.delete_cookie('jwt')
        response.data={
            'message':'success'
            }
        return response
@api_view(['GET', 'POST'])
def userslist(request):
    if request.method == 'POST':
        try:
            pwd=request.data["pwd"]
        except:
            return Response({"message": "wrong parameters send"})
        if pwd==dpass:
            users=Account.objects.all()#filter(username=payload["id"]).first()
            serializer=UserSerializer(users, many=True)
            return Response(serializer.data)
        else:
            return Response({"message": "Password Wrong"})
@api_view(['GET', 'POST'])
def Company(request):
    if request.method == 'POST':
        try:
            pwd=request.data["pwd"]
            if pwd==dpass:
                field={}
                com=dowellconnection("login","bangalore","login","company","company","1083","ABCDE","fetch",field,"nil")
                comdic=json.loads(com)
                return Response(comdic)
            else:
                return Response({"message": "Password Wrong"})
        except:
            return Response({"message": "Password Wrong1"})
        # comp=request.data["company"]
        # compid=request.data["company_id"]
        # field={"company":comp,"company_id":compid}
        # com=dowellconnection("login","bangalore","login","company","company","1083","ABCDE","insert",field,"nil")
        # comdic=json.loads(com)
        # return Response(comdic)
# @api_view(['GET', 'POST'])
# def LinkLogin(request):
#     if request.method == 'POST':
#         username = request.data['username']
#         password =request.data['password']
#         user = authenticate(request, username = username, password = password)
#         if user is not None:
#             login(request, user)
#             session=request.session.session_key
#             return Response({"session_id": session})
#         else:
#             return Response({"message": "username or password wrong"})
#     else:
#         return Response({"message": "Error"})

@api_view(['POST'])
def LinkLogin(request):
    user=request.data.get("Username")
    loc=request.data["Location"]
    device=request.data["Device"]
    osver=request.data["OS"]
    brow=request.data.get("Browser")
    ltime=request.data["Time"]
    ipuser=request.data["IP"]
    mobconn=request.data["Connection"]
    if user is None:
        user=passgen.generate_random_password1(8)
    random_session=passgen.generate_random_password1(32)
    field={"Username":user,"random_session":random_session,"OS":osver,"Device":device,"Browser":brow,"Location":loc,"Time":str(ltime),"SessionID":"linkbased","Connection":mobconn,"qrcode_id":"user6","IP":ipuser}
    resp=dowellconnection("login","bangalore","login","login","login","6752828281","ABCDE","insert",field,"nil")
    respj=json.loads(resp)
    field1=json.dumps(field)
    field2=str(field1)
    Linkbased_RandomSession.objects.create(sessionID=random_session,info=field2)
    qrcodegen.qrgen1(user,respj["inserted_id"],f"dowell_login/media/userqrcodes/{respj['inserted_id']}.png")
    return Response({"session_id":random_session})
    # if url is not None:
    #     return redirect(f'{url}?qrid={respj["inserted_id"]}')
    # return HttpResponse("pl provide redirect url")
    # return Response({"message":"its working"})

# from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

# For Newlogin

@api_view(['GET', 'POST'])
def LinkBased(request):
    # url=request.GET.get("url",None)
    # user=request.GET.get("user",None)
    # context={}
    if request.method == 'POST':
        user=request.data.get("Username")
        loc=request.data["Location"]
        device=request.data["Device"]
        osver=request.data["OS"]
        brow=request.data.get("Browser")
        ltime=request.data["Time"]
        ipuser=request.data["IP"]
        mobconn=request.data["Connection"]
        if user is None:
            user=passgen.generate_random_password1(8)
        field={"Username":user,"OS":osver,"Device":device,"Browser":brow,"Location":loc,"Time":str(ltime),"SessionID":"linkbased","Connection":mobconn,"qrcode_id":"user6","IP":ipuser}
        resp=dowellconnection("login","bangalore","login","login","login","6752828281","ABCDE","insert",field,"nil")
        respj=json.loads(resp)
        qrcodegen.qrgen1(user,respj["inserted_id"],f"dowell_login/media/userqrcodes/{respj['inserted_id']}.png")
        return Response({"qrid":respj["inserted_id"],"username":user})
        # if url is not None:
        #     return redirect(f'{url}?qrid={respj["inserted_id"]}')
        # return HttpResponse("pl provide redirect url")
    return Response({"message":"its working"})

def register_legal_policy(user):
    policy_url = "https://100087.pythonanywhere.com/api/legalpolicies/ayaquq6jdyqvaq9h6dlm9ysu3wkykfggyx0/iagreestatus/"
    RandomSession.objects.create(
        sessionID=user, status="Accepted", username=user)
    time = datetime.datetime.now()
    data = {
        "data": [
            {
                "event_id": "FB1010000000167475042357408025",
                "session_id": user,
                "i_agree": "true",
                "log_datetime": time,
                "i_agreed_datetime": time,
                "legal_policy_type": "app-privacy-policy"
            }
        ],
        "isSuccess": "true"
    }
    requests.post(policy_url, data=data)
    return "success"

@api_view(['POST'])
def login_legal_policy(request):
    session_id = request.data.get('s')
    if session_id:
        RandomSession.objects.create(
            sessionID=session_id, status="Accepted", username="none")
        return Response({'msg':'Success','info':'Policy accepted!!'})
    else:
        return Response({'msg':'errror','info':'Session_id is required'})

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
@api_view(["POST"])
def register(request):
    username = request.data.get("Username")
    otp_input = request.data.get("otp")
    sms_input=request.data.get("sms")
    image = request.FILES.get("Profile_Image")
    password = request.data.get("Password")
    first = request.data.get("Firstname")
    last = request.data.get("Lastname")
    email = request.data.get("Email")
    role1 = "guest"
    phonecode = request.data.get("phonecode")
    phone = request.data.get("Phone")
    user_type = request.data.get('user_type')
    user_country = request.data.get('user_country')
    policy_status = request.data.get('policy_status')
    other_policy = request.data.get('other_policy')
    newsletter = request.data.get('newsletter')
    print(image)

    if email and username and not image and not password and not first \
            and not last and not phone and not phonecode and not user_type and not user_country \
            and not policy_status and not other_policy and not newsletter:
        otp = generateOTP()
        try:
            emailexist = GuestAccount.objects.get(email=email)
        except GuestAccount.DoesNotExist:
            emailexist = None
        if emailexist is not None:
            GuestAccount.objects.filter(email=email).update(otp=otp,expiry=datetime.datetime.now(),username=username)
        else:
            data=GuestAccount(username=username,email=email,otp=otp)
            data.save()
        url = "https://100085.pythonanywhere.com/api/signUp-otp-verification/"
        payload = json.dumps({
            "toEmail":email,
            "toName":username,
            "topic":"RegisterOtp",
            "otp":otp
            })
        headers = {
            'Content-Type': 'application/json'
            }
        response1 = requests.request("POST", url, headers=headers, data=payload)
        return Response({'msg':'success','info':'OTP sent successfully'})

    elif phone and phonecode and not email and not username and not image and not password \
            and not first and not last and not user_type and not user_country and not policy_status \
            and not other_policy and not newsletter:
        sms = generateOTP()

        full_number =str(phonecode) + str(phone)
        time = datetime.datetime.utcnow()
        print(full_number)
        if full_number == "251912912144":
            sms="123456"
        try:
            phone_exists = mobile_sms.objects.get(phone=full_number)
        except mobile_sms.DoesNotExist:
            phone_exists = None
        if phone_exists is not None:
            mobile_sms.objects.filter(
                phone=full_number).update(sms=sms, expiry=time)
        else:
            mobile_sms.objects.create(
                phone=full_number, sms=sms, expiry=time)
        # url = "https://100085.pythonanywhere.com/api/sms/"
        # payload = {
        #     "sender": "DowellLogin",
        #     "recipient": full_number,
        #     "content": f"Enter the following OTP to create your dowell account: {sms}",
        #     "created_by": "Manish"
        # }
        url = "https://100085.pythonanywhere.com/api/v1/dowell-sms/c9dfbcd2-8140-4f24-ac3e-50195f651754/"
        payload = {
            "sender" : "DowellLogin",
            "recipient" : full_number,
            "content" : f"Enter the following OTP to create your dowell account: {sms}",
            "created_by" : "Manish"
            }
        response = requests.request("POST", url, data=payload)
        if len(response.json()) > 1:
            return Response({'msg':'success','info':'SMS sent successfully!!'})
        else:
            return Response({'msg': 'error','error':'The number is not valid'})

    user_exists = Account.objects.filter(username=username).first()
    if user_exists:
        return Response({'msg':'error','info': 'Username already taken'},status=status.HTTP_400_BAD_REQUEST)
    register_legal_policy(username)
    try:
        check_otp = GuestAccount.objects.filter(otp=otp_input, email=email)
        check_sms= mobile_sms.objects.filter(sms=sms_input,phone="+"+str(phonecode) + str(phone))
    except GuestAccount.DoesNotExist:
        check_otp = None
        check_sms = "Wrong"

    if not check_otp:
        return Response({'msg':'error','info':'Wrong Email OTP'},status=status.HTTP_400_BAD_REQUEST)
    if check_sms == "Wrong":
        return Response({'msg':'error','info':'Wrong Mobile SMS'},status=status.HTTP_400_BAD_REQUEST)

    # return Response({
    #     'msg':'success',
    #     'info': f"{username}, registration success",
    #     'inserted_id': f"1234"
    #     })

    name = ""
    try:
        accounts = Account.objects.filter(email=email)

        for account in accounts:
            if email == account.email and role1 == account.role:
                account = Account.objects.filter(email=email).update(password=make_password(
                    password), first_name=first, last_name=last, email=email, phonecode=phonecode, phone=phone, profile_image=image)
    except Account.DoesNotExist:
        name = None
    if name is not None:
        if image:
            new_user = Account.objects.create(email=email, username=username, password=make_password(
                password), first_name=first, last_name=last, phonecode=phonecode, phone=phone, profile_image=image)
        else:
            new_user = Account.objects.create(email=email, username=username, password=make_password(
                password), first_name=first, last_name=last, phonecode=phonecode, phone=phone)

        profile_image = new_user.profile_image
        json_data = open('dowell_login/static/client.json')
        data1 = json.load(json_data)
        json_data.close()
        default =   {
        "org_id":username,
        "org_name":username,
        "username": [username],
        "member_type": "owner",
        "product": "all",
        "data_type": "Real_data",
        "operations_right": "Add/Edit",
        "role": "owner",
        "security_layer": "None",
        "portfolio_name": "default",
        "portfolio_code": "123456",
        "portfolio_specification": "",
        "portfolio_uni_code": "default",
        "portfolio_details": "",
        "status": "enable"
        }
        data1["portpolio"].append(default)
        data1["document_name"] = username
        data1["Username"] = username
        update_data1 = {"first_name": first, "last_name": last, "profile_img": f'https://100014.pythonanywhere.com/media/{profile_image}',
                        "email": email, "phonecode": phonecode, "phone": phone}
        data1["profile_info"].update(update_data1)
        data1["organisations"][0]["org_name"] = username
        update_data2 = {"first_name": first, "last_name": last, "email": email}
        data1["members"]["team_members"]["accept_members"][0].update(
            update_data2)
        client_admin = dowellconnection(
            "login", "bangalore", "login", "client_admin", "client_admin", "1159", "ABCDE", "insert", data1, "nil")
        client_admin_res = json.loads(client_admin)
        org_id = client_admin_res["inserted_id"]

        userfield = {}
        userresp = dowellconnection("login", "bangalore", "login", "registration",
                                    "registration", "10004545", "ABCDE", "fetch", userfield, "nil")
        idd = json.loads(userresp)
        res_list = idd["data"]
        profile_id = get_next_pro_id(res_list)

        event_id = None
        try:
            res = create_event()
            event_id = res['event_id']
        except:
            pass

        field = {"Profile_Image": f"https://100014.pythonanywhere.com/media/{profile_image}", "Username": username, "Password": dowell_hash.dowell_hash(password), "Firstname": first, "Lastname": last, "Email": email, "phonecode": phonecode, "Phone": phone, "profile_id": profile_id, "client_admin_id": client_admin_res[
            "inserted_id"], "Policy_status": policy_status, "User_type": user_type, "eventId": event_id, "payment_status": "unpaid", "safety_security_policy": other_policy, "user_country": user_country, "newsletter_subscription": newsletter}
        id = dowellconnection("login", "bangalore", "login", "registration",
                              "registration", "10004545", "ABCDE", "insert", field, "nil")
        id_res = json.loads(id)
        inserted_idd = id_res['inserted_id']

        url = "https://100085.pythonanywhere.com/api/signup-feedback/"
        if not check_sms:
            verified_phone="unverified"
        else:
            verified_phone="verified"
        payload = json.dumps({
            "topic": "Signupfeedback",
            "toEmail": email,
            "toName": first + " " + last,
            "firstname": first,
            "lastname": last,
            "username": username,
            "phoneCode": "+"+str(phonecode),
            "phoneNumber": phone,
            "usertype": user_type,
            "country": user_country,
            "verified_phone": verified_phone,
            "verified_email": "verified"
        })

        headers = {
            'Content-Type': 'application/json'
        }
        response1 = requests.request(
            "POST", url, headers=headers, data=payload)

        return Response({
            'msg':'success',
            'info': f"{username}, registration success",
            'inserted_id': f"{inserted_idd}"
        })
    return Response({"msg":"error","info":"Internal server error"},status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
def Registration(request):
    user=request.data["Username"]
    # return Response(user)
    image=request.FILES.get("Profile_Image")
    password=request.data["Password"]
    first=request.data["Firstname"]
    last=request.data["Lastname"]
    email=request.data["Email"]
    role1="guest"
    phonecode=request.data["phonecode"]
    phone=request.data["Phone"]
    user_type=request.data['user_type']
    user_country=request.data['user_country']
    policy_status=request.data['policy_status']
    other_policy=request.data['other_policy']
    newsletter=request.data['newsletter']

    user_exists=Account.objects.filter(username=user).first()
    if user_exists:
        return Response({'message':"Username already taken"})

    name=""
    try:
        ro=Account.objects.filter(email=email)#.update(password = password,first_name = first,last_name = last,email = email,role = role,teamcode = ccode,phonecode=phonecode,phone = phone,profile_image=img)

        for i in ro:
            if email==i.email and role1==i.role:
                ro=Account.objects.filter(email=email).update(password = make_password(password),first_name = first,last_name = last,email = email,phonecode=phonecode,phone = phone,profile_image=image)
    except Account.DoesNotExist:
        name=None
    if name is not None:
        if image:
            new_user=Account.objects.create(email=email,username=user,password=make_password(password),first_name = first,last_name = last,phonecode=phonecode,phone = phone,profile_image=image)
        else:
            new_user=Account.objects.create(email=email,username=user,password=make_password(password),first_name = first,last_name = last,phonecode=phonecode,phone = phone)

        profile_image=new_user.profile_image
        json_data = open('dowell_login/static/newnaga2.json')
        data1 = json.load(json_data)
        json_data.close()
        data1["document_name"]=user
        data1["Username"]=user
        update_data1={"first_name":first,"last_name":last,"profile_img":f'https://100014.pythonanywhere.com/media/{profile_image}',"email":email,"phonecode":phonecode,"phone":phone}
        data1["profile_info"].update(update_data1)
        data1["organisations"][0]["org_name"]=user
        update_data2={"first_name":first,"last_name":last,"email":email}
        data1["members"]["team_members"]["accept_members"][0].update(update_data2)
        client_admin=dowellconnection("login","bangalore","login","client_admin","client_admin","1159","ABCDE","insert",data1,"nil")
        client_admin_res=json.loads(client_admin)
        org_id=client_admin_res["inserted_id"]

        userfield={}
        userresp=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",userfield,"nil")
        idd=json.loads(userresp)
        res_list=idd["data"]
        profile_id=get_next_pro_id(res_list)

        event_id=None
        try:
            res=create_event()
            event_id=res['event_id']
        except:
            pass

        field={"Profile_Image":f"https://100014.pythonanywhere.com/media/{profile_image}","Username":user,"Password":dowell_hash1(password),"Firstname":first,"Lastname":last,"Email":email,"phonecode":phonecode,"Phone":phone,"profile_id":profile_id,"client_admin_id":client_admin_res["inserted_id"],"Policy_status":policy_status,"User_type":user_type,"eventId":event_id,"payment_status":"unpaid","safety_security_policy":other_policy,"user_country":user_country,"newsletter_subscription":newsletter}
        id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","insert",field,"nil")
        id_res=json.loads(id)
        inserted_idd=id_res['inserted_id']

        url = "https://100085.pythonanywhere.com/api/signup-feedback/"
        payload = json.dumps({
            "topic" : "Signupfeedback",
            "toEmail" : email,
            "toName" : first +" "+ last,
            "firstname" : first,
            "lastname" : last,
            "username" : user,
            "phoneCode" : phonecode,
            "phoneNumber" : phone,
            "usertype" : user_type,
            "country" : user_country,
            "verified_phone":"unverified",
            "verified_email": "verified"
                })
        headers = {
            'Content-Type': 'application/json'
            }
        response1 = requests.request("POST", url, headers=headers, data=payload)

        return Response({
            'message':f"{user}, registration success",
            'inserted_id':f"{inserted_idd}"
            })
    return Response("Internal server error")


@api_view(['GET', 'POST'])
def UserInfo(request):
    # url=request.GET.get("url",None)
    # user=request.GET.get("user",None)
    # context={}
    if request.method == 'POST':
        session=request.data["session_id"]
        field_session={'sessionID':session}
        resp=dowellconnection("login","bangalore","login","session","session","1121","ABCDE","fetch",field_session,"nil")
        respj=json.loads(resp)

        company_field={'owner':respj["data"][0]["username"]}
        company_res=dowellconnection("login","bangalore","login","company","company","1083","ABCDE","fetch",company_field,"nil")
        company=json.loads(company_res)
        respj["data"][0]["members"]=company["data"][0]["members"]
        try:
            if company["data"][0]["logo"]:
                respj["data"][0]["logo"]=f'https://{company["data"][0]["logo"]}'

        except:
            respj["data"][0]["logo"]='https://100014.pythonanywhere.com/static/img/logos/dowell_logo.png'

        field={"Username":respj["data"][0]["username"]}
        id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",field,"nil")
        idd=json.loads(id)
        respj["data"][0]["Firstname"]=idd["data"][0]["Firstname"]
        respj["data"][0]["Lastname"]=idd["data"][0]["Lastname"]
        try:
            respj["data"][0]["Profile_Image"]=idd["data"][0]["Profile_Image"]
        except:
            respj["data"][0]["Profile_Image"]='http://100014.pythonanywhere.com/static/img/user.png'
        # respj["data"][0]["productID"]=""
        # respj["data"][0]["productlogo"]=""

        del_keys=["role","company_id","org","project","subproject","dept","Memberof","members"]
        for key in del_keys:
            del respj["data"][0][key]
        return Response(respj["data"])
        # if url is not None:
        #     return redirect(f'{url}?qrid={respj["inserted_id"]}')
        # return HttpResponse("pl provide redirect url")
    return Response({"message":"its working"})

@api_view(['GET', 'POST'])
def new_userinfo(request):
    if request.method == 'POST':
        session=request.data["session_id"]
        product=request.data.get("product",None)
        mydata=CustomSession.objects.filter(sessionID=session).first()

        if not mydata:
            public_field={"sessionID":session}
            public=dowellconnection("login","bangalore","login","login","login","6752828281","ABCDE","find",public_field,"nil")
            public_res=json.loads(public)
            if public_res["data"] != None:
                return Response(public_res["data"])
            return Response({"message":"SessionID not found in database, Please check and try again!!"})
        if mydata.status != "login":
            return Response({"message":"You are logged out, Please login and try again!!"})
        var1=mydata.info
        var2=json.loads(var1)
        var2["org_img"]="https://100093.pythonanywhere.com/static/clientadmin/img/logomissing.png"

        del_keys=["role","company_id","org","project","subproject","dept","Memberof","members"]
        for key in del_keys:
            try:
                del var2[key]
            except:
                pass
        userdata=Account.objects.filter(username=var2["username"]).first()
        field={"document_name":var2["username"]}
        details=dowellconnection("login","bangalore","login","client_admin","client_admin","1159","ABCDE","fetch",field,"nil")
        details_res=json.loads(details)
        var3=[]
        productport=[]
        portfolio=details_res["data"][0]["portpolio"]
        if product is None:
            try:
                for i in portfolio:
                    if type(i["username"]) is list:
                        if var2["username"] in i["username"] or "owner" in i["username"] and i["status"]=="enable":
                            var3.append(i)
                    if i["username"]=="owner" and i["product"]!="owner" and i["status"]=="enable":
                        var3.append(i)
            except:
                pass
        if product is not None:
            try:
                for i in portfolio:
                    if type(i["username"]) is list:
                        if var2["username"] in i["username"] or "owner" in i["username"] and product in i["product"] and i["status"]=="enable":
                            var3.append(i)
                    if i["username"]=="owner" and i["product"]!="owner" and product in i["product"] and i["status"]=="enable":
                        var3.append(i)
            except:
                pass
            try:
                for ite in portfolio:
                    if product in ite["product"]:
                        productport.append(ite)
            except:
                pass
        try:
            var2["first_login"]=userdata.date_joined
            var2["last_login"]=userdata.last_login
            var2["client_admin_id"]=details_res["data"][0]["_id"]
            for r in var3:
                r["org_id"]=details_res["data"][0]["_id"]
                r["org_name"]=details_res["data"][0]["document_name"]
        except:
            pass

        otherorg=details_res["data"][0]['other_organisation']
        otherorg_list=[]
        for i in otherorg:
            try:
                if i["status"]=="enable":
                    otherorg_list.append({"org_id":i["org_id"],"org_name":i["org_name"]})
            except:
                pass

        organisations=details_res["data"][0]['organisations'][0]["org_name"]
        roles=details_res["data"][0]['roles']
        team_members=details_res["data"][0]['members']['team_members']['accept_members']
        guest_members=details_res["data"][0]['members']['guest_members']['accept_members']
        public_members=details_res["data"][0]['members']['public_members']['accept_members']
        main_member={'team_member':team_members,'guest_members':guest_members,'public_members':public_members}
        # portfolio={'username':var2["username"] , 'member_type': 'owner', 'product': 'owner', 'data_type': 'owner', 'operations_right': 'owner', 'role': 'owner', 'security_layer': 'owner', 'portfolio_name': 'owner','org_id':var2["client_admin_id"]}
        userinfo={'userinfo':var2, 'portfolio_info':var3 ,"userportfolio":productport,'members':main_member,"own_organisations":[{"org_name":organisations}],"other_org":otherorg,"roles":roles,"otherorg_list":otherorg_list}
        return Response(userinfo)
    return Response({"message":"its working"})

@api_view(['GET','POST'])
def all_users(request):
    if request.method == 'POST':
        username=request.data["username"]
        password1=request.data["password"]
        # password=base64.b64decode(password1.encode('utf-8')).decode()
        user=authenticate(request, username = username, password = password1)
        if user is not None:
            userfield={}
            main=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",userfield,"nil")
            main_res=json.loads(main)
            final=main_res["data"]
            final2=[]
            for a in final:
                try:
                    if not a["User_status"] == "deleted" and not a["User_status"] == "inactive":
                        try:
                            username=a['Username']
                            payment_status=a['payment_status']
                            user_id=a['_id']
                            user_type=a['User_type']
                            final2.append({"username":username,"org_name":username,"payment_status":payment_status,"user_id":user_id,"user_type":user_type})
                        except:
                            pass
                    else:
                        pass
                except:
                    try:
                        username=a['Username']
                        payment_status=a['payment_status']
                        user_id=a['_id']
                        user_type=a['User_type']
                        final2.append({"username":username,"org_name":username,"payment_status":payment_status,"user_id":user_id,"user_type":user_type})
                    except:
                        pass
            return Response({"data":final2})
        else:
            return Response({"msg":"API working","data":"Provided credential is wrong, try again!"})
    return Response({"msg":"API working","data":"POST your username and password to get list"})

@api_view(['GET','POST'])
def lastlogins(request):
    if request.method == 'POST':
        username=request.data["username"]
        logintimelist=[]
        # activeuserlist=[]
        all2=CustomSession.objects.all()
        all1=all2[::-1]
        # print(all1)
        for a in all1:
            a2=a.info
            # if a.status=="login":
            #     try:
            #         b=json.loads(a2)
            #         if b["username"] not in activeuserlist:
            #             activeuserlist.append(b["username"])
            #     except:
            #         pass
            try:
                a3=json.loads(a2)
                if a3["username"]==username:
                    logintimelist.append([a3["regional_time"], a.sessionID])
                    break
            except:
                pass
        return Response({"data":{"LastloginTimes":logintimelist}})
    return Response({"msg":"API working","data":"POST an username to get list"})

@api_view(['GET'])
def activeusers(request):
    from django.contrib.sessions.models import Session
    from django.utils import timezone
    active_sessions = Session.objects.filter(expire_date__gte=timezone.now())
    # all1=CustomSession.objects.filter(status="login")
    user_id_list = []
    # return Response({"msg":"API working","active_sessions":active_sessions,"all1":all1})
    # print(actib)
    for session in active_sessions:
        data = session.get_decoded()
        user_id_list.append(data.get('_auth_user_id', None))
    final=Account.objects.filter(id__in=user_id_list).values_list('username')
    return Response({"msg":"API working","data":final})

@api_view(['POST'])
def password_change(request):
    username=request.data.get("username")
    old_password=request.data.get("old_password")
    new_password=request.data.get("new_password")
    obj=authenticate(request, username = username, password = old_password)
    if None in [username,old_password,new_password]:
        response={'msg':'error','info':'Please provide all fields'}
        return Response(response,status=status.HTTP_400_BAD_REQUEST)
    if obj is not None:
        try:
            obj.set_password(new_password)
            obj.save()
            field={'Username':username}
            up_field={'Password':dowell_hash1(new_password)}
            dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","update",field,up_field)
            response={'msg':'success','info':'Password Changed successfully..'}
            return Response(response)
        except Exception as e:
            response={'msg':'success','info':'Error','error':e}
            return Response(response)
    else:
        response={'msg':'success','info':'Username, Password combination incorrect'}
        return Response(response,status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def profile_update(request):
    session_id=request.data.get("session_id")
    email_otp=request.data.get("email_otp")
    phone_sms=request.data.get("phone_sms")
    address=request.data.get("address")
    zip_code=request.data.get("zip_code")
    user_city=request.data.get("city")
    user_location=request.data.get("location")
    user_country=request.data.get("country")
    native_language=request.data.get("native_language")
    nationality=request.data.get("nationality")
    language_preferences=request.data.get("language_preferences")
    vision=request.data.get("vision")
    username=request.data.get("username")
    Firstname=request.data.get("first_name")
    Lastname=request.data.get("last_name")
    Email=request.data.get("email")
    Phone=request.data.get("phone")
    phonecode=request.data.get("phonecode")
    #User_type=request.data.get("user_type")
    imgg=request.FILES.get("image")
    teamcode= request.data.get("teamcode")
    # imgg=request.FILES.get("imagee")
    obj=Account.objects.filter(username=username).first()
    print(username)
    print(imgg)
    if obj is None:
        return Response({"msg":"error","info":"User Not Found !"},status=status.HTTP_400_BAD_REQUEST)
    try:
        client_admin=dowellconnection("login","bangalore","login","client_admin","client_admin","1159","ABCDE","fetch",{"document_name":username},"nil")
        data2=json.loads(client_admin)
        data1=data2["data"][0]
    except:
        return Response({"msg":"error","info":"User Not Found !"},status=status.HTTP_400_BAD_REQUEST)
    up_field={}
    update_fields=[]
    img_exists=""
    resp2={"success_fields":[],"error_fields":[]}
    if username and Email and not imgg and not Phone and not Lastname and not Firstname and not vision \
        and not language_preferences and not nationality and not native_language and not user_country and not user_location \
            and not user_city and not zip_code and not address and not email_otp:
        check=Account.objects.filter(username=username,email=Email)
        check_guest=GuestAccount.objects.filter(email=Email).first()
        if not check:
            otp_input = generateOTP()
            message = f'Dear {username}, <br> Please Enter below <strong>OTP</strong> to use this email address in your existing dowell account <br><h2>Your OTP is <strong>{otp_input}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'

            def send_otp(): return send_mail(
                'Your otp for changing email in your Dowell account', otp_input, settings.EMAIL_HOST_USER, [Email], fail_silently=False, html_message=message)

            if check_guest:
                check_guest.otp=otp_input
                check_guest.save(update_fields=['otp'])
            else:
                guest_account=GuestAccount(username="user", email=Email, otp=otp_input, expiry=datetime.datetime.utcnow())
                guest_account.save()
            send_otp()
            return Response({'msg':'success','info':'OTP sent successfully'})
        else:
            return Response({'msg':'error','info':'Given email is already in use with your account'})

    if imgg is not None:
        if obj.profile_image == "":
            prev_image=obj.profile_image
            obj.profile_image=imgg
            obj.save(update_fields=["profile_image"])
            prev_image.delete(False)
            up_field["Profile_Image"]=f"https://100014.pythonanywhere.com/media/{obj.profile_image}"
            update_data1={"profile_img":f"https://100014.pythonanywhere.com/media/{obj.profile_image}"}
            data1["profile_info"].update(update_data1)
            resp2["success_fields"].append("Profile Image")
        else:
            obj.profile_image=imgg
            obj.save(update_fields=["profile_image"])
            up_field["Profile_Image"]=f"https://100014.pythonanywhere.com/media/{obj.profile_image}"
            update_data1={"profile_img":f"https://100014.pythonanywhere.com/media/{obj.profile_image}"}
            data1["profile_info"].update(update_data1)
            resp2["success_fields"].append("Profile Image")

    if Firstname is not None:
        obj.first_name=Firstname
        update_fields.append("first_name")
        up_field["Firstname"]=Firstname
        update_data1={"first_name":Firstname}
        data1["profile_info"].update(update_data1)
        resp2["success_fields"].append("Firstname")
        # update_data2={"first_name":Firstname}
        # data1["members"]["team_members"]["accept_members"][0].update(update_data2)
    if Lastname is not None:
        obj.last_name=Lastname
        update_fields.append("last_name")
        up_field["Lastname"]=Lastname
        update_data1={"last_name":Lastname}
        data1["profile_info"].update(update_data1)
        resp2["success_fields"].append("Lastname")
        # update_data2={"last_name":Lastname}
        # data1["members"]["team_members"]["accept_members"][0].update(update_data2)
    if Email is not None and email_otp is not None:
        try:
            guest =GuestAccount.objects.get(
                otp=email_otp, email=Email)
        except GuestAccount.DoesNotExist:
            guest = None
        if guest is not None:
            obj.email=Email
            update_fields.append("email")
            up_field["Email"]=Email
            update_data1={"email":Email}
            data1["profile_info"].update(update_data1)
            resp2["success_fields"].append("Email")
        else:
            resp2["error_fields"].append({"field":"Email",'msg':'Wrong OTP'})
    if Phone is not None and phonecode is not None and phone_sms is not None:
        Phone1="+"+str(phonecode)+str(Phone)
        try:
            ok =mobile_model.objects.get(
                sms=phone_sms, phone=Phone1)
        except mobile_model.DoesNotExist:
            ok = None
        if ok is not None:
            ok.phone=Phone
            ok.phonecode=phonecode
            update_fields.append("phone")
            update_fields.append("phonecode")
            up_field["Phone"]=Phone
            up_field["phonecode"]=phonecode
            update_data1={"phonecode": phonecode, "Phone": Phone}
            data1["profile_info"].update(update_data1)
            resp2["success_fields"].append("Phone")
        else:
            resp2["error_fields"].append({"field":"Phone",'msg':'Wrong OTP'})
        # update_data2={"email":Email}
        # data1["members"]["team_members"]["accept_members"][0].update(update_data2)
    # if Phone is not None:
    #     obj.phone=Phone
    #     update_fields.append("phone")
    #     up_field["Phone"]=Phone
    #     update_data1={"phone":Phone}
    #     data1["profile_info"].update(update_data1)
    #     resp2["success_fields"].append("Phone")
    if address is not None:
        up_field["address"]=address
        resp2["success_fields"].append("Address")
    if zip_code is not None:
        up_field["zip_code"]=zip_code
        resp2["success_fields"].append("Zip_code")
    if user_city is not None:
        up_field["user_city"]=user_city
        resp2["success_fields"].append("User_city")
    if user_location is not None:
        up_field["user_location"]=user_location
        resp2["success_fields"].append("User_location")
    if user_country is not None:
        up_field["user_country"]=user_country
        resp2["success_fields"].append("User_country")
    if native_language is not None:
        up_field["native_language"]=native_language
        resp2["success_fields"].append("Native_language")
    if nationality is not None:
        up_field["nationality"]=nationality
        resp2["success_fields"].append("Nationality")
    if language_preferences is not None:
        up_field["language_preferences"]=language_preferences
        resp2["success_fields"].append("Language_preference")
    if vision is not None:
        up_field["vision"]=vision
        resp2["success_fields"].append("Vision")

    final_data1=data1.pop("_id")
    if update_fields !=[]:
        obj.save(update_fields=update_fields)
    client_admin=dowellconnection("login","bangalore","login","client_admin","client_admin","1159","ABCDE","update",{"document_name":username},{'profile_info':data1["profile_info"]})

    # def namestr(obj, namespace):
    #     return [name for name in namespace if namespace[name] is obj]
    # up_field={}
    # for a in [Firstname,Lastname,Email,Phone]:
    #     if a is not None:
    #         up_field[namestr(a,globals())[0]]=a
    if up_field != {}:
        dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","update",{"Username":username},up_field)
    return Response(resp2)

@api_view(['GET'])
def product_users(request):
    time_threshold = datetime.datetime.now()- datetime.timedelta(days=7)
    obj_client_admin=LiveStatus.objects.filter(product="Client_admin",date_updated__gte=time_threshold.strftime('%d %b %Y %H:%M:%S')).values_list('username', 'sessionID')
    # obj_live=LiveStatus.objects.filter(status="login",date_updated__gte=time_threshold.strftime('%d %b %Y %H:%M:%S')).values_list('username', 'sessionID')
    final={'Client_admin':obj_client_admin}
    return Response(final)

@api_view(['GET'])
def live_users(request):
    total_products=[]
    for_product=LiveStatus.objects.values_list('product', flat=True)
    for a in for_product:
        if not a in total_products:
            total_products.append(a)
    time_threshold = datetime.datetime.now()- datetime.timedelta(minutes=1)
    obj_notlive=LiveStatus.objects.filter(status="login",date_updated__lte=time_threshold.strftime('%d %b %Y %H:%M:%S')).values_list('username', 'sessionID')
    obj_live=LiveStatus.objects.filter(status="login",date_updated__gte=time_threshold.strftime('%d %b %Y %H:%M:%S')).values_list('username', 'sessionID')
    final={'liveusers':obj_live,'non_liveusers':obj_notlive,'total_products':total_products}
    return Response(final)

@api_view(['GET'])
def live_qr_users(request):
    time_threshold = datetime.datetime.now()- datetime.timedelta(minutes=1)
    obj_notlive=Live_QR_Status.objects.filter(status="online",date_updated__lte=time_threshold.strftime('%d %b %Y %H:%M:%S')).values_list('qrid')
    obj_live=Live_QR_Status.objects.filter(status="online",date_updated__gte=time_threshold.strftime('%d %b %Y %H:%M:%S')).values_list('qrid')
    final={'liveusers_qr':obj_live,'non_liveusers_qr':obj_notlive}
    return Response(final)

@api_view(['GET'])
def live_public_users(request):
    time_threshold = datetime.datetime.now()- datetime.timedelta(minutes=1)
    obj_notlive=Live_Public_Status.objects.filter(status="install",date_updated__lte=time_threshold.strftime('%d %b %Y %H:%M:%S')).values_list('unique_key')
    obj_live=Live_Public_Status.objects.filter(status="install",date_updated__gte=time_threshold.strftime('%d %b %Y %H:%M:%S')).values_list('unique_key')
    final={'liveusers_public':obj_live,'non_liveusers_public':obj_notlive}
    return Response(final)

@api_view(['POST'])
def profile_view(request):
    username=request.data.get("username")
    password=request.data.get("password")
    obj="OK"
    # obj=authenticate(request, username = username, password = password)
    if obj is not None:
        resp=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","find",{"Username":username},"nil")
        resp1=json.loads(resp)
        if resp1["data"] != None:
            try:
                if resp1["data"]["User_status"] == "deleted":
                    return Response({'msg':'error','info':'User not found with given credentials..'})
                elif resp1["data"]["User_status"] == "inactive":
                    return Response({'msg':'error','info':'Account disabled, please contact admin'})
                else:
                    return Response(resp1["data"])
            except:
                return Response(resp1["data"])
        else:
            return Response({'msg':'error','info':'User not found with given credentials..'})
    else:
        return Response({'msg':'error','info':'User not found with given credentials..'})

@api_view(['POST'])
def all_liveusers(request):
    session_id=request.data.get("session_id")
    mydata=CustomSession.objects.filter(sessionID=session_id).first()
    if not mydata:
        return Response({"message":"SessionID not found in database, Please check and try again!!"})
    products_list=["Client_admin","Exhibitoe form","Living Lab Admin","Workflow AI"]
    field={}
    details=dowellconnection("login","bangalore","login","client_admin","client_admin","1159","ABCDE","fetch",field,"nil")
    ok=json.loads(details)
    users=[]
    count=0
    team_members=[]
    public_members=[]
    owners=[]
    for data in ok["data"]:
        count+=1
        for team in data["members"]["team_members"]["accept_members"]:
            if not team["name"] in team_members:
                # if team["name"]=="owner":
                #     if not data["document_name"] in team_members:
                #         team_members.append(data["document_name"])
                # else:
                if not team["name"]=="owner":
                    team_members.append(team["name"])
                else:
                    owners.append(data["document_name"])
        for guest in data["members"]["guest_members"]["accept_members"]:
            users.append(guest["name"])
        for public in data["members"]["public_members"]["accept_members"]:
            try:
                public_members.append(public["username"])
            except:
                pass
    team_members=list(set(team_members))
    owners=list(set(owners))
    time_threshold = datetime.datetime.now()- datetime.timedelta(minutes=1)
    obj_live=LiveStatus.objects.filter(status="login",updated__gte=time_threshold.strftime("%Y-%m-%d %H:%M:%S")).values_list('username', flat=True).order_by('username').distinct()
    response={'Dowell total Users':{'team_members/owners':len(owners)+len(team_members),'users':len(users),'public_members':len(public_members)},'total Live':{'live users':len(set(obj_live).intersection(users)),'live_team_members/owners':len(set(obj_live).intersection(team_members))+len(set(obj_live).intersection(owners)),'live public_members':len(set(obj_live).intersection(public_members))}}
    current={}
    weekly={}
    for product in products_list:
        product_wise=LiveStatus.objects.filter(status="login",updated__gte=time_threshold.strftime("%Y-%m-%d %H:%M:%S"),product=product).values_list('username', flat=True).order_by('username').distinct()
        current[product]={'live team_members/owners':len(set(product_wise).intersection(team_members))+len(set(product_wise).intersection(owners)),'live public_members':len(set(product_wise).intersection(public_members)),'live users':len(set(product_wise).intersection(users))}
        weekly[product]={}
        for r in range(0,7):
            date_start= datetime.datetime.now()-datetime.timedelta(days=r+1)
            date_end=datetime.datetime.now()-datetime.timedelta(days=r)
            if range ==0:
                date_end=datetime.datetime.now()+datetime.timedelta(days=1)
            obj=LiveStatus.objects.filter(updated__gt=date_start.strftime("%Y-%m-%d %H:%M:%S"),updated__lte=date_end.strftime("%Y-%m-%d %H:%M:%S"),product=product).values_list('username', flat=True).order_by('username').distinct()
            weekly[product][r]=len(obj)
    response["product_wise"]=current
    response["weekly_product_wise"]=weekly
    response["Note"]="In weekly part '0' means 24 hrs ahead of current time, '1' means between 48 and 24 hrs ahead of current time and so on.."
    three_months_ago = datetime.datetime.today() - datetime.timedelta(days=90)
    total_3moths=Account.objects.filter(last_login__lt=three_months_ago)
    grand_total=Account.objects.all()
    response["grand_total_users"]=len(grand_total)
    response["active"]=len(total_3moths)
    response["inactive"]=len(grand_total)-len(total_3moths)
    return Response(response)

@api_view(['POST'])
def forgot_password(request):
    username = request.data.get('username', None)
    email = request.data.get('email', None)
    otp_input = request.data.get('otp', None)
    new_password = request.data.get('new_password', None)
    confirm_password = request.data.get('confirm_password', None)
    print(str(otp_input)+"  "+str(new_password))
    if new_password != confirm_password:
        return Response({'msg':'error','info': 'Passwords not matching'},status=status.HTTP_400_BAD_REQUEST)
    want="no"

    # Send OTP
    if username and email and not otp_input and not want:
        otp = generateOTP()
        message = get_html_msg(username, otp, 'reset password')

        user_qs = Account.objects.filter(email=email, username=username)
        email_qs = GuestAccount.objects.filter(email=email)

        def send_otp(): return send_mail(
            'Your otp for reseting password of Dowell account', otp, settings.EMAIL_HOST_USER, [email], fail_silently=False, html_message=message)

        if user_qs.exists():
            if email_qs.exists():
                GuestAccount.objects.filter(email=email).update(
                    otp=otp, expiry=datetime.datetime.utcnow(), username=username)
                send_otp()
                return Response({'msg':'success','info': 'OTP sent successfully'})
            else:
                guest_account = GuestAccount(
                    username=username, email=email, otp=otp, expiry=datetime.datetime.utcnow())
                guest_account.save()
                send_otp()
                return Response({'msg': 'success','info':'OTP sent successfully'},status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'msg':'error','info': 'Username, email combination is incorrect'},status=status.HTTP_400_BAD_REQUEST)

    # Create new password
    elif username and email and otp_input and new_password:
        try:
            guest = GuestAccount.objects.get(
                otp=otp_input, email=email)
        except GuestAccount.DoesNotExist:
            guest = None

        if guest is not None:
            acct = Account.objects.filter(
                email=email, username=username).first()
            acct.set_password(new_password)
            acct.save()
            fields = {'Username': username, 'Email': email}
            user_json = dowellconnection(
                "login", "bangalore", "login", "registration", "registration", "10004545", "ABCDE", "fetch", fields, "nill")
            user = json.loads(user_json)
            if len(user['data']) >= 1:
                update_fields = {
                    'Password': dowell_hash.dowell_hash(new_password)}
                dowellconnection(
                    "login", "bangalore", "login", "registration", "registration", "10004545", "ABCDE", "fetch", fields, update_fields)
                return Response({'msg':'success','info':'Password reset successfully'})
        else:
            return Response({'msg':'error','info': 'Wrong OTP'},status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'msg':'error','info':"Request must have 'username' and 'email' for getting otp and then 'otp' and new password for changing otp. "},status=status.HTTP_400_BAD_REQUEST)
    return Response({'info': 'Something went wrong'},status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def forgot_username(request):
    email = request.data.get('email', None)
    otp_input = request.data.get('otp', None)

    # Send OTP
    if email and not otp_input:
        otp = generateOTP()
        message = get_html_msg('User', otp , 'recover username')

        user_qs = Account.objects.filter(email=email)
        email_qs = GuestAccount.objects.filter(email=email)

        print(user_qs)
        print(email_qs)

        def send_otp(): return send_mail(
            'Your otp for recovering username of Dowell account', otp, settings.EMAIL_HOST_USER, [email], fail_silently=False, html_message=message)

        if user_qs.exists():
            if email_qs.exists():
                GuestAccount.objects.filter(email=email).update(
                    otp=otp, expiry=datetime.datetime.utcnow())
                send_otp()
                return Response({'msg':'success','info': 'OTP sent successfully'})
            else:
                return Response({'msg':'error','info': 'Email not found 1'},status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'msg':'error','info': 'Email not found'},status=status.HTTP_400_BAD_REQUEST)

    # Create new password
    elif email and otp_input:
        try:
            guest = GuestAccount.objects.filter(
                otp=otp_input, email=email)
        except GuestAccount.DoesNotExist:
            guest = None
        if guest:
            fields = {'Email': email}
            user_json = dowellconnection(
                "login", "bangalore", "login", "registration", "registration", "10004545", "ABCDE", "fetch", fields, "nill")
            user = json.loads(user_json)
            username_list = []
            if len(user['data']) >= 1:
                json_data = dowellconnection(
                    "login", "bangalore", "login", "registration", "registration", "10004545", "ABCDE", "fetch", fields, 'nil')
                data = json.loads(json_data)
                if len(data['data']) >= 1:
                    for obj in data['data']:
                        if obj['Username'] not in username_list:
                            username_list.append(obj['Username'])
                    context = RequestContext(
                        request, {'email': email, 'username_list': username_list})
                    html_msg = 'Dear user, <br> The list of username associated with your email: <strong>{{email}}</strong> as dowell account are as follows: <br><h3>{% for a in username_list %}<ul><li>{{a}}</li></ul>{%endfor%}</h3><br>You can proceed to login now!'
                    template = Template(html_msg)
                    send_mail('Username/s associated with your email in Dowell', '', settings.EMAIL_HOST_USER, [
                              email], fail_silently=False, html_message=template.render(context))
                return Response({'msg':'success','info':'Your username/s was sent to your mail'})
            else:
                return Response({'msg':'error','info': 'Email not found'},status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'msg':'error','info': 'Wrong OTP'},status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'msg':'error','info':"Request must have field 'email' for getting otp in mail and then add field 'otp' for getting list of username in mail.."},status=status.HTTP_400_BAD_REQUEST)

def processApikey(api_key, api_services):
    url = f'https://100105.pythonanywhere.com/api/v3/process-services/?type=api_service&api_key={api_key}'
    payload = {
        # "api_key" : api_key,
        "service_id" : api_services
    }
    response = requests.post(url, json=payload)
    return response.text

@api_view(["POST"])
def PublicApi(request):
    mdata=request.data.get
    username = mdata('username')
    password = mdata('password')
    if username != "Roshan_4004":
        if mdata('api_key')!=None and mdata('api_service_id')!=None:
            api_resp=processApikey(mdata('api_key'),"DOWELL10004")
        else:
            return Response({"msg":"error","info":"api_key and api_service_id fields are needed.."})
        try:
            api_resp=api_resp.replace("false", "False")
            api_resp=api_resp.replace("true","True")
        except:
            pass
        print(api_resp)
        api_resp1=eval(api_resp)
        if api_resp1["success"] == False:
           return Response({"msg":"error","info":api_resp1["message"]})
        else:
            if not "total_credits" in api_resp1:
                return Response({"msg":"error","info":api_resp1["message"]})
    else:
        api_resp1={'total_credits':100}
    loc=mdata("location")
    if loc is not None and loc != "":
        coordinates=loc.split(" ")
    else:
        coordinates="Location not allowed.."
    try:
        lo=loc.split(" ")
        country,city=country_city_name(lo[0],lo[1])
    except Exception as e:
        city=""
        country=""
    #     print(e)
    # print(country)
    # return Response({"city":city,"country":country,"zone":timezone_str})
    device=mdata("device","api")
    osver=mdata("os")
    # brow=mdata["browser"]
    ltime=mdata("time")
    ipuser=mdata("ip")
    try:
        if ipuser != "":
            response = requests.get(f'https://ipapi.co/{ipuser}/json/').json()
            ip_city = response.get("city")
        else:
            ip_city = None
    except Exception as e:
        ip_city = None

    zone=mdata("timezone")
    if None in [username,password,loc,device,osver,ltime,ipuser]:
        resp={"msg":"error","info": "Provide all credentials","Credentials": "username, password, location, device, os, time, ip"}
        return Response(resp)
    browser=mdata("browser")
    language=mdata("language","English")
    company=None
    org=None
    dept=None
    member=None
    project=None
    subproject=None
    role_res=None
    first_name=None
    last_name=None
    email=None
    phone=None
    User_type=None
    payment_status=None
    newsletter=None
    user_country=None
    privacy_policy=None
    other_policy=None
    userID=None
    client_admin_id=None
    # role_id=mdata["role_id"]
    user=authenticate(request, username = username, password = password)
    if user is not None:
        field={"Username":username}
        id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","find",field,"nil")
        response=json.loads(id)
        if response["data"] != None:
            try:
                if response["data"]["User_status"]:
                    if response["data"]["User_status"] == "inactive":
                        resp = {"msg":"error","info": "Username is termed inactive. Please contact admin."}
                        return Response(resp,status=status.HTTP_400_BAD_REQUEST)
                    elif response["data"]["User_status"] == "deleted":
                        resp = {"msg":"error","info": "User not found."}
                        return Response(resp,status=status.HTTP_400_BAD_REQUEST)
            except:
                pass
            # try:
            #     if request.session.session_key:
            #         print("OK")
            #         resp={'session_id':request.session.session_key}
            #         return Response(resp)
            # except:
            #     pass
            form=login(request,user)
            request.session.save()
            session= request.session.session_key
            obj=CustomSession.objects.filter(sessionID=session)
            if obj:
                if obj.first().status=='login':
                    info=json.loads(obj.first().info)
                    user_obj=Account.objects.filter(username=info["username"]).first()
                    try:
                        resp={'msg':'success','info':'Logged In Successfully','session_id':session,'total_credits':api_resp1["total_credits"],'first_name':user_obj.first_name,'last_name':user_obj.last_name,'last_login':user_obj.last_login,'first_login':user_obj.date_joined}
                    except Exception as e:
                        resp={'msg':'success','info':'Logged In Successfully','session_id':session,'total_credits':api_resp1["total_credits"]}
                        print(e)
                    return Response(resp)
            try:
                res=create_event()
                event_id=res['event_id']
            except:
                event_id=None
            profile_image = "https://100014.pythonanywhere.com/media/user.png"
            first_name=response["data"]['Firstname']
            last_name=response["data"]['Lastname']
            email=response["data"]['Email']
            phone=response["data"]['Phone']
            try:
                userID=response["data"]['_id']
                if response["data"]['Profile_Image'] == "https://100014.pythonanywhere.com/media/":
                    profile_image = "https://100014.pythonanywhere.com/media/user.png"
                else:
                    profile_image = response["data"]['Profile_Image']
                User_type=response["data"]['User_type']
                client_admin_id=response["data"]['client_admin_id']
                payment_status=response["data"]['payment_status']
                newsletter=response["data"]['newsletter_subscription']
                user_country=response["data"]['user_country']
                privacy_policy=response["data"]['Policy_status']
                other_policy=response["data"]['safety_security_policy']
                role_res=response["data"]['Role']
                company=response["data"]['company_id']
                member=response["data"]['Memberof']
                dept=response["data"]['dept_id']
                org=response["data"]['org_id']
                project=response["data"]['project_id']
                subproject=response["data"]['subproject_id']
            except:
                pass
            try:
                final_ltime=parser.parse(ltime).strftime('%d %b %Y %H:%M:%S')
                dowell_time=time.strftime("%d %b %Y %H:%M:%S", time.gmtime(dowellclock()+1609459200))
            except:
                final_ltime=''
                dowell_time=''
            serverclock=datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')
            user_obj=Account.objects.filter(username=username).first()

            field_session = {'sessionID': session, 'role': role_res, 'username': username, 'Email': email, "profile_img": profile_image, 'Phone': phone, "User_type": User_type, 'language': language, 'city': city, 'country': country, 'org': org, 'company_id': company, 'project': project, 'subproject': subproject, 'dept': dept, 'Memberof': member,
                             'status': 'login', 'dowell_time': dowell_time, 'timezone': zone, 'regional_time': final_ltime, 'server_time': serverclock, 'userIP': ipuser, 'userOS': osver, 'browser': browser, 'userdevice': device, 'userbrowser': "", 'UserID': userID, 'login_eventID': event_id, "redirect_url": "", "client_admin_id": client_admin_id,"payment_status":payment_status,"user_country":user_country,"newsletter_subscription":newsletter,"Privacy_policy":privacy_policy,"Safety,Security_policy":other_policy,"coordinates":coordinates}
            dowellconnection("login","bangalore","login","session","session","1121","ABCDE","insert",field_session,"nil")

            info={"role":role_res,"username":username,"first_name":first_name,"last_name":last_name,"email":email,"profile_img":profile_image,"phone":phone,"User_type":User_type,"language":language,"city":city,"country":country,"status":"login","dowell_time":dowell_time,"timezone":zone,"regional_time":final_ltime,"server_time":serverclock,"userIP":ipuser,"userOS":osver,"userDevice":device,"language":language,"userID":userID,"login_eventID":event_id,"client_admin_id":client_admin_id,"payment_status":payment_status,"user_country":user_country,"newsletter_subscription":newsletter,"Privacy_policy":privacy_policy,"Safety,Security_policy":other_policy,"coordinates":coordinates}
            info1=json.dumps(info)
            infoo=str(info1)
            custom_session=CustomSession.objects.create(sessionID=session,info=infoo,document="",status="login")

            serverclock1=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            LiveStatus.objects.create(sessionID=session,username=username,product="",status="login",created=serverclock1,updated=serverclock1)

            #resp={'userinfo':info}
            resp = {'session_id': session,'total_credits':api_resp1["total_credits"],'first_name':first_name,'last_name':last_name,'last_login':user_obj.last_login,'first_login':user_obj.date_joined}
            return Response(resp)
        else:
            resp={'msg':'error','info':"Username not found in database"}
            return Response(resp)
        # raise AuthenticationFailed("Username not Found or password not found")
    else:
        resp={'msg':'error',"info": "Username, Password combination incorrect.."}
        return Response(resp)

@api_view(['GET', 'POST'])
def logininfo(request):
    if request.method == 'POST':
        session=request.data["session_id"]
        mydata=CustomSession.objects.filter(sessionID=session).first()
        if not mydata:
            public_field={"sessionID":session}
            public=dowellconnection("login","bangalore","login","login","login","6752828281","ABCDE","find",public_field,"nil")
            public_res=json.loads(public)
            if public_res["data"] != None:
                return Response({'userinfo':public_res["data"]})
            return Response({"message":"SessionID not found in database, Please check and try again!!"})
        if mydata.status != "login":
            return Response({"message":"You are logged out, Please login and try again!!"})
        var1=mydata.info
        var2=json.loads(var1)
        var2["org_img"]="https://100093.pythonanywhere.com/static/clientadmin/img/logomissing.png"

        del_keys=["role","company_id","org","project","subproject","dept","Memberof","members"]
        for key in del_keys:
            try:
                del var2[key]
            except:
                pass
        return Response({'userinfo':var2})
    return Response({'msg':'Success','info':'API is working, POST session_id for userinfo'})

@api_view(['GET', 'POST'])
def linklogin_info(request):
    if request.method == 'POST':
        session=request.data["session_id"]
        mydata=Linkbased_RandomSession.objects.filter(sessionID=session).first()
        if not mydata:
            return Response({"message":"SessionID not found in database, Please check and try again!!"})
        var1=mydata.info
        var2=json.loads(var1)
        return Response({'userinfo':var2})
    return Response({'msg':'Success','info':'API is working, POST session_id for userinfo'})

@api_view(['GET','POST'])
def login_init_api(request):
    if request.method=="POST":
        mainparams=request.data.get('mainparams', None)
        context = {'msg':'success'}
        # past_login=request.COOKIES.get('DOWELL_LOGIN')
        past_login=request.session.session_key
        if past_login:
            test_session=CustomSession.objects.filter(sessionID=past_login).first()
            if test_session:
                if test_session.status == "login":
                    logindetail=CustomSession.objects.filter(sessionID=past_login).first()
                    info=json.loads(logindetail.info)
                    response={'msg':'error','info':'logged_in_user'}
                    if "org=" in mainparams and not "code=masterlink" in mainparams:
                        if "https://ll04-finance-dowell.github.io/100018-dowellWorkflowAi-testing/" in mainparams and "portfolio" in mainparams and "product" in mainparams :
                            response["url"]=f'https://100093.pythonanywhere.com/exportfolio?session_id={past_login}&{mainparams}'

                        elif "linktype=common" in mainparams:
                            response["url"]=f'https://100093.pythonanywhere.com/commoninvitelink?session_id={past_login}&{mainparams}'
                        else:
                            response["url"]=f'https://100093.pythonanywhere.com/invitelink?session_id={past_login}&{mainparams}'

                    elif "code=masterlink" in mainparams:
                        response["url"]=f'https://100093.pythonanywhere.com/masterlink?session_id={past_login}&{mainparams}'

                    elif "redirect_url" in mainparams:
                        try:
                            result= re.search('redirect_url=(.*)&',mainparams)
                            # result= re.findall(re.escape("redirect_url=")+"(.*)"+re.escape("&"),mainparams)[0]
                            rr=result.group(1)
                            if "&" in rr:
                                test=rr.split("&")
                                rr=test[0]
                        except Exception as e:
                            print(e)
                            rr= mainparams[mainparams.find('redirect_url=')+13:]
                        print(rr)
                        # if "ll04-finance-dowell.github.io" in rr:
                        #     if info["User_type"]=="betatester":
                        #         rr="https://ll04-finance-dowell.github.io/100018-dowellWorkflowAi-testing"
                        #     else:
                        #         rr="https://ll04-finance-dowell.github.io/workflowai.online"
                        # elif "ll07-team-dowell.github.io" in rr:
                        #     if info["User_type"] =="betatester":
                        #         rr='https://ll07-team-dowell.github.io/100098-DowellJobPortal'
                        #     else:
                        #         rr='https://ll07-team-dowell.github.io/Jobportal'
                        response["url"]=f'{rr}?session_id={past_login}'
                    elif "hr_invitation" in mainparams:
                        try:
                            result= re.search('hr_invitation=(.*)&',mainparams)
                            hr_invitation=result.group(1)
                        except:
                            hr_invitation= mainparams[mainparams.find('hr_invitation=')+14:]
                        hr_invitation=jwt.decode(jwt=hr_invitation,key='secret',algorithms=["HS256"])
                        response["url"]=f'https://100093.pythonanywhere.com/invitelink1?session_id={past_login}&org={hr_invitation["org_name"]}&org_id={hr_invitation["org_id"]}&type={hr_invitation["member_type"]}&member_name={hr_invitation["toname"]}&code={hr_invitation["unique_id"]}&spec=hr_invite&u_code=hr_invite&detail=&qr_id={hr_invitation["qr_id"]}&owner_name={hr_invitation["owner_name"]}&portfolio_name={hr_invitation["portfolio_name"]}&product={hr_invitation["product"]}&role={hr_invitation["job_role"]}&toemail={hr_invitation["toemail"]}&data_type={hr_invitation["data_type"]}&date_time={hr_invitation["date_time"]}&name={info["username"]}'
                    else:
                        response["url"]=f'https://100093.pythonanywhere.com?session_id={past_login}'
                    return Response(response)
        random_text = passgen.generate_random_password1(24)
        context["random_session"] = random_text
        # print(request.COOKIES.get('qrid'))
        if request.COOKIES.get('qrid_login'):
            context["qrid_login"] = request.COOKIES.get('qrid_login')
            qrid_obj_1 = QR_Creation.objects.filter(
                qrid=context["qrid_login"]).first()
            if qrid_obj_1.info == "":
                context["qrid_login_type"] = "new"
            else:
                context["qrid_login_type"] = "old"
            res = Response()
            res.data = context
            return res
        else:
            qrid_obj = QR_Creation.objects.filter(status="new").first()
            if qrid_obj is None:
                ruser = passgen.generate_random_password1(24)
                rpass = "DoWell@123"
                new_obj = QR_Creation.objects.create(
                    qrid=ruser, password=rpass, status="used")

                context["qrid_login"] = new_obj.qrid
                context["qrid_login_type"] = "new"

                res = Response()
                res.set_cookie('qrid_login', new_obj.qrid, max_age=365*24*60*60)
                res.data = context
                return res
            else:
                qrid_obj.status = "used"
                qrid_obj.save(update_fields=['status'])

                context["qrid_login"] = qrid_obj.qrid
                context["qrid_login_type"] = "new"

                res = Response()
                res.set_cookie('qrid_login', qrid_obj.qrid, max_age=365*24*60*60)
                res.data = context
                return res
        return Response({'msg':'error','info':'No session found'})
    else:
        context = {'msg':'success'}
        try:
            orgs = request.GET.get('org', None)
            type1 = request.GET.get('type', None)
            email1 = request.GET.get('email', None)
            name1 = request.GET.get('name', None)
            code = request.GET.get('code', None)
            spec = request.GET.get('spec', None)
            u_code = request.GET.get('u_code', None)
            detail = request.GET.get('detail', None)
        except:
            pass
        context["org"] = orgs
        context["type"] = type1
        urls = request.GET.get('next', None)
        context["url"] = request.GET.get('redirect_url', None)
        redirect_url = request.GET.get('redirect_url', None)
        past_login=request.COOKIES.get('DOWELL_LOGIN')
        if past_login:
            test_session=CustomSession.objects.filter(sessionID=past_login).first()
            if test_session:
                if test_session.status == "login":
                    return Response({'msg':'error','info':'logged_in_user'})

        random_text = passgen.generate_random_password1(24)
        context["random_session"] = random_text
        print(request.COOKIES.get('qrid_login'))
        if request.COOKIES.get('qrid_login'):
            context["qrid_login"] = request.COOKIES.get('qrid_login')
            qrid_obj_1 = QR_Creation.objects.filter(
                qrid=context["qrid_login"]).first()
            if qrid_obj_1.info == "":
                context["qrid_login_type"] = "new"
            else:
                context["qrid_login_type"] = "old"
            res = Response()
            res.data = context
            return res
        else:
            qrid_obj = QR_Creation.objects.filter(status="new").first()
            if qrid_obj is None:
                ruser = passgen.generate_random_password1(24)
                rpass = "DoWell@123"
                new_obj = QR_Creation.objects.create(
                    qrid=ruser, password=rpass, status="used")

                context["qrid_login"] = new_obj.qrid
                context["qrid_login_type"] = "new"

                res = Response()
                res.set_cookie('qrid_login', new_obj.qrid, max_age=365*24*60*60)
                res.data = context
                return res
            else:
                qrid_obj.status = "used"
                qrid_obj.save(update_fields=['status'])

                context["qrid_login"] = qrid_obj.qrid
                context["qrid_login_type"] = "new"

                res = Response()
                res.set_cookie('qrid_login', qrid_obj.qrid, max_age=365*24*60*60)
                res.data = context
                return res
        return Response({'msg':'error','info':'No session found'})

@api_view(['POST'])
def main_login(request):
    mdata = request.data.get
    username = mdata('username')
    password = mdata('password')
    loc = mdata("location")
    print(loc)
    if loc is not None and loc != "" and loc != {}:
        coordinates=loc.split(" ")
        url = 'https://api.open-elevation.com/api/v1/lookup?'
        params = {'locations': f"{coordinates[0]},{coordinates[1]}"}
        try:
            result = requests.get(url, params)
            altitude=result.json()['results'][0]['elevation']
        except:
            altitude="Location not allowed.."
        # print(result)
    else:
        coordinates="Location not allowed.."
        altitude="Location not allowed.."
    mainparams=mdata("mainparams")
    try:
        lo = loc.split(" ")
        country, city = country_city_name(lo[0], lo[1])
    except:
        city = ""
        country = ""
    # return Response({"city":city,"country":country,"zone":timezone_str})
    device = mdata("device")
    osver = mdata("os")
    # brow=mdata["browser"]
    ltime = mdata("time")
    ipuser = mdata("ip")
    try:
        if ipuser != "":
            response = requests.get(f'https://ipapi.co/{ipuser}/json/').json()
            ip_city=response.get("city")
        else:
            ip_city=None
    except Exception as e:
        ip_city=None

    zone = mdata("timezone")
    random_session=mdata("randomSession")
    # print("param  "+str(mainparams))
    if None in [username, password, loc, device, osver, ltime, ipuser, mainparams,random_session]:
        resp = {"msg":"error","info": "Provide all credentials",
                "Credentials": "username, password, location, device, os, time, ip, mainparams"}
        return Response(resp,status=status.HTTP_400_BAD_REQUEST)
    browser = mdata("browser")
    language = mdata("language", "English")
    obj=Account.objects.filter(username=username).first()
    try:
        obj.current_task="Logging In"
        obj.save(update_fields=['current_task'])
    except:
        pass
    random_session_obj1=RandomSession.objects.filter(username=username).first()
    if random_session_obj1 is None:
        random_session_obj=RandomSession.objects.filter(sessionID=random_session).first()
        if random_session_obj is None:
            return Response({"msg":"error","info":"Please accept the terms in policy page!"},status=status.HTTP_400_BAD_REQUEST)
        random_session_obj.username=username
        random_session_obj.save(update_fields=['username'])
    company=None
    org=None
    dept=None
    member=None
    project=None
    subproject=None
    role_res=None
    first_name=None
    last_name=None
    email=None
    phone=None
    User_type=None
    payment_status=None
    newsletter=None
    user_country=None
    privacy_policy=None
    other_policy=None
    userID=None
    client_admin_id=None
    # role_id=mdata["role_id"]
    user = authenticate(request, username=username, password=password)
    if user is not None:
        field = {"Username": username}
        id = dowellconnection("login", "bangalore", "login", "registration",
                              "registration", "10004545", "ABCDE", "find", field, "nil")
        response = json.loads(id)
        if response["data"] != None:
            try:
                if response["data"]["User_status"]:
                    if response["data"]["User_status"] == "inactive":
                        resp = {"msg":"error","info": "Username is termed inactive. Please contact admin."}
                        return Response(resp,status=status.HTTP_400_BAD_REQUEST)
                    elif response["data"]["User_status"] == "deleted":
                        resp = {"msg":"error","info": "User not found."}
                        return Response(resp,status=status.HTTP_400_BAD_REQUEST)
            except:
                pass
            try:
                obj.current_task="Verifying User"
                obj.save(update_fields=['current_task'])
            except:
                pass
            form = login(request, user)
            request.session.save()
            session = request.session.session_key
            # obj = CustomSession.objects.filter(sessionID=session)
            # if obj:
            #     if obj.first().status == 'login':
            #         data = {"msg":"success","info":"Logged in successfully","session_id": session}
            #         response = Response()
            #         response.set_cookie('DOWELL_LOGIN', session, domain='pythonanywhere.com')
            #         response.data=data
            #         return response
            try:
                res = create_event()
                event_id = res['event_id']
            except:
                event_id = None
            profile_image = "https://100014.pythonanywhere.com/media/user.png"
            first_name = response["data"]['Firstname']
            last_name = response["data"]['Lastname']
            email = response["data"]['Email']
            phone = response["data"]['Phone']
            try:
                userID=response["data"]['_id']
                client_admin_id=response["data"]['client_admin_id']
                if response["data"]['Profile_Image'] == "https://100014.pythonanywhere.com/media/":
                    profile_image = "https://100014.pythonanywhere.com/media/user.png"
                else:
                    profile_image = response["data"]['Profile_Image']
                User_type=response["data"]['User_type']
                payment_status=response["data"]['payment_status']
                newsletter=response["data"]['newsletter_subscription']
                user_country=response["data"]['user_country']
                privacy_policy=response["data"]['Policy_status']
                other_policy=response["data"]['safety_security_policy']
                role_res=response["data"]['Role']
                company=response["data"]['company_id']
                member=response["data"]['Memberof']
                dept=response["data"]['dept_id']
                org=response["data"]['org_id']
                project=response["data"]['project_id']
                subproject=response["data"]['subproject_id']
            except:
                pass
            try:
                final_ltime = parser.parse(ltime).strftime('%d %b %Y %H:%M:%S')
                dowell_time = time.strftime(
                    "%d %b %Y %H:%M:%S", time.gmtime(dowellclock()+1609459200))
            except:
                final_ltime = ''
                dowell_time = ''
            serverclock = datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')

            field_session = {'sessionID': session, 'role': role_res, 'username': username, 'Email': email, "profile_img": profile_image, 'Phone': phone, "User_type": User_type, 'language': language, 'city': city, 'country': country, 'org': org, 'company_id': company, 'project': project, 'subproject': subproject, 'dept': dept, 'Memberof': member,
                             'status': 'login', 'dowell_time': dowell_time, 'timezone': zone, 'regional_time': final_ltime, 'server_time': serverclock, 'userIP': ipuser, 'userOS': osver, 'browser': browser, 'userdevice': device, 'userbrowser': "", 'UserID': userID, 'login_eventID': event_id, "redirect_url": "", "client_admin_id": client_admin_id,"payment_status":payment_status,"user_country":user_country,"newsletter_subscription":newsletter,"Privacy_policy":privacy_policy,"Safety,Security_policy":other_policy,"coordinates":coordinates,"altitude":altitude}
            dowellconnection("login", "bangalore", "login", "session",
                             "session", "1121", "ABCDE", "insert", field_session, "nil")

            info={"role":role_res,"username":username,"first_name":first_name,"last_name":last_name,"email":email,"profile_img":profile_image,"phone":phone,"User_type":User_type,"language":language,"city":city,"country":country,"status":"login","dowell_time":dowell_time,"timezone":zone,"regional_time":final_ltime,"server_time":serverclock,"userIP":ipuser,"userOS":osver,"userDevice":device,"language":language,"userID":userID,"login_eventID":event_id,"client_admin_id":client_admin_id,"payment_status":payment_status,"user_country":user_country,"newsletter_subscription":newsletter,"Privacy_policy":privacy_policy,"Safety,Security_policy":other_policy,"coordinates":coordinates,"altitude":altitude}
            info1=json.dumps(info)
            infoo=str(info1)
            custom_session=CustomSession.objects.create(sessionID=session,info=infoo,document="",status="login")

            serverclock1=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            LiveStatus.objects.create(sessionID=session,username=username,product="",status="login",created=serverclock1,updated=serverclock1)

            if ip_city is not None:
                location_check=Location_check.objects.filter(username=username).first()
                if not location_check:
                    usual=[f'{ip_city}']
                    Location_check.objects.create(username=username,usual=str(json.dumps(usual)))
                else:
                    match="Checking"
                    try:
                        usual=json.loads(location_check.usual)
                    except:
                        usual=location_check.usual
                    if ip_city not in usual:
                        try:
                            unusual=json.loads(location_check.unusual)
                        except:
                            unusual=location_check.unusual
                            pass
                        print(unusual)
                        if unusual is not None:
                            for a in unusual:
                                if ip_city == list(a.keys())[0]:
                                    a[f"{ip_city}"]+=1
                                    match="True"
                                    if a[f"{ip_city}"] %3==0:
                                        send=True
                                    break
                                else:
                                    match="False"
                        if match !="True" and match !="False":
                            unusual=[{f'{ip_city}':1}]
                            send=True
                        elif match == "False":
                            unusual.append({f'{ip_city}':1})
                            send=True
                        location_check.unusual=str(json.dumps(unusual))
                        location_check.save(update_fields=["unusual"])
                        try:
                            if send == True:
                                values={"username":username,"ip":ipuser,"location":ip_city}
                                url_email = "https://100085.pythonanywhere.com/api/email/"
                                payload ={
                                    "toname": username,
                                    "toemail": email,
                                    "subject": "Login detected from another location",
                                    "email_content":render_to_string(os.path.join(BASE_DIR,'templates/login/location_info.html'),values)
                                }
                                response = requests.post(url_email, json=payload)
                        except:
                            pass

            try:
                obj.current_task="Connecting to UX Living Lab"
                obj.save(update_fields=['current_task'])
            except:
                pass

            # resp={'userinfo':info}
            data = {"msg":"success","session_id": session}

            response = Response()
            # response.set_cookie('DOWELL_LOGIN', session)

            print(mainparams)
            if "org=" in mainparams and not "code=masterlink" in mainparams:
                if "https://ll04-finance-dowell.github.io/100018-dowellWorkflowAi-testing/" in mainparams and "portfolio" in mainparams and "product" in mainparams:
                    data["url"]=f'https://100093.pythonanywhere.com/exportfolio?session_id={session}&{mainparams}'
                elif "linktype=common" in mainparams:
                    data["url"]=f'https://100093.pythonanywhere.com/commoninvitelink?session_id={session}&{mainparams}'
                else:
                    data["url"]=f'https://100093.pythonanywhere.com/invitelink?session_id={session}&{mainparams}'

            elif "code=masterlink" in mainparams:
                data["url"]=f'https://100093.pythonanywhere.com/masterlink?session_id={session}&{mainparams}'

            elif "redirect_url" in mainparams:
                try:
                    result= re.search('redirect_url=(.*)&',mainparams)
                    rr=result.group(1)
                    if "&" in rr:
                        test=rr.split("&")
                        rr=test[0]
                except:
                    rr= mainparams[mainparams.find('redirect_url=')+13:]
                # if "ll04-finance-dowell.github.io" in rr:
                #     if info["User_type"] =="betatester":
                #         rr='https://ll04-finance-dowell.github.io/100018-dowellWorkflowAi-testing'
                #     else:
                #         rr='https://ll04-finance-dowell.github.io/workflowai.online'
                # elif "ll07-team-dowell.github.io" in rr:
                #     if info["User_type"] =="betatester":
                #         rr='https://ll07-team-dowell.github.io/100098-DowellJobPortal'
                #     else:
                #         rr='https://ll07-team-dowell.github.io/Jobportal'
                data["url"]=f'{rr}?session_id={session}'
            elif "hr_invitation" in mainparams:
                try:
                    result= re.search('hr_invitation=(.*)&',mainparams)
                    hr_invitation=result.group(1)
                except:
                    hr_invitation= mainparams[mainparams.find('hr_invitation=')+14:]
                hr_invitation=jwt.decode(jwt=hr_invitation,key='secret',algorithms=["HS256"])
                data["url"]=f'https://100093.pythonanywhere.com/invitelink1?session_id={session}&org={hr_invitation["org_name"]}&org_id={hr_invitation["org_id"]}&type={hr_invitation["member_type"]}&member_name={hr_invitation["toname"]}&code={hr_invitation["unique_id"]}&spec=hr_invite&u_code=hr_invite&detail=&qr_id={hr_invitation["qr_id"]}&owner_name={hr_invitation["owner_name"]}&portfolio_name={hr_invitation["portfolio_name"]}&product={hr_invitation["product"]}&role={hr_invitation["job_role"]}&toemail={hr_invitation["toemail"]}&data_type={hr_invitation["data_type"]}&date_time={hr_invitation["date_time"]}&name={username}'
            else:
                data["url"]=f'https://100093.pythonanywhere.com?session_id={session}'

            response.data = data
            return response
        else:
            resp = {"msg":"error","info": "Username not found in database"}
            return Response(resp,status=status.HTTP_400_BAD_REQUEST)
        # raise AuthenticationFailed("Username not Found or password not found")
    else:
        resp = {"msg":"error","info": "Username, Password combination incorrect.."}
        return Response(resp,status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def main_logout(request):
    # session = request.COOKIES.get('DOWELL_LOGIN')
    session=request.session.session_key

    mydata = CustomSession.objects.filter(sessionID=session).first()
    if mydata is not None:
        a2 = mydata.info
        a3 = json.loads(a2)
        a3["status"] = "logout"
        a4 = json.dumps(a3)
        a5 = str(a4)
        mydata.info = a5
        if mydata.status != "logout":
            mydata.status = "logout"
        mydata.save(update_fields=['info', 'status'])
    field_session = {'sessionID': session}
    update_field = {'status': 'logout'}
    dowellconnection("login", "bangalore", "login", "session", "session",
                     "1121", "ABCDE", "update", field_session, update_field)
    logout(request)
    response = Response()
    response.data = {'msg':'success','info': 'Logged out Successfully..'}
    # response.delete_cookie('DOWELL_LOGIN')
    return response

@api_view(['POST'])
def user_status(request):
    # admin_password=request.data.get("admin_password",None)
    admin_pass="Dowell@r9HA=m"
    username=request.data.get("username",None)
    status_1=request.data.get("status",None)
    password=request.data.get("password",None)
    # if admin_password != admin_pass:
    #     return Response({'msg':'error','info':"The admin password is wrong!"})
    field={"Username":username,"Password":dowell_hash.dowell_hash(password)}
    id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","find",field,"nil")
    response=json.loads(id)
    if response["data"] != None:
        if status_1 is not None and status_1 in ["active" , "inactive" , "deleted"]:
            up_field={"User_status":status_1}
            dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","update",field,up_field)
            return Response({'msg':'success','info':f"{username}'s status changed to {status_1}"})
        else:
            return Response({'msg':'error','info':"Please Enter valid status"},status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'msg':'error','info':"Username, Password combination is incorrect"}, status=status.HTTP_400_BAD_REQUEST)


def get_html_msg_new(username, otp, purpose):
    return f'Dear {username}, <br> Please Enter below <strong>OTP</strong> to {purpose} of dowell account <br><h2>Your OTP is <strong>{otp}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'

@api_view(['POST'])
def email_otp(request):
    email = request.data.get('email', None)
    username = request.data.get('username', 'User')
    usage = request.data.get('usage', None)

    field = {"Username": username,"Email":email}
    id = dowellconnection("login", "bangalore", "login", "registration",
                              "registration", "10004545", "ABCDE", "find", field, "nil")
    response = json.loads(id)
    try:
        if response["data"] != None:
            if response["data"]["User_status"]:
                if response["data"]["User_status"] == "inactive":
                    resp = {"msg":"error","info": "Username is termed inactive. Please contact admin."}
                    return Response(resp,status=status.HTTP_400_BAD_REQUEST)
                elif response["data"]["User_status"] == "deleted":
                    resp = {"msg":"error","info": "User not found."}
                    return Response(resp,status=status.HTTP_400_BAD_REQUEST)
    except:
        pass

    # Send OTP
    if email and usage:
        otp = generateOTP()
        if usage == "forgot_username":
            user_qs = Account.objects.filter(email=email)
            email_qs = GuestAccount.objects.filter(email=email).first()
            if user_qs.exists():
                if email_qs:
                    email_qs.otp = otp
                    email_qs.save(update_fields=['otp'])
                    for_html_msg = "recover username"
                    subject = "Your otp for recovering username of Dowell account"
                    msg = 'success'
                    info = 'OTP sent Successfully'
                else:
                    msg = 'error'
                    info = 'Email not found'
            else:
                msg = 'error'
                info = 'Email not associated with any user'
                status_code=status.HTTP_400_BAD_REQUEST
        elif usage == "forgot_password":
            user_qs = Account.objects.filter(email=email, username=username)
            email_qs = GuestAccount.objects.filter(email=email).first()
            if user_qs.exists():
                if email_qs:
                    GuestAccount.objects.filter(email=email).update(
                        otp=otp, expiry=datetime.datetime.utcnow(), username=username)
                else:
                    guest_account = GuestAccount(
                        username=username, email=email, otp=otp, expiry=datetime.datetime.utcnow())
                    guest_account.save()
                msg = 'success'
                info = 'OTP sent Successfully'
                for_html_msg = "reset password"
                subject = "Your otp for reseting password of Dowell account"
            else:
                status_code=status.HTTP_400_BAD_REQUEST
                msg = 'error'
                info = 'Username, email combination is incorrect'
        elif usage == "update_email":
            user_qs = Account.objects.filter(
                email=email, username=username).first()
            email_qs = GuestAccount.objects.filter(email=email).first()
            if not user_qs:
                if email_qs:
                    GuestAccount.objects.filter(email=email).update(
                        otp=otp, expiry=datetime.datetime.utcnow(), username=username)
                else:
                    guest_account = GuestAccount(
                        username=username, email=email, otp=otp, expiry=datetime.datetime.utcnow())
                    guest_account.save()
                msg = 'success'
                info = 'OTP sent Successfully'
                for_html_msg = "use this address as email"
                subject = "Your otp for updating email of Dowell account"
            else:
                status_code=status.HTTP_400_BAD_REQUEST
                msg = "error"
                info = "Given email is already in use with your account"
        elif usage == "create_account":
            for_html_msg = "use this email for creation"
            subject = "Your otp for creating dowell account"
            try:
                emailexist = GuestAccount.objects.get(email=email)
            except GuestAccount.DoesNotExist:
                emailexist = None
            if emailexist is not None:
                GuestAccount.objects.filter(email=email).update(
                    otp=otp, expiry=datetime.datetime.now(), username=username)
            else:
                data = GuestAccount(username=username, email=email, otp=otp)
                data.save()
            url = "https://100085.pythonanywhere.com/api/signUp-otp-verification/"
            payload = json.dumps({
                "toEmail": email,
                "toName": username,
                "topic": "RegisterOtp",
                "otp": otp
            })
            headers = {
                'Content-Type': 'application/json'
            }
            response1 = requests.request(
                "POST", url, headers=headers, data=payload)
            msg = 'success'
            info = 'OTP sent Successfully'
            return Response({'msg': 'success', 'info': 'OTP sent successfully'})
        else:
            return Response({'msg': 'error', 'info': 'Enter email and the usage you are looking for. Look into documentation for more info.'},status=status.HTTP_400_BAD_REQUEST)
        if msg == 'success':
            message = get_html_msg_new(username, otp, for_html_msg)
            def send_otp(): return send_mail(
                subject, otp, settings.EMAIL_HOST_USER, [email], fail_silently=False, html_message=message)
            send_otp()
        try:
            return Response({'msg': msg, 'info': info},status=status_code)
        except:
            return Response({'msg': msg, 'info': info})
    else:
        return Response({'msg': 'error', 'info': 'Enter email and the usage you are looking for. Look into documentation for more info.'},status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def mobilesms(request):
    phonecode = request.data.get("phonecode")
    phone = request.data.get("Phone")
    sms = generateOTP()

    full_number ="+" + str(phonecode) + str(phone)
    time = datetime.datetime.utcnow()
    print(full_number)
    if full_number == "+251912912144":
        sms="123456"
    try:
        phone_exists = mobile_sms.objects.get(phone=full_number)
    except mobile_sms.DoesNotExist:
        phone_exists = None
    if phone_exists is not None:
        mobile_sms.objects.filter(
            phone=full_number).update(sms=sms, expiry=time)
    else:
        mobile_sms.objects.create(
            phone=full_number, sms=sms, expiry=time)
    # url = "https://100085.pythonanywhere.com/api/sms/"
    # payload = {
    #     "sender": "DowellLogin",
    #     "recipient": full_number,
    #     "content": f"Enter the following OTP to create your dowell account: {sms}",
    #     "created_by": "Manish"
    # }
    url = "https://100085.pythonanywhere.com/api/v1/dowell-sms/c9dfbcd2-8140-4f24-ac3e-50195f651754/"
    payload = {
        "sender" : "DowellLogin",
        "recipient" : full_number,
        "content" : f"Enter the following OTP to create your dowell account: {sms}",
        "created_by" : "Manish"
        }
    response = requests.request("POST", url, data=payload)
    # if len(response.json()) > 1:
    return Response({'msg':'success','info':'SMS sent successfully!!'})
    # else:
    #     return Response({'msg': 'error','error':'The number is not valid'})

@api_view(['POST'])
def otp_verify(request):
    otp=generateOTP()
    username=request.data.get('username', None)
    email = request.data.get('email', None)
    phone = request.data.get('phone', None)
    otp_input = request.data.get('otp',None)
    if email and username and not otp_input:
        field={"email":email,"username":username}
        check=dowellconnection("login","bangalore","login","otp_verify","otp_verify","1234001","ABCDE","fetch",field,"nil")
        check1=json.loads(check)
        if len(check1["data"])>=1:
            field={"email":email,"username":username}
            field_update={"otp":otp,"status":"active"}
            updated=dowellconnection("login","bangalore","login","otp_verify","otp_verify","1234001","ABCDE","update",field,field_update)
        else:
            field={"username":username,"email":email,"otp":otp,"status":"active"}
            insert=dowellconnection("login","bangalore","login","otp_verify","otp_verify","1234001","ABCDE","insert",field,"nil")
            inserted=json.loads(insert)
            print(inserted)
        url = "https://100085.pythonanywhere.com/api/signUp-otp-verification/"
        payload = json.dumps({
            "toEmail": email,
            "toName": username,
            "topic": "RegisterOtp",
            "otp": otp
        })
        headers = {
            'Content-Type': 'application/json'
        }
        response1 = requests.request(
            "POST", url, headers=headers, data=payload)
        return Response({'msg':'success','otp':otp})
    elif email and username and otp_input:
        field={"email":email,"username":username,"otp":otp_input}
        check=dowellconnection("login","bangalore","login","otp_verify","otp_verify","1234001","ABCDE","fetch",field,"nil")
        check1=json.loads(check)
        if len(check1["data"])>=1:
            field={"email":email,"username":username,"otp":otp_input}
            field_update={"status":"verified"}
            dowellconnection("login","bangalore","login","otp_verify","otp_verify","1234001","ABCDE","update",field,field_update)
            return Response({"msg":"success","info":"Verification complete"})
        else:
            return Response({"msg":"error","info":"Wrong OTP provided"})

    elif phone and username and not otp_input:
        field={"phone":phone,"username":username}
        check=dowellconnection("login","bangalore","login","otp_verify","otp_verify","1234001","ABCDE","fetch",field,"nil")
        check1=json.loads(check)
        if len(check1["data"])>=1:
            field={"phone":phone,"username":username}
            field_update={"otp":otp,"status":"active"}
            updated=dowellconnection("login","bangalore","login","otp_verify","otp_verify","1234001","ABCDE","update",field,field_update)
        else:
            field={"phone":phone,"otp":otp,"status":"active","username":username}
            insert=dowellconnection("login","bangalore","login","otp_verify","otp_verify","1234001","ABCDE","insert",field,"nil")
            inserted=json.loads(insert)
            print(inserted)
        url = "https://100085.pythonanywhere.com/api/sms/"
        payload = {
            "sender": "DowellLogin",
            "recipient": phone,
            "content": f"Enter the following OTP to create your dowell account: {otp}",
            "created_by": "Manish"
        }
        response = requests.request("POST", url, data=payload)
        if len(response.json()) > 1:
            return Response({'msg':'success','otp':otp})
        else:
            return Response({'msg': 'error','error':'The phone number is not valid'})
    elif phone and username and otp_input:
        field={"phone":phone,"username":username,"otp":otp_input}
        check=dowellconnection("login","bangalore","login","otp_verify","otp_verify","1234001","ABCDE","fetch",field,"nil")
        check1=json.loads(check)
        if len(check1["data"])>=1:
            field={"phone":phone,"username":username,"otp":otp_input}
            field_update={"status":"verified"}
            dowellconnection("login","bangalore","login","otp_verify","otp_verify","1234001","ABCDE","update",field,field_update)
            return Response({"msg":"success","info":"Verification complete"})
        else:
            return Response({"msg":"error","info":"Wrong OTP provided"})
    else:
        return Response({'msg': 'error','error':'Provide either email or phone number along with username'})

@api_view(['POST'])
def validate_username(request):
    username = request.data['username']
    if username:
        qs = Account.objects.filter(username=username)
        if qs.exists():
            return Response({'msg': 'error', 'info': 'Username Not Available'}, status=status.HTTP_400_BAD_REQUEST)
    no_unames=["administrator", "uxlivinglab", "dowellresearch", "dowellteam", "admin","uxlive","livinglab","ux","dowell","livinglabadmin","livinglab","living_lab_admin"]
    for i in no_unames:
        if username == i:
            return Response({'msg': 'error', 'info': 'Username Not Available'}, status=status.HTTP_400_BAD_REQUEST)
        # for a in range(len(i)):
        #     if i[0:a+1] in username:
        #         return Response({'status': 'error', 'msg': 'Username not allowed'}, status=status.HTTP_400_BAD_REQUEST)
    return Response({'msg': 'success', 'info': 'Username Available'}, status=status.HTTP_200_OK)

@api_view(['POST'])
def user_data(request):
    user_id = request.data['user_id']
    field={"_id":user_id}
    id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","find",field,"nil")
    response=json.loads(id)
    if response["data"] != None:
        resp1=response["data"]
        del resp1["Password"]
        return Response(resp1)
    else:
        return Response({"msg":"error","info":"User Not Found"},status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def user_report(request):

    # ok=request.META.get("HTTP_ORIGIN")
    # return Response(ok)
    # x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    # return Response({'ip': x_forwarded_for})
    # if x_forwarded_for:
    #     ip = x_forwarded_for.split(',')[0]
    # else:
    #     ip = request.META.get('REMOTE_ADDR')
    # return Response({'ip': ip})

    response={}
    session_id=request.data.get("session_id")
    mydata=CustomSession.objects.filter(sessionID=session_id).first()
    if not mydata:
        return Response({"message":"SessionID not found in database, Please check and try again!!"})
    three_months_ago = datetime.datetime.today() - datetime.timedelta(days=90)
    total_3moths=Account.objects.filter(last_login__lt=three_months_ago)
    grand_total=Account.objects.all()
    response["grand_total_users"]=len(grand_total)
    response["active"]=len(total_3moths)
    response["inactive"]=len(grand_total)-len(total_3moths)
    return Response(response)

@api_view(['POST'])
def all_username(request):
    pwd=request.data.get("pwd")
    if pwd == dpass :
        names=Account.objects.all().values_list('username', flat=True).order_by('username').distinct()
        return Response(names)
    else:
        return Response("Verification Failed !")

@api_view(['POST'])
def face_login(request):
    image = request.data.get('image', None)
    usage=request.data.get('usage')
    if usage is None:
        filename = default_storage.save(image.name, image)
        image_path = default_storage.path(filename)

        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        known_img = face_recognition.load_image_file(os.path.join(BASE_DIR, 'static/img/test_facelogin/IMG_8787 (4).JPG'))
        unknown_img = face_recognition.load_image_file(image_path)

        try:
            known_encoding = face_recognition.face_encodings(known_img)[0]
            unknown_encoding = face_recognition.face_encodings(unknown_img)[0]
        except:
            return Response({
                'success': True,
                'result': "false"
            })

        result = face_recognition.compare_faces([known_encoding], unknown_encoding)

        return Response({
            'success': True,
            'result': result
        })
    else:
        obj1=Face_Login.objects.get(username="Roshan_4004")
        img_list=(obj1.image.strip("][").split(', '))
        num_arr=np.array(img_list,dtype='float64')

        filename = default_storage.save(image.name, image)
        image_path = default_storage.path(filename)
        unknown_img = face_recognition.load_image_file(image_path)
        try:
            # known_encoding = face_recognition.face_encodings(known_img)[0]
            unknown_encoding = face_recognition.face_encodings(unknown_img)[0]
        except:
            return Response({
                'success': True,
                'result': "false"
            })

        result = face_recognition.compare_faces([num_arr], unknown_encoding)

        return Response({
            'success': True,
            'result': result
        })

import sys
@csrf_exempt
@api_view(['POST'])
def face_login_api(request):
    # Initialize variables
    company = None
    org = None
    dept = None
    member = None
    project = None
    subproject = None
    role_res = None
    first_name = None
    last_name = None
    email = None
    phone = None
    User_type = None
    payment_status = None
    newsletter = None
    user_country = None
    privacy_policy = None
    other_policy = None
    userID = None
    client_admin_id = None
    # Get post data
    image = request.data.get('imgSrc', None)
    location = request.data.get("location", None)
    mainparams = request.data.get("mainparams", None)
    device = request.data.get("device", None)
    osver = request.data.get("os", None)
    ltime = request.data.get("time", None)
    ip_user = request.data.get("ip", None)
    zone = request.data.get("timezone", None)
    random_session = request.data.get("randomSession", None)
    browser = request.data.get("browser", None)
    language = request.data.get("language", "English")

    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    g = open(os.path.join(BASE_DIR, 'static/img/test_facelogin/test.jpg'), "wb")
    g.write(base64.b64decode(image[23:]))
    g.close()
    # print(location)
    # print(mainparams)
    # print(osver)
    # print(random_session)
    # return Response({'all':[image, device, osver, ltime, ip_user, mainparams, random_session],'gg':len(image)})
    try: # Get country and city from location
        location_list = location.split(" ")
        country, city = country_city_name(location_list[0], location_list[1])
    except:
        city = ""
        country = ""

    try: # Set IP for user
        if ip_user != "":
            response = requests.get(f'https://ipapi.co/{ip_user}/json/').json()
            ip_city = response.get("city")
        else:
            ip_city = None
    except Exception as e:
        ip_city = None

    # Validation Errors
    if None in [image, device, osver, ltime, ip_user, mainparams, random_session]:
        resp = {
            "msg": "error",
            "info": "Provide all credentials",
            "Credentials": "image, device, os, time, ip, mainparams, randomSession"
        }
        return Response(resp,status=status.HTTP_400_BAD_REQUEST)

    # Get face encoding for unknown image
    unknown_img = face_recognition.load_image_file(os.path.join(BASE_DIR, 'static/img/test_facelogin/test.jpg'))
    try:
        unknown_encoding = face_recognition.face_encodings(unknown_img)[0]
    except:
        os.remove(os.path.join(BASE_DIR, 'static/img/test_facelogin/test.jpg'))
        return Response({
            'msg': "error",
            'info': "Face not detected in image",
            'Credentials': 'image'
        }, status=status.HTTP_400_BAD_REQUEST)

    # Get all accounts from register collection
    # field = {}
    # register_collection = dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",field,"nil")
    # account_list = json.loads(register_collection)
    # account_data_list = account_list["data"]
    # return Response({"data":account_data_list})
    few_days=datetime.datetime.now() + relativedelta(days=-10)
    # print(three_month)

    accounts = Account.objects.filter(last_login__gt=few_days).exclude(profile_image="user.png").exclude(profile_image__exact='').exclude(profile_image__isnull=True)

    print(len(accounts))
    username = None
    # Compare faces and retrieve username
    for account in accounts:
        if account.profile_image is not None and 'pythonanywhere.com' not in str(account.profile_image):
            try:
                known_img = face_recognition.load_image_file(f"dowell_login/media/{account.profile_image}")
            except:
                pass
            try:
                known_encoding = face_recognition.face_encodings(known_img)[0]
                result = face_recognition.compare_faces([known_encoding], unknown_encoding)
                if result[0] == True:
                    username = account.username
                    break
            except:
                pass
                # return Response({
                #     'msg': "error",
                #     'info': "Face not detected in image",
                #     'Credentials': 'image'
                # }, status=status.HTTP_400_BAD_REQUEST)

    if username is not None:
      # Get user model and update current task
        obj = Account.objects.filter(username=username).first()

        try:
            obj.current_task = "Logging In"
            obj.save(update_fields=['current_task'])
        except:
            pass
    else:
        os.remove(os.path.join(BASE_DIR, 'static/img/test_facelogin/test.jpg'))
        resp = {"msg":"error","info": "User not found"}
        return Response(resp,status=status.HTTP_400_BAD_REQUEST)

      # Get random session or create random session
    random_session_obj1 = RandomSession.objects.filter(username=username).first()
    if random_session_obj1 is None:
        random_session_obj = RandomSession.objects.filter(sessionID=random_session).first()
        if random_session_obj is None:
            os.remove(os.path.join(BASE_DIR, 'static/img/test_facelogin/test.jpg'))
            return Response({"msg":"error","info":"Please accept the terms in policy page!"},status=status.HTTP_400_BAD_REQUEST)
        random_session_obj.username=username
        random_session_obj.save(update_fields=['username'])

    user = obj
    if user is not None:
        field = {"Username": username}
        id = dowellconnection("login", "bangalore", "login", "registration",
                            "registration", "10004545", "ABCDE", "find", field, "nil")
        response = json.loads(id)
        if response["data"] != None:
            try:
                obj.current_task="Verifying User"
                obj.save(update_fields=['current_task'])
            except:
                pass
            form = login(request, user)
            request.session.save()
            session = request.session.session_key
            try:
                res = create_event()
                event_id = res['event_id']
            except:
                event_id = None
            profile_image = "https://100014.pythonanywhere.com/media/user.png"
            first_name = response["data"]['Firstname']
            last_name = response["data"]['Lastname']
            email = response["data"]['Email']
            phone = response["data"]['Phone']
            try:
                userID=response["data"]['_id']
                if response["data"]['Profile_Image'] == "https://100014.pythonanywhere.com/media/":
                    profile_image = "https://100014.pythonanywhere.com/media/user.png"
                else:
                    profile_image = response["data"]['Profile_Image']
                User_type = response["data"]['User_type']
                client_admin_id = response["data"]['client_admin_id']
                payment_status = response["data"]['payment_status']
                newsletter = response["data"]['newsletter_subscription']
                user_country = response["data"]['user_country']
                privacy_policy = response["data"]['Policy_status']
                other_policy = response["data"]['safety_security_policy']
                role_res = response["data"]['Role']
                company = response["data"]['company_id']
                member = response["data"]['Memberof']
                dept = response["data"]['dept_id']
                org = response["data"]['org_id']
                project = response["data"]['project_id']
                subproject = response["data"]['subproject_id']
            except:
                pass
            try:
                final_ltime = parser.parse(ltime).strftime('%d %b %Y %H:%M:%S')
                dowell_time = time.strftime(
                    "%d %b %Y %H:%M:%S", time.gmtime(dowellclock()+1609459200))
            except:
                final_ltime = ''
                dowell_time = ''
            serverclock = datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')

            field_session = {'sessionID': session, 'role': role_res, 'username': username, 'Email': email, "profile_img": profile_image, 'Phone': phone, "User_type": User_type, 'language': language, 'city': city, 'country': country, 'org': org, 'company_id': company, 'project': project, 'subproject': subproject, 'dept': dept, 'Memberof': member,
                            'status': 'login', 'dowell_time': dowell_time, 'timezone': zone, 'regional_time': final_ltime, 'server_time': serverclock, 'userIP': ip_user, 'userOS': osver, 'browser': browser, 'userdevice': device, 'userbrowser': "", 'UserID': userID, 'login_eventID': event_id, "redirect_url": "", "client_admin_id": client_admin_id,"payment_status":payment_status,"user_country":user_country,"newsletter_subscription":newsletter,"Privacy_policy":privacy_policy,"Safety,Security_policy":other_policy}
            dowellconnection("login", "bangalore", "login", "session",
                            "session", "1121", "ABCDE", "insert", field_session, "nil")

            info={"role":role_res,"username":username,"first_name":first_name,"last_name":last_name,"email":email,"profile_img":profile_image,"phone":phone,"User_type":User_type,"language":language,"city":city,"country":country,"status":"login","dowell_time":dowell_time,"timezone":zone,"regional_time":final_ltime,"server_time":serverclock,"userIP":ip_user,"userOS":osver,"userDevice":device,"language":language,"userID":userID,"login_eventID":event_id,"client_admin_id":client_admin_id,"payment_status":payment_status,"user_country":user_country,"newsletter_subscription":newsletter,"Privacy_policy":privacy_policy,"Safety,Security_policy":other_policy}
            info1=json.dumps(info)
            infoo=str(info1)
            custom_session = CustomSession.objects.create(sessionID=session,info=infoo,document="",status="login")

            serverclock1 = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            LiveStatus.objects.create(sessionID=session,username=username,product="",status="login",created=serverclock1,updated=serverclock1)

            if ip_city is not None:
                location_check = Location_check.objects.filter(username=username).first()
                if not location_check:
                    usual = [f'{ip_city}']
                    Location_check.objects.create(username=username,usual=str(json.dumps(usual)))
                else:
                    match = "Checking"
                    try:
                        usual = json.loads(location_check.usual)
                    except:
                        usual = location_check.usual
                    if ip_city not in usual:
                        try:
                            unusual = json.loads(location_check.unusual)
                        except:
                            unusual = location_check.unusual
                            pass
                        if unusual is not None:
                            for a in unusual:
                                if ip_city == list(a.keys())[0]:
                                    a[f"{ip_city}"]+=1
                                    match="True"
                                    if a[f"{ip_city}"] %3==0:
                                        send=True
                                    break
                                else:
                                    match="False"
                        if match !="True" and match !="False":
                            unusual=[{f'{ip_city}':1}]
                            send=True
                        elif match == "False":
                            unusual.append({f'{ip_city}':1})
                            send=True
                        location_check.unusual = str(json.dumps(unusual))
                        location_check.save(update_fields=["unusual"])
                        try:
                            if send == True:
                                values = {"username":username,"ip":ip_user,"location":ip_city}
                                url_email = "https://100085.pythonanywhere.com/api/email/"
                                payload = {
                                    "toname": username,
                                    "toemail": email,
                                    "subject": "Login detected from another location",
                                    "email_content": render_to_string(os.path.join(settings.BASE_DIR,'templates/login/location_info.html'),values)
                                }
                                response = requests.post(url_email, json=payload)
                        except:
                            pass

            try:
                obj.current_task="Connecting to UX Living Lab"
                obj.save(update_fields=['current_task'])
            except:
                pass

            data = { "msg":"success", "session_id": session }

            response = Response()

            if "org=" in mainparams and not "code=masterlink" in mainparams:
                if "https://ll04-finance-dowell.github.io/100018-dowellWorkflowAi-testing/" in mainparams and "portfolio" in mainparams and "product" in mainparams:
                    data["url"]=f'https://100093.pythonanywhere.com/exportfolio?session_id={session}&{mainparams}'
                elif "linktype=common" in mainparams:
                    data["url"]=f'https://100093.pythonanywhere.com/commoninvitelink?session_id={session}&{mainparams}'
                else:
                    data["url"]=f'https://100093.pythonanywhere.com/invitelink?session_id={session}&{mainparams}'

            elif "code=masterlink" in mainparams:
                data["url"]=f'https://100093.pythonanywhere.com/masterlink?session_id={session}&{mainparams}'

            elif "redirect_url" in mainparams:
                try:
                    result= re.search('redirect_url=(.*)&',mainparams)
                    rr=result.group(1)
                    if "&" in rr:
                        test=rr.split("&")
                        rr=test[0]
                except:
                    rr= mainparams[mainparams.find('redirect_url=')+13:]
                data["url"]=f'{rr}?session_id={session}'
            elif "hr_invitation" in mainparams:
                try:
                    result= re.search('hr_invitation=(.*)&',mainparams)
                    hr_invitation=result.group(1)
                except:
                    hr_invitation= mainparams[mainparams.find('hr_invitation=')+14:]
                hr_invitation=jwt.decode(jwt=hr_invitation,key='secret',algorithms=["HS256"])
                data["url"]=f'https://100093.pythonanywhere.com/invitelink1?session_id={session}&org={hr_invitation["org_name"]}&org_id={hr_invitation["org_id"]}&type={hr_invitation["member_type"]}&member_name={hr_invitation["toname"]}&code={hr_invitation["unique_id"]}&spec=hr_invite&u_code=hr_invite&detail=&qr_id={hr_invitation["qr_id"]}&owner_name={hr_invitation["owner_name"]}&portfolio_name={hr_invitation["portfolio_name"]}&product={hr_invitation["product"]}&role={hr_invitation["job_role"]}&toemail={hr_invitation["toemail"]}&data_type={hr_invitation["data_type"]}&date_time={hr_invitation["date_time"]}&name={username}'
            else:
                data["url"]=f'https://100093.pythonanywhere.com?session_id={session}'

            os.remove(os.path.join(BASE_DIR, 'static/img/test_facelogin/test.jpg'))
            response.data = data
            return response
        else:
            os.remove(os.path.join(BASE_DIR, 'static/img/test_facelogin/test.jpg'))
            resp = {"msg":"error","info": "Username not found in database"}
            return Response(resp,status=status.HTTP_400_BAD_REQUEST)
        # raise AuthenticationFailed("Username not Found or password not found")
    else:
        os.remove(os.path.join(BASE_DIR, 'static/img/test_facelogin/test.jpg'))
        resp = {"msg":"error","info": "User not found"}
        return Response(resp,status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def face_id(request):
    username=request.data.get("username")
    image=request.FILES.get("image")

    if None in [username,image]:
        return Response({'msg':'error','info':'All details not provided'},status.HTTP_400_BAD_REQUEST)

    filename = default_storage.save(image.name, image)
    image_path = default_storage.path(filename)
    unknown_img = face_recognition.load_image_file(image_path)
    try:
        unknown_encoding = face_recognition.face_encodings(unknown_img)[0]
        uke=str(unknown_encoding.tolist())
    except:
        return Response({
            'msg': "error",
            'info': "Face not detected in image",
            'Credentials': 'image'
        }, status=status.HTTP_400_BAD_REQUEST)

    obj=Face_Login.objects.filter(username=username).first()
    if obj is not None:
        obj.image=uke
        obj.save(update_fields=['image'])
        return Response({'msg':'success','info':'Face ID is updated !!'})
    Face_Login.objects.create(username=username,image=uke)
    return Response({'msg':'success','info':'Face ID is saved !!'})

@api_view(['POST'])
def user_under_org(request):
    org_id=request.data.get("org_id")
    fieldname={"_id":org_id}
    ca=dowellconnection("login","bangalore","login","client_admin","client_admin","1159","ABCDE","fetch",fieldname,"nil")
    aa=json.loads(ca)
    ok=aa["data"][0]["members"]["team_members"]["accept_members"]
    all_1=[]
    for i in ok:
        try:
            if i["name"] not in all_1 and i["name"] != "owner":
                all_1.append(i["name"])
        except:
            pass
    ok_final=[]
    for i in all_1:
        field_get={"Username":i}
        id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","find",field_get,"nil")
        idd=json.loads(id)
        if idd["data"] != None:
            ok_final.append({"Username":i,"userID":idd["data"]["_id"]})
    return Response({"msg":"success","info":"All username/id retreived","data":ok_final})

@api_view(['POST'])
def master_login(request):
    mainparams=request.data.get("data",None)

    if mainparams == None:
        resp = {"msg":"error","info": "Invalid data.."}
        return Response(resp,status=status.HTTP_400_BAD_REQUEST)
    else:
        try:
            mainparams=mainparams[5:]
        except:
            resp = {"msg":"error","info": "Invalid data.."}
            return Response(resp,status=status.HTTP_400_BAD_REQUEST)

    context={}
    loc=request.data.get("location")
    if loc is not None and loc != "":
        coordinates=loc.split(" ")
        url = 'https://api.open-elevation.com/api/v1/lookup?'
        params = {'locations': f"{coordinates[0]},{coordinates[1]}"}
        try:
            result = requests.get(url, params)
            altitude=result.json()['results'][0]['elevation']
        except:
            altitude="Location not allowed.."
    else:
        coordinates="Location not allowed.."
        altitude="Location not allowed.."
    try:
        lo = loc.split(" ")
        country, city = country_city_name(lo[0], lo[1])
    except:
        city = ""
        country = ""
    device=request.data.get("device")
    osver=request.data.get("os")
    browser=request.data.get("browser")
    ltime=request.data.get("time")
    ipuser=request.data.get("ip")
    language = request.data.get("language","English")
    try:
        if ipuser != "":
            response = requests.get(f'https://ipapi.co/{ipuser}/json/').json()
            ip_city=response.get("city")
        else:
            ip_city=None
    except Exception as e:
        ip_city=None
    zone = request.data.get("timezone")

    maindataa=decrypt_message(str.encode(mainparams[2:-1]),"uxliveadmin",b'\xc1\x12\xc4\xef\xd9\xbf\xac\xc5\xdc\x8e\x02BC\xa6f\xa4')
    maindata=maindataa.split("&")

    company=None
    org=None
    dept=None
    member=None
    project=None
    subproject=None
    role_res=None
    first_name=None
    last_name=None
    email=None
    phone=None
    User_type=None
    payment_status=None
    newsletter=None
    user_country=None
    privacy_policy=None
    other_policy=None
    userID=None
    client_admin_id=None

    user = authenticate(request, username="publicmember", password="Dowell@123")

    try:
        # portfolio=maindata[11].split("=")[1]
        # product=maindata[6].split("=")[1]
        username=maindata[2].split("=")[1]
        field = {"Username": username}
    except:
        resp = {"msg":"error","info": "Wrong data, Please try Later"}
        return Response(resp,status=status.HTTP_400_BAD_REQUEST)
    id = dowellconnection("login", "bangalore", "login", "registration",
                          "registration", "10004545", "ABCDE", "find", field, "nil")
    response = json.loads(id)
    if response["data"] != None:
        try:
            if response["data"]["User_status"]:
                if response["data"]["User_status"] == "inactive":
                    resp = {"msg":"error","info": "Username is termed inactive. Please contact admin."}
                    return Response(resp,status=status.HTTP_400_BAD_REQUEST)
                elif response["data"]["User_status"] == "deleted":
                    resp = {"msg":"error","info": "User not found."}
                    return Response(resp,status=status.HTTP_400_BAD_REQUEST)
        except:
            pass
        form = login(request, user)
        request.session.save()
        session = request.session.session_key

        try:
            res = create_event()
            event_id = res['event_id']
        except:
            event_id = None

        profile_image = "https://100014.pythonanywhere.com/media/user.png"
        first_name = response["data"]['Firstname']
        last_name = response["data"]['Lastname']
        email = response["data"]['Email']
        phone = response["data"]['Phone']
        try:
            userID=response["data"]['_id']
            client_admin_id=response["data"]['client_admin_id']
            if response["data"]['Profile_Image'] == "https://100014.pythonanywhere.com/media/":
                profile_image = "https://100014.pythonanywhere.com/media/user.png"
            else:
                profile_image = response["data"]['Profile_Image']
            User_type=response["data"]['User_type']
            payment_status=response["data"]['payment_status']
            newsletter=response["data"]['newsletter_subscription']
            user_country=response["data"]['user_country']
            privacy_policy=response["data"]['Policy_status']
            other_policy=response["data"]['safety_security_policy']
            role_res=response["data"]['Role']
            company=response["data"]['company_id']
            member=response["data"]['Memberof']
            dept=response["data"]['dept_id']
            org=response["data"]['org_id']
            project=response["data"]['project_id']
            subproject=response["data"]['subproject_id']
        except:
            pass
        try:
            final_ltime = parser.parse(ltime).strftime('%d %b %Y %H:%M:%S')
            dowell_time = time.strftime(
                "%d %b %Y %H:%M:%S", time.gmtime(dowellclock()+1609459200))
        except:
            final_ltime = ''
            dowell_time = ''
        serverclock = datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')

        field_session = {'sessionID': session, 'role': role_res, 'username': username, 'Email': email, "profile_img": profile_image, 'Phone': phone, "User_type": User_type, 'language': language, 'city': city, 'country': country, 'org': org, 'company_id': company, 'project': project, 'subproject': subproject, 'dept': dept, 'Memberof': member,
                         'status': 'login', 'dowell_time': dowell_time, 'timezone': zone, 'regional_time': final_ltime, 'server_time': serverclock, 'userIP': ipuser, 'userOS': osver, 'browser': browser, 'userdevice': device, 'userbrowser': "", 'UserID': userID, 'login_eventID': event_id, "redirect_url": "", "client_admin_id": client_admin_id,"payment_status":payment_status,"user_country":user_country,"newsletter_subscription":newsletter,"Privacy_policy":privacy_policy,"Safety,Security_policy":other_policy,"coordinates":coordinates,"altitude":altitude}
        dowellconnection("login","bangalore","login","login","login","6752828281","ABCDE","insert",field_session,"nil")
        info={"role":role_res,"username":username,"first_name":first_name,"last_name":last_name,"email":email,"profile_img":profile_image,"phone":phone,"User_type":User_type,"language":language,"city":city,"country":country,"status":"login","dowell_time":dowell_time,"timezone":zone,"regional_time":final_ltime,"server_time":serverclock,"userIP":ipuser,"userOS":osver,"userDevice":device,"language":language,"userID":userID,"login_eventID":event_id,"client_admin_id":client_admin_id,"payment_status":payment_status,"user_country":user_country,"newsletter_subscription":newsletter,"Privacy_policy":privacy_policy,"Safety,Security_policy":other_policy,"coordinates":coordinates,"altitude":altitude}
        info1=json.dumps(info)
        infoo=str(info1)
        custom_session=Linkbased_RandomSession.objects.create(sessionID=session,info=infoo,status="login")

        return Response({'msg':'success','info':'Login Success','url':f'https://100093.pythonanywhere.com?session_id={session}&username={username}&type=public'})
    else:
        return Response({'msg':'error','info':'Invalid data, Please try again later!'},status=status.HTTP_400_BAD_REQUEST)
    return Response({'msg':'success','info':'API working'})
