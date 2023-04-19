import base64,io
from rest_framework.response import Response
from django.contrib.sessions.models import Session
from django.contrib.auth import authenticate, login
from newlogin import dowell_func,qrcodegen,dowell_hash
from newlogin.dowell_func import dowellclock
import json
from collections import namedtuple
from loginapp.models import Account, CustomSession
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
import jwt
from lavapp import passgen
import time,pytz
from dateutil import parser
from newlogin.views import country_city_name
from newlogin.dowell_hash import dowell_hash as dowell_hash1
from PIL import Image
from django.core.files.base import ContentFile
import os

dpass="d0wellre$tp@$$"
import datetime
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
def MobileView(request):
    mdata=request.data.get
    username = mdata('username')
    password = mdata('password')
    loc=mdata("location")
    try:
        lo=loc.split(" ")
        country,city=country_city_name(lo[0],lo[1])
    except :
        city=""
        country=""
    # return Response({"city":city,"country":country,"zone":timezone_str})
    device=mdata("device")
    osver=mdata("os")
    # brow=mdata["browser"]
    ltime=mdata("time")
    ipuser=mdata("ip")
    zone=mdata("timezone")
    if None in [username,password,loc,device,osver,ltime,ipuser]:
        resp={"data":"Provide all credentials","Credentials":"username, password, location, device, os, time, ip"}
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
    user_id=None
    first_name=None
    last_name=None
    email=None
    phone=None
    User_type=None
    # role_id=mdata["role_id"]
    user=authenticate(request, username = username, password = password)
    if user is not None:
        field={"Username":username}
        id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","find",field,"nil")
        response=json.loads(id)
        if response["data"] != None:
            form=login(request,user)
            # try:
            #     if request.session.session_key:
            #         print("OK")
            #         resp={'session_id':request.session.session_key}
            #         return Response(resp)
            # except:
            #     pass
            request.session.save()
            session= request.session.session_key
            if CustomSession.objects.filter(sessionID=session).exists() :
                print("OK")
                resp={'session_id':session}
                return Response(resp)
            try:
                res=create_event()
                event_id=res['event_id']
            except:
                event_id=None
            first_name=response["data"]['Firstname']
            last_name=response["data"]['Lastname']
            email=response["data"]['Email']
            phone=response["data"]['Phone']
            try:
                User_type=response["data"]['User_type']
                client_admin_id=response["data"]['client_admin_id']
                user_id=response["data"]['profile_id']
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

            field_session={'sessionID':session,'role':role_res,'username':username,'Email':email,'Phone':phone,"User_type":User_type,'language':language,'city':city,'country':country,'org':org,'company_id':company,'project':project,'subproject':subproject,'dept':dept,'Memberof':member,'status':'login','dowell_time':dowell_time,'timezone':zone,'regional_time':final_ltime,'server_time':serverclock,'userIP':ipuser,'userOS':osver,'browser':browser,'userdevice':device,'userbrowser':"",'UserID':user_id,'login_eventID':event_id,"redirect_url":"","client_admin_id":client_admin_id}
            dowellconnection("login","bangalore","login","session","session","1121","ABCDE","insert",field_session,"nil")

            info={"role":role_res,"username":username,"email":email,"phone":phone,"User_type":User_type,"language":language,"city":city,"country":country,"status":"login","dowell_time":dowell_time,"timezone":zone,"regional_time":final_ltime,"server_time":serverclock,"userIP":ipuser,"browser":browser,"userOS":osver,"userDevice":device,"userBrowser":"","userID":user_id,"login_eventID":event_id,"client_admin_id":client_admin_id}
            info1=json.dumps(info)
            infoo=str(info1)
            custom_session=CustomSession.objects.create(sessionID=session,info=infoo,document="",status="login")

            #resp={'userinfo':info}
            resp={'session_id':session}
            return Response(resp)
        else:
            resp={"data":"Username not found in database"}
            return Response(resp)
        # raise AuthenticationFailed("Username not Found or password not found")
    else:
        resp={"data":"Username, Password combination incorrect.."}
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
@api_view(['GET', 'POST'])
def LinkLogin(request):
    if request.method == 'POST':
        username = request.data['username']
        password =request.data['password']
        user = authenticate(request, username = username, password = password)
        if user is not None:
            login(request, user)
            session=request.session.session_key
            return Response({"session_id": session})
        else:
            return Response({"message": "username or password wrong"})
    else:
        return Response({"message": "Error"})

# from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

# For Newlogin

@api_view(['GET', 'POST'])
def LinkBased(request):
    # url=request.GET.get("url",None)
    # user=request.GET.get("user",None)
    # context={}
    if request.method == 'POST':
        user=request.data["Username"]
        loc=request.data["Location"]
        device=request.data["Device"]
        osver=request.data["OS"]
        brow=request.data["Browser"]
        ltime=request.data["Time"]
        ipuser=request.data["IP"]
        mobconn=request.data["Connection"]
        field={"Username":user,"OS":osver,"Device":device,"Browser":brow,"Location":loc,"Time":str(ltime),"SessionID":"linkbased","Connection":mobconn,"qrcode_id":"user6","IP":ipuser}
        resp=dowellconnection("login","bangalore","login","login","login","6752828281","ABCDE","insert",field,"nil")
        respj=json.loads(resp)
        qrcodegen.qrgen1(user,respj["inserted_id"],f"dowell_login/media/userqrcodes/{respj['inserted_id']}.png")
        return Response({"qrid":respj["inserted_id"]})
        # if url is not None:
        #     return redirect(f'{url}?qrid={respj["inserted_id"]}')
        # return HttpResponse("pl provide redirect url")
    return Response({"message":"its working"})

@api_view(["POST"])
def Registration(request):
    user=request.data["Username"]
    # return Response(user)
    image=request.data["Profile_Image"]
    password=request.data["Password"]
    first=request.data["Firstname"]
    last=request.data["Lastname"]
    email=request.data["Email"]
    role="User"
    ccode=request.data["Team_Code"]
    phonecode=request.data["phonecode"]
    phone=request.data["Phone"]

    field_user={'Username':user}
    check_username=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",field_user,"nil")
    check_response_username=json.loads(check_username)

    if len(check_response_username['data'])>0:
        return Response({'message':"Username already taken"})

    field1={}
    id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",field1,"nil")
    idd=json.loads(id)
    res_list=idd["data"]
    profile_id=dowell_func.get_next_pro_id(res_list)


    company_field={ 'owner': user, 'company': user, 'members': [], 'layer1': 0, 'layer2': 1, 'layer3': 1, 'layer4': 1, 'layer5': 1, 'layer6': 1}
    company_res=dowellconnection("login","bangalore","login","company","company","1083","ABCDE","insert",company_field,"nil")
    company_r=json.loads(company_res)

    company_id=company_r['inserted_id']
    org_id=[]
    project_id=[]
    subproject_id=[]
    dept_id=[]
    Memberof={}


    field={"Username":user,"Password":dowell_hash.dowell_hash(password),"Profile_Image":image,"Firstname":first,"Lastname":last,"Email":email,"Role":role,"Team_Code":ccode,"phonecode":phonecode,"Phone":phone,"profile_id":profile_id,'org_id':org_id,'company_id':company_id,'project_id':project_id,'subproject_id':subproject_id,'dept_id':dept_id,'Memberof':Memberof}
    id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","insert",field,"nil")
    idd=json.loads(id)
    inserted_id=idd['inserted_id']

    return Response({
        'message':f"{user}, registration success",
        'inserted_id':f"{inserted_id}"
        })

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
                        if "owner" in i["username"]:
                            var3.append(i)
                    if i["username"]=="owner" and i["product"]!="owner":
                        var3.append(i)
            except:
                pass
        if product is not None:
            try:
                for i in portfolio:
                    if type(i["username"]) is list:
                        if "owner" in i["username"] and product in i["product"]:
                            var3.append(i)
                    if i["username"]=="owner" and i["product"]!="owner" and product in i["product"]:
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
            var2["client_admin_id"]=details_res["data"][0]["_id"]
            for r in var3:
                r["org_id"]=details_res["data"][0]["_id"]
                r["org_name"]=details_res["data"][0]["document_name"]
        except:
            pass
        organisations=details_res["data"][0]['organisations'][0]["org_name"]
        otherorg=details_res["data"][0]['other_organisation']
        team_members=details_res["data"][0]['members']['team_members']['accept_members']
        guest_members=details_res["data"][0]['members']['guest_members']['accept_members']
        public_members=details_res["data"][0]['members']['public_members']['accept_members']
        main_member={'team_member':team_members,'guest_members':guest_members,'public_members':public_members}
        # portfolio={'username':var2["username"] , 'member_type': 'owner', 'product': 'owner', 'data_type': 'owner', 'operations_right': 'owner', 'role': 'owner', 'security_layer': 'owner', 'portfolio_name': 'owner','org_id':var2["client_admin_id"]}
        userinfo={'userinfo':var2, 'portfolio_info':var3 ,"userportfolio":productport,'members':main_member,"own_organisations":[{"org_name":organisations}],"other_org":otherorg}
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
                    username=a['Username']
                    payment_status=a['payment_status']
                    final2.append({"member_name":username,"org_name":username,"payment_status":payment_status})
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
        all1=CustomSession.objects.all()
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
                    logintimelist.append(a3["regional_time"])
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
        response={'data':'Please provide all fields'}
        return Response(response)
    if obj is not None:
        print("ok")
        try:
            obj.set_password(new_password)
            obj.save()
            field={'Username':username}
            up_field={'Password':dowell_hash1(new_password)}
            dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","update",field,up_field)
            response={'data':'Password Changed successfully..'}
            return Response(response)
        except Exception as e:
            response={'data':'Error','error':e}
            return Response(response)
    else:
        response={'data':'Username, Password combination incorrect'}
        return Response(response)

@api_view(['POST'])
def profile_update(request):
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
    #User_type=request.data.get("user_type")
    Profile_Image=request.data.get("image")
    obj=Account.objects.filter(username=username).first()
    field={"document_name":username}
    client_admin=dowellconnection("login","bangalore","login","client_admin","client_admin","1159","ABCDE","fetch",field,"nil")
    data2=json.loads(client_admin)
    print(data2)
    data1=data2["data"][0]
    up_field={}
    update_fields=[]
    if Profile_Image is not None:
        img = Image.open(io.BytesIO(base64.decodebytes(bytes(Profile_Image, "utf-8"))))
        if obj.profile_image == "":
            img.save(f"dowell_login/static/img/api_upload/{username}.png")
            im = Image.open(f"dowell_login/static/img/api_upload/{username}.png")
            thumb_io = io.BytesIO()
            im.save(thumb_io, im.format, quality=60)
            obj.profile_image.save(im.filename,ContentFile(thumb_io.getvalue()), save=False )
            try:
                os.remove(f"dowell_login/static/img/api_upload/{username}.png")
            except:
                pass
            obj.save()
            up_field["Profile_Image"]=f"https://100014.pythonanywhere.com/media/{obj.profile_image}"
            update_data1={"profile_img":f"https://100014.pythonanywhere.com/media/{obj.profile_image}"}
            data1["profile_info"].update(update_data1)
        else:
            img.save(f"dowell_login/media/{obj.profile_image}")
    if Firstname is not None:
        obj.first_name=Firstname
        update_fields.append("first_name")
        up_field["Firstname"]=Firstname
        update_data1={"first_name":Firstname}
        data1["profile_info"].update(update_data1)
        # update_data2={"first_name":Firstname}
        # data1["members"]["team_members"]["accept_members"][0].update(update_data2)
    if Lastname is not None:
        obj.last_name=Lastname
        update_fields.append("last_name")
        up_field["Lastname"]=Lastname
        update_data1={"last_name":Lastname}
        data1["profile_info"].update(update_data1)
        # update_data2={"last_name":Lastname}
        # data1["members"]["team_members"]["accept_members"][0].update(update_data2)
    if Email is not None:
        obj.email=Email
        update_fields.append("email")
        up_field["Email"]=Email
        update_data1={"email":Email}
        data1["profile_info"].update(update_data1)
        # update_data2={"email":Email}
        # data1["members"]["team_members"]["accept_members"][0].update(update_data2)
    if Phone is not None:
        obj.phone=Phone
        update_fields.append("phone")
        up_field["Phone"]=Phone
        update_data1={"phone":Phone}
        data1["profile_info"].update(update_data1)
    if address is not None:
        up_field["address"]=address
    if zip_code is not None:
        up_field["zip_code"]=zip_code
    if user_city is not None:
        up_field["user_city"]=user_city
    if user_location is not None:
        up_field["user_location"]=user_location
    if user_country is not None:
        up_field["user_country"]=user_country
    if native_language is not None:
        up_field["native_language"]=native_language
    if nationality is not None:
        up_field["nationality"]=nationality
    if language_preferences is not None:
        up_field["language_preferences"]=language_preferences
    if vision is not None:
        up_field["vision"]=vision

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

    response={"data":"Updated successfully.."}
    return Response(response)

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
            return Response(resp1["data"])
        else:
            return Response({"Error":"Credentials wrong1"})
    else:
        return Response({"Error":"Credentials wrong"})



