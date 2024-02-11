
from django.shortcuts import render,redirect,HttpResponse
from django.utils.decorators import method_decorator
from loginapp import dowell_func
from urllib import parse
from loginapp.models import Account, CustomSession, RandomSession, QR_Creation, LiveStatus, Live_QR_Status, Live_Public_Status, Linkbased_RandomSession, Location_check
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.utils.translation import gettext as _
from loginapp import forms
from lavapp import passgen
from newlogin import qrcodegen
from newlogin.dowell_hash import dowell_hash
from newlogin.dowell_func import get_next_pro_id,dowellclock,generateOTP, decrypt_message
import json
from django.views.decorators.clickjacking import (
    xframe_options_exempt, xframe_options_deny, xframe_options_sameorigin,
)
from loginapp import models
from django.contrib.auth.decorators import login_required
#from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import authenticate, login, logout
from loginapp.event_function import event_creation, create_event
from django.core.mail import send_mail,EmailMessage,get_connection
from django.contrib import messages
#from django.core.files.storage import FileSystemStorage
from django.core.files.storage import default_storage
import os
from django.contrib.auth.hashers import make_password
import datetime
from loginapp.dowellconnection import dowellconnection
from newlogin.views import country_city_name
import requests
import time
from dateutil import parser
import ast
import base64
from django.http import JsonResponse
from functools import wraps
from django.template import RequestContext, Template
from otp import mobilnumber,mobilotp
from rest_framework.decorators import api_view
import jwt
from django.template.loader import render_to_string
from dowell_login.settings import BASE_DIR

linkl=""
linklabel=""
usersession=object()

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def LinkBased(request):
    url=request.GET.get("redirect_url",None)
    murl=request.GET.get("mobileapp",None)
    mobileurl=f'intent://{murl}/_n/mainfeed/#Intent;package={murl};scheme=https;end'
    user=request.GET.get("user",None)
    context={}
    if request.method == 'POST':
        loc=request.POST["loc"]
        device=request.POST["dev"]
        osver=request.POST["os"]
        brow=request.POST["brow"]
        ltime=request.POST["time"]
        ipuser=request.POST["ip"]
        mobconn=request.POST["conn"]
        if user is None:
            user=passgen.generate_random_password1(8)
            # field={"status":"offline"}
            # resp=dowellconnection("login","bangalore","login","public_members","public_members","1242001","ABCDE","fetch",field,"nil")
            # respj=json.loads(resp)
            # this_user=respj["data"][0]
            # del this_user["status"]
            # field_up={"OS":osver,"Device":device,"Browser":brow,"Location":loc,"Time":str(ltime),"SessionID":"linkbased","Connection":mobconn,"qrcode_id":"user6","IP":ipuser,"status":"online"}
            # resp_up=dowellconnection("login","bangalore","login","public_members","public_members","1242001","ABCDE","update",this_user,field_up)
            # respj_up=json.loads(resp_up)
            # if murl is not None:
            #     # return HttpResponse("<script>function lav(){alert(%s) };lav();</script>" % (murl))
            #     return HttpResponse(f'<script>url={mobileurl};window.location.replace(url);</script>')
            # if url is not None:
            #     return redirect(f'{url}?qrid={respj_up["inserted_id"]}')
            # return HttpResponse("pl provide redirect url")
        field={"Username":user,"OS":osver,"Device":device,"Browser":brow,"Location":loc,"Time":str(ltime),"SessionID":"linkbased","Connection":mobconn,"qrcode_id":"user6","IP":ipuser,"type":"public_members"}
        resp=dowellconnection("login","bangalore","login","login","login","6752828281","ABCDE","insert",field,"nil")
        respj=json.loads(resp)
        qrcodegen.qrgen1(user,respj["inserted_id"],f"dowell_login/media/userqrcodes/{respj['inserted_id']}.png")
        if murl is not None:
            # return HttpResponse("<script>function lav(){alert(%s) };lav();</script>" % (murl))
            return HttpResponse(f'<script>url={mobileurl};window.location.replace(url);</script>')

        if url is not None:
            return redirect(f'{url}?qrid={respj["inserted_id"]}')
        return HttpResponse("pl provide redirect url")
    return render(request,"login/linkbased.html",context)

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def LinkLogin(request):
    mainparams=request.get_full_path()
    mainparams=mainparams[mainparams.find('?')+1:]
    r_url=request.GET.get("redirect_url",None)
    user=request.GET.get("user",None)
    portfolio_name=request.GET.get("portfolio_name",None)
    portfolio_code=request.GET.get("portfolio_code",None)
    org_name=request.GET.get("org_name",None)
    murl=request.GET.get("mobileapp",None)
    mobileurl=f'intent://{murl}/_n/mainfeed/#Intent;package={murl};scheme=https;end'
    context={}
    if request.method == 'POST':
        loc=request.POST["loc"]
        device=request.POST["dev"]
        osver=request.POST["os"]
        brow=request.POST["brow"]
        ltime=request.POST["time"]
        ipuser=request.POST["ip"]
        mobconn=request.POST["conn"]
        if user is None and portfolio_code is None:
            # return HttpResponse("Username is required..")
            field={"status":"offline"}
            resp=dowellconnection("login","bangalore","login","public_members","public_members","1242001","ABCDE","fetch",field,"nil")
            respj=json.loads(resp)
            this_user=respj["data"][0]
            del this_user["status"]
            field_up={"status":"online"}
            resp_up=dowellconnection("login","bangalore","login","public_members","public_members","1242001","ABCDE","update",this_user,field_up)
            respj_up=json.loads(resp_up)

            random_session=passgen.generate_random_password1(32)
            field_session={"session_id":random_session,"userinfo":{"Username":this_user["Username"],"OS":osver,"Device":device,"Browser":brow,"Location":loc,"Time":str(ltime),"Connection":mobconn,"qrcode_id":"user6","IP":ipuser}}
            final=dowellconnection("login","bangalore","login","login","login","6752828281","ABCDE","insert",field_session,"nil")
            final_r=json.loads(final)
            qrcodegen.qrgen1(user,final_r["inserted_id"],f"dowell_login/media/userqrcodes/{final_r['inserted_id']}.png")
            if murl is not None:
                # return HttpResponse("<script>function lav(){alert(%s) };lav();</script>" % (murl))
                return HttpResponse(f'<script>url={mobileurl};window.location.replace(r_url);</script>')
            if r_url is not None:
                return redirect(f'{r_url}?qrid={final_r["inserted_id"]}')
            return HttpResponse("pl provide redirect url")
        field={"Username":user}
        resp=dowellconnection("login","bangalore","login","public_members","public_members","1242001","ABCDE","find",field,"nil")
        respj=json.loads(resp)
        if respj["data"] == None:
            return HttpResponse("Username is invalid..")
        up_field1={"status":"online"}
        resp1=dowellconnection("login","bangalore","login","public_members","public_members","1242001","ABCDE","update",field,up_field1)
        respj1=json.loads(resp1)

        client_field={"document_name":org_name}
        client_resp=dowellconnection("login","bangalore","login","client_admin","client_admin","1159","ABCDE","find",client_field,"nil")
        client_respj=json.loads(client_resp)
        if client_respj["data"] != None:
            port=client_respj["data"]["portpolio"]
            try:
                for i in port:
                    if i["portfolio_code"]== portfolio_code:
                        break
                if i["portfolio_code"] != portfolio_code:
                    return HttpResponse("Portfolio Code is invalid..")
            except:
                return HttpResponse("Provided data is invalid")
        else:
            return HttpResponse("Org Name is invalid..")

        product_list=["Workflow AI","Living Lab Scales","Legalzard","Permutation Calculator","Team Management","Social Media Automation","Customer Experience", "Living Lab Chat","Living Lab Admin","Wifi QR Code","Living Lab Monitoring","Living Lab API","Secure Repositories"]
        urls=["https://ll04-finance-dowell.github.io/workflowai.online","https://100035.pythonanywhere.com/client","https://ll09-legalcompliance-dowell.github.io","https://100050.pythonanywhere.com/calculator","https://ll07-team-dowell.github.io/Jobportal","https://www.socialmediaautomation.uxlivinglab.online","https://ll03-identity-dowell.github.io/100096-DowellChat/#/customer-support","https://ll03-identity-dowell.github.io/100096-DowellChat/#/living-lab-chat","https://100093.pythonanywhere.com/home","https://l.ead.me/dowellwifiqrcode","http://100082.pythonanywhere.com","https://ll05-ai-dowell.github.io/100105-DowellApiKeySystem","https://ll07-team-dowell.github.io/100045-SecureRepository"]
        if i["product"] in product_list:
            url=urls[product_list.index(i["product"])]
        else:
            url="https://100014.pythonanywhere.com/testingRoshan"

        i["org_id"]=client_respj["data"]["_id"]
        random_session=passgen.generate_random_password1(32)
        field_session={"session_id":random_session,"userinfo":{"Username":user,"OS":osver,"Device":device,"Browser":brow,"Location":loc,"Time":str(ltime),"Connection":mobconn,"IP":ipuser},"portfolio_info":i,"type":"public_members"}
        dowellconnection("login","bangalore","login","login","login","6752828281","ABCDE","insert",field_session,"nil")

        # qrcodegen.qrgen1(user,random_session,f"dowell_login/media/userqrcodes/{respj['inserted_id']}.png")

        return redirect(f'{url}?session_id={random_session}&mainparams')

        if "code=masterlink1" in mainparams:
            return redirect(f'https://100093.pythonanywhere.com/masterlink?session_id={random_session}&{mainparams}')

        if url is not None:
            return redirect(f'https://100093.pythonanywhere.com?linklogin_id={random_session}&redirect_url={url}')
        return redirect(f'https://100093.pythonanywhere.com/public_link?linklogin_id={random_session}')
    return render(request,"login/linkbased.html",context)

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def home(request):
    context={}
    context["title"]="dowell_home"
    context['hello']=_("Hellow")
    return render(request,"index.html",context)
@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def test_login(request):
    context={}
    if request.method == 'POST':
        user=request.POST["user"]
        username=""
        pwd=request.POST["pwd"]
        field={"Username":user}
        usr=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",field,"nil")
        r=json.loads(usr)
        for i in r["data"]:
            username=i["Username"]
        if user==username:
            auth_user=authenticate(username=user, password=pwd)
            if auth_user is not None:
                form = login(request, auth_user)
                return redirect("main")
            else:
               return HttpResponse("sorry baby")
        return HttpResponse("sorry baby1")
    # user = authenticate(request, username = user, password = passs)
    return render(request, 'test_login.html', context)
@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def test_login1(request):
    user="valimai"
    passs="Nagaswrn$14"
    user = authenticate(request, username = user, password = passs)
@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def directlinktest(request):
    context={}
    context["title"]="Link Check"
    ip=request.META.get("REMOTE_ADDR")
    usr=request.GET.get('user',None)
    ltime=request.GET.get('ltime',None)
    code=request.GET.get('code',None)
    netwk=dowell_func.host_check('http://google.com')
    sys=dowell_func.host_check('https://100014.pythonanywhere.com/')
    if netwk!="Error":
        context["network"]="Network Ok"
        if sys!="Error":
            context["system"]="System Ok"
            if usr and code:
                user = authenticate(request, username = usr, password = code)
                if user is not None:
                    form = login(request, user)
                    context["username"]=usr
                    session=request.session.session_key
                    try:
                        event_id=event_creation("FB","101","0","pfm","1","1","1029",str(os.urandom(20)),str(os.urandom(25)),usr,"5029","testing",ip,session,"locaton not get",str(ltime),"nil")
                        field={"Username":usr,"OS":"Not get","Device":"Not get","Browser":"Not get","Location":'Not get',"Time":str(ltime),"SessionID":session,"Connection":"Not get","event_id":event_id}
                        dowellconnection("login","bangalore","login","login","login","6752828281","ABCDE","insert",field,"nil")
                    except:
                        context["api"]="api not work"
                    #return render(request, 'lav_dash.html',context)
                    return redirect('dashboard')
                else:
                    pass
                context["link"]="Link Ok"
            else:
                context["link"]="Link not Recognised"
        else:
            context["system"]="System Error"
    else:
        context["network"]="Network Error"
    return render(request, 'link_check.html', context)
@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def FaceCheck(request):
    context={}
    context["title"]="Face Check"
    if request.method == 'POST':
        netwk=dowell_func.host_check('http://google.com')
        sys=dowell_func.host_check('https://100014.pythonanywhere.com/')
        image=request.FILES['profile_image']
        file_name = default_storage.save(image.name, image)
        file_url = default_storage.url(file_name)
        if netwk!="Error":
            context["network"]="Network Ok"
            if sys!="Error":
                context["system"]="System Ok"
                import face_recognition
                #images = models.Account.objects.all()
                picture_of_me = face_recognition.load_image_file(f'dowell_login{file_url}')
                try:
                    my_face_encoding = face_recognition.face_encodings(picture_of_me)[0]
                    context["face"]="Face ID Recognised"
                except IndexError as e:
                    context["face"]="Face ID not Recognised"
                        #return render(request,'login.html',context)
            else:
                context["system"]="System Error"
        else:
            context["network"]="Network Error"
        return render(request, 'face_check.html', context)
@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def selectLanguage(request):
    context={}
    context["title"]="Language"
    context["redirect_to"]=redirect('https://100014.pythonanywhere.com/direct')
    return render(request,'lang.html',context)
@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def selectLanguage1(request):
    context={}
    context["title"]="Language"
    context["redirect_to"]=redirect('https://100014.pythonanywhere.com/direct')
    return render(request,'lang1.html',context)
@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def directLink(request):
    context={}
    if request.method == 'POST':
        netwk=dowell_func.host_check('http://google.com')
        sys=dowell_func.host_check('https://100014.pythonanywhere.com/')
        if netwk!="Error":
            context["network"]="Network Ok"
            if sys!="Error":
                context["system"]="System Ok"
                url = request.POST['link']
                logincode = request.POST['logincode']
                if url is not None:
                    params = dict(parse.parse_qsl(parse.urlsplit(url).query))
                    if "user" in params:
                        user = authenticate(request, username = params["user"], password = params["code"])
                        if user is not None:
                            form = login(request, user)

                            return redirect('main')
                        else:
                            context["link"]="Link not Recognised"
                    else:
                        context["link"]="Link not Recognised"
                else:
                    context["link"]="Link not Recognised"
            else:
                context["system"]="System Error"
        else:
            context["network"]="Network Error"
        return render(request,'link_check1.html',context)
    context["title"]="Direct Link"
    return render(request,'directlink.html',context)

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def GuestPage(request):
    context={}
    if request.method == 'POST':
        email = request.POST['email']
        user = request.POST['user']
        otp=dowell_func.generateOTP()
        time = datetime.datetime.now()
        try:
            emailexist = models.GuestAccount.objects.get(email=email)
        except models.GuestAccount.DoesNotExist:
            emailexist = None
        if emailexist is not None:
            models.GuestAccount.objects.filter(email=email).update(otp=otp,expiry=time,username=user)
            # q = MyModel.objects.get(pk=some_value)
            # q.field1 = 'some value'
            # q.save()
            htmlgen = f'Dear {user}, <br> Please Enter below <strong>OTP</strong> to login dowell account <br><h2>Your OTP is <strong>{otp}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'
            send_mail('Your OTP for logging in Dowell account',otp,'dowelllogintest@gmail.com',[email], fail_silently=False, html_message=htmlgen)
            context["user"]=user
            context["email"]=email
            return render(request,'login/new_guest_verify.html',context)
        else:
            htmlgen = f'Dear {user}, <br> Please Enter below <strong>OTP</strong> to login dowell account <br><h2>Your OTP is <strong>{otp}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'
            send_mail('Your OTP for logging in Dowell account',otp,'dowelllogintest@gmail.com',[email], fail_silently=False, html_message=htmlgen)
            insertdata=models.GuestAccount(username=user,email=email,otp=otp)
            insertdata.save()
            context["user"]=user
            context["email"]=email
            return render(request,'login/new_guest_verify.html',context)
    return render(request, 'login/new_guest.html')

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def GuestVerify(request):
    context={}
    if request.method == 'POST':

        email = request.POST['email']
        user = request.POST['user']
        otp = request.POST['otp']
        loc=request.POST["loc"]
        device=request.POST["dev"]
        osver=request.POST["os"]
        brow=request.POST["brow"]
        ltime=request.POST["time"]
        ipuser=request.POST["ip"]
        mobconn=request.POST["conn"]
        if otp.isnumeric():
            try:
                valid = models.GuestAccount.objects.get(otp=otp,email=email)
            except models.GuestAccount.DoesNotExist:
                valid=None

            if valid is not None:
                user1=user
                pwd=f'{user.capitalize()}@1234'
                useradd=Account(username =user1,password = pwd,first_name = "guest",last_name = "guest",email = email,role = 'guest',teamcode = 'guest',phonecode='91',phone = '1234567890')
                useradd.save()
                login(request, useradd, backend='django.contrib.auth.backends.ModelBackend')
                try:
                    event_id=event_creation("FB","101","0","pfm","1","1","1029",str(os.urandom(20)),str(os.urandom(25)),username,"5029","testing",ipuser,session,loc,str(ltime),"nil")
                    field={"Username":username,"OS":osver,"Device":device,"Browser":brow,"Location":loc,"Time":str(ltime),"SessionID":session,"Connection":mobconn,"event_id":event_id,"IP":ipuser}
                    dowellconnection("login","bangalore","login","login","login","6752828281","ABCDE","insert",field,"nil")
                except:
                    context["api"]="api not work"
                return redirect('main')
            else:
                context["error"]="Wrong OTP"
                context["user"]=user
                context["email"]=email
                return render(request,'login/new_guest_verify.html',context)
        else:
                context["error"]="Enter only numeric"
                context["user"]=user
                context["email"]=email
                return render(request,'login/new_guest_verify.html',context)

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def RegisterPage(request):
    otp_user=generateOTP()
    context={}
    # orgs=None
    type1=None
    # For countrycode
    URL='https://100074.pythonanywhere.com/countries/johnDoe123/haikalsb1234/100074/'
    r=requests.get(url=URL)
    finallist=[]
    for a in r.json():
        mylist=["+"+a["country_code"],a["name"]+"(+"+a["country_code"]+")"]
        finallist.append(mylist)
    orgs=request.GET.get("org",None)
    # url=request.GET.get("redirect_url",None)
    if is_ajax(request=request):
        if request.POST.get('form')=='verify_otp':
            otp=request.POST.get('otp')
            email=request.POST.get('email')
            try:
                valid = models.GuestAccount.objects.get(otp=otp,email=email)
            except models.GuestAccount.DoesNotExist:
                valid=None
            if valid:
                return JsonResponse({'verified':'True'})
            else:
                return JsonResponse({'verified':'False'})
        elif request.POST.get('form')=='mobileotp':
            sms=generateOTP()
            code=request.POST.get("phonecode")
            phone=request.POST.get("phone")
            user=request.POST.get("user")
            full_number=code+phone
            time=datetime.datetime.now()
            try:
                phone_exists = models.mobile_sms.objects.get(phone=full_number)
            except models.mobile_sms.DoesNotExist:
                phone_exists = None
            if phone_exists is not None:
                models.mobile_sms.objects.filter(phone=full_number).update(sms=sms,expiry=time,username=user)
            else:
                models.mobile_sms.objects.create(phone=full_number,sms=sms,expiry=time,username=user)
            # url = "https://100085.pythonanywhere.com/api/sms/"
            # payload = {
            #     "sender" : "DowellLogin",
            #     "recipient" : full_number,
            #     "content" : f"Enter the following OTP to create your dowell account: {sms}",
            #     "created_by" : "Manish"
            #     }
            url = "https://100085.pythonanywhere.com/api/v1/dowell-sms/c9dfbcd2-8140-4f24-ac3e-50195f651754/"
            payload = {
                "sender" : "DowellLogin",
                "recipient" : full_number,
                "content" : f"Enter the following OTP to create your dowell account: {sms}",
                "created_by" : "Manish"
                }
            response = requests.request("POST", url, data=payload)
            # resp=json.loads(response)
            if len(response.json())>1:
                return JsonResponse({'msg':'SMS sent successfully!!'})
            else:
                return JsonResponse({'msg':'error'})
        elif request.POST.get('form')=='verify_sms':
            code=request.POST.get("phonecode")
            phone=request.POST.get("phone")
            sms=request.POST.get("sms")
            full_number=code+phone
            try:
                valid = models.mobile_sms.objects.get(sms=sms,phone=full_number)
            except models.mobile_sms.DoesNotExist:
                valid=None
            if valid:
                return JsonResponse({'verified':'True'})
            else:
                return JsonResponse({'verified':'False'})
        else:
            user=request.POST.get('username',"User")
            email_ajax=request.POST.get('email',None)
            time=datetime.datetime.now()
            try:
                emailexist = models.GuestAccount.objects.get(email=email_ajax)
            except models.GuestAccount.DoesNotExist:
                emailexist = None
            if emailexist is not None:
                models.GuestAccount.objects.filter(email=email_ajax).update(otp=otp_user,expiry=time,username=user)
                url = "https://100085.pythonanywhere.com/api/signUp-otp-verification/"
                payload = json.dumps({
                    "toEmail":email_ajax,
                    "toName":user,
                    "topic":"RegisterOtp",
                    "otp":otp_user
                    })
                headers = {
                    'Content-Type': 'application/json'
                    }
                response1 = requests.request("POST", url, headers=headers, data=payload)
                # htmlgen = f'Dear {user}, <br> Please Enter below <strong>OTP</strong> to create your dowell account <br><h2>Your OTP is <strong>{otp_user}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'
                # send_mail('Your OTP for creating your Dowell account',otp_user,settings.EMAIL_HOST_USER,[email_ajax], fail_silently=False, html_message=htmlgen)
                response = {}
                return JsonResponse(response)
            else:
                insertdata=models.GuestAccount(username=user,email=email_ajax,otp=otp_user)
                insertdata.save()
                url = "https://100085.pythonanywhere.com/api/signUp-otp-verification/"
                payload = json.dumps({
                    "toEmail":email_ajax,
                    "toName":user,
                    "topic":"RegisterOtp",
                    "otp":otp_user
                    })
                headers = {
                    'Content-Type': 'application/json'
                    }
                response1 = requests.post(url, data=payload)
                print(response1)
                # response1 = requests.request("POST", url, headers=headers, data=payload)
                print(response1.text)
                response = {"error":""}
                response1=json.loads(response1)
                if "error" in response1:
                    response["error"]=response1["error"]
                # htmlgen = f'Dear {user}, <br> Please Enter below <strong>OTP</strong> to create account <br><h2>Your OTP is <strong>{otp_user}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'
                # send_mail('Your OTP for creating your Dowell account',otp_user,settings.EMAIL_HOST_USER,[email_ajax], fail_silently=False, html_message=htmlgen)
                return JsonResponse(response)

    if request.method == 'POST':
        valid=request.POST.get('otp_status',None)
        mainparams=request.POST.get('mainparams',None)
        type1=request.POST.get('type',None)
        otp=request.POST.get('otp')
        sms=request.POST.get('sms')
        org=request.POST.get('org',None)
        form = forms.UserRegisterForm(request.POST,request.FILES)
        policy_status=request.POST.get('policy_status')
        other_policy=request.POST.get('other_policy')
        newsletter=request.POST.get('newsletter')
        user = request.POST['username']
        password1 = request.POST['password1']
        password2 = request.POST['password2']
        first = request.POST['first_name']
        last = request.POST['last_name']
        email = request.POST['email']
        phonecode=request.POST["phonecode"]
        phone = request.POST['phone']
        user_type=request.POST.get('user_type')
        user_country=request.POST.get('user_country')
        role1="guest"
        img=request.FILES.get("profile_image",None)
        name=""
        # if other_policy !="Accepted":
        #     context["error"]="Safety and Security policy not accepted.."
        #     return render(request, "login/new_register.html", context)
        if policy_status !="Accepted":
            context["error"]="Policy not accepted.."
            return render(request, "login/new_register.html", context)
        if password1 != password2:
            context["error"]="Passwords Not Matching.."
            return render(request, "login/new_register.html", context)
        # try:
        #     valid = models.GuestAccount.objects.get(otp=otp,email=email)
        # except models.GuestAccount.DoesNotExist:
        #     valid=None
        user_exists=Account.objects.filter(username=user).first()
        if user_exists:
            context["error"]="The username is already taken!"
            return render(request, "login/new_register.html", context)
        if valid is not None:
            try:
                ro=Account.objects.filter(email=email)#.update(password = password,first_name = first,last_name = last,email = email,role = role,teamcode = ccode,phonecode=phonecode,phone = phone,profile_image=img)

                for i in ro:
                    if email==i.email and role1==i.role:
                        ro=Account.objects.filter(email=email).update(password = make_password(password1),first_name = first,last_name = last,email = email,phonecode=phonecode,phone = phone,profile_image=img)
            except Account.DoesNotExist:
                name=None
        else:
            context["error"]="Wrong OTP!!"
            return render(request, "login/new_register.html", context)
        if name is not None:
            if img:
                new_user=Account.objects.create(email=email,username=user,password=make_password(password1),first_name = first,last_name = last,phonecode=phonecode,phone = phone,profile_image=img)
            else:
                new_user=Account.objects.create(email=email,username=user,password=make_password(password1),first_name = first,last_name = last,phonecode=phonecode,phone = phone)
            profile_image=new_user.profile_image
            # if user == "Testing400442":
            json_data = open('dowell_login/static/client.json')
            data1 = json.load(json_data)
            json_data.close()
            # main={"username": [],"member_type": "owner","product": "Living Lab Admin","data_type": "Real_Data","operations_right": "Add/Edit","role": "default","portfolio_name": "default","portfolio_code": "01","portfolio_specification": "default","portfolio_uni_code": "default","portfolio_details": "default","status": "enable"}
            # product_list=["Workflow AI", "Digital Queue", "Wifi QR Code", "Living Lab Chat","User Experience Live","Social Media Automation","Living Lab Scales","Logo Scan","Legalzard","Living Lab Maps","Customer Experience","Living Lab Admin","Team Management","Living Lab Monitoring","Live Stream Dashboard","Sales Agent","Permutation Calculator","Dowell Customer Support Centre","Secure Repositories","Secure Data"]
            # for i in range(len(product_list)):
            #     main["username"]=[user]
            #     main["product"]=product_list[i]
            #     main["portfolio_code"]=i+1
            #     # print(main)
            #     data1["portpolio"].append(main.copy())
            # else:
            # json_data = open('dowell_login/static/client_admin.json')
            # data1 = json.load(json_data)
            # json_data.close()
            default =   {
            "org_id":user,
            "org_name":user,
            "username": [user],
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

            # company_field={ 'owner': user, 'company': user, 'members': [user], 'layer1': 0, 'layer2': 1, 'layer3': 1, 'layer4': 1, 'layer5': 1, 'layer6': 1}
            # company_res=dowellconnection("login","bangalore","login","company","company","1083","ABCDE","insert",company_field,"nil")
            # company_r=json.loads(company_res)
            event_id=None
            try:
                res=create_event()
                event_id=res['event_id']
            except:
                pass

            field={"Profile_Image":f"https://100014.pythonanywhere.com/media/{profile_image}","Username":user,"Password":dowell_hash(password1),"Firstname":first,"Lastname":last,"Email":email,"phonecode":phonecode,"Phone":phone,"profile_id":profile_id,"client_admin_id":client_admin_res["inserted_id"],"Policy_status":policy_status,"User_type":user_type,"eventId":event_id,"payment_status":"unpaid","safety_security_policy":other_policy,"user_country":user_country,"newsletter_subscription":newsletter}
            #field={"Username":user,"Password":password,"Firstname":first,"Lastname":last,"Email":email,"Role":role,"Team_Code":ccode,"phonecode":phonecode,"Phone":phone,"user_id":"userid"}
            if sms == "" or sms==None:
                sms_verified="unverified"
                field["verified"]="False"
            else:
                sms_verified="verified"
                field["verified"]="True"
            id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","insert",field,"nil")

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
                "verified_phone":sms_verified,
                "verified_email": "verified"
                    })
            headers = {
                'Content-Type': 'application/json'
                }
            response1 = requests.request("POST", url, headers=headers, data=payload)

            # field_owner={'owner':username}
            # usr=dowellconnection("login","bangalore","login","company","company","1083","ABCDE","fetch",field_owner,"nil")
            # r=json.loads(usr)
            # a=r["data"][0]["members"]
            # if a==[]:
            #     a.append(username)
            #     update_company={'members':a}
            #     dowellconnection("login","bangalore","login","company","company","1083","ABCDE","update",field_owner,update_company)
            if org != "None":
                return redirect(f'https://100014.pythonanywhere.com/?{mainparams}')
            else:
                return render(request,'login/after_register.html',{'user':user,'mainparams':mainparams})
        else:

            return HttpResponse("check")
            form = forms.UserRegisterForm(request.POST,request.FILES)

            if form.is_valid():
                user = form.cleaned_data['username']
                password = form.cleaned_data['password1']
                first = form.cleaned_data['first_name']
                last = form.cleaned_data['last_name']
                email = form.cleaned_data['email']
                role = form.cleaned_data['role']
                ccode = form.cleaned_data['teamcode']
                phonecode=form.cleaned_data["phonecode"]
                phone = form.cleaned_data['phone']
                form.save()

                #userid=form.id
                try:

                    field={"Username":user,"Password":password,"Firstname":first,"Lastname":last,"Email":email,"Role":role,"Team_Code":ccode,"phonecode":phonecode,"Phone":phone,"user_id":"userid"}
                    id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","insert",field,"nil")
                    return redirect('login')
                except:
                    pass
            # username = form.cleaned_data.get('username')
            # email = form.cleaned_data.get('email')
            # msg.attach_alternative(html_content, "text/html")
            # msg.send()
            # messages.success(request, f'Your account has been created ! You are now able to log in')
            # htmly = get_template('user/Email.html')
            # d = { 'username': username }
            # subject, from_email, to = 'welcome', 'your_email@gmail.com', email
            # html_content = htmly.render(d)
            # msg = EmailMultiAlternatives(subject, html_content, from_email, [to])
                return redirect('login')
    else:
        form = forms.UserRegisterForm()
    #return render(request, 'user/register.html', {'form': form, 'title':'reqister here'})
    return render(request,'login/new_register.html',{'form': form, 'title':'reqister here','country_resp':finallist,'org':orgs,'type':type1})


@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def LoginWithFace(request):
    context={}
    if request.method == 'POST':
        image=request.FILES['profile_image']
        # fs = FileSystemStorage(location=folder) #defaults to   MEDIA_ROOT
        # filename = fs.save(image.name, image)
        file_name = default_storage.save(image.name, image)
        path=settings.MEDIA_ROOT
        #  Reading file from storage
        #file = default_storage.open(file_name)
        file_url = default_storage.url(file_name)
        #return HttpResponse(f'<img src="{file_url}"/> <br> <h1>{path}</h1>')
        import face_recognition
        images = models.Account.objects.all()
        picture_of_me = face_recognition.load_image_file(f'dowell_login{file_url}')
        try:
            my_face_encoding = face_recognition.face_encodings(picture_of_me)[0]
        except IndexError as e:
            context["img"]="face not found in this image"
            return render(request,'login.html',context)
        for img in images:
            if "user.png" in img.profile_image.url or "lav.png" in img.profile_image.url:
                continue
            pimg = face_recognition.load_image_file(f'dowell_login{img.profile_image.url}')
            try:
                pimg_encoding = face_recognition.face_encodings(pimg)[0]
                results = face_recognition.compare_faces([my_face_encoding], pimg_encoding)
                if results[0] == True:
                    # return HttpResponse(img.username)
                    user = models.Account.objects.get(username=img.username)
                    if user is not None:
                        form = login(request, user)
                        return redirect('main')
                    break
                else:
                    context["img"]="Could not match any r image"
                    return render(request,'login.html',context)
            except IndexError as e:
                pass
        context["img"]="Some Error in database"
        return render(request,'login.html',context)
    return render(request,'login.html',context)

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def master_login(request):
    mainparams=request.GET.get("data",None)
    # print(request.GET)
    # return HttpResponse(request.GET)
    context={}
    if request.method == 'POST':
        loc=request.POST["loc"]
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
        device=request.POST["dev"]
        osver=request.POST["os"]
        browser=request.POST.get("brow")
        ltime=request.POST["time"]
        ipuser=request.POST["ip"]
        language = request.POST.get("language", "English")
        try:
            if ipuser != "":
                response = requests.get(f'https://ipapi.co/{ipuser}/json/').json()
                ip_city=response.get("city")
            else:
                ip_city=None
        except Exception as e:
            ip_city=None
        mobconn=request.POST["conn"]
        zone = request.POST.get("timezone")
        maindataa=decrypt_message(str.encode(mainparams[2:-1]),"uxliveadmin",b'\xc1\x12\xc4\xef\xd9\xbf\xac\xc5\xdc\x8e\x02BC\xa6f\xa4')
        # print(maindata)
        maindata=maindataa.split("&")
        print(maindata)
        # return HttpResponse(f"{maindata}")

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
            return HttpResponse("Invalid data..")
        id = dowellconnection("login", "bangalore", "login", "registration",
                              "registration", "10004545", "ABCDE", "find", field, "nil")
        response = json.loads(id)
        if response["data"] != None:
            try:
                if response["data"]["User_status"]:
                    if response["data"]["User_status"] == "inactive":
                        return HttpResponse("Username is termed inactive. Please contact admin.")
                    elif response["data"]["User_status"] == "deleted":
                        return HttpResponse("User not found.")
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

            return redirect(f'https://100093.pythonanywhere.com?session_id={session}&username={username}&type=public')
        else:
            return HttpResponse("Invalid data, Please try again later..")
    return render(request,"login/linkbased.html",context)

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def LoginPage(request):
    context={}
    orgs=None
    type1=None
    email1=None
    name1=None
    u_code=None
    spec=None
    code=None
    detail=None
    try:
        # https://100014.pythonanywhere.com/?type=Z3Vlc3RfbWVtYmVycw==&name=VGVzdGluZ180MDA0MQ==&code=MTIz&spec=MjM0&u_code=NDU2&detail=MzQ1&org=Um9zaGFuXzQwMDQ=
        orgs=request.GET.get('org',None)
        type1=request.GET.get('type',None)
        # type1=request.GET.get('type',None)
        email1=request.GET.get('email',None)
        name1=request.GET.get('name',None)
        code=request.GET.get('code',None)
        spec=request.GET.get('spec',None)
        u_code=request.GET.get('u_code',None)
        detail=request.GET.get('detail',None)
    except:
        pass
    hr_invitation=request.GET.get('hr_invitation',None)
    context["hr_invitation"]=hr_invitation
    context["org"]=orgs
    context["type"]=type1
    urls=request.GET.get('next',None)
    context["url"]=request.GET.get('redirect_url',None)
    redirect_url=request.GET.get('redirect_url',None)
    r_url=request.GET.get('redirect_url','Nope')
    country=""
    city=""
    mainparams=request.get_full_path()
    mainparams=mainparams[mainparams.find('?')+1:]
    if "code=masterlink1" in mainparams:
        return redirect(f"https://100014.pythonanywhere.com/linklogin?{mainparams}")
    userr=request.session.session_key
    if userr:
        if orgs:
            if "https://ll04-finance-dowell.github.io/100018-dowellWorkflowAi-testing/" in r_url and "portfolio" in mainparams and "product" in mainparams:
                return redirect(f'https://100093.pythonanywhere.com/exportfolio?session_id={userr}&{mainparams}')
            elif "linktype=common" in mainparams:
                return redirect(f'https://100093.pythonanywhere.com/commoninvitelink?session_id={userr}&{mainparams}')
            else:
                # return redirect(f'https://100093.pythonanywhere.com/invitelink?session_id={session}&{mainparams}')
                return redirect(f'https://100093.pythonanywhere.com/invitelink?session_id={userr}&org={orgs}&type={type1}&name={name1}&code={code}&spec={spec}&u_code={u_code}&detail={detail}')
        elif "code=masterlink" in mainparams or "code=masterlink1" in mainparams:
            return redirect(f'https://100093.pythonanywhere.com/masterlink?session_id={userr}&{mainparams}')

        elif redirect_url:
            # logindetail=CustomSession.objects.filter(sessionID=userr).first()
            # info=json.loads(logindetail.info)
            # if "ll04-finance-dowell.github.io" in redirect_url:
            #     if info["User_type"] =="betatester":
            #         return redirect(f'https://ll04-finance-dowell.github.io/100018-dowellWorkflowAi-testing?session_id={userr}')
            #     else:
            #         return redirect(f'https://ll04-finance-dowell.github.io/workflowai.online?session_id={userr}')
            # if "ll07-team-dowell.github.io/100098-DowellJobPortal" in redirect_url or "ll07-team-dowell.github.io/Jobportal" in redirect_url:
            #     if info["User_type"] =="betatester":
            #         return redirect(f'https://ll07-team-dowell.github.io/100098-DowellJobPortal?session_id={userr}')
            #     else:
            #         return redirect(f'https://ll07-team-dowell.github.io/Jobportal?session_id={userr}')
            # else:
            return HttpResponse(f"<script>window.location.replace('{redirect_url}?session_id={userr}');</script>")
            return redirect(f'{redirect_url}?session_id={userr}')
        elif hr_invitation:
            hr_invitation=jwt.decode(jwt=hr_invitation,key='secret',algorithms=["HS256"])
            logindetail=CustomSession.objects.filter(sessionID=userr).first()
            info=json.loads(logindetail.info)
            return redirect(f'https://100093.pythonanywhere.com/invitelink1?session_id={userr}&org={hr_invitation["org_name"]}&org_id={hr_invitation["org_id"]}&type={hr_invitation["member_type"]}&member_name={hr_invitation["toname"]}&code={hr_invitation["unique_id"]}&spec=hr_invite&u_code=hr_invite&detail=&qr_id={hr_invitation["qr_id"]}&owner_name={hr_invitation["owner_name"]}&portfolio_name={hr_invitation["portfolio_name"]}&product={hr_invitation["product"]}&role={hr_invitation["job_role"]}&toemail={hr_invitation["toemail"]}&data_type={hr_invitation["data_type"]}&date_time={hr_invitation["date_time"]}&name={info["username"]}')
        elif "code=masterlink" in mainparams:
            return redirect(f'https://100093.pythonanywhere.com/masterlink?session_id={userr}&{mainparams}')
        else:
            return redirect(f'https://100093.pythonanywhere.com/?session_id={userr}')
    var1=passgen.generate_random_password1(24)
    context["random_session"]=var1
    if request.COOKIES.get('qrid'):
        context["qrid"]=request.COOKIES.get('qrid')
        qrid_obj_1=QR_Creation.objects.filter(qrid=context["qrid"]).first()
        if qrid_obj_1.info == "":
            context["qrid_type"]="new"
        else:
            context["qrid_type"]="old"
    else:
        qrid_obj=QR_Creation.objects.filter(status="new").first()
        if qrid_obj is None:
            ruser=passgen.generate_random_password1(24)
            rpass="DoWell@123"
            new_obj = QR_Creation.objects.create(qrid=ruser,password=rpass,status="used")
            context["qrid"]=new_obj.qrid
            context["qrid_type"]="new"
            html=render(request,'login/new_login.html',context)
            html.set_cookie('qrid',new_obj.qrid, max_age = 365*24*60*60)
            return html
        else:
            qrid_obj.status="used"
            qrid_obj.save(update_fields=['status'])
            context["qrid"]=qrid_obj.qrid
            context["qrid_type"]="new"
            html=render(request,'login/new_login.html',context)
            html.set_cookie('qrid',qrid_obj.qrid, max_age = 365*24*60*60)
            return html
    if request.method == 'POST':
        username = request.POST['username']
        obj=Account.objects.filter(username=username).first()
        try:
        #obj.current_task="Data taken, Checking policy acceptance and  User registration..."
            obj.current_task="Logging In"
            obj.save(update_fields=['current_task'])
        except:
            pass
        random_session=request.POST.get('random_session',None)
        random_session_obj1=RandomSession.objects.filter(username=username).first()
        if random_session_obj1 is None:
            random_session_obj=RandomSession.objects.filter(sessionID=random_session).first()
            if random_session_obj is None:
                context["error"]="Please accept the terms in policy page!"
                return render(request,'login/new_login.html',context)
            random_session_obj.username=username
            random_session_obj.save(update_fields=['username'])
        mainparams=request.POST.get('mainparams',None)
        org1=request.POST.get('org',None)
        type1=request.POST.get('type',None)
        url=request.POST.get('url',None)
        username = request.POST['username']
        password = request.POST['password']
        loc=request.POST["loc"]
        zone=request.POST.get("zone",None)
        hr_invitation=request.POST.get("hr_invitation",None)
        try:
            lo=loc.split(" ")
            country,city=country_city_name(lo[0],lo[1])
        except Exception as e:
            city=""
            country=""
        language=request.POST.get("language","en-us")
        device=request.POST.get("dev","")
        osver=request.POST.get("os","")
        brow=request.POST.get("brow","")
        ltime=request.POST["time"]
        ipuser=request.POST.get("ip","")
        try:
            if ipuser != "":
                response = requests.get(f'https://ipapi.co/{ipuser}/json/').json()
                ip_city=response.get("city")
            else:
                ip_city=None
        except Exception as e:
            ip_city=None
        mobconn=request.POST["conn"]

        user = authenticate(request, username = username, password = password)

        if user is not None:
            form = login(request, user)
            context["username"]=username
            context["user"]=user
            if user.role=="Admin":
                linkl="createusers"
                linklabel="Create User Links"
                usersession=user
                context["linkl"]=linkl
                context["linklabel"]=linklabel
                context["user"]=usersession
            session=request.session.session_key
            try:

                #event_id=event_creation("FB","101","0","pfm","1","1","1029",str(os.urandom(20)),str(os.urandom(25)),username,"5029","testing",ipuser,session,loc,str(ltime),"nil")
                res=create_event()
                event_id=res['event_id']
                # field={"Username":username,"OS":osver,"Device":device,"Browser":brow,"Location":loc,"Time":str(ltime),"SessionID":session,"Connection":mobconn,"event_id":event_id,"IP":ipuser,"user_id":user.id}
                # dowellconnection("login","bangalore","login","login","login","6752828281","ABCDE","insert",field,"nil")
            except:
                event_id=None
                context["api"]="api not work"
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
            profile_image="https://100014.pythonanywhere.com/media/user.png"
            client_admin_id=""
            field={"Username":username}
            id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","find",field,"nil")
            response=json.loads(id)
            if response["data"] != None:
                try:
                    if response["data"]["User_status"] == "deleted":
                        print("Yes")
                        context["error"]="Username, Password combination is incorrect!"
                        logout(request)
                        return render(request,'login/new_login.html',context)
                    elif response["data"]["User_status"] == "inactive":
                        context["error"]="Account disabled, please contact admin"
                        logout(request)
                        return render(request,'login/new_login.html',context)
                    obj.current_task="Verifying User"
                    #obj.current_task="Logging In"
                    obj.save(update_fields=['current_task'])
                except:
                    pass
                first_name=response["data"]['Firstname']
                last_name=response["data"]['Lastname']
                email=response["data"]['Email']
                phone=response["data"]['Phone']
                try:
                    userID=response["data"]['_id']
                    if response["data"]['Profile_Image'] =="https://100014.pythonanywhere.com/media/":
                        profile_image="https://100014.pythonanywhere.com/media/user.png"
                    else:
                        profile_image=response["data"]['Profile_Image']
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
                except Exception as e:
                    pass

            try:
                final_ltime=parser.parse(ltime).strftime('%d %b %Y %H:%M:%S')
                dowell_time=time.strftime("%d %b %Y %H:%M:%S", time.gmtime(dowellclock()+1609459200))
            except:
                final_ltime=''
                dowell_time=''
            serverclock=datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')

            field_session={'sessionID':session,'role':role_res,'username':username,"first_name":first_name,"last_name":last_name,'Email':email,'profile_img':profile_image,'Phone':phone,"User_type":User_type,'language':language,'city':city,'country':country,'org':org,'company_id':company,'project':project,'subproject':subproject,'dept':dept,'Memberof':member,'status':'login','dowell_time':dowell_time,'timezone':zone,'regional_time':final_ltime,'server_time':serverclock,'userIP':ipuser,'userOS':osver,'userdevice':device,'userbrowser':brow,'userID':userID,'login_eventID':event_id,"redirect_url":redirect_url,"client_admin_id":client_admin_id,"payment_status":payment_status,"user_country":user_country,"newsletter_subscription":newsletter,"Privacy_policy":privacy_policy,"Safety,Security_policy":other_policy}
            dowellconnection("login","bangalore","login","session","session","1121","ABCDE","insert",field_session,"nil")
            try:
                obj.current_task="Connecting to UX Living Lab"
                obj.save(update_fields=['current_task'])
            except:
                pass

            info={"role":role_res,"username":username,"first_name":first_name,"last_name":last_name,"email":email,"profile_img":profile_image,"phone":phone,"User_type":User_type,"language":language,"city":city,"country":country,"status":"login","dowell_time":dowell_time,"timezone":zone,"regional_time":final_ltime,"server_time":serverclock,"userIP":ipuser,"userOS":osver,"userDevice":device,"userBrowser":brow,"language":language,"userID":userID,"login_eventID":event_id,"client_admin_id":client_admin_id,"payment_status":payment_status,"user_country":user_country,"newsletter_subscription":newsletter,"Privacy_policy":privacy_policy,"Safety,Security_policy":other_policy}
            info1=json.dumps(info)
            infoo=str(info1)
            custom_session=CustomSession.objects.create(sessionID=session,info=infoo,document="",status="login")

            # live_status_obj=LiveStatus.objects.filter(username=username).first()
            # # print(live_status_obj)
            # if live_status_obj is not None:
            #     live_status_obj.sessionID=session
            #     live_status_obj.date_created=serverclock
            #     live_status_obj.date_updated=serverclock
            #     live_status_obj.status="login"
            #     live_status_obj.save(update_fields=['sessionID','date_created','date_updated','status'])
            # else:
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


            if "org" in mainparams and not "code=masterlink" in mainparams:
                # org_resp1=json.loads(org_resp)
                # main={"name":username,"member_code":org_resp1["u_code"],"member_spec":org_resp1["spec"],"member_uni_code":org_resp1["uni_code"],"member_details":org_resp1["detail"],"status":"used"}
                if "https://ll04-finance-dowell.github.io/100018-dowellWorkflowAi-testing/" in url and "portfolio" in mainparams and "product" in mainparams:
                    return redirect(f'https://100093.pythonanywhere.com/exportfolio?session_id={session}&{mainparams}')
                elif "linktype=common" in mainparams:
                    return redirect(f'https://100093.pythonanywhere.com/commoninvitelink?session_id={session}&{mainparams}')
                else:
                    return redirect(f'https://100093.pythonanywhere.com/invitelink?session_id={session}&{mainparams}')
            elif "hr_invitation" in mainparams:
                hr_invitation=jwt.decode(jwt=hr_invitation,key='secret',algorithms=["HS256"])
                return redirect(f'https://100093.pythonanywhere.com/invitelink1?session_id={session}&org={hr_invitation["org_name"]}&org_id={hr_invitation["org_id"]}&type={hr_invitation["member_type"]}&member_name={hr_invitation["toname"]}&code={hr_invitation["unique_id"]}&spec=hr_invite&u_code=hr_invite&detail=&qr_id={hr_invitation["qr_id"]}&owner_name={hr_invitation["owner_name"]}&portfolio_name={hr_invitation["portfolio_name"]}&product={hr_invitation["product"]}&role={hr_invitation["job_role"]}&toemail={hr_invitation["toemail"]}&data_type={hr_invitation["data_type"]}&date_time={hr_invitation["date_time"]}&name={username}')

            elif "code=masterlink" in mainparams:
                return redirect(f'https://100093.pythonanywhere.com/masterlink?session_id={session}&{mainparams}')

            if url=="None":
                return redirect(f'https://100093.pythonanywhere.com/?session_id={session}')
            else:
                # if "ll04-finance-dowell.github.io" in url:
                #     if User_type =="betatester":
                #         return redirect(f'https://ll04-finance-dowell.github.io/100018-dowellWorkflowAi-testing?session_id={session}')
                #     else:
                #         return redirect(f'https://ll04-finance-dowell.github.io/workflowai.online?session_id={session}')
                # elif "ll07-team-dowell.github.io" in url:
                #     if User_type =="betatester":
                #         return redirect(f'https://ll07-team-dowell.github.io/100098-DowellJobPortal?session_id={session}')
                #     else:
                #         return redirect(f'https://ll07-team-dowell.github.io/Jobportal?session_id={session}')
                # else:
                return HttpResponse(f"<script>window.location.replace('{url}?session_id={session}');</script>")
                return redirect(f'{url}?session_id={session}')
        else:
            context["error"]="Username, Password combination is incorrect!"
            context["main_logo"]='dowelllogo.png'
            return render(request,'login/new_login.html',context)
    #form = AuthenticationForm()
    if redirect_url is None:
        context["main_logo"]='logos/dowelllogo.png'
    else:
        if '100084' in redirect_url:
            context["main_logo"]='logos/dowell_workflow_AI.png'
        else:
            context["main_logo"]='logos/dowelllogo.png'
        # logos=[]
        # path='dowell_login/static/img/logos'
        # for path1 in os.listdir(path):
        #     if os.path.isfile(os.path.join(path,path1)):
        #         logos.append(path1)
        # return HttpResponse(logos)
    return render(request,'login/new_login.html',context)


def LogoutView(request):
    context={}
    returnurl=request.GET.get('returnurl',None)
    context["returnurl"]=returnurl
    session=request.session.session_key
    live_status_obj=LiveStatus.objects.filter(sessionID=session).first()
    if live_status_obj is not None:
        live_status_obj.status="logout"
        live_status_obj.save(update_fields=['status'])
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
    context["info"]='Logged Out Successfully!!'
    return render(request, 'login/new_beforelogout.html',context)

def signout(request):
    context={}
    returnurl=request.GET.get('returnurl',None)
    context["returnurl"]=returnurl
    return render(request, 'login/new_beforelogout.html',context)

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def CreateUsersPage(request):
    context={}
    if request.method == 'POST':
        pattern = request.POST['userpattern']
        role = request.POST['role']
        code = request.POST['teamcode']
        qty=int(request.POST["qty"])
        lk=[]
        ls=[]
        pwd=[]
        for i in range(qty +1):
            if i==0:
                continue
            rpass=passgen.generate_random_password(10)
            ls.append(f'{pattern}{i}')
            pwd.append(f'{rpass}')
            lk.append(f'https://100014.pythonanywhere.com/linkcheck?user={pattern}{i}&code={pwd}')
            try:
                user = models.Account.objects.create_user(username=f'{pattern}{i}',email=f'{pattern}{i}@lav.com',password=rpass,role=role,teamcode=code)
            except:
                context["errorusers"]="Error : User already exist or something wrong"
                return render(request,'createusers.html',context)
        context["ls"]=zip(ls,pwd,lk)
        context["errorusers"]="Users Successfully Created"
        return render(request,'createusers.html',context)

def MainPage(request):
    return render(request, 'landing.html')
def BookShow(request):
    import requests
    def book(movie):
        from bs4 import BeautifulSoup
        res = requests.get('https://in.bookmyshow.com/explore/home/madanapalle/')
        soup = BeautifulSoup(res.content, 'html.parser')
        # url = urllib.request.urlopen("https://in.bookmyshow.com/explore/home/madanapalle/").read()
        # soup = BeautifulSoup(url)

        for line in soup.find_all('a'):
            if line.get("href") is not None :
                if movie in line.get('href'):
                    print(line.get('href'))
                    link=line.get('href')
                    if link is not None:
                        res = requests.get(link)
                        soup = BeautifulSoup(res.content, 'html.parser')
                        book=soup.find("Book tickets")
                        htmlgen = f'Dear {user}, <br> Please Enter below <strong>OTP</strong> to login dowell account <br><h2>Your OTP is <strong>{otp}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'
                        send_mail('you can book now',"Sarkari vari pata",'dowelllogintest@gmail.com',[email], fail_silently=False, html_message=htmlgen)
                        return HttpResponse("book now")
                        break
            else:
                return HttpResponse("sorry")
    book("https://in.bookmyshow.com/madanapalle/movies/sarkaru-vaari-paata/")
    return HttpResponse("sorry")
def SysError(request):
    return render(request, 'syserror.html')
def CopyUsers(request):
    context={}
    ids=[]
    usrs = models.Account.objects.all().order_by("id")
    context["ct"]=len(usrs)
    for i in usrs:
        field={"Username":i.username}
        user=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",field,"nil")
        try:
            ls=json.loads(user)
            dicto=dict(ls["data"][0])
            if dicto["Username"]:
                continue
        except:
            pass
        field={"Username":i.username,"Password":i.password,"Firstname":i.first_name,"Lastname":i.last_name,"Email":i.email,"Role":i.role,"Code":i.teamcode,"Phone_Code":i.phonecode, "Phone":i.phone}
        id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","insert",field,"nil")
        context["lv"]=usrs
        if "true" in id:
            ids.append(id)
        else:
            context["id"]=id
            return render(request, 'copyusers.html',context)
            context["ids"]=ids
        context["ct1"]=len(ids)
    return render(request, 'copyusers.html',context)
def AccountError(request):
    return render(request, 'accounterror.html')
def NwError(request):
    return render(request, 'nwerror.html')
def CheckPage(request):
    return render(request, 'landing.html')
@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def LandPage(request):
    context={}
    ruser=passgen.generate_random_password1(8)
    rpass=passgen.generate_random_password(10)
    try:
        user = models.Account.objects.create_user(username=ruser,email=f'{ruser}@lav.com',password=rpass,role="Freelancer",teamcode="67890")

    except:
        context["link"]="land"
        context["color"]="red"
        context["msg"]="Try again"
    context["link"]="simplelogin"
    context["user"]=ruser
    context["passwd"]=rpass
    context["msg"]="Login"
    context["color"]="white"
    return render(request, 'land.html',context)
@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def SimpleLoginPage(request):
    if request.method == 'POST':
        username = request.POST['user']
        password = request.POST['password']
        user = authenticate(request, username = username, password = password)
        if user is not None:
            form = login(request, user)
            return redirect('main')
    return redirect("/")
@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def testlogin(request):
    context={}
    import requests
    def Dowell_Login(username,password,location,device,os,browser,time,ip,type_of_conn):
        url="https://100014.pythonanywhere.com/api/login/"
        userurl="http://100014.pythonanywhere.com/api/user/"
        payload = {
            'username': username,
            'password': password,
            'location':location,
            'device':device,
            'os':os,
            'browser':browser,
            'time':time,
            'ip':ip,
            'type_of_conn':type_of_conn
        }
        with requests.Session() as s:
            p = s.post(url, data=payload)
            return p.text
            # if "Username" in p.text:
            #     return p.text
            # else:
            #     user = s.get(userurl)
            #     return user.text
    if request.method == 'POST':
        username = request.POST['user']
        password = request.POST['pass']
        loc=request.POST["loc"]
        device=request.POST["dev"]
        osver=request.POST["os"]
        brow=request.POST["brow"]
        ltime=request.POST["time"]
        ipuser=request.POST["ip"]
        mobconn=request.POST["conn"]
        reme=Dowell_Login("username","password","loc","device","oser","brow","ltime","ipuser","mobconn")
        jwtdic=json.loads(reme)
        response=HttpResponse("Cookie Set")
        response.set_cookie(key=list(jwtdic.keys())[0], value=list(jwtdic.values())[0])
        return HttpResponse("success")
    return render(request,'testlogin.html',context)
def CreateUser(request):
    ruser=passgen.generate_random_password1(8)
    rpass=passgen.generate_random_password(10)
    user = Account.objects.create_user(username=ruser,email=f'{ruser}@lav.com',password=rpass,role="Freelancer",teamcode="15692532")
    return HttpResponse("<h1 align='center'>Thank you for Visit our website </h1>")
@csrf_exempt
def LoginwithLink(request):
    rt=request.data
    username=rt["username"]
    password=rt["password"]
    user = authenticate(request, username = username, password = password)
    if user is not None:
        login(request, user)
        return HttpResponse(request.session.session_key)
    # usr=request.GET.get('user',None)
    # code=request.GET.get('code',None)
    # loc=request.GET.get('loc',None)
    # device=request.GET.get('device',None)
    # osver=request.GET.get('osver',None)
    # brow=request.GET.get('brow',None)
    # ltime=request.GET.get('ltime',None)
    # ipuser=request.GET.get('ipuser',None)
    # mobconn=request.GET.get('conn',None)
    # redirecturl=request.GET.get('url',None)
    #usr=""&code=""&loc=""&device=""&osver=""&brow=""&ltime="",ipuser=""&conn=""&url="your url"
    # user = authenticate(request, username = username, password = password)
    # if user is not None:
    #     login(request, user)
    #     session=request.session.session_key
    #     field={"Username":user,"OS":osver,"Device":device,"Browser":brow,"Location":loc,"Time":str(ltime),"SessionID":session,"Connection":mobconn,"event_id":event_id,"IP":ipuser,"user_id":user.id}
    #     dowellconnection("login","bangalore","login","login","login","6752828281","ABCDE","insert",field,"nil")
    return redirect(redirecturl)

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def forgot_password(request):
    context={}
    otp_password=generateOTP()
    if is_ajax(request=request):
        if request.POST.get('form')=="otp_form":
            user=request.POST.get('user',"User")
            email_ajax=request.POST.get('email',None)
            time=datetime.datetime.now()
            user_obj = Account.objects.filter(email=email_ajax,username=user)
            if user_obj.exists():
                try:
                    emailexist = models.GuestAccount.objects.get(email=email_ajax)
                except models.GuestAccount.DoesNotExist:
                    emailexist = None
                if emailexist is not None:
                    models.GuestAccount.objects.filter(email=email_ajax).update(otp=otp_password,expiry=time,username=user)
                    # url = "https://100085.pythonanywhere.com/api/signUp-otp-verification/"
                    # payload = json.dumps({
                    #     "toEmail":email_ajax,
                    #     "toName":user,
                    #     "topic":"RegisterOtp",
                    #     "otp":otp_password
                    #     })
                    # headers = {
                    #     'Content-Type': 'application/json'
                    #     }
                    # response1 = requests.request("POST", url, headers=headers, data=payload)
                    htmlgen = f'Dear {user}, <br> Please Enter below <strong>OTP</strong> to change password of dowell account <br><h2>Your OTP is <strong>{otp_password}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'
                    send_mail('Your OTP for changing password of Dowell account',otp_password,settings.EMAIL_HOST_USER,[email_ajax], fail_silently=False, html_message=htmlgen)
                    response = {'msg':''}
                    return JsonResponse(response)
                else:
                    insertdata=models.GuestAccount(username=user,email=email_ajax,otp=otp_password)
                    insertdata.save()
                    # url = "https://100085.pythonanywhere.com/api/signUp-otp-verification/"
                    # payload = json.dumps({
                    #     "toEmail":email_ajax,
                    #     "toName":user,
                    #     "topic":"RegisterOtp",
                    #     "otp":otp_password
                    #     })
                    # headers = {
                    #     'Content-Type': 'application/json'
                    #     }
                    # response1 = requests.request("POST", url, headers=headers, data=payload)
                    htmlgen = f'Dear {user}, <br> Please Enter below <strong>OTP</strong> to change password of dowell account <br><h2>Your OTP is <strong>{otp_password}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'
                    send_mail('Your OTP for changing password of Dowell account',otp_password,settings.EMAIL_HOST_USER,[email_ajax], fail_silently=False, html_message=htmlgen)
                    response = {'msg':''}
                    return JsonResponse(response)
            else:
                response = {'msg':'Username, Email combination is incorrect!'}
                return JsonResponse(response)
        else:
            username=request.POST['user']
            email=request.POST['email']
            password2=request.POST['password2']
            otp=request.POST['otp']
            try:
                valid = models.GuestAccount.objects.get(otp=otp,email=email)
            except models.GuestAccount.DoesNotExist:
                valid=None
            if valid is not None:
                aa=Account.objects.filter(email=email,username=username).first()
                aa.set_password(password2)
                aa.save()
                field={'Username':username,'Email':email}
                check=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",field,"nil")
                check_res=json.loads(check)
                if len(check_res["data"])>=1:
                    update_field={'Password':dowell_hash(password2)}
                    dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","update",field,update_field)
                response = {'msg':''}
                return JsonResponse(response)
            else:
                response = {'msg':'Wrong OTP'}
                return JsonResponse(response)
    return render(request,'login/new_forgotpassword.html',context)
@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def forgot_username(request):
    context={}
    otp_username=generateOTP()
    if is_ajax(request=request):
        if request.POST.get('form')=="otp_form":
            user="user"
            email_ajax=request.POST.get('email',None)
            time=datetime.datetime.now()
            obj=models.GuestAccount.objects.filter(email=email_ajax)
            if obj.exists():
                obj.update(otp=otp_username,expiry=time)
                htmlgen1 = f'Dear {user}, <br> Please Enter below <strong>OTP</strong> to recover username of dowell account <br><h2>Your OTP is <strong>{otp_username}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'
                send_mail('Your OTP to recover username of Dowell account',otp_username,settings.EMAIL_HOST_USER,[email_ajax], fail_silently=False, html_message=htmlgen1)
                response = {'msg':''}
                return JsonResponse(response)
            else:
                response={'msg':'Email not found!!'}
                return JsonResponse(response)
        else:
            email=request.POST['email']
            otp=request.POST['otp']
            try:
                valid = models.GuestAccount.objects.get(otp=otp,email=email)
            except models.GuestAccount.DoesNotExist:
                valid=None
            if valid is not None:
                field={'Email':email}
                check=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",field,"nil")
                check_res=json.loads(check)
                list_unames=[]
                if len(check_res["data"]) >= 1:
                    for data in check_res["data"]:
                        if data["Username"] not in list_unames:
                            list_unames.append(data["Username"])
                    context=RequestContext(request, {"email":email,"list_unames":list_unames})
                    htmlgen2 = 'Dear user, <br> The list of username associated with your email: <strong>{{email}}</strong> as dowell account are as follows: <br><h3>{% for a in list_unames %}<ul><li>{{a}}</li></ul>{%endfor%}</h3><br>You can proceed to login now!'
                    template=Template(htmlgen2)
                    send_mail('Username/s associated with your email in Dowell','',settings.EMAIL_HOST_USER,[email], fail_silently=False, html_message=template.render(context))
                    response = {'msg':''}
                    return JsonResponse(response)
                else:
                    response = {'msg':'Email Not found..'}
                    return JsonResponse(response)
            else:
                response = {'msg':'Wrong OTP'}
                return JsonResponse(response)
    return render(request,'login/new_forgotusername.html',context)

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def redirect_url(request):
    # org1=request.GET.get('org',None)
    # org2=org1.encode('utf-8')
    # org3=base64.b64decode(org2)
    org=base64.b64decode(request.GET.get('org',None).encode('utf-8')).decode()
    type1=base64.b64decode(request.GET.get('type',None).encode('utf-8')).decode()
    email=request.GET.get('email',None)
    name=base64.b64decode(request.GET.get('name',None).encode('utf-8')).decode()
    # print([org,type1,email,name])
    # sessionID=request.session.session_key
    # if sessionID:
    #     return redirect("login")
    # else:
    return redirect(f'https://100014.pythonanywhere.com/register?type={type1}&email={email}&org={org}&name={name}')
    # https://100014.pythonanywhere.com/redirect_url?member_type=User&email=gautamroshan332@gmail.com&org=Dowell&name=Roshan
    # https://100014.pythonanywhere.com/redirect_url?member_type=VXNlcg==&email=Z2F1dGFtcm9zaGFuMzMyQGdtYWlsLmNvbQ==&org=RG93ZWxs&name=Um9zaGFu
    # return redirect("login")

def timer(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        duration = (time.time() - start) * 1000
        print('view {} takes {:.2f} ms'.format(
            func.__name__,
            duration
            ))
        return result
    return wrapper

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def design_login(request):
    context={}
    orgs=None
    type1=None
    email1=None
    name1=None
    u_code=None
    spec=None
    code=None
    detail=None
    try:
        # https://100014.pythonanywhere.com/?type=Z3Vlc3RfbWVtYmVycw==&name=VGVzdGluZ180MDA0MQ==&code=MTIz&spec=MjM0&u_code=NDU2&detail=MzQ1&org=Um9zaGFuXzQwMDQ=
        orgs=request.GET.get('org',None)
        type1=request.GET.get('type',None)
        # type1=request.GET.get('type',None)
        email1=request.GET.get('email',None)
        name1=request.GET.get('name',None)
        code=request.GET.get('code',None)
        spec=request.GET.get('spec',None)
        u_code=request.GET.get('u_code',None)
        detail=request.GET.get('detail',None)
    except:
        pass
    portfolio=request.GET.get('portfolio',None)
    context["portfolio"]=portfolio
    # member_type=request.GET.get('member_type',None)
    # member_name=request.GET.get('member_name',None)
    # if orgs and member_type=='public' and member_name :
    #     field_public={"document_name":orgs}
    #     ca=dowellconnection("login","bangalore","login","client_admin","client_admin","1159","ABCDE","fetch",field_public,"nil")
    #     ca_resp=json.loads(ca)
    #     if len(ca_resp["data"])>=1:
    #         public_members=ca_resp["data"][0]["members"]["public_members"]["accept_members"]
    #         for member in public_members:
    #             if member_name == member["name"]:
    #                 return HttpResponse("Public user found, I will create sessionID after this")
    #         else:
    #             return HttpResponse("Public user not found in org")
    #     else:
    #         return HttpResponse("Org not found")
    context["org"]=orgs
    context["type"]=type1
    urls=request.GET.get('next',None)
    context["url"]=request.GET.get('redirect_url',None)
    redirect_url=request.GET.get('redirect_url',None)
    country=""
    city=""
    userr=request.session.session_key
    if userr:
        if orgs:
            return redirect(f'https://100093.pythonanywhere.com/invitelink?session_id={userr}&org={orgs}&type={type1}&name={name1}&code={code}&spec={spec}&u_code={u_code}&detail={detail}')
        elif redirect_url:
            return HttpResponse(f"<script>window.location.replace('{redirect_url}?session_id={userr}');</script>")
            return redirect(f'{redirect_url}?session_id={userr}')
        else:
            return redirect(f'https://100093.pythonanywhere.com/home?session_id={userr}')
    var1=passgen.generate_random_password1(24)
    context["random_session"]=var1
    # if request.COOKIES.get('qrid'):
    #     context["qrid"]=request.COOKIES.get('qrid')
    #     qrid_obj_1=QR_Creation.objects.filter(qrid=context["qrid"]).first()
    #     if qrid_obj_1.info == "":
    #         context["qrid_type"]="new"
    #     else:
    #         context["qrid_type"]="old"
    # else:
    #     qrid_obj=QR_Creation.objects.filter(status="new").first()
    #     qrid_obj.status="used"
    #     qrid_obj.save(update_fields=['status'])
    #     context["qrid"]=qrid_obj.qrid
    #     context["qrid_type"]="new"
    #     html=render(request,'login/testlogin2.html',context)
    #     html.set_cookie('qrid',qrid_obj.qrid, max_age = 365*24*60*60)
    #     return html
    if request.method == 'POST':
        username = request.POST['username']
        obj=Account.objects.filter(username=username).first()
        try:
            obj.current_task="Data taken, Checking policy acceptance and  User registration..."
            obj.save(update_fields=['current_task'])
        except:
            pass
        random_session=request.POST.get('random_session',None)
        random_session_obj1=RandomSession.objects.filter(username=username).first()
        if random_session_obj1 is None:
            random_session_obj=RandomSession.objects.filter(sessionID=random_session).first()
            if random_session_obj is None:
                context["error"]="Please accept the terms in policy page!"
                return render(request,'login/testlogin2.html',context)
            random_session_obj.username=username
            random_session_obj.save(update_fields=['username'])
        mainparams=request.POST.get('mainparams',None)
        org1=request.POST.get('org',None)
        portfolio=request.POST.get('portfolio',None)
        type1=request.POST.get('type',None)
        url=request.POST.get('url',None)
        username = request.POST['username']
        password = request.POST['password']
        loc=request.POST["loc"]
        try:
            lo=loc.split(" ")
            country,city=country_city_name(lo[0],lo[1])
        except Exception as e:
            city=""
        language=request.POST.get("language","en-us")
        device=request.POST.get("dev","")
        osver=request.POST.get("os","")
        brow=request.POST.get("brow","")
        ltime=request.POST["time"]
        ipuser=request.POST.get("ip","")
        mobconn=request.POST["conn"]
        session=123
        print(org1)
        print("portfolio" in mainparams)
        if "org" in mainparams:
            # org_resp1=json.loads(org_resp)
            # main={"name":username,"member_code":org_resp1["u_code"],"member_spec":org_resp1["spec"],"member_uni_code":org_resp1["uni_code"],"member_details":org_resp1["detail"],"status":"used"}
            if url=="https://ll04-finance-dowell.github.io/100018-dowellWorkflowAi-testing/" and "portfolio" in mainparams and "product" in mainparams:
                print(f"{mainparams} and {url} 2")
                return redirect(f'https://100093.pythonanywhere.com/exportfolio?session_id={session}&{mainparams}')
            else:
                return redirect(f'https://100093.pythonanywhere.com/invitelink?session_id={session}&{mainparams}')

        if url=="None":
            print("url")
            return redirect(f'https://100093.pythonanywhere.com/home?session_id={session}')

        else:
            return HttpResponse(f"<script>window.location.replace('{url}?session_id={session}');</script>")
            return redirect(f'{url}?session_id={session}')

        user = authenticate(request, username = username, password = password)

        if user is not None:
            form = login(request, user)
            context["username"]=username
            context["user"]=user
            if user.role=="Admin":
                linkl="createusers"
                linklabel="Create User Links"
                usersession=user
                context["linkl"]=linkl
                context["linklabel"]=linklabel
                context["user"]=usersession
            session=request.session.session_key
            event_id=None
            try:

                #event_id=event_creation("FB","101","0","pfm","1","1","1029",str(os.urandom(20)),str(os.urandom(25)),username,"5029","testing",ipuser,session,loc,str(ltime),"nil")
                res=create_event()
                event_id=res['event_id']
                # field={"Username":username,"OS":osver,"Device":device,"Browser":brow,"Location":loc,"Time":str(ltime),"SessionID":session,"Connection":mobconn,"event_id":event_id,"IP":ipuser,"user_id":user.id}
                # dowellconnection("login","bangalore","login","login","login","6752828281","ABCDE","insert",field,"nil")
            except:
                context["api"]="api not work"
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
            client_admin_id=""
            field={"Username":username}
            id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","find",field,"nil")
            response=json.loads(id)
            if response["data"] != None:
                try:
                    obj.current_task="User found, Inserting Session Details..."
                    obj.save(update_fields=['current_task'])
                except:
                    pass
                first_name=response["data"]['Firstname']
                last_name=response["data"]['Lastname']
                email=response["data"]['Email']
                phone=response["data"]['Phone']
                try:
                    client_admin_id=response["data"]['client_admin_id']
                    user_id=response["data"]['profile_id']
                    role_res=response["data"]['Role']
                    company=response["data"]['company_id']
                    member=response["data"]['Memberof']
                    dept=response["data"]['dept_id']
                    org=response["data"]['org_id']
                    project=response["data"]['project_id']
                    subproject=response["data"]['subproject_id']
                except Exception as e:
                    pass

            try:
                final_ltime=parser.parse(ltime).strftime('%d %b %Y %H:%M:%S')
                dowell_time=time.strftime("%d %b %Y %H:%M:%S", time.gmtime(dowellclock()+1609459200))
            except:
                final_ltime=''
                dowell_time=''
            serverclock=datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')

            field_session={'sessionID':session,'role':role_res,'username':username,'Email':email,'Phone':phone,'language':language,'city':city,'country':country,'org':org,'company_id':company,'project':project,'subproject':subproject,'dept':dept,'Memberof':member,'status':'login','dowell_time':dowell_time,'regional_time':final_ltime,'server_time':serverclock,'userIP':ipuser,'userOS':osver,'userdevice':device,'userbrowser':brow,'UserID':user_id,'login_eventID':event_id,"redirect_url":redirect_url,"client_admin_id":client_admin_id}
            dowellconnection("login","bangalore","login","session","session","1121","ABCDE","insert",field_session,"nil")

            try:
                obj.current_task="Session inserted, Redirecting to client-admin..."
                obj.save(update_fields=['current_task'])
            except:
                pass

            info={"role":role_res,"username":username,"email":email,"phone":phone,"city":city,"country":country,"status":"login","dowell_time":dowell_time,"regional_time":final_ltime,"server_time":serverclock,"userIP":ipuser,"userOS":osver,"userDevice":device,"userBrowser":brow,"language":language,"userID":user_id,"login_eventID":event_id,"client_admin_id":client_admin_id}
            info1=json.dumps(info)
            infoo=str(info1)
            custom_session=CustomSession.objects.create(sessionID=session,info=infoo,document="",status="login")
            print("{mainparams} and {url}")
            if "org" in mainparams:
                print("org1")
                # org_resp1=json.loads(org_resp)
                # main={"name":username,"member_code":org_resp1["u_code"],"member_spec":org_resp1["spec"],"member_uni_code":org_resp1["uni_code"],"member_details":org_resp1["detail"],"status":"used"}
                if url != "None" and "portfolio" in mainparams and "product" in mainparams:
                    print("{mainparams} and {url}")
                    return redirect(f'https://100093.pythonanywhere.com/exportfolio?session_id={session}&{mainparams}')
                else:
                    return redirect(f'https://100093.pythonanywhere.com/invitelink?session_id={session}&{mainparams}')

            if url=="None":
                print("url")
                return redirect(f'https://100093.pythonanywhere.com/?session_id={session}')

            else:
                return HttpResponse(f"<script>window.location.replace('{url}?session_id={session}');</script>")
                return redirect(f'{url}?session_id={session}')
        else:
            context["error"]="Username, Password combination is incorrect!"
            context["main_logo"]='dowelllogo.png'
            return render(request,'login/testlogin2.html',context)
    #form = AuthenticationForm()
    if redirect_url is None:
        context["main_logo"]='logos/dowelllogo.png'
    else:
        if '100084' in redirect_url:
            context["main_logo"]='logos/dowell_workflow_AI.png'
        else:
            context["main_logo"]='logos/dowelllogo.png'
        # logos=[]
        # path='dowell_login/static/img/logos'
        # for path1 in os.listdir(path):
        #     if os.path.isfile(os.path.join(path,path1)):
        #         logos.append(path1)
        # return HttpResponse(logos)
    return render(request,'login/testlogin2.html',context)

def change_password(request):
    context={}
    username=request.GET.get("username","")
    context["username"]=username
    if is_ajax(request=request):
        if request.method=="POST":
            username= request.POST.get("username",None)
            new_password=request.POST.get("new_password",None)
            old_password=request.POST.get("old_password",None)
            print(old_password)
            user = authenticate(request, username = username, password = old_password)
            if user is not None:
                obj=Account.objects.filter(username=username).first()
                obj.set_password(new_password)
                obj.save()
                field={"Username":username}
                update_field={"Password":dowell_hash(new_password)}
                dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","update",field,update_field)
                return JsonResponse({"msg":"success","info":"Password Changed Successfully!!"})
            else:
                return JsonResponse({"msg":"error","info":"Username, Password combination is incorrect"})
        else:
            return JsonResponse({"msg":"success","info":"Running correctly"})
    return render(request,'login/change_password.html',context)

def allow_location(request):
    username=request.GET.get("username")
    location=request.GET.get("location")
    location_check=Location_check.objects.filter(username=username).first()
    if location is not None:
        if location_check:
            try:
                usual=json.loads(location_check.usual)
            except:
                usual=location_check.usual
            try:
                unusual=json.loads(location_check.unusual)
            except:
                unusual=location_check.unusual
            for a in unusual:
                if location == list(a.keys())[0]:
                    unusual.remove(a)
                    if location not in usual:
                        usual.append(location)
            location_check.usual=str(json.dumps(usual))
            location_check.unusual=str(json.dumps(unusual))
            location_check.save(update_fields=["usual","unusual"])
            return HttpResponse("Location info is updated, You can proceed to login!!")
        else:
            return HttpResponse("User not found")
    else:
        return HttpResponse("Not location given to update..")

def is_ajax(request):
    return request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest'
def Registertest(request):
    otp_user=generateOTP()
    context={}
    orgs=request.GET.get('org',None)
    type1=None
    # For countrycode
    # URL='https://100074.pythonanywhere.com/countries/johnDoe123/haikalsb1234/100074/'
    # r=requests.get(url=URL)
    # finallist=[]
    # for a in r.json():
    #     mylist=["+"+a["country_code"],a["country_short"]+"(+"+a["country_code"]+")"]
    #     finallist.append(mylist)
    # orgs=request.GET.get("org",None)
    url=request.GET.get("redirect_url",None)
    if is_ajax(request=request):
        if request.POST.get('form')=="emailotp":
            user=request.POST.get('username',"User")
            email_ajax=request.POST.get('email',None)
            time=datetime.datetime.now()
            try:
                emailexist = models.GuestAccount.objects.get(email=email_ajax)
            except models.GuestAccount.DoesNotExist:
                emailexist = None
            if emailexist is not None:
                models.GuestAccount.objects.filter(email=email_ajax).update(otp=otp_user,expiry=time,username=user)


                url = "https://100085.pythonanywhere.com/api/signUp-otp-verification/"
                payload = json.dumps({
                    "toEmail":email_ajax,
                    "toName":user,
                    "topic":"RegisterOtp",
                    "otp":otp_user
                    })
                headers = {
                    'Content-Type': 'application/json'
                    }

                response = requests.request("POST", url, headers=headers, data=payload)
                # htmlgen = f'Dear {user}, <br> Please Enter below <strong>OTP</strong> to create your dowell account <br><h2>Your OTP is <strong>{otp_user}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'
                # send_mail('Your OTP for creating your Dowell account',otp_user,settings.EMAIL_HOST_USER,[email_ajax], fail_silently=False, html_message=htmlgen)
                response = {}
                return JsonResponse(response)
            else:
                insertdata=models.GuestAccount(username=user,email=email_ajax,otp=otp_user)
                insertdata.save()
                URL='https://100085.pythonanywhere.com/api/send-mail/'
                data={"toEmail":email_ajax,"toName":user,"topic":"RegisterOtp","otp":otp_user}
                r=requests.post(url=URL,data=data)
                # htmlgen = f'Dear {user}, <br> Please Enter below <strong>OTP</strong> to create account <br><h2>Your OTP is <strong>{otp_user}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'
                # send_mail('Your OTP for creating your Dowell account',otp_user,settings.EMAIL_HOST_USER,[email_ajax], fail_silently=False, html_message=htmlgen)
                response = {}
                return JsonResponse(response)
        else:
            otp_sms=generateOTP()
            # otp=request.POST.get("otp_phone",None)
            code=request.POST.get("code")
            phone=request.POST.get("phone")
            phonenum=code+phone
            # print(phonenum)
            url = "https://100085.pythonanywhere.com/api/sms/"
            payload = json.dumps({
                "sender" : "Roshan",
                "recipient" : phone,
                "content" : otp_sms,
                "created_by" : "Manish"
                })

            response = requests.request("POST", url, data=payload)
            resp=json.loads(response)
            print(resp)
            if len(resp)>1:
                return JsonResponse({'msg':'SMS sent successfully!!'})
            else:
                return JsonResponse({'msg':'error'})
            # try:
            #     rt=mobilnumber(phonenum)
            # except:
            #     response={'msg':'Geo Blocked, You can proceed without verifying','error':'yes'}
            #     return JsonResponse(response)
            # if rt=="pending":
            #     response={'msg':"OTP successfully sent to your mobile number",'error':''}
            #     return JsonResponse(response)
            #     # context["msg"]="OTP successfully sent to your mobile number"
            # else:
            #     response={'msg':"Error",'error':'yes'}
            #     return JsonResponse(response)
            # response={'msg':"Error"}
            # return JsonResponse(response)


                # context['msg']=rt
            # if otp is not None:
                # rtsa=mobilotp(phonenum,otp)
                # if rtsa=="approved":
                #     response={'msg':"Verified"}
                #     return JsonResponse(response)
                # else:
                #     response={'msg':"Wrong Mobile OTP"}
                #     return JsonResponse(response)


    if request.method == 'POST':
        phone_number1=request.POST.get('phone_number1',None)
        phone_code1=request.POST.get('phone_code1',None)
        otp_mobile=request.POST.get('otp_mobile',None)
        mainparams=request.POST.get('mainparams',None)
        type1=request.POST.get('type',None)
        otp=request.POST.get('otp')
        org=request.POST.get('org',None)
        form = forms.UserRegisterForm(request.POST,request.FILES)
        policy_status=request.POST.get('policy_status')
        user = request.POST['username']
        password1 = request.POST['password1']
        password2 = request.POST['password2']
        first = request.POST['first_name']
        last = request.POST['last_name']
        email = request.POST['email']
        phonecode=request.POST["phonecode"]
        phone = request.POST['phone']
        role1="guest"
        img=request.FILES.get("profile_image",None)
        name=""
        if otp_mobile !=""and otp_mobile is not None:
            phonenum=phone_code1+phone_number1
            try:
                rtsa=mobilotp(phonenum,otp_mobile)
                if rtsa != "approved":
                    context["error"]="Wrong Mobile OTP"
                    return render(request, "login/test_register.html", context)
            except:
                pass
        # if policy_status !="Accepted":
        #     context["error"]="Policy not accepted.."
        #     return render(request, "login/test_register.html", context)
        if password1 != password2:
            context["error"]="Passwords Not Matching.."
            return render(request, "login/test_register.html", context)
        # try:
        #     valid = models.GuestAccount.objects.get(otp=otp,email=email)
        # except models.GuestAccount.DoesNotExist:
        #     valid=None
        valid="ok"
        if valid is not None:
            try:
                ro=Account.objects.filter(email=email)#.update(password = password,first_name = first,last_name = last,email = email,role = role,teamcode = ccode,phonecode=phonecode,phone = phone,profile_image=img)

                for i in ro:
                    if email==i.email and role1==i.role:
                        ro=Account.objects.filter(email=email).update(password = make_password(password1),first_name = first,last_name = last,email = email,phonecode=phonecode,phone = phone,profile_image=img)
            except Account.DoesNotExist:
                name=None
        else:
            context["error"]="Wrong Email OTP!!"
            return render(request, "login/test_register.html", context)
        if name is not None:

            # new_user=Account.objects.create(email=email,username=user,password=make_password(password1),first_name = first,last_name = last,phonecode=phonecode,phone = phone,profile_image=img)
            # profile_image=new_user.profile_image
            profile_image="user.png"
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
            # client_admin=dowellconnection("login","bangalore","login","client_admin","client_admin","1159","ABCDE","insert",data1,"nil")
            # client_admin_res=json.loads(client_admin)

            userfield={}
            # userresp=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",userfield,"nil")
            # idd=json.loads(userresp)
            res_list="ok"
            profile_id="ok"
            # profile_id=get_next_pro_id(res_list)

            # company_field={ 'owner': user, 'company': user, 'members': [user], 'layer1': 0, 'layer2': 1, 'layer3': 1, 'layer4': 1, 'layer5': 1, 'layer6': 1}
            # company_res=dowellconnection("login","bangalore","login","company","company","1083","ABCDE","insert",company_field,"nil")
            # company_r=json.loads(company_res)



            # field={"Profile_Image":f'https://100014.pythonanywhere.com/media/{profile_image}',"Username":user,"Password":dowell_hash(password1),"Firstname":first,"Lastname":last,"Email":email,"phonecode":phonecode,"Phone":phone,"profile_id":profile_id,'org_id':[],"company_id":"",'project_id':[],'subproject_id':[],'dept_id':[],'Memberof':{},'client_admin_id':client_admin_res['inserted_id'],'Policy_status':policy_status}
            #field={"Username":user,"Password":password,"Firstname":first,"Lastname":last,"Email":email,"Role":role,"Team_Code":ccode,"phonecode":phonecode,"Phone":phone,"user_id":"userid"}
            # id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","insert",field,"nil")
            htmlgen_final = f'Hi {first} {last}, <br> Welcome to UX Living Lab. Your new account details are,<br><h3><ul><li>Firstname: {first}</li><li>Lastname: {last}</li><li>Username: {user}</li><li>Phone Number: {phonecode} {phone}</li><li>Email: {email}</li></ul></h3><br>Login to UX Living Lab to use your workspace. Watch this video to learn more.<br>https://youtube.com/playlist?list=PLa-BPmUzAKKfVgomvrIsWd9ZGQFTiT0Xb<br><strong>Thank You</strong><br>UX Living Lab'

            connection=get_connection()
            connection.open()
            email=EmailMessage(
               'A Dowell account was created',
               htmlgen_final,
               settings.EMAIL_HOST_USER,
               to = [email],
            #   bcc=['customersupport@dowellresearch.sg']
            )
            email.content_subtype="html"
            # email.send()
            connection.close()


            # send_mail('A Dowell account was created','A Dowell account was created',settings.EMAIL_HOST_USER,[email], fail_silently=False, html_message=htmlgen_final)

            # field_owner={'owner':username}
            # usr=dowellconnection("login","bangalore","login","company","company","1083","ABCDE","fetch",field_owner,"nil")
            # r=json.loads(usr)
            # a=r["data"][0]["members"]
            # if a==[]:
            #     a.append(username)
            #     update_company={'members':a}
            #     dowellconnection("login","bangalore","login","company","company","1083","ABCDE","update",field_owner,update_company)
            print(org)
            if org != "None":
                print("org")
                return redirect(f'https://100014.pythonanywhere.com/?{mainparams}')
            elif url:
                print("url")
                return redirect(f'/?redirect_url={url}')
            else:
                print("done")
                return render(request,'login/after_register.html',{'user':user})
        else:

            return HttpResponse("check")
            form = forms.UserRegisterForm(request.POST,request.FILES)

            if form.is_valid():
                user = form.cleaned_data['username']
                password = form.cleaned_data['password1']
                first = form.cleaned_data['first_name']
                last = form.cleaned_data['last_name']
                email = form.cleaned_data['email']
                role = form.cleaned_data['role']
                ccode = form.cleaned_data['teamcode']
                phonecode=form.cleaned_data["phonecode"]
                phone = form.cleaned_data['phone']
                form.save()

                #userid=form.id
                try:

                    field={"Username":user,"Password":password,"Firstname":first,"Lastname":last,"Email":email,"Role":role,"Team_Code":ccode,"phonecode":phonecode,"Phone":phone,"user_id":"userid"}
                    id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","insert",field,"nil")
                    return redirect('login')
                except:
                    pass
            # username = form.cleaned_data.get('username')
            # email = form.cleaned_data.get('email')
            # msg.attach_alternative(html_content, "text/html")
            # msg.send()
            # messages.success(request, f'Your account has been created ! You are now able to log in')
            # htmly = get_template('user/Email.html')
            # d = { 'username': username }
            # subject, from_email, to = 'welcome', 'your_email@gmail.com', email
            # html_content = htmly.render(d)
            # msg = EmailMultiAlternatives(subject, html_content, from_email, [to])
                return redirect('login')
    else:
        form = forms.UserRegisterForm()
    #return render(request, 'user/register.html', {'form': form, 'title':'reqister here'})
    return render(request,'login/test_register.html',{'form': form, 'title':'reqister here','country_resp':[['aa','aa']],'org':orgs,'type':type1})

@method_decorator(xframe_options_exempt,name='dispatch')
@csrf_exempt
def check_status(request):
    username=request.GET.get('username')
    if username is not None:
        obj=Account.objects.filter(username=username).first()
        try:
            status=obj.current_task
            return render(request,'login/check_status.html',{'status':status})
        except:
            return render(request,'login/check_status.html')
    return render(request,'login/check_status.html')

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def LegalP(request):
    s=request.GET.get('s')
    # print(f"legal func: {s}")
    obj=RandomSession.objects.create(sessionID=s,status="Accepted",username="none")
    return render(request,"login/policy.html")
    # return HttpResponse("<h3 align='center' style='background-color:#28a745!important;color:white'>Accepted<h3>")
def Policy(request):
    policyurl="https://100087.pythonanywhere.com/api/legalpolicies/ayaquq6jdyqvaq9h6dlm9ysu3wkykfggyx0/iagreestatus/"
    if is_ajax(request=request):
        if request.POST.get('form')=="policyform":
            user=request.POST.get('user',"User")
            obj_check=RandomSession.objects.filter(username=user).first()
            if obj_check is not None:
                response = {'error':'Username Already taken..','msg':''}
                return JsonResponse(response)
            obj=RandomSession.objects.create(sessionID=user,status="Accepted",username=user)
            policy=request.POST.get('policy',None)
            time=datetime.datetime.now()
            data= {"data":[{"event_id": "FB1010000000167475042357408025","session_id": user,"i_agree": "true","log_datetime":time,"i_agreed_datetime":time,"legal_policy_type": "app-privacy-policy"}],"isSuccess": "true"}
            rep=requests.post(policyurl,data=data)
            # print(rep)
            response = {'msg':f'Accepted'}
            return JsonResponse(response)

@api_view(['POST'])
@method_decorator(xframe_options_exempt,name='dispatch')
@csrf_exempt
def live_status(request):
    if request.method=="POST":
        sessionID=request.data.get('session_id')
        qrid=request.data.get('qrcode_id')
        uid=request.data.get('device_unique_id')
        product=request.data.get('product')
        if sessionID is not None:
            obj=LiveStatus.objects.filter(sessionID=sessionID).first()
            if obj is not None:
                serverclock=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                obj.product=product
                obj.updated=serverclock
                obj.save(update_fields=['product','updated'])
                return JsonResponse({"msg":"OK"})
            else:
                return JsonResponse({"msg":"Given session_id not found in database!"})
        elif qrid is not None:
            obj=Live_QR_Status.objects.filter(qrid=qrid).first()
            if obj is not None:
                serverclock=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                obj.product=product
                obj.updated=serverclock
                obj.save(update_fields=['product','updated'])
                return JsonResponse({"msg":"OK","remarks":"Old object updated"})
            else:
                serverclock=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                Live_QR_Status.objects.create(qrid=qrid,product=product,created=serverclock,updated=serverclock,status="online")
                return JsonResponse({"msg":"OK","remarks":"New object created"})
        elif uid is not None:
            obj=Live_Public_Status.objects.filter(unique_key=uid).first()
            if obj is not None:
                serverclock=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                obj.product=product
                obj.updated=serverclock
                obj.save(update_fields=['product','updated'])
                return JsonResponse({"msg":"OK","remarks":"Old object updated"})
            else:
                serverclock=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                Live_Public_Status.objects.create(unique_key=uid,product=product,created=serverclock,updated=serverclock,status="install")
                return JsonResponse({"msg":"OK","remarks":"New object created"})
        else:
            return JsonResponse({"msg":"Error","remarks":"One among session_id,qrcode_id and device_unique_id is required"})
    else:
        return HttpResponse("You don't have permission to access this page")

@method_decorator(xframe_options_exempt,name='dispatch')
@csrf_exempt
def live_qr_status(request):
    if request.method=="POST":
        qrid=request.POST.get('qrid')
        product=request.POST.get('product')
        obj=Live_QR_Status.objects.filter(qrid=qrid).first()
        if obj is not None:
            serverclock=datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')
            obj.product=product
            obj.date_updated=serverclock
            obj.save(update_fields=['product','date_updated'])
            return JsonResponse({"msg":"OK","remarks":"Old object updated"})
        else:
            serverclock=datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')
            Live_QR_Status.objects.create(qrid=qrid,product=product,date_created=serverclock,date_updated=serverclock,status="online")
            return JsonResponse({"msg":"OK","remarks":"New object created"})
    else:
        return HttpResponse("You don't have permission to access this page")

@method_decorator(xframe_options_exempt,name='dispatch')
@csrf_exempt
def live_public_status(request):
    if request.method=="POST":
        uid=request.POST.get('uid')
        product=request.POST.get('product')
        obj=Live_Public_Status.objects.filter(unique_key=uid).first()
        if obj is not None:
            serverclock=datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')
            obj.product=product
            obj.date_updated=serverclock
            obj.save(update_fields=['product','date_updated'])
            return JsonResponse({"msg":"OK","remarks":"Old object updated"})
        else:
            serverclock=datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')
            Live_Public_Status.objects.create(unique_key=uid,product=product,date_created=serverclock,date_updated=serverclock,status="install")
            return JsonResponse({"msg":"OK","remarks":"New object created"})
    else:
        return HttpResponse("You don't have permission to access this page")

@login_required
def qr_creation(request):
    if request.user.is_superuser:
        if request.method=="POST":
            number=request.POST["user_number"]
            if int(number) > 0:
                for a in range(int(number)):
                    ruser=passgen.generate_random_password1(24)
                    rpass="DoWell@123"
                    user = QR_Creation.objects.create(qrid=ruser,password=rpass,status="new")
                    # field={'qrid':ruser,'password':rpass}
                    # dowellconnection("login","bangalore","login","qrcodes","qrcodes","1178","ABCDE","insert",field,"nil")
                return render(request,'login/create_users.html',{'msg':f'Successfully {number} users Created'})
            else:
                return render(request,'login/create_users.html',{'msg':'Provide number greater than 0'})
        return render(request,'login/create_users.html')
    else:
        return HttpResponse("You don not have access to this page")
    return HttpResponse("You don not have access to this page")

def update_qrobj(request):
    if is_ajax(request=request):
        loc=request.POST.get("loc")
        device=request.POST.get("dev")
        osver=request.POST.get("os")
        brow=request.POST.get("brow")
        ltime=request.POST.get("time")
        ipuser=request.POST.get("ip")
        mobconn=request.POST.get("conn")
        qrid=request.POST.get("qrid")
        qrobj=QR_Creation.objects.filter(qrid=qrid).first()
        qrobj.info="Data Updated.."
        qrobj.save(update_fields=["info"])
        # field={"qrid":qrid,"OS":osver,"Device":device,"Browser":brow,"Location":loc,"Time":str(ltime),"SessionID":"linkbased","Connection":mobconn,"qrcode_id":"user6","IP":ipuser}
        # field1=json.dumps(field)
        # field2=str(field1)
        # print(field2)
        # qrobj.info=field2
        # qrobj.save(update_fields=['status','info'])
        field={"qrid":qrid,"OS":osver,"Device":device,"Browser":brow,"Location":loc,"Time":str(ltime),"Connection":mobconn,"IP":ipuser}
        dowellconnection("login","bangalore","login","qrcodes","qrcodes","1178","ABCDE","insert",field,"nil")
        response={'msg':f'Updated {qrid}'}
        return JsonResponse(response)
    return HttpResponse("You don not have access to this page")
@method_decorator(xframe_options_exempt,name='dispatch')
@csrf_exempt
def mobileotp(request):
    from otp import mobilnumber,mobilotp
    if request.method=="POST":
        otp=request.POST.get("otp",None)

        context={}
        code=request.POST.get("code")
        phone=request.POST.get("phone")

        phonenum=code+phone
        if otp is not None:
            rtsa=mobilotp(phonenum,otp)
            if rtsa=="approved":
                return HttpResponse("your mobile verified")
            else:
                return HttpResponse("something wrong")
        context["phone"]=phone
        context["code"]=code
        rt=mobilnumber(phonenum)
        if rt=="pending":
            context["msg"]="OTP successfully sent to your mobile number"
        else:
            context['msg']=rt
        return render(request,"checks.html",context)
    return render(request,"checks.html")

from django.db.models import Count
from django.db.models.functions import TruncDay
def userdetails(request):
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
    public_members=list(set(public_members))
    users=list(set(users))
    time_threshold = datetime.datetime.now()- datetime.timedelta(minutes=1)
    obj_live=LiveStatus.objects.filter(status="login",updated__gte=time_threshold.strftime("%Y-%m-%d %H:%M:%S")).values_list('username', flat=True).order_by('username').distinct()
    response={'users':len(set(obj_live).intersection(users)),'live_team_members':len(set(obj_live).intersection(team_members)),'live_public_members':len(set(obj_live).intersection(public_members)),'live_owners':len(set(obj_live).intersection(owners))}
    current={}
    weekly={}
    for product in products_list:
        product_wise=LiveStatus.objects.filter(status="login",updated__gte=time_threshold.strftime("%Y-%m-%d %H:%M:%S"),product=product).values_list('username', flat=True).order_by('username').distinct()
        current[product]={'team_members':len(set(product_wise).intersection(team_members)),'public_members':len(set(product_wise).intersection(public_members)),'users':len(set(product_wise).intersection(users)),'owners':len(set(product_wise).intersection(owners))}
        weekly[product]={}
        # date_start= datetime.datetime.now()-datetime.timedelta(days=6)
        # obj = LiveStatus.objects.filter(
        #     updated__gte=date_start.strftime("%Y-%m-%d %H:%M:%S"),
        # ).annotate(
        #     day=TruncDay('updated'),
        #     created_count=Count('updated__date')
        # ).values(
        #     'day',
        #     'created_count'
        # )
        # weekly[product]=f'{obj}'
        for r in range(0,7):
            date_start= datetime.datetime.now()-datetime.timedelta(days=r+1)
            date_end=datetime.datetime.now()-datetime.timedelta(days=r)
            if range ==0:
                date_end=datetime.datetime.now()+datetime.timedelta(days=1)
            obj=LiveStatus.objects.filter(updated__gt=date_start.strftime("%Y-%m-%d %H:%M:%S"),updated__lte=date_end.strftime("%Y-%m-%d %H:%M:%S"),product=product).values_list('username', flat=True).order_by('username').distinct()
            weekly[product][r]=len(obj)
    response["current"]=current
    response["weekly"]=weekly
    resp=response
    return render(request,'login/userdetails1.html',{"resp":resp})

@login_required
def add_public(request):
    if request.user.is_superuser:
        if request.method=="POST":
            number=request.POST["user_number"]
            if int(number) > 0:
                for a in range(int(number)):
                    ruser=passgen.generate_random_password1(32)
                    field={"Username":ruser,"status":"offline"}
                    resp=dowellconnection("login","bangalore","login","public_members","public_members","1242001","ABCDE","insert",field,"nil")
                    respj=json.loads(resp)
                return render(request,'login/create_users.html',{'msg':f'Successfully {number} users Created'})
            else:
                return render(request,'login/create_users.html',{'msg':'Provide number greater than 0'})
        return render(request,'login/create_users.html')
    else:
        return HttpResponse("You don not have access to this page")
    return HttpResponse("You don not have access to this page")

def removeaccount(request):
    if is_ajax(request=request):
        username=request.POST.get("username",None)
        status=request.POST.get("status",None)
        password=request.POST.get("password",None)
        field={"Username":username,"Password":dowell_hash(password)}
        id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","find",field,"nil")
        response=json.loads(id)
        if response["data"] != None:
            try:
                if response["data"]["User_status"]:
                    if response["data"]["User_status"] == "inactive":
                        resp = {"msg":"error","info": "Username is termed inactive. Please contact admin."}
                        return JsonResponse(resp,)
                    elif response["data"]["User_status"] == "deleted":
                        resp = {"msg":"error","info": "User not found."}
                        return JsonResponse(resp)
            except:
                pass
            if status is not None and status in ["active" , "inactive" , "deleted"]:
                up_field={"User_status":status}
                dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","update",field,up_field)
                return JsonResponse({'msg':'success','info':f"{username}'s status changed to {status}"})
            else:
                return JsonResponse({'msg':'error','info':"Please Enter valid status"})
        else:
            return JsonResponse({'msg':'error','info':"Username, Password combination is incorrect"})
    else:
        return render(request, 'login/removeaccount.html')
