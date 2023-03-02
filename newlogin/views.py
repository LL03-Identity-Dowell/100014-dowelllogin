from django.shortcuts import render,HttpResponse,redirect
from .forms import UserRegisterForm
from django.core.mail import send_mail
from django.contrib import messages
from newlogin import dowell_func,qrcodegen
import datetime
from django.conf import settings
import json
from newlogin import passgen
from newlogin.decorator import loginrequired
from dowellconnection import dowellconnection
from django.views.decorators.csrf import csrf_exempt
from django.core.files.storage import default_storage
from django.utils.translation import gettext as _
import base64
from .dowell_func import generateOTP,get_next_pro_id,encode,decode
from django.utils.decorators import method_decorator
from django.views.decorators.clickjacking import xframe_options_exempt
from geopy.geocoders import Nominatim
from .dowell_hash import dowell_hash
from django.contrib.auth import authenticate
from loginapp import models

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
        field={"Username":user,"OS":osver,"Device":device,"Browser":brow,"Location":loc,"Time":str(ltime),"SessionID":"linkbased","Connection":mobconn,"qrcode_id":"user6","IP":ipuser}
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
def GuestView(request):
    context={}
    if request.method == 'POST':
        email = request.POST['email']
        user = request.POST['user']
        otp=dowell_func.generateOTP()
        time = str(datetime.datetime.now())
        dowelltime=dowell_func.dowellclock()
        field={"email":email}
        response=dowellconnection("login","bangalore","login","guest_login","guest_login","1118","ABCDE","fetch",field,"nil")
        resp=json.loads(response)
        if len(resp["data"])>0:
            field1={"email":email}
            updatefield={"otp":otp}
            dowellconnection("login","bangalore","login","guest_login","guest_login","1118","ABCDE","update",field1,updatefield)
            htmlgen = f'Dear {user}, <br> Please Enter below <strong>OTP</strong> to login dowell account <br><h2>Your OTP is <strong>{otp}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'
            send_mail('Your OTP for logging in Dowell account',otp,'dowelllogintest@gmail.com',[email], fail_silently=False, html_message=htmlgen)
            context["user"]=user
            context["email"]=email
            return render(request,'login/newlogin_guest_verify.html',context)
        else:
            htmlgen = f'Dear {user}, <br> Please Enter below <strong>OTP</strong> to login dowell account <br><h2>Your OTP is <strong>{otp}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'
            send_mail('Your OTP for logging in Dowell account',otp,'dowelllogintest@gmail.com',[email], fail_silently=False, html_message=htmlgen)
            field2={"username":f'{user}_guest',"email":email,"otp":otp,"regionaltime":time,"dowelltime":dowelltime}
            dowellconnection("login","bangalore","login","guest_login","guest_login","1118","ABCDE","insert",field2,"nil")
            context["user"]=user
            context["email"]=email
            return render(request,'login/newlogin_guest_verify.html',context)
    return render(request,"login/new_guest.html")

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
        pwd=f'{user.capitalize()}@1234'
        dowelltime=dowell_func.dowellclock()
        if otp.isnumeric():
            field={"email":email,"otp":otp}
            response=dowellconnection("login","bangalore","login","guest_login","guest_login","1118","ABCDE","fetch",field,"nil")
            resp=json.loads(response)
            if len(resp["data"])>0:
                field={}
                respuser=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",field,"nil")
                userresp=json.loads(respuser)
                profile=dowell_func.get_next_pro_id(userresp["data"])
                field={"Username":user,"Password":dowell_hash(pwd),"Firstname":"guest","Lastname":"guest","Email":email,"Role":"guest","Team_Code":"guest","phonecode":"guest","Phone":"guest","datatype":"guest","profile_id":profile,'org_id':[],'company_id':'guest','project_id':[],'subproject_id':[],'dept_id':[],'Memberof':{}}
                dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","insert",field,"nil")
                role=f'100_{profile}'
                s=dowell_func.encode(settings.ENCRYPT_KEY,role)
                session=request.session["sessionID"]=s.decode()
                request.session["user"]='guest'
                request.session["encrypted"]=session
                fields={"Username":user,"sessionID":session,"regionaltime":ltime,"dowelltime":dowelltime,"status":"login"}
                dowellconnection("login","bangalore","login","session","session","1121","ABCDE","insert",fields,"nil")
                #event_id=event_creation("FB","101","0","pfm","1","1","1029",str(os.urandom(20)),str(os.urandom(25)),username,"5029","testing",ipuser,session,loc,str(ltime),"nil")
                field={"Username":user,"OS":osver,"Device":device,"Browser":brow,"Location":loc,"Time":str(ltime),"SessionID":session,"Connection":mobconn,"event_id":"guest","IP":ipuser}
                dowellconnection("login","bangalore","login","login","login","6752828281","ABCDE","insert",field,"nil")
                return redirect("/login")
            else:
                context["error"]="Wrong OTP"
                context["user"]=user
                context["email"]=email
                return render(request,'login/newlogin_guest_verify.html',context)
        else:
                context["error"]="Enter only numeric"
                context["user"]=user
                context["email"]=email
                return render(request,'login/newlogin_guest_verify.html',context)

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def RegisterView(request):
    otp_user=generateOTP()
    redirect_url=request.GET.get('redirect_url',None)
    if request.method == 'POST':
        form = UserRegisterForm(request.POST,request.FILES)
        image=request.FILES.get('profile_image', False)
        if image:
            file_name = default_storage.save(image.name, image)
            file_url = default_storage.url(file_name)
        else:
            file_url=''

        if form.is_valid():
            password1 = request.POST['password1']
            password2 = request.POST['password2']
            user = request.POST['username']
            first = request.POST['first_name']
            last = request.POST['last_name']
            email = request.POST['email']
            role = request.POST['role']
            ccode = request.POST['teamcode']
            phonecode=request.POST["phonecode"]
            phone = request.POST['phone']
            time=datetime.datetime.now()
            ltime=datetime.date.today().strftime("%Y-%m-%d")
            if password1==password2:
                context={'ltime':ltime,'redirect_url':redirect_url,'image':file_url,'user':user,'password':password2,'first':first,'last':last,'email':email,'role':role,'ccode':ccode,'phonecode':phonecode,'phone':phone}
                field_user={'Username':user}
                check_username=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",field_user,"nil")
                check_response_username=json.loads(check_username)

                if len(check_response_username['data'])>0:
                    messages.info(request,_("Username already taken"))
                    return redirect('/login/register')

                else:
                    try:
                        emailexist = models.GuestAccount.objects.get(email=email)
                    except models.GuestAccount.DoesNotExist:
                        emailexist = None
                    if emailexist is not None:
                        models.GuestAccount.objects.filter(email=email).update(otp=otp_user,expiry=time,username=user)
                        htmlgen = f'Dear {user}, <br> Please Enter below <strong>OTP</strong> to login dowell account <br><h2>Your OTP is <strong>{otp_user}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'
                        send_mail('Your OTP for logging in Dowell account',otp_user,'dowelllogintest@gmail.com',[email], fail_silently=False, html_message=htmlgen)
                        return render(request,'login/newlogin_user_verify.html',context)
                    else:
                        insertdata=models.GuestAccount(username=user,email=email,otp=otp_user)
                        insertdata.save()
                        htmlgen = f'Dear {user}, <br> Please Enter below <strong>OTP</strong> to login dowell account <br><h2>Your OTP is <strong>{otp_user}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'
                        send_mail('Your OTP for logging in Dowell account',otp_user,'dowelllogintest@gmail.com',[email], fail_silently=False, html_message=htmlgen)
                        return render(request,'login/newlogin_user_verify.html',context)
            else:
                messages.info(request,_("Passwords not matching.."))
                return redirect('/login/register')
    else:
        form=UserRegisterForm()
        return render(request,'login/new_register.html',{'form':form})

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def RegisterVerify(request):
    context={}
    if request.method == 'POST':
        ltime=request.POST['ltime']
        image=request.POST['image']
        otp = request.POST['otp']
        user=request.POST['user']
        password=request.POST['password']
        first=request.POST['first']
        last=request.POST['last']
        email=request.POST['email']
        role=request.POST['role']
        ccode=request.POST['ccode']
        phonecode=request.POST['phonecode']
        phone=request.POST['phone']
        url=request.POST['url']
        context["url"]=url
        if otp.isnumeric():
            try:
                valid = models.GuestAccount.objects.get(otp=otp,email=email)
            except models.GuestAccount.DoesNotExist:
                valid=None

            if valid is not None:
                field1={}
                id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",field1,"nil")
                idd=json.loads(id)
                res_list=idd["data"]
                profile_id=get_next_pro_id(res_list)
                company_field={ 'owner': user, 'company': user, 'members': [], 'layer1': 0, 'layer2': 1, 'layer3': 1, 'layer4': 1, 'layer5': 1, 'layer6': 1}
                company_res=dowellconnection("login","bangalore","login","company","company","1083","ABCDE","insert",company_field,"nil")
                company_r=json.loads(company_res)

                field={'Date_Joined':ltime,'last_login':'',"Profile_Image":image,"Username":user,"Password":dowell_hash(password),"Firstname":first,"Lastname":last,"Email":email,"Role":role,"Team_Code":ccode,"phonecode":phonecode,"Phone":phone,"profile_id":profile_id,'org_id':[],'company_id':company_r['inserted_id'],'project_id':[],'subproject_id':[],'dept_id':[],'Memberof':{}}
                dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","insert",field,"nil")
                messages.info(request,"Logged in successfully")
                return redirect(f'/login?redirect_url={url}')
            else:
                context["error"]=_("Wrong OTP")
                context["user"]=user
                context["email"]=email
                # return HttpResponse(request.path)
                return render(request,'login/newlogin_user_verify.html',context)
        else:
                context["error"]=_("Enter only numeric")
                context["user"]=user
                context["email"]=email
                return render(request,'login/newlogin_user_verify.html',context)
def location(loc):
    geolocator = Nominatim(user_agent="geoapiExercises")
    local = geolocator.reverse(loc)
    address = local.address
    return address

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def LoginView(request):
    context={}
    redirect_url=request.GET.get('redirect_url',None)
    if request.method=="POST":
        loc=request.POST.get("loc",None)
        if request.POST["loc"]:
            role=request.POST['roles']
            lang=request.POST.get('language', 'en-us')
            user=request.POST["username"]
            pwd=request.POST["password"]
            loc=request.POST["loc"]
            lo=loc.split(" ")
            locate=location(loc.replace(" ",","))
            # city=city_name(lo[0],lo[1])
            city='Wellington'
            osver=request.POST["os"]
            brow=request.POST["brow"]
            ltime1=request.POST["time"]
            device=request.POST["dev"]
            ipuser=request.POST["ip"]
            mobconn=request.POST["conn"]
            company=None
            dept=None
            org=None
            project=None
            subproject=None
            user_check = authenticate(request, username = user, password = pwd)
            field={"Username":user,"Password":dowell_hash(pwd)}
            id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",field,"nil")
            response=json.loads(id)
            if len(response["data"])>=1:
                user_check=True
            if user_check is not None:
                profile_id=response["data"][0]["profile_id"]
                role_res=response["data"][0]['Role']
                try:
                    company=response["data"][0]['company_id']
                    member=response["data"][0]['Memberof']
                    dept=response["data"][0]['dept_id']
                    org=response["data"][0]['org_id']
                    project=response["data"][0]['project_id']
                    subproject=response["data"][0]['subproject_id']
                except Exception as e:
                    pass
                if role_res==role:
                    role_id=role_res
                else:
                    messages.info(request,_('Role not matching..'))
                    return redirect('/login')

                field_location={}
                location_res=dowellconnection("login","bangalore","login","locations","locations","1107","ABCDE","fetch",field_location,"nil")
                location1=json.loads(location_res)
                if len(location1["data"])>=1:
                    for i in location1["data"]:
                        if 'city' in i:
                            if i['city']==city:
                                city_id=i['cityID']
                                break
                    else:
                        messages.info(request,_('Location Not matching with database'))
                        return redirect('/login')
                else:
                    messages.info(request,_('Database error'))
                    return redirect('/login')
                if 'last_login' in response["data"][0].keys():
                    login_date=datetime.date.today().strftime("%Y-%m-%d")
                    field_time={'last_login':login_date}
                    dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","update",field,field_time)

                key=str(profile_id)+str(city_id)+str(role_id)+str(lang)
                encrypted_key=encode(settings.ENCRYPT_KEY,key)
                field_session={'sessionID':key,'role':role,'username':user,'language':lang,'city':city,'org':org,'company_id':company,'project':project,'subproject':subproject,'dept':dept,'Memberof':member,'status':'login'}
                dowellconnection("login","bangalore","login","session","session","1121","ABCDE","insert",field_session,"nil")
                request.session["sessionID"]=key
                request.session["user"]=user
                encrypted_str=encrypted_key.decode()
                request.session["encrypted"]=encrypted_str
                if redirect_url is not None:
                    return redirect(redirect_url)
                else:
                    return redirect('dashboard')
            else:
                messages.info(request,_('User not found with given credentials'))
        else:
            return HttpResponse("<script>alert('pl give the location permission');window.location.href = '/';</script>")
    return render(request,"login/login.html")

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def LoginWithFace(request):
    context={}
    if request.method=="POST":
        image=request.FILES['profile_image']
        file_name = default_storage.save(image.name, image)
        file_url = default_storage.url(file_name)
        import face_recognition
        field={}
        id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",field,"nil")
        idd=json.loads(id)
        idd_res=idd["data"]

        picture_of_me = face_recognition.load_image_file(f'dowell_login{file_url}')
        try:
            my_face_encoding = face_recognition.face_encodings(picture_of_me)[0]
        except IndexError as e:
            print(e)
            context["img"]="face not found in this image"
            return render(request,'login/login.html',context)
        images=[]
        for value in idd_res:
            if 'Profile_Image' in value.keys() :
                images.append(value['Profile_Image'])
        for img in images:
            pimg = face_recognition.load_image_file(f'dowell_login{img}')
            try:
                pimg_encoding = face_recognition.face_encodings(pimg)[0]
                results = face_recognition.compare_faces([my_face_encoding], pimg_encoding)
                if results[0] == True:
                    for value in idd_res:
                        if 'Profile_Image' in value.keys():
                            if value['Profile_Image']==img:
                                user=value["Username"]
                                return HttpResponse(user)
            except IndexError as e:
                pass
        context["img"]="Face is not matching "
        return render(request,'login/login.html',context)
    return render(request,'login/login.html',context)

@loginrequired
def HomeView(request):
    return render(request,"login/main.html")

def LogoutView(request):
    session_id=request.GET.get("session_id",None)
    if session_id is not None:
        field={"sessionID":session_id}
        update_field={"status":"logout"}
        dowellconnection("login","bangalore","login","session","session","1121","ABCDE","update",field,update_field)
        return redirect('/login')
    else:
        keys=request.session.get("sessionID")
        user=request.session.get("user")
        encrypted_key=request.session.get("encrypted")
        field={"sessionID":keys}
        update_field={"status":"logout"}
        dowellconnection("login","bangalore","login","session","session","1121","ABCDE","update",field,update_field)
        del request.session["sessionID"]
        del request.session["user"]
        del request.session["encrypted"]
        return redirect('/login')


def signout(request):
    return render(request, 'login/newlogin_beforelogout.html')

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def embed(request):
    session=request.GET.get("sessionID",None)
    user=request.GET.get("username",None)

    if request.method=="POST":
        loc=request.POST["loc"]
        lo=loc.split(" ")
        # locate=location1(loc.replace(" ",","))
        # locate=location(lo[0],lo[1])
        osver=request.POST["os"]
        brow=request.POST["brow"]
        ltime=request.POST["time"]
        device=request.POST["dev"]
        ipuser=request.POST["ip"]
        mobconn=request.POST["conn"]
        field={"Username":user,"OS":osver,"Device":device,"Browser":brow,"Location":loc,"Time":str(ltime),"SessionID":"linkbased","Connection":mobconn,"qrcode_id":"user6","IP":ipuser}
        resp=dowellconnection("login","bangalore","login","login","login","6752828281","ABCDE","insert",field,"nil")
        context={'session_code':session,'user_1':user,'ltime':ltime}
        return render(request,'login/embed.html',context)
    return render(request,'login/embed.html')

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def forgot_password(request):
    otp_password=generateOTP()
    if request.method=='POST':
        time=datetime.datetime.now()
        username=request.POST['username']
        email=request.POST['email']
        field={'Username':username,'Email':email}
        check=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",field,"nil")
        check_res=json.loads(check)
        context={'Email':email,'Username':username}
        if len(check_res["data"])>=1:
            try:
                emailexist = models.GuestAccount.objects.get(email=email)
            except models.GuestAccount.DoesNotExist:
                emailexist = None
            if emailexist is not None:
                models.GuestAccount.objects.filter(email=email).update(otp=otp_password,expiry=time,username=username)
                htmlgen = f'Dear {username}, <br> Please Enter below <strong>OTP</strong> to change password of your dowell account <br><h2>Your OTP is <strong>{otp_password}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'
                send_mail('Your OTP for changing password of your Dowell account',otp_password,'dowelllogintest@gmail.com',[email], fail_silently=False, html_message=htmlgen)
                return render(request, 'login/change_password.html',context)
            else:
                insertdata=models.GuestAccount(username=username,email=email,otp=otp_password)
                insertdata.save()
                htmlgen = f'Dear {username}, <br> Please Enter below <strong>OTP</strong> to login dowell account <br><h2>Your OTP is <strong>{otp_password}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'
                send_mail('Your OTP for logging in Dowell account',otp_password,'dowelllogintest@gmail.com',[email], fail_silently=False, html_message=htmlgen)
                return render(request,'login/change_password.html',context)
        else:
            messages.info(request,_('Username, Email combination is incorrect'))
            return redirect('/login')
    return render(request,'login/new_forgot_password.html')

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def change_password(request):
    context={}
    username=request.POST['user']
    email=request.POST['email']
    password1=request.POST['password1']
    password2=request.POST['password2']
    otp=request.POST['otp']
    if otp.isnumeric():
        try:
            valid = models.GuestAccount.objects.get(otp=otp,email=email)
        except models.GuestAccount.DoesNotExist:
            valid=None

        if valid is not None:
            if password1==password2:
                field={'Username':username,'Email':email}
                update_field={'Password':dowell_hash(password2)}
                dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","update",field,update_field)
                messages.info(request,_('Password changed..'))
                return redirect('/login')
            messages.info(request,_('Passwords not matching'))
            return redirect('/login')
        else:
            context["error"]=_("Wrong OTP")
            context["user"]=username
            context["email"]=email
            return render(request,'login/change_password.html',context)
    else:
        context["error"]=_("Enter only numeric")
        context["user"]=username
        context["email"]=email
        return render(request,'login/change_password.html',context)

@method_decorator(xframe_options_exempt, name='dispatch')
@csrf_exempt
def iframe(request):
    return render(request,'login/iframe.html')

def country_city_name(latitude,longitude):
    geolocator = Nominatim(user_agent="geoapiExercises")
    Latitudes = latitude
    Longitudes = longitude
    rloc=geolocator.reverse(Latitudes+","+Longitudes)
    address=rloc.raw['address']
    city=address.get('city', '')
    country=address.get('country','')
    return(country,city)
