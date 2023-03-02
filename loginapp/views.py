from django.shortcuts import render,redirect
from loginapp import forms
from loginapp import models
from loginapp import dowell_func
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import authenticate, login
from loginapp.event_function import event_creation
from django.core.mail import send_mail
from django.contrib import messages
import os
import datetime
from loginapp import dowell_func
from loginapp.dowellconnection import dowellconnection


def d_login(request):
    context={}
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
        user = authenticate(request, username = username, password = password)
        if user is not None:
            form = login(request, user)
            context["username"]=username
            session=request.session.session_key
            try:
                event_id=event_creation("FB","101","0","pfm","1","1","1029",str(os.urandom(20)),str(os.urandom(25)),username,"5029","testing",ipuser,session,loc,str(ltime),"nil")
                field={"Username":username,"OS":osver,"Device":device,"Browser":brow,"Location":loc,"Time":str(ltime),"SessionID":session,"Connection":mobconn,"event_id":event_id,"IP":ipuser}
                dowellconnection("login","bangalore","login","login","login","6752828281","ABCDE","insert",field,"nil")
            except:
                context["api"]="api not work"
            return redirect('dashboard')
        else:
            context["user"]="pl login first"
            return render(request,'lav_login.html',context)
    form = AuthenticationForm()
    return render(request,'lav_login.html',context)
def d_validate(request):
    context={}
    if request.method == 'POST':
        email = request.POST['email']
        user = request.POST['user']
        otp = request.POST['otp']
        try:
            valid = models.GuestAccount.objects.get(otp=otp)
        except models.GuestAccount.DoesNotExist:
            valid=None

        if valid is not None:
            user = authenticate(request, username = "guest", password = "guest@1234")
            form = login(request, user)
            return redirect('dashboard')
        else:
            context["error"]="Wrong OTP"
            context["user"]=user
            context["email"]=email
            return render(request,'lav_verify.html',context)

def d_guest(request):
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
            models.GuestAccount.objects.filter(email=email).update(otp=otp,expiry=time)
            # q = MyModel.objects.get(pk=some_value)
            # q.field1 = 'some value'
            # q.save()
            htmlgen = f'Dear {user}, <br> Please Enter below <strong>OTP</strong> to login dowell account <br><h2>Your OTP is <strong>{otp}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'
            send_mail('Your OTP for logging in Dowell account',otp,'dowelllogintest@gmail.com',[email], fail_silently=False, html_message=htmlgen)
            context["user"]=user
            context["email"]=email
            return render(request,'lav_verify.html',context)
        else:
            htmlgen = f'Dear {user}, <br> Please Enter below <strong>OTP</strong> to login dowell account <br><h2>Your OTP is <strong>{otp}</strong></h2><br>Note: This OTP is valid for the next 2 hours only.'
            send_mail('Your OTP for logging in Dowell account',otp,'dowelllogintest@gmail.com',[email], fail_silently=False, html_message=htmlgen)
            insertdata=models.GuestAccount(username=user,email=email,otp=otp)
            insertdata.save()
            context["user"]=user
            context["email"]=email
            return render(request,'lav_verify.html',context)
    return render(request,'lav_guest.html',context)
def d_guestcheck(request):
    context={}
    if request.method == 'POST':
        form = forms.GuestForm(request.POST,None)
        if form.is_valid():
            form.save()
            return redirect('d_login')
    else:
        form = forms.GuestForm()
    return render(request,'guest.html',{'form': form})

def d_register(request):
    context={}
    if request.method == 'POST':
        form = forms.UserRegisterForm(request.POST,request.FILES)
        if form.is_valid():
            form.save()
            # username = form.cleaned_data.get('username')
            # email = form.cleaned_data.get('email')
            # htmly = get_template('user/Email.html')
            # d = { 'username': username }
            # subject, from_email, to = 'welcome', 'your_email@gmail.com', email
            # html_content = htmly.render(d)
            # msg = EmailMultiAlternatives(subject, html_content, from_email, [to])
            # msg.attach_alternative(html_content, "text/html")
            # msg.send()
            # messages.success(request, f'Your account has been created ! You are now able to log in')
            return redirect('d_login')
    else:
        form = forms.UserRegisterForm()
    #return render(request, 'user/register.html', {'form': form, 'title':'reqister here'})
    return render(request,'lav_register.html',{'form': form, 'title':'reqister here'})
@login_required
def d_success(request):
    return render(request,'lav_dash.html')
def lav_nw_error(request):
    return render(request,'lav_nw_error.html')
def newhome(request):
    pass
    # context={}
    # ip=request.META.get("REMOTE_ADDR")
    # usr=request.GET.get('user',None)
    # ltime=request.GET.get('ltime',None)
    # code=request.GET.get('code',None)
    # netwk=dowell_func.host_check('http://google.com')
    # sys=dowell_func.host_check('http://127.0.0.1:8000')
    # if netwk!="Error":
    #     context["network"]="Network Ok"
    #     if sys!="Error":
    #         context["system"]="System Ok"
    #         if usr and code:
    #             user = authenticate(request, username = usr, password = code)
    #             if user is not None:
    #                 form = login(request, user)
    #                 context["username"]=usr
    #                 session=request.session.session_key
    #                 try:
    #                     event_id=event_creation("FB","101","0","pfm","1","1","1029",str(os.urandom(20)),str(os.urandom(25)),usr,"5029","testing",ip,session,"locaton not get",str(ltime),"nil")
    #                     field={"Username":usr,"OS":"Not get","Device":"Not get","Browser":"Not get","Location":'Not get',"Time":str(ltime),"SessionID":session,"Connection":"Not get","event_id":event_id}
    #                     dowellconnection("login","bangalore","login","login","login","6752828281","ABCDE","insert",field,"nil")
    #                 except:
    #                     context["api"]="api not work"
    #                 #return render(request, 'lav_dash.html',context)
    #                 return redirect('dashboard')
    #             else:
    #                 pass
    #         else:
    #             context["link"]="Link not Recognised"
    #     else:
    #         context["system"]="System Error"
    # else:
    #     #context["network"]="Network Error"
    #     return render(request, 'lav_nw_error.html', context)