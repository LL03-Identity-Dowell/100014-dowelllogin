from django.shortcuts import render,redirect
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required
from lavapp import passgen
from voc_nps.dowell_scale import Scale,Scale_user
import json
from django.http import JsonResponse

import random
from base64 import b64encode
from cryptography.fernet import Fernet
from PIL import Image
from django.views.decorators.csrf import csrf_exempt
from loginapp.models import Account
from voc_nps import models
from django.core.mail import send_mail
from django.contrib import messages
def encode(key,text):
    cipher_suite = Fernet(key.encode())
    encoded_text = cipher_suite.encrypt(text.encode())
    return encoded_text
def decode(key,decodetext):
    cipher_suite = Fernet(key.encode())
    decoded_text = cipher_suite.decrypt(decodetext.encode())
    return decoded_text.decode()
key="l6h8C92XGJmQ_aXpPN7_VUMzA8LS8Bg50A83KNcrVhQ="
#, xframe_options_deny, xframe_options_sameorigin,
from django.views.decorators.clickjacking import (
    xframe_options_exempt
)
from . import qrcodegen
from django.contrib.sessions.models import Session
import pickle
from api.serializers import UserSerializer
import base64

def checksession(request):
    # i=request.POST["key"]
    session = Session.objects.get(session_key=request.session.session_key)
    uid = session.get_decoded()#.get('_auth_user_id')
    #red=Account.objects.get(id=uid)
    #serializer=UserSerializer(red)
    return HttpResponse(request.session.a)

@method_decorator(xframe_options_exempt, name='dispatch')
def index(request):
    return render(request,'voc/nps_index.html')
@method_decorator(xframe_options_exempt, name='dispatch')
def home(request):
    return render(request,'voc/home.html')
@method_decorator(xframe_options_exempt, name='dispatch')
def preview(request):
    return render(request,'voc/nps_privew.html')
@method_decorator(xframe_options_exempt, name='dispatch')
def emcode(request):
    return render(request,'voc/nps_emcode.html')
def dowell_scale(request,tname):
    context={}
    context["brand"]=request.GET.get('brand',None)
    context["product"]=request.GET.get('product',None)
    context["logo"]=request.GET.get('logo',None)
    # if request.user.is_authenticated():
    #     username = request.user.username
    if request.user.is_authenticated:
        role=Scale_user(request.user)
        if role=="Admin" or role=="TeamMember":
            context["url"]="../scaleadmin"
            context["urltext"]="Create new scale"
            context["btn"]="btn btn-dark"
            context["hist"]="Scale History"
            context["bglight"]="bg-light"
            context["left"]="border:silver 2px solid; box-shadow:2px 2px 2px 2px rgba(0,0,0,0.3)"
            context["npsall"]=models.Rating.objects.all().order_by('-id')
            default=models.Rating.objects.filter(template_name=tname)
            context["defaults"]=default
            for i in default:
                context["text"]=i.text.split('+')
            return render(request,'voc/scaleadmin.html',context)
    default=models.Rating.objects.filter(template_name=tname)
    context["defaults"]=default
    for i in default:
        context["text"]=i.text.split('+')
    return render(request,'voc/scale.html',context)
@login_required
def dowell_scale_admin(request):
    context={}
    user=request.user
    role=Scale_user(user)
    if role=="Admin" or role=="TeamMember":
        if request.method == 'POST':
            name=request.POST['nameofscale']
            orientation  = request.POST['orientation']
            numberrating  = request.POST['numberof']
            scalecolor  = request.POST['scolor']
            roundcolor  = request.POST['rcolor']
            fontcolor  = request.POST['fcolor']
            fomat  = request.POST['format']
            left=request.POST["left"]
            right=request.POST["right"]
            center=request.POST["center"]
            time  = request.POST['time']
            text=f"{left}+{center}+{right}"
            rand_num = random.randrange(1,10000)
            template_name = f"{name}{rand_num}"
            r=Scale(role,orientation,scalecolor,roundcolor,fontcolor,fomat,numberrating,time,template_name,text,name)
            # objcolor = models.Rating.objects.create(orientation=orientation,rating=numberrating,scolor=scalecolor,rcolor=roundcolor,fcolor=fontcolor,format=fomat,time=time,template_name=template_name,name=name,text=text)
            # objcolor.save()
            if r=="success":
                return redirect(f"https://100014.pythonanywhere.com/nps/dowellscale/{template_name}")
            else:
                context["Error"]="Error Occured while save the custom pl contact admin"
        return render(request,'voc/scale_admin.html',context)
    else:
        return redirect("https://100014.pythonanywhere.com/nps/dowellscale/default")
    # context["url"]="/scaleadmin"
    # context["urltext"]="Create new scale"

@method_decorator(xframe_options_exempt, name='dispatch')
@login_required
def scale(request):
    context={}
    # context["brand"]=request.GET.get('brand',None)
    # context["product"]=request.GET.get('product',None)
    # context["logo"]=request.GET.get('logo',None)
    return render(request,'voc/form.html',context)
@method_decorator(xframe_options_exempt, name='dispatch')
def qrGen(request):
    context={}
    if request.method == 'POST':
        brand1 = request.POST['brand']
        brand=encode(key,brand1)
        product1 = request.POST['product']
        product=encode(key,product1)
        is_accept = request.POST['checkbox']
        logo=request.FILES['logo']
        ruser=passgen.generate_random_password1(8)
        rpass=passgen.generate_random_password(10)
        user = Account.objects.create_user(username=ruser,email=f'{ruser}@lav.com',password=rpass,role="Freelancer",teamcode="15692532")
        r={'user_id':user.id,'username':ruser}
        qrcodegen.qrgen1(json.dumps(r),f"dowell_login/media/userqrcodes/{user.id}.png")
        logoname1=logo.name.replace(" ","")
        logoname=encode(key,logoname1)
        qrcodegen.qrgen(logo,"https://100014.pythonanywhere.com/nps/brandurl",brand.decode(),product.decode(),f"dowell_login/media/qrcodes/{logoname1}",logoname.decode())
        insertdata=models.voc_nps(brand=brand,product=product,is_accept=is_accept,upload=logo,username=ruser,qrcodename=f'dowell_login/media/qrcodes/{logoname1}.png',userqrcode=f'dowell_login/media/userqrcodes/{user.id}.png',link=f"https://100014.pythonanywhere.com/nps/brandurl/?brand={brand},product={product},logo={logoname.decode()}")
        insertdata.save()
        with Image.open(f"dowell_login/media/qrcodes/{logoname1}") as image:
            image.thumbnail((128,128))
            image.save(f"dowell_login/media/qrcodes/thumbnails/{logoname1}","JPEG")
        with Image.open(f"dowell_login/media/brandlogos/{logo.name.replace(' ','_')}") as image:
            image.thumbnail((256,256))
            image.save(f"dowell_login/media/brandlogos/thumbnails/{logoname1}",quality=100)
        context["linkurl"]=f"https://100014.pythonanywhere.com/nps/brandurl?brand={brand.decode()}&product={product.decode()}&logo={logoname.decode()}"
        context["brnd"]=brand1
        context["prd"]=product1
        context["img"]=logoname1
        return render(request,'voc/nps_showqr.html',context)
    return render(request,'voc/nps_emcode.html')
@method_decorator(xframe_options_exempt, name='dispatch')
def ShowQr(request):
    context={}
    en=encode(key,"dowell_test")
    context["encd"]=en
    context["enc"]=decode(key,en.decode())
    return render(request,'voc/nps_showqr.html',context)
@method_decorator(xframe_options_exempt, name='dispatch')
def ShowVideo(request):
    context={}

    return render(request,'voc/nps_video.html',context)
@xframe_options_exempt
def iframesend(request):
    context={}
    if request.method == 'POST':
        rate = request.POST['rate']
        brand = request.POST['brand']
        return render(request,'voc/nps_responsive_preview.html',context)
    return render(request,'voc/test.html',context)
@method_decorator(xframe_options_exempt, name='dispatch')
def sendscale(request):
    context={}
    if request.method == 'POST':
        rates = request.POST['rate']
        brands = request.POST['brand']
        products = request.POST['product']
        # return HttpResponse(f"{rates} {brands} {products}")
        insertdata=models.Rating_Report(brand=brands,product=products,rating=rates)
        insertdata.save()
        context["success"]="Thank you for rating our product"
        return HttpResponse("<h1 align='center'>Thank you for rating our product</h1>")
@method_decorator(xframe_options_exempt, name='dispatch')
def sendfeed(request):
    context={}
    context["success"]="Thank you for rating our product"
    if request.method == 'POST':
        rate = request.POST['rate']
        brand = request.POST['brand']
        product = request.POST['product']
        baseurl = request.POST['baseurl']
        context["success"]="Thank you for rating our product"
        context["baseurl"]=baseurl
        #return render(request,'voc/nps_preview.html',context)
        #return redirect(baseurl)
        return render(request,'voc/test.html',context)
    context["brand"]=request.GET.get('brand',None)
    context["product"]=request.GET.get('product',None)
    context["logo"]=request.GET.get('logo',None)
    return render(request,'voc/nps_responsive_preview.html',context)
    #return render(request,'voc/nps_responsive_preview.html',context)
@method_decorator(xframe_options_exempt, name='dispatch')
def preview1(request):
    context={}
    if request.method == 'POST':
        rate = request.POST['rate']
        brand = request.POST['brand']
        product = request.POST['product']
        context["success"]="Thank you for rating our product"
        return render(request,'voc/test.html',context)
    brand=request.GET.get('brand',None)
    context["brand"]=decode(key,brand)
    product=request.GET.get('product',None)
    context["product"]=decode(key,product)
    logo=request.GET.get('logo',None)
    context["logo"]=decode(key,logo)
    return render(request,'voc/nps_responsive_preview.html',context)
@method_decorator(xframe_options_exempt, name='dispatch')
def SendMail(request):
    context={}
    if request.method == 'POST':
        email = request.POST['email']
        user = request.POST['user']
        img = request.POST['imager']
        urlim = request.POST['urlsr']
        context["email"]=email
        # html_message = render_to_string('dowell_login/templates/voc/nps_preview.html', { 'context': context, })

        # message = EmailMessage(subject, html_message, from_email, [to_email])
        # message.content_subtype = 'html' # this is required because there is no plain text email message
        # message.send()
        # qr = qrtools.QR()
        # rt=qr.decode(f'dowell_login/media/qrcodes/{img}')
        # htmlgen = f"Dear {user}, <br> QR code link  is <strong>https://100014.pythonanywhere.com/media/qrcodes/{img}</strong> <br/> <h2><br> Embed this code to your website copy this and paste your website</h2><br>&lt;iframe width='300' height='500' style='background-color:white' src='{urlim}' style='-webkit-transform:scale(0.7);-moz-transform-scale(0.7);' FRAMEBORDER='no' BORDER='0' SCROLLING='no'&gt;&lt;/iframe&gt;>"
        # send_mail('Embed your code to your website',"Thank You",'dowelllogintest@gmail.com',[email], fail_silently=False, html_message=htmlgen)
        context["user"]=user
        context["email"]=email
        context["urlm"]=urlim
        return render(request,'voc/nps_qrsend.html',context)
@method_decorator(xframe_options_exempt, name='dispatch')
def getcookie(request):
    context={}

    return render(request,'voc/getlocalstorage.html',context)
@method_decorator(xframe_options_exempt, name='dispatch')
def cookie(request):
    context={}

    return render(request,'voc/index.html',context)