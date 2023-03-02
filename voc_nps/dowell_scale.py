from loginapp.models import Account
from voc_nps import models
def Scale_user(user):
    getuser=Account.objects.filter(username = user)
    for User in getuser:
        role=User.role
        return role
        if role=="Admin" or role=="Team Member":
            function={"url":"/scaleadmin","urltext":"Create new scale","btn":"btn btn-dark","hist":"Scale History","bglight":"bg-light","left":"border:silver 2px solid; box-shadow:2px 2px 2px 2px rgba(0,0,0,0.3)"}

def Scale(user,Oriantation,Scolor,Rcolor,Fcolor,formatof,numbers,Time,tname,Text,Name):
    # if user=="Admin":
    #     insertdata=models.Scale(maintext=MainText)
    #     insertdata.save()
    try:
        objcolor=models.Rating(orientation=Oriantation,scolor=Scolor,rcolor=Rcolor,fcolor=Fcolor,rating=numbers,format=formatof,time=Time,template_name=tname,text=Text,name=Name)
        objcolor.save()
        return "success"
    except:
        return "Error"

        # if User.role=="admin":
        #     insertdata=models.Scale(maintext=MainText)
        #     insertdata.save()
        #     return insertdata
        # elif user=="Teammember":
        #     objcolor=models.Rating(orientation=Oriantation,scolor=Scolor,rcolor=Rcolor,fcolor=Fcolor,rating=numbers,format=formatof,time=Time,template_name=name,text=Text)
        #     objcolor.save()
        #     return objcolor.template_name
        # else:
        #     getdefault=models.Rating.objects.filter(template_name="default")
        #     return getdefault