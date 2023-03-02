import urllib.request
import random
import math
import json
from .dowellconnection import dowellconnection
def host_check(host):
    try:
        urllib.request.urlopen(host)
        return "Connected"
    except:
        return "Error"

# Generate random OTP
def generateOTP() :
     digits = "0123456789"
     OTP = ""
     for i in range(6) :
        OTP += digits[math.floor(random.random() * 10)]
     return OTP

# Security layer before logging in user
def dowellsecuritylayer(profile_id,location,connectivity,device,OS,ProcessID):
    field={'profile_id':profile_id,'location':location}
    locRights=dowellconnection("login","bangalore","login","locations","locations","1107","ABCDE","fetch",field,"nil")
    loc_Rights=json.loads(locRights)

    if loc_Rights["data"]>0:
        field={'profile_id':profile_id,'Connectivity':connectivity}
        connRights=dowellconnection("login","bangalore","login","connections","connections","1110","ABCDE","fetch",field,"nil")                       
        conn_Rights=json.loads(connRights)
    
        if conn_Rights["data"]>0:
            field={'profile_id':profile_id,'Device':device}
            devRights=dowellconnection("login","bangalore","login","devices","devices","1106","ABCDE","fetch",field,"nil")
            dev_Rights=json.loads(devRights)

            if dev_Rights["data"]>0:
                field={'profile_id':profile_id,'OS':OS}
                OSRights=dowellconnection("login","bangalore","login","os","os","1108","ABCDE","fetch",field,"nil")
                OS_Rights=json.loads(OSRights)

                if OS_Rights["data"]>0:
                    field={'profile_id':profile_id,'ProcessID':ProcessID}
                    PIDRights=dowellconnection("login","bangalore","login","processes","processes","1111","ABCDE","fetch",field,"nil")
                    PID_Rights=json.loads(PIDRights)

                    if PID_Rights["data"]>0:
                        # finalRights=dowellintersection('locRights','connRights','devRights','osRights','processRights','userRights')
                        # loginsessionID= profile_id+languageID + sessionID + role_id +city_id + designation_id 
                        loginsessionID=profile_id+1033+ 111+ 1001 +2232+4004
                        # final_field=["loginsessionID","finalRights","Device","OS","Connectivity","Location","EVENT","DATE+TIME","Dowelltime"]
                        return (loginsessionID)
                        # dowellconnection("login","bangalore","login","dowell_users","dowell_users","1116","ABCDE","insert",final_field,"nil")
                    
                    return("Process ID not found")
                return("OS not found")
            return('Device not found')
        return("Connection not found")
    return("Location Not found in Database")

# Get next profile id by checking max id currently
def get_next_pro_id(res_list):
    list=[]
    for value in res_list:
        if 'profile_id' in value.keys() :
            list.append(value['profile_id'])
    return(max(list)+1)


"""
if(accuracy<face-accuracy):
return HttpResponse('face cannot be matched)
else:
if dowellsecuritylayer():
field={'userID','Varlocation'}
locRights=dowellconnection("login","bangalore","login","dowell_users","dowell_users","1116","ABCDE","insert",field,"nil")

field={'userID','VarConnectivity'}
connRights=dowellconnection("login","bangalore","login","dowell_users","dowell_users","1116","ABCDE","insert",field,"nil")                       

field={'userID','VarDevice'}
devRights=dowellconnection("login","bangalore","login","dowell_users","dowell_users","1116","ABCDE","insert",field,"nil")

field={'userID','VarOS'}
osRights=dowellconnection("login","bangalore","login","dowell_users","dowell_users","1116","ABCDE","insert",field,"nil")

field={'userID','VarProcessid'}
processRights=dowellconnection("login","bangalore","login","dowell_users","dowell_users","1116","ABCDE","insert",field,"nil")

field={'userID'}
userRights=dowellconnection("login","bangalore","login","dowell_users","dowell_users","1116","ABCDE","insert",field,"nil")

finalRights=dowellintersection('locRights','connRights','devRights','osRights','processRights','userRights')
loginsessionID= user ID+languageID + sessionID
final_field=["loginsessionID","finalRights","Device","OS","Connectivity","Location","EVENT","DATE+TIME","Dowelltime"]

dowellconnection("login","bangalore","login","dowell_users","dowell_users","1116","ABCDE","insert",final_field,"nil")

"""