import datetime
import json
from dowellconnection1 import dowellconnection
def dowellclock():
        oldt=1609459200
        import time
        t1=time.time()
        dowell=t1-oldt
        return dowell
dd=datetime.datetime.now()
def dowelllogin(username, password):
#,image, voice,face_accuracy,voice_accuracy, language, sessionID,location, device, OSver, conn, processID):
    
    # loc=location
    # con=conn
    # dev=device
    # OS=OSver
    # pid=processID
    user=username
    passwd=password
    field={"Username":user,"Password":passwd}
    login=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",field,"nil")
    try:
        ls=json.loads(login)
        if len(ls)>=1:
            dicto=dict(ls[0])
            if dicto["Username"]:
                usr=dicto["Username"]
                usr_id=dicto["_id"]
                return (usr,usr_id)
                #fieldimage={"image":image}					
                # imageret=dowellconnection(cluster,platform,database,collection,document,team_member_ID,function_ID,INSERT,field,update_field)
                # fieldvoice={"voice":voice}									
                # voiceret=dowellconnection(cluster,platform,database,collection,document,team_member_ID,function_ID,INSERT,field,update_field)
                # voiceid=dowellvoiceid(user_id, location, voice)
                # voiceid1=json.loads(voiceid)
                # vaccuracy=voiceid1["accuracy"]
                # imageid=dowellvoiceid(user_id, location, voice)
                # imageid1=json.loads(imageid)
                # imgaccuracy=imageid1["accuracy"]
                # if imgaccuracy<face_accuracy:
                #     return "face cannot matched"
                # if imgaccuracy>face_accuracy:
                #     security=dowellSecurityLayer()
                #     if security:
                #         fieldloc={"user ID":user_id,"location":loc}
                #         locarr=dowellconnection(cluster,platform,database,collection,document,team_member_ID,function_ID,FETCH,fieldloc,update_field)
                #         arr_loc=json.loads(locarr)
                #         fieldconn={"user ID":user_id,"connectivity":con}
                #         connarr=dowellconnection(cluster,platform,database,collection,document,team_member_ID,function_ID,FETCH,fieldconn,update_field)
                #         arr_conn=json.loads(connarr)
                #         fielddev={"user ID":user_id,"device":dev}
                #         devarr=dowellconnection(cluster,platform,database,collection,document,team_member_ID,function_ID,FETCH,fielddev,update_field)
                #         arr_dev=json.loads(devarr)
                #         fieldos={"user ID":user_id,"OS":OSver}
                #         osarr=dowellconnection(cluster,platform,database,collection,document,team_member_ID,function_ID,FETCH,fieldos,update_field)
                #         arr_os=json.loads(osarr)
                #         fieldprocess={"user ID":user_id,"process_id":processID}
                #         processarr=dowellconnection(cluster,platform,database,collection,document,team_member_ID,function_ID,FETCH,fieldprocess,update_field)
                #         arr_process=json.loads(processarr)
                #         fieldusr={"user ID":user_id}
                #         usrarr=dowellconnection(cluster,platform,database,collection,document,team_member_ID,function_ID,FETCH,fieldusr,update_field)
                #         arr_usr=json.loads(usrarr)
                #         finalrt=dowellintersection(arr_loc,arr_conn,arr_dev,arr_os,arr_process,arr_usr)
                #         loginsessionID = user_id + language + sessionID
                #         fieldevent = [loginsessionID,finalrt, dev, OSver, con, loc, "EVENT", dd, dowellclock]
                #         EventId=dowellconnection(cluster,platform,database,collection,document,team_member_ID,function_ID,INSERT,fieldevent,update_field)
                #         return EventId
            else:
                return "User Not Found, Signup"
        else:
            return "User Not Found, Signup"
    except:
        return "something wrong"