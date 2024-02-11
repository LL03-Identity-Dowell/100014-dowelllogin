import json
import requests
import datetime
start=datetime.datetime.now()
print(f"\n \t start time : {start} \n\n")
url = "http://uxlivinglab.pythonanywhere.com"

payload = json.dumps({
    "cluster": "login",
    "database": "login",
    "collection": "registration",
    "document": "registration",
    "team_member_ID": "10004545",
    "function_ID": "ABCDE",
    "command": "find",
    "field": {
        "Username":"lav"
    },
    "update_field": {
        "order_nos": 21
    },
    "platform": "bangalore"
})
headers = {
    'Content-Type': 'application/json'
}

response = requests.request("POST", url, headers=headers, data=payload)
endt=datetime.datetime.now()

print(response.text)
print(f"\n \t end time : {endt} \n")
total_time_taken=endt-start
print(f"\n \t total time : {total_time_taken}")
