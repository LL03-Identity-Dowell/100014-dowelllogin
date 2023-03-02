import urllib.request
import random
import math
def host_check(host):
    try:
        urllib.request.urlopen(host)
        return "Connected"
    except:
        return "Error"
def generateOTP() :
     digits = "0123456789"
     OTP = ""
     for i in range(6) :
         OTP += digits[math.floor(random.random() * 10)]
     return OTP