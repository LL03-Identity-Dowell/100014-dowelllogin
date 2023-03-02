import urllib.request
def host_check(host):
    try:
        urllib.request.urlopen(host)
        return "Connected"
    except:
        return "Error"