from django.http import HttpResponse
from django.shortcuts import redirect


def unauthenticated_user(view_func):
    def wrapper_func(request, *args, **kwargs):
        username = request.session.get('username')
        if username is None:
            return view_func(request, *args, **kwargs)
        else:
            return redirect('home')

    return wrapper_func


def loginrequired(view_func):
    def wrapper_func(request, *args, **kwargs):
        useranme = request.session.get('sessionID')
        if useranme is None:
            return redirect('https://100014.pythonanywhere.com/login/login')
        return view_func(request, *args, **kwargs)
    return wrapper_func

