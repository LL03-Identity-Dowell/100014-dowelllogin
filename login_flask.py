import re
from dowellconnection1 import dowellconnection
from multiprocessing import context
from flask import Flask, Response, redirect, url_for, request, session, g, render_template
from aessecurity import AEScipher
from login_fun import dowelllogin
import os
app = Flask(__name__)
app.secret_key = os.urandom(24)
@app.route('/',methods =["GET","POST"])
def login():
    context={}
    if (request.method=="POST"):
            session.pop('username',None)
            form=request.form.to_dict()
            user=form["user"]
            pwd=form["pass"]
            # image=request.files['img']
            # image.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(image.filename)))
            # voice=request.files['voice']
            # voice.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(voice.filename)))
            # lang=form["language"]
            # loc=form["loc"]
            # device=form["dev"]
            # osver=form["os"]
            # conn=form["conn"]
            pwd1=AEScipher(pwd)
            userid=dowelllogin(user,pwd1.encrypt())
            if "User Not Found" in userid:
                context["signup"]="User Not Found : pl Register your account"
                # return redirect(url_for('login'))
            else:
                session['loggedin'] = True
                session['id'] = userid[1]
                session['username'] = userid[0]
                msg="this only readable page"
                return render_template('profile.html', msg = msg)
    return render_template("home.html",context=context)
@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))
@app.route('/home',methods =["GET","POST"])
def home():
    if g.user:
        return render_template("profile.html",user=session['username'])
    else:
        return redirect(url_for('login'))
@app.route('/register',methods =["POST"])
def register():
    if (request.method=="POST"):
        context={}
        form=request.form.to_dict()
        user=form["user"]
        field={"Username":user}
        login=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","fetch",field,"nil")
        
        pwd=form["pass"]
        first=form["first"]
        last=form["last"]
        email=form["email"]
        role=form["role"]
        ccode=form["ccode"]
        phone=form["phone"]
        if user in login:
            context["error"]="Username already exist"
            return render_template("test.html",context=context)
        elif phone in login:
            context["error"]="Phone number already exist"
            return render_template("test.html",context=context)
        elif email in login:
            context["error"]="Email already exist"
            return render_template("test.html",context=context)    
        if re.fullmatch(r'[A-Za-z0-9@#$%^&+=]{8,}', pwd):
            pwd1=AEScipher(pwd)
            try:
                field={"Username":user,"Password":pwd1.encrypt(),"Firstname":first,"Lastname":last,"Email":email,"Role":role,"Code":ccode,"Phone":phone}
                id=dowellconnection("login","bangalore","login","registration","registration","10004545","ABCDE","insert",field,"nil")
                #id=dowellconnection("mstr","bangalore","nysql","registration","registration","10004545","ABCDE","insert",field,"nil")
                context["error"]=id
                return render_template("test.html",context=context)
            except:
                context["error"]="pl check database connectivity"
                return render_template("test.html",context=context)
        else:
            context["error"]="password must be alpanumeric and special charecter"
            return render_template("test.html",context=context)       
@app.before_request
def before_request():
    g.user=None
    if 'username' in session:
        g.user=session["username"]

if __name__=='__main__':
    app.run(debug=True,ssl_context='adhoc')

