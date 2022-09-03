

"""
when the user tries to register, we check if all the inputs are filled then whether the email belongs to another user in the database. if everything is okay, then a new user record will be added and the user will be redirected to the login page
"""
@app.route('DefaultRoutePlaceHolder', methods=['GET', 'POST'])
def DefaultRouteFunctionPlaceHolder_route(DefaultVarsPlaceHolder):
    if request.method=='POST':
        complete=True
        if request.form.get('email','').strip()=='':
            complete=False
            flask.flash(flask_admin.babel.gettext('missing email.'), 'error')
        if request.form.get('firstname','').strip()=='':
            complete=False
            flask.flash(flask_admin.babel.gettext('missing firstname.'), 'error')
        if request.form.get('lastname','').strip()=='':
            complete=False
            flask.flash(flask_admin.babel.gettext('missing lastname.'), 'error')
        if request.form.get('telephone','').strip()=='':
            complete=False
            flask.flash(flask_admin.babel.gettext('missing telephone.'), 'error')
        if request.form.get('password','').strip()=='':
            complete=False
            flask.flash(flask_admin.babel.gettext('missing password.'), 'error')
        user=MongoDbAPI.mongo_read_one('Users',{"email": request.form.get('email')})
        if complete==True and user!=None:
            flask.flash(flask_admin.babel.gettext('email already in use.'), 'error')
        elif complete==True and user==None:
            data={}
            #we only take what we need from the form so no additional/malicious data will be inserted here
            for x in ['email','firstname','lastname','telephone','password']:
                data.update({x:request.form.get(x,'').strip()})
            data.update({'balance':100,'image':'/static/user_uploads/user_avatar.png'})
            data['password']=PasswordsAPI.encrypt(data['password'])
            MongoDbAPI.mongo_insert_one('Users',data)
            return redirect('/login')
    return flask.render_template('register.html')
    
