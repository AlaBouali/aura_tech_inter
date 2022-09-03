

@app.route('/')
def urls_index_py__route():
    return flask.render_template('index.html')
    




"""
here we are going to:

1- fetch 2 variables for the same/current user
2- check if the "old_password" hash is the same as user's current password's hash
3- if they match , then we are going to create a new password hash and place it in one of the variables mentioned earlier (new_user) and finally update the user's records, else a flash message will display an error
"""
@app.route('/change_pwd', methods=['GET', 'POST'])
def urls_change_pwd_py__route():
    #print(session)
    if request.method=='POST':
        old_user=MongoDbAPI.mongo_read_one('Users',{"_id": ObjectId(SessionAPI.get_user_variable(session,'id'))})
        new_user=MongoDbAPI.mongo_read_one('Users',{"_id": ObjectId(SessionAPI.get_user_variable(session,'id'))})
        if PasswordsAPI.encrypt(request.form.get('old_password'))==old_user['password']:
            new_user['password']=PasswordsAPI.encrypt(request.form.get('new_password'))
            MongoDbAPI.mongo_update_one('Users',old_user,new_user)
            flask.flash(flask_admin.babel.gettext('password changed successfully.'), 'success')
        else:
            flask.flash(flask_admin.babel.gettext('incorrect old password.'), 'error')
    return flask.render_template('change_pwd.html')
    




"""
here we are going to:

1- fetch 2 variables for the same/current user
2- check if the "old_password" hash is the same as user's current password's hash
3- if they match , then we are going to create a new password hash and place it in one of the variables mentioned earlier (new_user) and finally update the user's records, else a flash message will display an error
"""
@app.route('/change_pwd/', methods=['GET', 'POST'])
def urls_change_pwd_py___route():
    #print(session)
    if request.method=='POST':
        old_user=MongoDbAPI.mongo_read_one('Users',{"_id": ObjectId(SessionAPI.get_user_variable(session,'id'))})
        new_user=MongoDbAPI.mongo_read_one('Users',{"_id": ObjectId(SessionAPI.get_user_variable(session,'id'))})
        if PasswordsAPI.encrypt(request.form.get('old_password'))==old_user['password']:
            new_user['password']=PasswordsAPI.encrypt(request.form.get('new_password'))
            MongoDbAPI.mongo_update_one('Users',old_user,new_user)
            flask.flash(flask_admin.babel.gettext('password changed successfully.'), 'success')
        else:
            flask.flash(flask_admin.babel.gettext('incorrect old password.'), 'error')
    return flask.render_template('change_pwd.html')
    




"""
This page will load all the users in the database and pass them as a list to the template "list-users.html" where their full names are hyper links with this format: /show-user-profile/<user_id>
"""
@app.route('/list-users')
def urls_list_users_py__route():
    users=MongoDbAPI().mongo_read_all('Users')
    if users:
        for user in users:
            user['id']=str(user['_id'])
            del user['_id']
    else:
        users={}
    return flask.render_template('list-users.html',users=users)
    




"""
This page will load all the users in the database and pass them as a list to the template "list-users.html" where their full names are hyper links with this format: /show-user-profile/<user_id>
"""
@app.route('/list-users/')
def urls_list_users_py___route():
    users=MongoDbAPI().mongo_read_all('Users')
    if users:
        for user in users:
            user['id']=str(user['_id'])
            del user['_id']
    else:
        users={}
    return flask.render_template('list-users.html',users=users)
    




"""
in the login process , as always , we will check if the email and password hash matches any in the database. if it does, then a user session will start and the whole informations from the user fetched will be added to the seesion for easy loading for the infos instead of loading them from the database each time !
"""
@app.route('/login', methods=['GET', 'POST'])
def urls_login_py__route():
    if request.method=='POST':
        user=MongoDbAPI.mongo_read_one('Users',{"email": request.form.get('email'),'password':PasswordsAPI.encrypt(request.form.get('password'))})
        if user:
            user['id']=str(user['_id'])
            del user['_id']
            SessionAPI.start_user_session(session,dict(user))
            return redirect('/')
        else:
            flask.flash(flask_admin.babel.gettext('incorrect email/password.'), 'error')
    return flask.render_template('login.html')
    




"""
in the login process , as always , we will check if the email and password hash matches any in the database. if it does, then a user session will start and the whole informations from the user fetched will be added to the seesion for easy loading for the infos instead of loading them from the database each time !
"""
@app.route('/login/', methods=['GET', 'POST'])
def urls_login_py___route():
    if request.method=='POST':
        user=MongoDbAPI.mongo_read_one('Users',{"email": request.form.get('email'),'password':PasswordsAPI.encrypt(request.form.get('password'))})
        if user:
            user['id']=str(user['_id'])
            del user['_id']
            SessionAPI.start_user_session(session,dict(user))
            return redirect('/')
        else:
            flask.flash(flask_admin.babel.gettext('incorrect email/password.'), 'error')
    return flask.render_template('login.html')
    





@app.route('/logout', methods=['GET', 'POST'])
def urls_logout_py__route():
    SessionAPI.end_user_session(session)
    return redirect('/')




@app.route('/logout/', methods=['GET', 'POST'])
def urls_logout_py___route():
    SessionAPI.end_user_session(session)
    return redirect('/')




"""
when the user tries to register, we check if all the inputs are filled then whether the email belongs to another user in the database. if everything is okay, then a new user record will be added and the user will be redirected to the login page
"""
@app.route('/register', methods=['GET', 'POST'])
def urls_register_py__route():
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
    





"""
when the user tries to register, we check if all the inputs are filled then whether the email belongs to another user in the database. if everything is okay, then a new user record will be added and the user will be redirected to the login page
"""
@app.route('/register/', methods=['GET', 'POST'])
def urls_register_py___route():
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
    




"""
first, we load all users and collect all their emails to pass them to the template where they will be useful for searching for the user to send money to (autosearch with js).
when the POST request is sent, wecheck if the amount of the money is in the correct range (0,current user's balance). then we get 2 variables for each user (sender/receiver) and update their balanes.

"""

@app.route('/send-money', methods=['GET', 'POST'])
def urls_send_money_py__route():
    users=MongoDbAPI.mongo_read_all('Users')
    emails=[]
    if users:
        for user in users:
            for x in user:
                if x=='email' and user[x]!=SessionAPI.get_user_variable(session,'email'):
                    emails.append(user[x])
    else:
        emails=[]
    if request.method=='POST':
        if int(request.form.get('amount',0)) in range(SessionAPI.get_user_variable(session,'balance')):
            old_recv=MongoDbAPI.mongo_read_one('Users',{"email": request.form.get('email')})
            old_send=MongoDbAPI.mongo_read_one('Users',{"email": SessionAPI.get_user_variable(session,'email')})
            new_recv=MongoDbAPI.mongo_read_one('Users',{"email": request.form.get('email')})
            new_send=MongoDbAPI.mongo_read_one('Users',{"email": SessionAPI.get_user_variable(session,'email')})
            new_recv['balance']=int(old_recv['balance'])+int(request.form.get('amount',0))
            new_send['balance']=int(old_send['balance'])-int(request.form.get('amount',0))
            MongoDbAPI.mongo_update_one('Users',old_send,new_send)
            MongoDbAPI.mongo_update_one('Users',old_recv,new_recv)
            SessionAPI.set_user_variables(session,{'balance':new_send['balance']})
        else:
            flask.flash(flask_admin.babel.gettext('No enough money.'), 'error')
    return flask.render_template('send-money.html',users=emails)
    




"""
first, we load all users and collect all their emails to pass them to the template where they will be useful for searching for the user to send money to (autosearch with js).
when the POST request is sent, wecheck if the amount of the money is in the correct range (0,current user's balance). then we get 2 variables for each user (sender/receiver) and update their balanes.

"""

@app.route('/send-money/', methods=['GET', 'POST'])
def urls_send_money_py___route():
    users=MongoDbAPI.mongo_read_all('Users')
    emails=[]
    if users:
        for user in users:
            for x in user:
                if x=='email' and user[x]!=SessionAPI.get_user_variable(session,'email'):
                    emails.append(user[x])
    else:
        emails=[]
    if request.method=='POST':
        if int(request.form.get('amount',0)) in range(SessionAPI.get_user_variable(session,'balance')):
            old_recv=MongoDbAPI.mongo_read_one('Users',{"email": request.form.get('email')})
            old_send=MongoDbAPI.mongo_read_one('Users',{"email": SessionAPI.get_user_variable(session,'email')})
            new_recv=MongoDbAPI.mongo_read_one('Users',{"email": request.form.get('email')})
            new_send=MongoDbAPI.mongo_read_one('Users',{"email": SessionAPI.get_user_variable(session,'email')})
            new_recv['balance']=int(old_recv['balance'])+int(request.form.get('amount',0))
            new_send['balance']=int(old_send['balance'])-int(request.form.get('amount',0))
            MongoDbAPI.mongo_update_one('Users',old_send,new_send)
            MongoDbAPI.mongo_update_one('Users',old_recv,new_recv)
            SessionAPI.set_user_variables(session,{'balance':new_send['balance']})
        else:
            flask.flash(flask_admin.babel.gettext('No enough money.'), 'error')
    return flask.render_template('send-money.html',users=emails)
    





"""
first we load the user from the database then update the session (just to keep the "balance" variable in the user session updated)
when the user update with POST request, if only the form inputs that have values are updated with new values before updating the user in the database and we make sure that the email is always uniques accross all users !
"""
@app.route('/update_profile', methods=['GET', 'POST'])
def urls_update_profile_py__route():
    user=MongoDbAPI.mongo_read_one('Users',{"_id": ObjectId(SessionAPI.get_user_variable(session,'id'))})
    if user:
            usr=dict(user)
            usr['id']=str(usr['_id'])
            del usr['_id']
            SessionAPI.start_user_session(session,dict(usr))
    if request.method=='POST':
        new_user=MongoDbAPI.mongo_read_one('Users',{"_id": ObjectId(SessionAPI.get_user_variable(session,'id'))})
        if request.form.get('firstname','').strip()!='':
            new_user['firstname']=request.form.get('firstname','')
            SessionAPI.set_user_variables(session,{'firstname':request.form.get('firstname','')})
        if request.form.get('lastname','').strip()!='':
            new_user['lastname']=request.form.get('lastname','')
            SessionAPI.set_user_variables(session,{'lastname':request.form.get('lastname','')})
        if request.form.get('telephone','').strip()!='':
            new_user['telephone']=request.form.get('telephone','')
            SessionAPI.set_user_variables(session,{'telephone':request.form.get('telephone','')})
        if request.files.get('image','').strip()!='':
            new_user['image']=request.files.get('image','')
            SessionAPI.set_user_variables(session,{'image':request.files.get('image','')})
        if request.form.get('email','').strip()!='' and SessionAPI.get_user_variable(session,'email')!=request.form.get('email',''):
            if MongoDbAPI.mongo_read_one('Users',{"email": request.form.get('email')}):
                flask.flash(flask_admin.babel.gettext('email already in use.'), 'error')
            else:
                if request.form.get('email','').strip()!='':
                    new_user['email']=request.form.get('email','')
                    SessionAPI.set_user_variables(session,{'email':request.form.get('email','')})
        MongoDbAPI.mongo_update_one('Users',user,new_user)
        flask.flash(flask_admin.babel.gettext('Profile updated successfully.'), 'success')
    return flask.render_template('update_profile.html')
    





"""
first we load the user from the database then update the session (just to keep the "balance" variable in the user session updated)
when the user update with POST request, if only the form inputs that have values are updated with new values before updating the user in the database and we make sure that the email is always uniques accross all users !
"""
@app.route('/update_profile/', methods=['GET', 'POST'])
def urls_update_profile_py___route():
    user=MongoDbAPI.mongo_read_one('Users',{"_id": ObjectId(SessionAPI.get_user_variable(session,'id'))})
    if user:
            usr=dict(user)
            usr['id']=str(usr['_id'])
            del usr['_id']
            SessionAPI.start_user_session(session,dict(usr))
    if request.method=='POST':
        new_user=MongoDbAPI.mongo_read_one('Users',{"_id": ObjectId(SessionAPI.get_user_variable(session,'id'))})
        if request.form.get('firstname','').strip()!='':
            new_user['firstname']=request.form.get('firstname','')
            SessionAPI.set_user_variables(session,{'firstname':request.form.get('firstname','')})
        if request.form.get('lastname','').strip()!='':
            new_user['lastname']=request.form.get('lastname','')
            SessionAPI.set_user_variables(session,{'lastname':request.form.get('lastname','')})
        if request.form.get('telephone','').strip()!='':
            new_user['telephone']=request.form.get('telephone','')
            SessionAPI.set_user_variables(session,{'telephone':request.form.get('telephone','')})
        if request.files.get('image','').strip()!='':
            new_user['image']=request.files.get('image','')
            SessionAPI.set_user_variables(session,{'image':request.files.get('image','')})
        if request.form.get('email','').strip()!='' and SessionAPI.get_user_variable(session,'email')!=request.form.get('email',''):
            if MongoDbAPI.mongo_read_one('Users',{"email": request.form.get('email')}):
                flask.flash(flask_admin.babel.gettext('email already in use.'), 'error')
            else:
                if request.form.get('email','').strip()!='':
                    new_user['email']=request.form.get('email','')
                    SessionAPI.set_user_variables(session,{'email':request.form.get('email','')})
        MongoDbAPI.mongo_update_one('Users',user,new_user)
        flask.flash(flask_admin.babel.gettext('Profile updated successfully.'), 'success')
    return flask.render_template('update_profile.html')
    




"""
here we take the "user_id" variable from the URL and use it to fetch the user from the database, if the "user_id" doesn't match any user, the it will returns "404 Not found" page
"""
@app.route('/show-user-profile/<user_id>')
def urls_show_user_profile__user_id__py__route(user_id):
    user=MongoDbAPI.mongo_read_one('Users',{"_id": ObjectId(user_id)})
    if user:
        user['id']=str(user['_id'])
        del user['_id']
    else:
        return flask.abort(404)
    return flask.render_template('show-user-profile/{user_id}.html',user=user)
    




"""
here we take the "user_id" variable from the URL and use it to fetch the user from the database, if the "user_id" doesn't match any user, the it will returns "404 Not found" page
"""
@app.route('/show-user-profile/<user_id>/')
def urls_show_user_profile__user_id__py___route(user_id):
    user=MongoDbAPI.mongo_read_one('Users',{"_id": ObjectId(user_id)})
    if user:
        user['id']=str(user['_id'])
        del user['_id']
    else:
        return flask.abort(404)
    return flask.render_template('show-user-profile/{user_id}.html',user=user)
    



