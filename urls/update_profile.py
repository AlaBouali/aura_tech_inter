

"""
first we load the user from the database then update the session (just to keep the "balance" variable in the user session updated)
when the user update with POST request, if only the form inputs that have values are updated with new values before updating the user in the database and we make sure that the email is always uniques accross all users !
"""
@app.route('DefaultRoutePlaceHolder', methods=['GET', 'POST'])
def DefaultRouteFunctionPlaceHolder_route(DefaultVarsPlaceHolder):
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
    
